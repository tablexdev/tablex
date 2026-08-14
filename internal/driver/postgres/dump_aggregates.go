package postgres

// The aggregate dump pass: CREATE OR REPLACE AGGREGATE reconstruction
// from the pg_aggregate surface. Split from dump_routines.go by role (the
// file-size ratchet keeps it that way).

import (
	"context"
	"database/sql"
	"strconv"
	"strings"

	"github.com/tablexdev/tablex/internal/driver"
)

// dumpAggregates reconstructs CREATE OR REPLACE AGGREGATE from the
// complete pg_aggregate surface — plain state, moving-aggregate state,
// combine/serial/deserial support, FINALFUNC_EXTRA/_MODIFY, SORTOP, PARALLEL —
// with aggkind selected EXPLICITLY: 'o' ordered-set and 'h' hypothetical-set
// share the direct/ORDER BY signature split (aggnumdirectargs), but only 'h'
// renders HYPOTHETICAL; without the kind a hypothetical aggregate would
// restore as a plain ordered-set one. Aggregates built on C support functions
// inherit the conditional shared-library caveat via those functions' own
// warnings.
func (d dialect) dumpAggregates(ctx context.Context, db *sql.DB, schema string, procDeps map[int64][]string, plan *driver.DumpPlan) error {
	qualify := func(name string) string { return d.QuoteIdent(schema) + "." + d.QuoteIdent(name) }
	rows, err := db.QueryContext(ctx, `
		SELECT p.oid, p.proname,
		       pg_get_function_identity_arguments(p.oid),
		       agg.aggkind::text, agg.aggnumdirectargs, p.pronargs,
		       agg.aggtransfn::regproc::text,
		       pg_catalog.format_type(agg.aggtranstype, NULL),
		       agg.aggtransspace,
		       CASE WHEN agg.aggfinalfn = 0 THEN '' ELSE agg.aggfinalfn::regproc::text END,
		       agg.aggfinalextra, agg.aggfinalmodify::text,
		       CASE WHEN agg.aggcombinefn = 0 THEN '' ELSE agg.aggcombinefn::regproc::text END,
		       CASE WHEN agg.aggserialfn = 0 THEN '' ELSE agg.aggserialfn::regproc::text END,
		       CASE WHEN agg.aggdeserialfn = 0 THEN '' ELSE agg.aggdeserialfn::regproc::text END,
		       agg.agginitval IS NOT NULL, COALESCE(agg.agginitval, ''),
		       CASE WHEN agg.aggmtransfn = 0 THEN '' ELSE agg.aggmtransfn::regproc::text END,
		       CASE WHEN agg.aggminvtransfn = 0 THEN '' ELSE agg.aggminvtransfn::regproc::text END,
		       CASE WHEN agg.aggmtranstype = 0 THEN '' ELSE pg_catalog.format_type(agg.aggmtranstype, NULL) END,
		       agg.aggmtransspace,
		       CASE WHEN agg.aggmfinalfn = 0 THEN '' ELSE agg.aggmfinalfn::regproc::text END,
		       agg.aggmfinalextra, agg.aggmfinalmodify::text,
		       agg.aggminitval IS NOT NULL, COALESCE(agg.aggminitval, ''),
		       CASE WHEN agg.aggsortop = 0 THEN '' ELSE agg.aggsortop::regoper::text END,
		       p.proparallel::text,
		       COALESCE((SELECT string_agg(
		           CASE args.mode WHEN 'v' THEN 'VARIADIC ' ELSE '' END ||
		           pg_catalog.format_type(args.typ, NULL), E'\x1f' ORDER BY args.ord)
		         FROM (SELECT u.ord, u.typ,
		                      CASE WHEN p.proargmodes IS NULL THEN 'i' ELSE p.proargmodes[u.ord] END AS mode
		               FROM unnest(COALESCE(p.proallargtypes, p.proargtypes::oid[])) WITH ORDINALITY AS u(typ, ord)) args), ''),
		       COALESCE(obj_description(p.oid, 'pg_proc'), '')
		FROM pg_proc p
		JOIN pg_aggregate agg ON agg.aggfnoid = p.oid
		JOIN pg_namespace n ON n.oid = p.pronamespace
		WHERE n.nspname = $1 AND p.prokind = 'a'
		  AND NOT EXISTS (SELECT 1 FROM pg_depend dep
		      WHERE dep.classid = 'pg_proc'::regclass AND dep.objid = p.oid AND dep.deptype = 'e')
		ORDER BY p.proname, pg_get_function_identity_arguments(p.oid)`, schema)
	if err != nil {
		return err
	}
	defer rows.Close()
	modify := func(code string) string {
		switch code {
		case "r":
			return "READ_ONLY"
		case "s":
			return "SHAREABLE"
		case "w":
			return "READ_WRITE"
		}
		return ""
	}
	for rows.Next() {
		var oid, ndirect, nargs, transspace, mtransspace int64
		var name, idArgs, aggkind, transfn, transtype, finalfn, finalmodify string
		var combinefn, serialfn, deserialfn, initval string
		var mtransfn, minvfn, mtranstype, mfinalfn, mfinalmodify, minitval string
		var sortop, parallel, argsRaw, comment string
		var finalextra, hasInit, mfinalextra, hasMinit bool
		if err := rows.Scan(&oid, &name, &idArgs, &aggkind, &ndirect, &nargs,
			&transfn, &transtype, &transspace,
			&finalfn, &finalextra, &finalmodify,
			&combinefn, &serialfn, &deserialfn,
			&hasInit, &initval,
			&mtransfn, &minvfn, &mtranstype, &mtransspace,
			&mfinalfn, &mfinalextra, &mfinalmodify,
			&hasMinit, &minitval,
			&sortop, &parallel, &argsRaw, &comment); err != nil {
			return err
		}
		var argList []string
		if argsRaw != "" {
			argList = strings.Split(argsRaw, "\x1f")
		}
		var sig string
		switch {
		case aggkind != "n":
			// Ordered-set / hypothetical signature split. When every argument is
			// direct (the VARIADIC "any" hypothetical shape) the ORDER BY list
			// repeats the trailing variadic (pg_dump parity).
			nd := int(ndirect)
			if len(argList) == 0 {
				// aggnumdirectargs > 0 with no argument list is not a shape the
				// catalog can produce, but the else-branch below slices
				// argList[:nd] behind a guard that only covered len > 0 — so such
				// a row would PANIC rather than degrade. Skip it with a warning,
				// exactly as the type dumper does for shapes it cannot render.
				plan.Warnings = append(plan.Warnings,
					"aggregate "+schema+"."+name+" was not dumped (ordered-set aggregate with no argument list); dependents may fail to restore")
				continue
			}
			if nd < 0 || nd >= len(argList) {
				sig = "(" + strings.Join(argList, ", ") + " ORDER BY " + argList[len(argList)-1] + ")"
			} else {
				sig = "(" + strings.Join(argList[:nd], ", ") + " ORDER BY " + strings.Join(argList[nd:], ", ") + ")"
			}
		case len(argList) == 0:
			sig = "(*)"
		default:
			sig = "(" + strings.Join(argList, ", ") + ")"
		}
		opts := []string{"SFUNC = " + transfn, "STYPE = " + transtype}
		if transspace > 0 {
			opts = append(opts, "SSPACE = "+strconv.FormatInt(transspace, 10))
		}
		if finalfn != "" {
			opts = append(opts, "FINALFUNC = "+finalfn)
			if finalextra {
				opts = append(opts, "FINALFUNC_EXTRA")
			}
			if m := modify(finalmodify); m != "" {
				opts = append(opts, "FINALFUNC_MODIFY = "+m)
			}
		}
		if combinefn != "" {
			opts = append(opts, "COMBINEFUNC = "+combinefn)
		}
		if serialfn != "" {
			opts = append(opts, "SERIALFUNC = "+serialfn)
		}
		if deserialfn != "" {
			opts = append(opts, "DESERIALFUNC = "+deserialfn)
		}
		if hasInit {
			opts = append(opts, "INITCOND = "+d.QuoteString(initval))
		}
		if mtransfn != "" {
			opts = append(opts, "MSFUNC = "+mtransfn, "MINVFUNC = "+minvfn, "MSTYPE = "+mtranstype)
			if mtransspace > 0 {
				opts = append(opts, "MSSPACE = "+strconv.FormatInt(mtransspace, 10))
			}
			if mfinalfn != "" {
				opts = append(opts, "MFINALFUNC = "+mfinalfn)
				if mfinalextra {
					opts = append(opts, "MFINALFUNC_EXTRA")
				}
				if m := modify(mfinalmodify); m != "" {
					opts = append(opts, "MFINALFUNC_MODIFY = "+m)
				}
			}
			if hasMinit {
				opts = append(opts, "MINITCOND = "+d.QuoteString(minitval))
			}
		}
		if sortop != "" {
			// An operator name cannot contain '.', so a dot means a schema
			// qualification — wrap in OPERATOR() (required for qualified names).
			if strings.Contains(sortop, ".") {
				sortop = "OPERATOR(" + sortop + ")"
			}
			opts = append(opts, "SORTOP = "+sortop)
		}
		if aggkind == "h" {
			opts = append(opts, "HYPOTHETICAL")
		}
		switch parallel {
		case "s":
			opts = append(opts, "PARALLEL = SAFE")
		case "r":
			opts = append(opts, "PARALLEL = RESTRICTED")
		}
		// DROP AGGREGATE takes the aggregate-shaped signature — the same
		// direct/ORDER BY split as the CREATE, and (*) for a zero-argument
		// aggregate — which plain identity arguments cannot express. A grouped
		// DROP ROUTINE instead needs the FLAT input list (aggregates have no OUT
		// arguments, so it is every argument with the VARIADIC marker dropped).
		flat := make([]string, 0, len(argList))
		for _, a := range argList {
			flat = append(flat, strings.TrimPrefix(a, "VARIADIC "))
		}
		plan.Routines = append(plan.Routines, driver.DumpScript{
			Kind:      "routine",
			Name:      routineNodeID(schema, name, idArgs),
			DependsOn: procDeps[oid],
			Comment:   "Aggregate " + name,
			Drop:      "DROP AGGREGATE IF EXISTS " + qualify(name) + sig,
			DropForm: driver.DropForm{
				Class:      "AGGREGATE",
				Ref:        qualify(name) + sig,
				RoutineRef: qualify(name) + "(" + strings.Join(flat, ", ") + ")",
			},
			SQL: "CREATE OR REPLACE AGGREGATE " + qualify(name) + sig + " (" + strings.Join(opts, ", ") + ")",
		})
		if comment != "" {
			// The aggregate-shaped sig, exactly as the DROP above uses it: a
			// zero-argument aggregate is (*) in the aggr_args grammar, which
			// plain identity arguments cannot express — f() is a syntax error
			// on restore.
			plan.Routines = append(plan.Routines, driver.DumpScript{
				Kind:    "routine",
				Comment: "Comment for aggregate " + name,
				SQL:     "COMMENT ON AGGREGATE " + qualify(name) + sig + " IS " + d.QuoteString(comment),
			})
		}
	}
	return rows.Err()
}
