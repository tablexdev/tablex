// Routine-adjacent dump passes that pg_get_functiondef cannot produce:
// aggregates (reconstructed from the full pg_aggregate surface), operators,
// operator families and operator classes.

package postgres

import (
	"context"
	"database/sql"
	"strconv"
	"strings"

	"github.com/tablexdev/tablex/internal/driver"
)

// dumpOperators emits the schema's user operators, operator FAMILIES
// and operator CLASSES. Commutator/negator links restore via the CREATE-only
// define-first bootstrap on every supported version: for an in-scope mutual
// pair only the LATER operator (collection order) names the link — PostgreSQL
// backfills the earlier one — because ALTER OPERATOR SET
// (COMMUTATOR/NEGATOR/HASHES/MERGES) is PG17+ and must never be emitted
// (PG13–16 allow only RESTRICT/JOIN there). HASHES/MERGES ride the CREATE
// clauses (all versions). An explicitly-named family (no same-named opclass)
// gets its own CREATE OPERATOR FAMILY; class-owned members (pg_depend
// ownership on the OPCLASS, never a cross-type heuristic) ride the CREATE
// OPERATOR CLASS body; family-loose members ride ALTER OPERATOR FAMILY … ADD.
// Access method is part of every identity. Operator-family Drop is
// deliberately EMPTY: DROP OPERATOR FAMILY drops contained (possibly
// target-only) opclasses even without CASCADE — the collateral-drop hazard.
func (d dialect) dumpOperators(ctx context.Context, db *sql.DB, schema string, r *dumpNodeResolver, plan *driver.DumpPlan) error {
	// Operators. A shell operator (oprcode = 0 — created by a forward
	// commutator/negator reference that was never defined) is skipped like
	// pg_dump does; the backfill recreates it on restore.
	opRows, err := db.QueryContext(ctx, `
		SELECT o.oid, o.oprname,
		       o.oprleft, CASE WHEN o.oprleft = 0 THEN '' ELSE pg_catalog.format_type(o.oprleft, NULL) END,
		       o.oprright, CASE WHEN o.oprright = 0 THEN '' ELSE pg_catalog.format_type(o.oprright, NULL) END,
		       o.oprcode::regproc::text, o.oprcode::oid,
		       o.oprcom, CASE WHEN o.oprcom = 0 THEN '' ELSE o.oprcom::regoper::text END,
		       o.oprnegate, CASE WHEN o.oprnegate = 0 THEN '' ELSE o.oprnegate::regoper::text END,
		       CASE WHEN o.oprrest = 0 THEN '' ELSE o.oprrest::regproc::text END,
		       CASE WHEN o.oprjoin = 0 THEN '' ELSE o.oprjoin::regproc::text END,
		       o.oprcanhash, o.oprcanmerge,
		       COALESCE(obj_description(o.oid, 'pg_operator'), ''),
		       COALESCE((SELECT e.extname FROM pg_depend dep JOIN pg_extension e ON e.oid = dep.refobjid
		                 WHERE dep.classid = 'pg_operator'::regclass AND dep.objid = o.oid AND dep.deptype = 'e'
		                 LIMIT 1), '')
		FROM pg_operator o
		JOIN pg_namespace n ON n.oid = o.oprnamespace
		WHERE n.nspname = $1 AND o.oprcode <> 0
		ORDER BY o.oprname, o.oprleft, o.oprright`, schema)
	if err != nil {
		return err
	}
	type opRow struct {
		oid, left, right, codeOID, comOID, negOID int64
		name, leftT, rightT, code                 string
		com, neg, rest, join                      string
		canHash, canMerge                         bool
		comment, ext                              string
	}
	var ops []opRow
	seenOp := map[int64]int{} // oid → 1-based collection position (define-first split)
	for opRows.Next() {
		var o opRow
		if err := opRows.Scan(&o.oid, &o.name, &o.left, &o.leftT, &o.right, &o.rightT,
			&o.code, &o.codeOID, &o.comOID, &o.com, &o.negOID, &o.neg,
			&o.rest, &o.join, &o.canHash, &o.canMerge, &o.comment, &o.ext); err != nil {
			opRows.Close()
			return err
		}
		ops = append(ops, o)
		seenOp[o.oid] = len(ops)
	}
	opRows.Close()
	if err := opRows.Err(); err != nil {
		return err
	}
	wrapOp := func(name string) string {
		if strings.Contains(name, ".") {
			return "OPERATOR(" + name + ")"
		}
		return name
	}
	for i, o := range ops {
		if o.ext != "" {
			plan.Warnings = append(plan.Warnings,
				"operator "+schema+"."+o.name+" belongs to extension "+o.ext+" and is not dumped; CREATE EXTENSION "+o.ext+" in the target recreates it only if it is part of the extension's install script")
			continue
		}
		var deps []string
		opts := []string{"FUNCTION = " + o.code}
		if id := r.proc[o.codeOID]; id != "" {
			deps = append(deps, id)
		}
		if o.leftT != "" {
			opts = append(opts, "LEFTARG = "+o.leftT)
			if id := r.typ[o.left]; id != "" {
				deps = append(deps, id)
			}
		}
		if o.rightT != "" {
			opts = append(opts, "RIGHTARG = "+o.rightT)
			if id := r.typ[o.right]; id != "" {
				deps = append(deps, id)
			}
		}
		// Define-first bootstrap: name an IN-SCOPE commutator/negator only from
		// the LATER member of the pair (or a self-commutator); the CREATE then
		// backfills the earlier/link target. Out-of-scope links are named as-is
		// (boundary — restoring creates a shell the target completes).
		linkFrom := func(kw string, target int64, ref string) {
			if target == 0 || ref == "" {
				return
			}
			if pos, inScope := seenOp[target]; inScope && target != o.oid && pos > i+1 {
				return // the LATER pair member names the link
			}
			opts = append(opts, kw+" = "+wrapOp(ref))
			if target != o.oid {
				if id := r.op[target]; id != "" {
					deps = append(deps, id)
				}
			}
		}
		linkFrom("COMMUTATOR", o.comOID, o.com)
		linkFrom("NEGATOR", o.negOID, o.neg)
		if o.rest != "" && o.rest != "-" {
			opts = append(opts, "RESTRICT = "+o.rest)
		}
		if o.join != "" && o.join != "-" {
			opts = append(opts, "JOIN = "+o.join)
		}
		if o.canHash {
			opts = append(opts, "HASHES")
		}
		if o.canMerge {
			opts = append(opts, "MERGES")
		}
		qop := d.QuoteIdent(schema) + "." + o.name
		leftDrop, rightDrop := o.leftT, o.rightT
		if leftDrop == "" {
			leftDrop = "NONE"
		}
		if rightDrop == "" {
			rightDrop = "NONE"
		}
		plan.Routines = append(plan.Routines, driver.DumpScript{
			Kind:      "operator",
			Name:      r.op[o.oid],
			DependsOn: deps,
			Comment:   "Operator " + o.name,
			Drop:      "DROP OPERATOR IF EXISTS " + qop + " (" + leftDrop + ", " + rightDrop + ")",
			DropForm:  driver.DropForm{Class: "OPERATOR", Ref: qop + " (" + leftDrop + ", " + rightDrop + ")"},
			SQL:       "CREATE OPERATOR " + qop + " (" + strings.Join(opts, ", ") + ")",
		})
		if o.comment != "" {
			plan.Routines = append(plan.Routines, driver.DumpScript{
				Kind:    "operator",
				Comment: "Comment for operator " + o.name,
				SQL:     "COMMENT ON OPERATOR " + qop + " (" + leftDrop + ", " + rightDrop + ") IS " + d.QuoteString(o.comment),
			})
		}
	}

	// Operator families: an explicit CREATE only when no same-named opclass
	// (same AM) exists — an opclass without a FAMILY clause auto-creates its
	// same-named family.
	famRows, err := db.QueryContext(ctx, `
		SELECT f.oid, am.amname, f.opfname,
		       COALESCE(obj_description(f.oid, 'pg_opfamily'), ''),
		       EXISTS (SELECT 1 FROM pg_opclass oc
		               WHERE oc.opcfamily = f.oid AND oc.opcname = f.opfname AND oc.opcmethod = f.opfmethod),
		       COALESCE((SELECT e.extname FROM pg_depend dep JOIN pg_extension e ON e.oid = dep.refobjid
		                 WHERE dep.classid = 'pg_opfamily'::regclass AND dep.objid = f.oid AND dep.deptype = 'e'
		                 LIMIT 1), '')
		FROM pg_opfamily f
		JOIN pg_am am ON am.oid = f.opfmethod
		JOIN pg_namespace n ON n.oid = f.opfnamespace
		WHERE n.nspname = $1
		ORDER BY am.amname, f.opfname`, schema)
	if err != nil {
		return err
	}
	type famRow struct {
		oid               int64
		am, name, comment string
		implicit          bool
		ext               string
	}
	var fams []famRow
	for famRows.Next() {
		var f famRow
		if err := famRows.Scan(&f.oid, &f.am, &f.name, &f.comment, &f.implicit, &f.ext); err != nil {
			famRows.Close()
			return err
		}
		fams = append(fams, f)
	}
	famRows.Close()
	if err := famRows.Err(); err != nil {
		return err
	}
	for _, f := range fams {
		if f.ext != "" {
			plan.Warnings = append(plan.Warnings,
				"operator family "+schema+"."+f.name+" USING "+f.am+" belongs to extension "+f.ext+" and is not dumped")
			continue
		}
		qfam := d.QuoteIdent(schema) + "." + d.QuoteIdent(f.name)
		if !f.implicit {
			plan.Routines = append(plan.Routines, driver.DumpScript{
				Kind:    "opfamily",
				Name:    r.opf[f.oid],
				Comment: "Operator family " + f.name + " USING " + f.am,
				// Drop deliberately EMPTY: DROP OPERATOR FAMILY drops contained,
				// possibly target-only opclasses even without CASCADE.
				SQL: "CREATE OPERATOR FAMILY " + qfam + " USING " + d.QuoteIdent(f.am),
			})
		}
		if f.comment != "" {
			plan.Routines = append(plan.Routines, driver.DumpScript{
				Kind:    "opfamily",
				Comment: "Comment for operator family " + f.name,
				SQL:     "COMMENT ON OPERATOR FAMILY " + qfam + " USING " + d.QuoteIdent(f.am) + " IS " + d.QuoteString(f.comment),
			})
		}
	}

	// Members: pg_amop/pg_amproc rows classified class-owned vs family-loose by
	// their pg_depend OWNERSHIP edge (refclassid pg_opclass vs pg_opfamily) —
	// never by a cross-type heuristic (GIN/GiST/SP-GiST make soft family
	// dependencies regardless of operand types).
	type member struct {
		text string
		deps []string
	}
	classMembers := map[int64][]member{} // opclass oid → members
	looseMembers := map[int64][]member{} // opfamily oid → members
	amopRows, err := db.QueryContext(ctx, `
		SELECT ao.amopfamily, ao.amopstrategy,
		       ao.amopopr::regoperator::text, ao.amopopr,
		       ao.amoppurpose::text,
		       CASE WHEN ao.amopsortfamily = 0 THEN '' ELSE
		         (SELECT quote_ident(sn.nspname) || '.' || quote_ident(sf.opfname)
		          FROM pg_opfamily sf JOIN pg_namespace sn ON sn.oid = sf.opfnamespace
		          WHERE sf.oid = ao.amopsortfamily) END,
		       dep.refclassid::regclass::text, dep.refobjid
		FROM pg_amop ao
		JOIN pg_opfamily f ON f.oid = ao.amopfamily
		JOIN pg_namespace n ON n.oid = f.opfnamespace
		JOIN pg_depend dep ON dep.classid = 'pg_amop'::regclass AND dep.objid = ao.oid
		  AND dep.refclassid IN ('pg_opclass'::regclass, 'pg_opfamily'::regclass)
		WHERE n.nspname = $1
		ORDER BY ao.amopstrategy, ao.amoplefttype, ao.amoprighttype`, schema)
	if err != nil {
		return err
	}
	for amopRows.Next() {
		var famOID, oprOID, ownerOID int64
		var strategy int
		var opr, purpose, sortFam, ownerClass string
		if err := amopRows.Scan(&famOID, &strategy, &opr, &oprOID, &purpose, &sortFam, &ownerClass, &ownerOID); err != nil {
			amopRows.Close()
			return err
		}
		m := member{text: "OPERATOR " + strconv.Itoa(strategy) + " " + opr}
		if purpose == "o" && sortFam != "" {
			m.text += " FOR ORDER BY " + sortFam
		}
		if id := r.op[oprOID]; id != "" {
			m.deps = append(m.deps, id)
		}
		if ownerClass == "pg_opclass" {
			classMembers[ownerOID] = append(classMembers[ownerOID], m)
		} else {
			looseMembers[famOID] = append(looseMembers[famOID], m)
		}
	}
	amopRows.Close()
	if err := amopRows.Err(); err != nil {
		return err
	}
	amprocRows, err := db.QueryContext(ctx, `
		SELECT ap.amprocfamily, ap.amprocnum,
		       pg_catalog.format_type(ap.amproclefttype, NULL), pg_catalog.format_type(ap.amprocrighttype, NULL),
		       ap.amproc::regprocedure::text, ap.amproc::oid,
		       dep.refclassid::regclass::text, dep.refobjid
		FROM pg_amproc ap
		JOIN pg_opfamily f ON f.oid = ap.amprocfamily
		JOIN pg_namespace n ON n.oid = f.opfnamespace
		JOIN pg_depend dep ON dep.classid = 'pg_amproc'::regclass AND dep.objid = ap.oid
		  AND dep.refclassid IN ('pg_opclass'::regclass, 'pg_opfamily'::regclass)
		WHERE n.nspname = $1
		ORDER BY ap.amprocnum, ap.amproclefttype, ap.amprocrighttype`, schema)
	if err != nil {
		return err
	}
	for amprocRows.Next() {
		var famOID, fnOID, ownerOID int64
		var num int
		var leftT, rightT, fn, ownerClass string
		if err := amprocRows.Scan(&famOID, &num, &leftT, &rightT, &fn, &fnOID, &ownerClass, &ownerOID); err != nil {
			amprocRows.Close()
			return err
		}
		m := member{text: "FUNCTION " + strconv.Itoa(num) + " (" + leftT + ", " + rightT + ") " + fn}
		if id := r.proc[fnOID]; id != "" {
			m.deps = append(m.deps, id)
		}
		if ownerClass == "pg_opclass" {
			classMembers[ownerOID] = append(classMembers[ownerOID], m)
		} else {
			looseMembers[famOID] = append(looseMembers[famOID], m)
		}
	}
	amprocRows.Close()
	if err := amprocRows.Err(); err != nil {
		return err
	}

	// Operator classes with their class-owned members inline.
	opcRows, err := db.QueryContext(ctx, `
		SELECT c.oid, am.amname, c.opcname,
		       pg_catalog.format_type(c.opcintype, NULL), c.opcintype, c.opcdefault,
		       CASE WHEN c.opckeytype = 0 THEN '' ELSE pg_catalog.format_type(c.opckeytype, NULL) END,
		       c.opcfamily, f.opfname, fn.nspname,
		       (c.opcname = f.opfname AND c.opcmethod = f.opfmethod AND c.opcnamespace = f.opfnamespace),
		       COALESCE(obj_description(c.oid, 'pg_opclass'), ''),
		       COALESCE((SELECT e.extname FROM pg_depend dep JOIN pg_extension e ON e.oid = dep.refobjid
		                 WHERE dep.classid = 'pg_opclass'::regclass AND dep.objid = c.oid AND dep.deptype = 'e'
		                 LIMIT 1), '')
		FROM pg_opclass c
		JOIN pg_am am ON am.oid = c.opcmethod
		JOIN pg_opfamily f ON f.oid = c.opcfamily
		JOIN pg_namespace fn ON fn.oid = f.opfnamespace
		JOIN pg_namespace n ON n.oid = c.opcnamespace
		WHERE n.nspname = $1
		ORDER BY am.amname, c.opcname`, schema)
	if err != nil {
		return err
	}
	for opcRows.Next() {
		var oid, intypeOID, famOID int64
		var am, name, intype, keytype, famName, famSchema, comment, ext string
		var isDefault, sameNamedFam bool
		if err := opcRows.Scan(&oid, &am, &name, &intype, &intypeOID, &isDefault, &keytype,
			&famOID, &famName, &famSchema, &sameNamedFam, &comment, &ext); err != nil {
			opcRows.Close()
			return err
		}
		if ext != "" {
			plan.Warnings = append(plan.Warnings,
				"operator class "+schema+"."+name+" USING "+am+" belongs to extension "+ext+" and is not dumped")
			continue
		}
		qopc := d.QuoteIdent(schema) + "." + d.QuoteIdent(name)
		sql := "CREATE OPERATOR CLASS " + qopc
		if isDefault {
			sql += " DEFAULT"
		}
		sql += " FOR TYPE " + intype + " USING " + d.QuoteIdent(am)
		var deps []string
		if id := r.typ[intypeOID]; id != "" {
			deps = append(deps, id)
		}
		if !sameNamedFam {
			sql += " FAMILY " + d.QuoteIdent(famSchema) + "." + d.QuoteIdent(famName)
			if id := r.opf[famOID]; id != "" {
				deps = append(deps, id)
			}
		}
		var items []string
		for _, m := range classMembers[oid] {
			items = append(items, m.text)
			deps = append(deps, m.deps...)
		}
		if keytype != "" {
			items = append(items, "STORAGE "+keytype)
		}
		if len(items) == 0 {
			// Every member is family-loose (declared with explicit operand types)
			// and there is no explicit key type: the grammar needs at least one
			// item, and STORAGE = the input type is a faithful no-op (PostgreSQL
			// normalizes it back to opckeytype 0).
			items = append(items, "STORAGE "+intype)
		}
		sql += " AS\n  " + strings.Join(items, ",\n  ")
		plan.Routines = append(plan.Routines, driver.DumpScript{
			Kind:      "opclass",
			Name:      r.opc[oid],
			DependsOn: deps,
			Comment:   "Operator class " + name + " USING " + am,
			Drop:      d.opclassDropStatement(qopc, am),
			// DROP OPERATOR CLASS has single-object syntax only: never grouped.
			SQL: sql,
		})
		if comment != "" {
			plan.Routines = append(plan.Routines, driver.DumpScript{
				Kind:    "opclass",
				Comment: "Comment for operator class " + name,
				SQL:     "COMMENT ON OPERATOR CLASS " + qopc + " USING " + d.QuoteIdent(am) + " IS " + d.QuoteString(comment),
			})
		}
	}
	opcRows.Close()
	if err := opcRows.Err(); err != nil {
		return err
	}

	// Family-loose members (added via ALTER OPERATOR FAMILY … ADD in the
	// source; the ownership edge points at the FAMILY). An IMPLICIT family has
	// no CREATE script of its own — it materializes with its same-named
	// opclass — so the ADD depends on the OPCLASS node instead.
	for _, f := range fams {
		if f.ext != "" {
			continue
		}
		members := looseMembers[f.oid]
		if len(members) == 0 {
			continue
		}
		famDep := r.opf[f.oid]
		if f.implicit {
			famDep = "opclass:" + f.am + "\x00" + schema + "\x00" + f.name
		}
		var items []string
		deps := []string{famDep}
		for _, m := range members {
			items = append(items, m.text)
			deps = append(deps, m.deps...)
		}
		qfam := d.QuoteIdent(schema) + "." + d.QuoteIdent(f.name)
		plan.Routines = append(plan.Routines, driver.DumpScript{
			Kind:      "opfamily",
			Name:      "opfamily-add:" + f.am + "\x00" + schema + "\x00" + f.name,
			DependsOn: deps,
			// The loose members are part of the family's own definition, so
			// this ALTER is a second CREATION STAGE of famDep — the family, or
			// (for an implicit family) the opclass that materializes it. That
			// puts the member edges on the surviving object: a retained family
			// still HOLDS its members, so their drops must be retained with it,
			// while an implicit family's members drop with their opclass.
			StageOf: famDep,
			Comment: "Loose members of operator family " + f.name,
			SQL:     "ALTER OPERATOR FAMILY " + qfam + " USING " + d.QuoteIdent(f.am) + " ADD\n  " + strings.Join(items, ",\n  "),
		})
	}
	return nil
}

// builtinAccessMethods are the index access methods every PostgreSQL server
// ships (pinned at initdb). Any other name is extension-provided, so it may be
// ABSENT from a restore target — which is what makes an operator-class drop
// naming it unsafe (see opclassDropStatement).
var builtinAccessMethods = map[string]bool{
	"btree": true, "hash": true, "gist": true, "gin": true, "spgist": true, "brin": true,
}

// opclassDropStatement renders a FRESH-TARGET-SAFE teardown drop for one
// operator class. Every other class TableX drops — routines, aggregates,
// casts, operators — no-ops harmlessly under `IF EXISTS` on a fresh target even
// when its identity names a user-defined type that does not exist yet, because
// PostgreSQL propagates missing_ok into that type lookup (verified live). The
// ONE exception is the access method: get_object_address_opcf resolves it with
// missing_ok=false, so `DROP OPERATOR CLASS … USING custom_am` raises
// undefined_object even under IF EXISTS, and the importer aborts at the first
// error. For a non-built-in access method the drop is therefore wrapped in an
// error-tolerant DO guard (PL/pgSQL — the default language) with two escaping
// layers: QuoteString doubles any ' in the identifier so it cannot terminate
// the EXECUTE literal, and the dollar tag is chosen to appear nowhere in the
// body so an identifier containing $$ cannot terminate the block.
func (d dialect) opclassDropStatement(qopc, am string) string {
	drop := "DROP OPERATOR CLASS IF EXISTS " + qopc + " USING " + d.QuoteIdent(am)
	if builtinAccessMethods[am] {
		return drop
	}
	body := "BEGIN EXECUTE " + d.QuoteString(drop) + "; EXCEPTION WHEN undefined_object THEN NULL; END"
	tag := collisionFreeDollarTag(body)
	return "DO " + tag + " " + body + " " + tag
}

// collisionFreeDollarTag returns a dollar-quote tag that does not occur in body.
func collisionFreeDollarTag(body string) string {
	for i := 0; ; i++ {
		tag := "$tablex$"
		if i > 0 {
			tag = "$tablex" + strconv.Itoa(i) + "$"
		}
		if !strings.Contains(body, tag) {
			return tag
		}
	}
}

// dumpRoutines emits the schema's functions and procedures, and returns each
// routine's resolved dependency edges keyed by OID — dumpAggregates reuses them
// rather than re-reading pg_depend.
func (o *objectDump) dumpRoutines(ctx context.Context, db *sql.DB) (map[int64][]string, error) {
	d, schema, resolver := o.d, o.schema, o.resolver
	qualify, plan := o.qualify, &o.plan

	// Each routine's dependency edges from pg_depend — a PG14+ SQL-body
	// (BEGIN ATOMIC) routine records real edges to the tables/views/routines
	// its body reads (parsed at creation, NOT deferred by
	// check_function_bodies), and every routine records edges for its
	// argument-DEFAULT expressions and user-type signature. These drive the
	// pre-data topological order and the cycle staging below.
	type procRef struct {
		class string
		oid   int64
	}
	procRefs := map[int64][]procRef{}
	procDeps := map[int64][]string{}
	pdRows, err := db.QueryContext(ctx, `
		SELECT p.oid, dep.refclassid::regclass::text, dep.refobjid
		FROM pg_proc p
		JOIN pg_namespace n ON n.oid = p.pronamespace
		JOIN pg_depend dep ON dep.classid = 'pg_proc'::regclass
		  AND dep.objid = p.oid AND dep.deptype = 'n'
		WHERE n.nspname = $1
		  AND dep.refclassid IN ('pg_class'::regclass, 'pg_proc'::regclass, 'pg_type'::regclass, 'pg_operator'::regclass)`, schema)
	if err != nil {
		return nil, err
	}
	for pdRows.Next() {
		var oid, refOID int64
		var refClass string
		if err := pdRows.Scan(&oid, &refClass, &refOID); err != nil {
			pdRows.Close()
			return nil, err
		}
		procRefs[oid] = append(procRefs[oid], procRef{refClass, refOID})
		if id := resolver.resolveRef(refClass, refOID); id != "" {
			procDeps[oid] = append(procDeps[oid], id)
		}
	}
	pdRows.Close()
	if err := pdRows.Err(); err != nil {
		return nil, err
	}

	// Routines: full definitions, excluding extension-owned ones. The dump
	// preamble sets check_function_bodies=false, so string-literal bodies
	// referencing objects created later in the dump still restore; atomic
	// bodies rely on the graph edges above instead. The defaultless argument
	// list and result feed the cycle STUB: same signature, every
	// argument default omitted (the whole trailing group — a partial
	// omission is invalid DDL), an unchecked placeholder body; the original
	// CREATE OR REPLACE then restores body/language/defaults as the "-final"
	// stage. TABLE(...) columns (mode 't') ride the result, not the list.
	rrows, err := db.QueryContext(ctx, `
		SELECT p.oid, p.proname,
		       CASE p.prokind WHEN 'p' THEN 'Procedure' ELSE 'Function' END,
		       p.prokind::text, l.lanname,
		       pg_get_functiondef(p.oid),
		       pg_get_function_identity_arguments(p.oid),
		       COALESCE(pg_get_function_result(p.oid), ''),
		       COALESCE((SELECT string_agg(
		           CASE args.mode WHEN 'o' THEN 'OUT ' WHEN 'b' THEN 'INOUT ' WHEN 'v' THEN 'VARIADIC ' ELSE '' END ||
		           CASE WHEN args.argname IS NULL OR args.argname = '' THEN '' ELSE quote_ident(args.argname) || ' ' END ||
		           pg_catalog.format_type(args.typ, NULL), ', ' ORDER BY args.ord)
		         FROM (SELECT u.ord, u.typ,
		                      CASE WHEN p.proargmodes IS NULL THEN 'i' ELSE p.proargmodes[u.ord] END AS mode,
		                      CASE WHEN p.proargnames IS NULL THEN NULL ELSE p.proargnames[u.ord] END AS argname
		               FROM unnest(COALESCE(p.proallargtypes, p.proargtypes::oid[])) WITH ORDINALITY AS u(typ, ord)) args
		         WHERE args.mode <> 't'), ''),
		       array_to_string(ARRAY[p.prorettype]::oid[] || COALESCE(p.proallargtypes, p.proargtypes::oid[]), ','),
		       COALESCE(obj_description(p.oid, 'pg_proc'),''),
		       -- The FLAT INPUT signature for a grouped DROP ROUTINE.
		       -- proargmodes subscripts align with proallargtypes, so the two
		       -- MUST be zipped together (pairing modes with proargtypes would
		       -- misclassify inputs whenever an OUT/TABLE arg is interleaved);
		       -- when proargmodes is NULL, proallargtypes is too and every
		       -- proargtypes entry is an input.
		       COALESCE((SELECT string_agg(pg_catalog.format_type(args.typ, NULL), ', ' ORDER BY args.ord)
		         FROM (SELECT u.ord, u.typ,
		                      CASE WHEN p.proargmodes IS NULL THEN 'i' ELSE p.proargmodes[u.ord] END AS mode
		               FROM unnest(COALESCE(p.proallargtypes, p.proargtypes::oid[])) WITH ORDINALITY AS u(typ, ord)) args
		         WHERE args.mode IN ('i','b','v')), ''),
		       -- An INTERNAL dependency means the routine is a SUB-PART of
		       -- another object (a range type's auto-created constructors) and
		       -- is not independently droppable — PostgreSQL refuses with "you
		       -- can drop <owner> instead". It carries no drop of its own.
		       COALESCE((SELECT dep.refclassid::regclass::text FROM pg_depend dep
		           WHERE dep.classid = 'pg_proc'::regclass AND dep.objid = p.oid AND dep.deptype = 'i' LIMIT 1), ''),
		       COALESCE((SELECT dep.refobjid::bigint FROM pg_depend dep
		           WHERE dep.classid = 'pg_proc'::regclass AND dep.objid = p.oid AND dep.deptype = 'i' LIMIT 1), 0)
		FROM pg_proc p
		JOIN pg_namespace n ON n.oid = p.pronamespace
		JOIN pg_language l ON l.oid = p.prolang
		WHERE n.nspname = $1 AND p.prokind IN ('f','p','w')
		  -- LANGUAGE c AND internal user functions are now included
		  -- best-effort (a user-schema internal function references a built-in
		  -- symbol — the base-type/range-canonical bootstrap recipe); built-ins
		  -- live in pg_catalog and are excluded structurally by the schema
		  -- filter.
		  -- Classid makes the extension-membership test precise — objid
		  -- alone is ambiguous across catalogs (the other four passes already
		  -- scope theirs; this one was the stray).
		  AND NOT EXISTS (SELECT 1 FROM pg_depend dep
		      WHERE dep.classid = 'pg_proc'::regclass AND dep.objid = p.oid AND dep.deptype = 'e')
		ORDER BY p.proname, pg_get_function_identity_arguments(p.oid)`, schema)
	if err != nil {
		return nil, err
	}
	for rrows.Next() {
		var oid int64
		var name, kind, prokind, lang, def, args, result, stubArgs, sigOids, comment, flatArgs, ownerClass string
		var ownerOID int64
		if err := rrows.Scan(&oid, &name, &kind, &prokind, &lang, &def, &args, &result, &stubArgs, &sigOids,
			&comment, &flatArgs, &ownerClass, &ownerOID); err != nil {
			rrows.Close()
			return nil, err
		}
		// StubDeps: the signature-type edges the stub RETAINS (its argument/
		// return types must exist); everything else — body and default-arg
		// edges — is what staging cuts. A shell-staged (base/range) signature
		// type ITSELF resolves to its SHELL stage — that is the bootstrap:
		// the canonical/I-O support functions must create between shell and
		// final — while a side-effect multirange/auto-array in the signature
		// keeps the FINAL (it only exists after the completing CREATE). The
		// full dependency set resolves the same way, PER REFERENCED OID (an
		// id-level remap would be ambiguous: the range and its multirange
		// share one final node).
		sigSet := map[int64]bool{}
		var stubDeps []string
		for _, tok := range strings.Split(sigOids, ",") {
			if n, err := strconv.ParseInt(tok, 10, 64); err == nil {
				sigSet[n] = true
				if id := resolver.signatureTypeNode(n); id != "" {
					stubDeps = append(stubDeps, id)
				}
			}
		}
		var deps []string
		for _, ref := range procRefs[oid] {
			var id string
			if ref.class == "pg_type" && sigSet[ref.oid] {
				id = resolver.signatureTypeNode(ref.oid)
			} else {
				id = resolver.resolveRef(ref.class, ref.oid)
			}
			if id != "" {
				deps = append(deps, id)
			}
		}
		// Window ('w') and LANGUAGE c/internal routines are best-effort —
		// the definition round-trips as DDL, but the target needs the same
		// shared library / built-in symbol, plus superuser to create them (and
		// window functions cannot be stubbed: LANGUAGE sql cannot declare
		// WINDOW, so a pathological cycle through one preflight-fails).
		switch lang {
		case "c":
			plan.Warnings = append(plan.Warnings,
				"function "+schema+"."+name+" is LANGUAGE C; restoring it requires its shared library ('AS obj_file, link_symbol') and superuser in the target")
		case "internal":
			plan.Warnings = append(plan.Warnings,
				"function "+schema+"."+name+" is LANGUAGE internal; restoring it requires superuser in the target")
		}
		stub := ""
		if result != "trigger" && result != "event_trigger" && prokind != "w" {
			if prokind == "p" {
				stub = "CREATE PROCEDURE " + qualify(name) + "(" + stubArgs + ") LANGUAGE sql AS 'SELECT NULL'"
			} else {
				stub = "CREATE FUNCTION " + qualify(name) + "(" + stubArgs + ") RETURNS " + result + " LANGUAGE sql AS 'SELECT NULL'"
			}
		}
		// pg_get_functiondef emits CREATE OR REPLACE, so the CREATE side needs
		// no Drop — but the drop-first teardown does: a routine whose
		// signature names a dumped type BLOCKS that type's DROP under RESTRICT,
		// so the routine drop must precede it in the reversed stream. The
		// identity arguments are the drop signature (PostgreSQL ignores the OUT
		// arguments they may carry, verified live); the flat input signature is
		// kept separately for a grouped DROP ROUTINE.
		dropKw := "FUNCTION" // 'f' and 'w' (window) alike
		if prokind == "p" {
			dropKw = "PROCEDURE"
		}
		dropRef := qualify(name) + "(" + args + ")"
		script := driver.DumpScript{
			Kind:      "routine",
			Name:      routineNodeID(schema, name, args),
			DependsOn: deps,
			Stub:      stub,
			StubDeps:  stubDeps,
			Comment:   kind + " " + name,
			Drop:      "DROP " + dropKw + " IF EXISTS " + dropRef,
			DropForm: driver.DropForm{
				Class:      dropKw,
				Ref:        dropRef,
				RoutineRef: qualify(name) + "(" + flatArgs + ")",
			},
			SQL: strings.TrimRight(strings.TrimSpace(def), ";"),
		}
		// An internally-owned routine (a range type's auto-created
		// constructors) is a PART of its owner, not an object of its own: it
		// cannot be dropped independently and it dies with the owner. Marking
		// it a creation stage of that owner drops both — the bogus DROP and
		// the false conclusion that this routine SURVIVES teardown and so
		// blocks its own prerequisites.
		if ownerClass != "" {
			if owner := resolver.resolveRef(ownerClass, ownerOID); owner != "" {
				script.StageOf = teardownNode(owner)
				script.Drop, script.DropForm = "", driver.DropForm{}
			}
		}
		plan.Routines = append(plan.Routines, script)
		if comment != "" {
			// Routine comments restore like column comments do in the table DDL.
			plan.Routines = append(plan.Routines, driver.DumpScript{
				Kind:    "routine",
				Comment: "Comment for " + kind + " " + name,
				SQL: "COMMENT ON " + strings.ToUpper(kind) + " " +
					qualify(name) + "(" + args + ") IS " + d.QuoteString(comment),
			})
		}
	}
	rrows.Close()
	if err := rrows.Err(); err != nil {
		return nil, err
	}
	return procDeps, nil
}
