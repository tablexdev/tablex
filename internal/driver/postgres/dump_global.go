// Server-scope (global) objects: roles, tablespaces, foreign-data wrappers,
// foreign servers, user mappings, publications and subscriptions - everything a
// server dump emits once, before any database section.

package postgres

import (
	"context"
	"database/sql"
	"strconv"
	"strings"

	"github.com/tablexdev/tablex/internal/driver"
)

// DumpGlobalObjects (GlobalDumper) is the once-per-database collector
// for non-schema-owned object classes: user-defined CASTS (dumpable via the
// pg_dump OID-threshold built-in test plus the not-internal/automatic rule and
// the explicit pg_range range→multirange selector), FOREIGN DATA WRAPPERS,
// SERVERS and USER MAPPINGS under the provenance/redaction policy.
// Emitted only for database/server-scope exports (the self-contained paths).
func (d dialect) DumpGlobalObjects(ctx context.Context, db *sql.DB, structure bool) (driver.DumpPlan, error) {
	plan := driver.DumpPlan{}
	if !structure {
		return plan, nil // every global class is structure
	}
	resolver, err := d.buildNodeResolver(ctx, db)
	if err != nil {
		return plan, err
	}

	// --- Casts. Built-ins are excluded by the OID threshold (matching
	// pg_dump's `oid <= g_last_builtin_oid`; normal-operation OIDs start at
	// 16384) — there are many pinned built-in casts with no pg_depend rows, so
	// a dependency test alone is insufficient. Auto-generated casts are
	// excluded by the internal/automatic-dependency rule, EXCEPT the PG14+
	// range→multirange cast, whose OID is above the threshold and which pg_dump
	// excludes with a dedicated pg_range check: skip a cast ONLY in that exact
	// direction (a user-created multirange→range cast is legitimate and kept).
	castRows, err := db.QueryContext(ctx, `
		SELECT c.oid,
		       pg_catalog.format_type(c.castsource, NULL), c.castsource,
		       pg_catalog.format_type(c.casttarget, NULL), c.casttarget,
		       c.castfunc, CASE WHEN c.castfunc = 0 THEN '' ELSE c.castfunc::regprocedure::text END,
		       c.castcontext::text, c.castmethod::text,
		       COALESCE(obj_description(c.oid, 'pg_cast'), ''),
		       COALESCE((SELECT e.extname FROM pg_depend dep JOIN pg_extension e ON e.oid = dep.refobjid
		                 WHERE dep.classid = 'pg_cast'::regclass AND dep.objid = c.oid AND dep.deptype = 'e'
		                 LIMIT 1), '')
		FROM pg_cast c
		WHERE c.oid >= 16384
		  AND NOT EXISTS (SELECT 1 FROM pg_depend dep
		      WHERE dep.classid = 'pg_cast'::regclass AND dep.objid = c.oid AND dep.deptype IN ('i','a'))
		  AND NOT EXISTS (SELECT 1 FROM pg_range rng
		      WHERE c.castsource = rng.rngtypid
		        AND c.casttarget = COALESCE((to_jsonb(rng)->>'rngmultitypid')::bigint, 0))
		ORDER BY c.oid`)
	if err != nil {
		return plan, err
	}
	for castRows.Next() {
		var oid, srcOID, tgtOID, fnOID int64
		var src, tgt, fn, castContext, method, comment, ext string
		if err := castRows.Scan(&oid, &src, &srcOID, &tgt, &tgtOID, &fnOID, &fn, &castContext, &method, &comment, &ext); err != nil {
			castRows.Close()
			return plan, err
		}
		target := "(" + src + " AS " + tgt + ")"
		if ext != "" {
			plan.Warnings = append(plan.Warnings,
				"cast "+target+" belongs to extension "+ext+" and is not dumped; CREATE EXTENSION "+ext+" in the target recreates it only if it is part of the extension's install script")
			continue
		}
		var deps []string
		sql := "CREATE CAST " + target
		switch method {
		case "f":
			sql += " WITH FUNCTION " + fn
			if id := resolver.proc[fnOID]; id != "" {
				deps = append(deps, id)
			}
		case "i":
			sql += " WITH INOUT"
		default: // 'b'
			sql += " WITHOUT FUNCTION"
		}
		switch castContext {
		case "i":
			sql += " AS IMPLICIT"
		case "a":
			sql += " AS ASSIGNMENT"
		}
		for _, t := range []int64{srcOID, tgtOID} {
			if id := resolver.typ[t]; id != "" {
				deps = append(deps, id)
			}
		}
		// Casts are EDGE-LESS from their consumers' side (an expression records
		// a dependency only on the cast's function/types, never the pg_cast
		// row), so the early class-priority slot — the global section leads and
		// Types precede every consumer class — is what orders them before
		// views/defaults that use them.
		plan.Types = append(plan.Types, driver.DumpScript{
			Kind:      "cast",
			Name:      "cast:" + strconv.FormatInt(srcOID, 10) + "\x00" + strconv.FormatInt(tgtOID, 10),
			DependsOn: deps,
			Comment:   "Cast " + src + " AS " + tgt,
			Drop:      "DROP CAST IF EXISTS " + target,
			SQL:       sql,
		})
		if comment != "" {
			plan.Types = append(plan.Types, driver.DumpScript{
				Kind:    "cast",
				Comment: "Comment for cast",
				SQL:     "COMMENT ON CAST " + target + " IS " + d.QuoteString(comment),
			})
		}
	}
	castRows.Close()
	if err := castRows.Err(); err != nil {
		return plan, err
	}

	// --- Foreign-data wrappers (superuser-only to create; handler/validator
	// are C functions → conditional). No built-in instances exist, so
	// dumpability is classid-scoped extension membership + the option policy,
	// never an OID threshold.
	states, err := d.foreignServerStates(ctx, db)
	if err != nil {
		return plan, err
	}
	fdwRows, err := db.QueryContext(ctx, `
		SELECT w.fdwname,
		       CASE WHEN w.fdwhandler = 0 THEN '' ELSE w.fdwhandler::regproc::text END,
		       CASE WHEN w.fdwvalidator = 0 THEN '' ELSE w.fdwvalidator::regproc::text END,
		       COALESCE(array_to_string(w.fdwoptions, E'\x1f'), ''),
		       COALESCE(obj_description(w.oid, 'pg_foreign_data_wrapper'), ''),
		       COALESCE((SELECT e.extname FROM pg_depend dep JOIN pg_extension e ON e.oid = dep.refobjid
		                 WHERE dep.classid = 'pg_foreign_data_wrapper'::regclass AND dep.objid = w.oid AND dep.deptype = 'e'
		                 LIMIT 1), '')
		FROM pg_foreign_data_wrapper w
		ORDER BY w.fdwname`)
	if err != nil {
		return plan, err
	}
	for fdwRows.Next() {
		var name, handler, validator, opts, comment, ext string
		if err := fdwRows.Scan(&name, &handler, &validator, &opts, &comment, &ext); err != nil {
			fdwRows.Close()
			return plan, err
		}
		if ext != "" {
			plan.Warnings = append(plan.Warnings,
				"foreign-data wrapper "+name+" belongs to extension "+ext+" and is not dumped; run CREATE EXTENSION "+ext+" (superuser) in the target before restoring its servers")
			continue
		}
		sql := "CREATE FOREIGN DATA WRAPPER " + d.QuoteIdent(name)
		if handler != "" && handler != "-" {
			sql += " HANDLER " + handler
		}
		if validator != "" && validator != "-" {
			sql += " VALIDATOR " + validator
		}
		if opts != "" {
			// An unknown wrapper's options may all be secrets: redact every one.
			// With options redacted the wrapper cannot be reproduced faithfully —
			// state (c): an inert commented template, never executable DDL.
			var keys []string
			for _, kv := range splitOptions(opts) {
				keys = append(keys, kv[0])
			}
			plan.Warnings = append(plan.Warnings,
				"foreign-data wrapper "+name+" is not dumped: its options ("+strings.Join(keys, ", ")+") are redacted by policy; template: "+sql+" OPTIONS (…) -- re-create manually with the original options")
			continue
		}
		plan.Warnings = append(plan.Warnings,
			"foreign-data wrapper "+name+" requires superuser to restore, and its handler/validator functions' shared library in the target")
		plan.Types = append(plan.Types, driver.DumpScript{
			Kind:    "foreign-data",
			Name:    "fdw:" + name,
			Comment: "Foreign-data wrapper " + name,
			Drop:    "DROP FOREIGN DATA WRAPPER IF EXISTS " + d.QuoteIdent(name),
			SQL:     sql,
		})
		if comment != "" {
			plan.Types = append(plan.Types, driver.DumpScript{
				Kind:    "foreign-data",
				Comment: "Comment for foreign-data wrapper " + name,
				SQL:     "COMMENT ON FOREIGN DATA WRAPPER " + d.QuoteIdent(name) + " IS " + d.QuoteString(comment),
			})
		}
	}
	fdwRows.Close()
	if err := fdwRows.Err(); err != nil {
		return plan, err
	}

	// --- Servers, then user mappings (a mapping is NEVER an extension member —
	// ALTER EXTENSION has no ADD USER MAPPING — so it is emitted whenever its
	// server is state (a) or (b), with every option redacted: user-mapping
	// options carry credentials by design).
	srvRows, err := db.QueryContext(ctx, `
		SELECT s.srvname, w.fdwname,
		       COALESCE(s.srvtype, ''), COALESCE(s.srvversion, ''),
		       COALESCE(array_to_string(s.srvoptions, E'\x1f'), ''),
		       COALESCE(obj_description(s.oid, 'pg_foreign_server'), ''),
		       COALESCE((SELECT e.extname FROM pg_depend dep JOIN pg_extension e ON e.oid = dep.refobjid
		                 WHERE dep.classid = 'pg_foreign_server'::regclass AND dep.objid = s.oid AND dep.deptype = 'e'
		                 LIMIT 1), '')
		FROM pg_foreign_server s
		JOIN pg_foreign_data_wrapper w ON w.oid = s.srvfdw
		ORDER BY s.srvname`)
	if err != nil {
		return plan, err
	}
	for srvRows.Next() {
		var name, fdw, srvType, srvVersion, opts, comment, ext string
		if err := srvRows.Scan(&name, &fdw, &srvType, &srvVersion, &opts, &comment, &ext); err != nil {
			srvRows.Close()
			return plan, err
		}
		st := states[name]
		if ext != "" {
			plan.Warnings = append(plan.Warnings,
				"foreign server "+name+" belongs to extension "+ext+" and is not dumped; it must exist in the target (via the extension or manual creation) before its dependents restore")
			continue
		}
		if st.state == 'c' {
			plan.Warnings = append(plan.Warnings,
				"foreign server "+name+" is not dumped: its wrapper "+st.wrapper+" could not be reproduced (options redacted); template: CREATE SERVER "+name+" FOREIGN DATA WRAPPER "+st.wrapper+" OPTIONS (…) -- re-create manually")
			continue
		}
		sql := "CREATE SERVER " + d.QuoteIdent(name)
		if srvType != "" {
			sql += " TYPE " + d.QuoteString(srvType)
		}
		if srvVersion != "" {
			sql += " VERSION " + d.QuoteString(srvVersion)
		}
		sql += " FOREIGN DATA WRAPPER " + d.QuoteIdent(fdw)
		clause, redacted := d.foreignOptionsClause(st.kind, "server", opts)
		sql += clause
		if len(redacted) > 0 {
			plan.Warnings = append(plan.Warnings,
				"foreign server "+name+": options "+strings.Join(redacted, ", ")+" are redacted by policy and must be re-supplied after restore (ALTER SERVER … OPTIONS)")
		}
		if st.kind != "" {
			plan.Warnings = append(plan.Warnings,
				"foreign server "+name+" needs CREATE EXTENSION "+st.wrapper+" (superuser) in the target before it restores")
		}
		plan.Types = append(plan.Types, driver.DumpScript{
			Kind:      "foreign-data",
			Name:      "server:" + name,
			DependsOn: []string{"fdw:" + fdw}, // boundary when the wrapper is extension-provided
			Comment:   "Foreign server " + name,
			Drop:      "DROP SERVER IF EXISTS " + d.QuoteIdent(name),
			SQL:       sql,
		})
		if comment != "" {
			plan.Types = append(plan.Types, driver.DumpScript{
				Kind:    "foreign-data",
				Comment: "Comment for foreign server " + name,
				SQL:     "COMMENT ON SERVER " + d.QuoteIdent(name) + " IS " + d.QuoteString(comment),
			})
		}
	}
	srvRows.Close()
	if err := srvRows.Err(); err != nil {
		return plan, err
	}

	umRows, err := db.QueryContext(ctx, `
		SELECT COALESCE(r.rolname, 'PUBLIC'), s.srvname,
		       COALESCE(array_to_string(um.umoptions, E'\x1f'), '') <> ''
		FROM pg_user_mapping um
		JOIN pg_foreign_server s ON s.oid = um.umserver
		LEFT JOIN pg_roles r ON r.oid = um.umuser
		ORDER BY s.srvname, 1`)
	if err != nil {
		return plan, err
	}
	for umRows.Next() {
		var role, server string
		var hadOptions bool
		if err := umRows.Scan(&role, &server, &hadOptions); err != nil {
			umRows.Close()
			return plan, err
		}
		st := states[server]
		if st.state == 'c' {
			plan.Warnings = append(plan.Warnings,
				"user mapping for "+role+" on server "+server+" is not dumped (its server could not be reproduced); re-create it manually")
			continue
		}
		plan.Types = append(plan.Types, driver.DumpScript{
			Kind:      "foreign-data",
			Name:      "usermapping:" + server + "\x00" + role,
			DependsOn: []string{"server:" + server},
			Comment:   "User mapping for " + role + " on " + server,
			Drop:      "DROP USER MAPPING IF EXISTS FOR " + d.roleRef(role) + " SERVER " + d.QuoteIdent(server),
			SQL:       "CREATE USER MAPPING FOR " + d.roleRef(role) + " SERVER " + d.QuoteIdent(server),
		})
		note := "user mapping for " + role + " on server " + server + ": the role must pre-exist in the target"
		if hadOptions {
			note += "; ALL its options are redacted by policy (they carry credentials) and must be re-supplied (ALTER USER MAPPING … OPTIONS)"
		}
		plan.Warnings = append(plan.Warnings, note)
	}
	umRows.Close()
	return plan, umRows.Err()
}
