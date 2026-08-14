// Foreign data for the dump path: foreign tables (structure only - their rows
// live on the remote server), the foreign-option redaction that keeps
// credentials out of a dump, and the mixed local/foreign partition-tree split.

package postgres

import (
	"context"
	"database/sql"
	"strings"

	"github.com/tablexdev/tablex/internal/driver"
)

// foreignServerState classifies a foreign-data object per the three-state
// model: (a) emitted executable, (b) external prerequisite (extension-owned —
// CREATE EXTENSION recreates it in the target; dependents stay executable with
// a prerequisite note), (c) unavailable — an unknown wrapper whose options
// were redacted; its DDL is rendered only as an inert commented template and
// its dependents are suppressed/templated.
type foreignServerState struct {
	state   byte   // 'a', 'b', 'c'
	wrapper string // wrapper name
	kind    string // "postgres_fdw", "file_fdw", "" (unrecognized)
}

// splitOptions parses an array_to_string(options, \x1f) payload into key/value
// pairs (each element is key=value, split at the FIRST '=').
func splitOptions(raw string) [][2]string {
	if raw == "" {
		return nil
	}
	var out [][2]string
	for _, kv := range strings.Split(raw, "\x1f") {
		k, v, _ := strings.Cut(kv, "=")
		out = append(out, [2]string{k, v})
	}
	return out
}

// dsnShaped reports whether a value looks like a conninfo/URI rather than a
// plain database-name literal — defense-in-depth: postgres_fdw itself connects
// with expand_dbname=false, but a DSN-shaped dbname could carry a credential,
// so it is redacted rather than emitted (security.md: no credential/DSN in
// responses).
func dsnShaped(v string) bool {
	return strings.ContainsAny(v, "= \t\n") || strings.Contains(v, "://")
}

// allowForeignOption reports whether one option of a PROVENANCE-recognized
// wrapper is known non-secret. objKind is "server", "table" or "column";
// everything not allowlisted — including every option of an unrecognized
// wrapper and all user-mapping options — is redacted.
func allowForeignOption(wrapperKind, objKind, key, value string) bool {
	switch wrapperKind {
	case "postgres_fdw":
		switch objKind {
		case "server":
			if key == "host" || key == "port" {
				return true
			}
			return key == "dbname" && !dsnShaped(value)
		case "table":
			return key == "schema_name" || key == "table_name"
		case "column":
			return key == "column_name"
		}
	case "file_fdw":
		if objKind == "table" {
			return key == "format" || key == "header"
		}
	}
	return false
}

// foreignOptionsClause renders the OPTIONS (…) clause from the allowlisted
// subset of options, reporting the redacted keys. Values are emitted through
// QuoteString, keys through QuoteIdent-less bare form only when identifier-safe.
func (d dialect) foreignOptionsClause(wrapperKind, objKind, raw string) (clause string, redacted []string) {
	var kept []string
	for _, kv := range splitOptions(raw) {
		if allowForeignOption(wrapperKind, objKind, kv[0], kv[1]) && safeReloptionName(kv[0]) {
			kept = append(kept, kv[0]+" "+d.QuoteString(kv[1]))
		} else {
			redacted = append(redacted, kv[0])
		}
	}
	if len(kept) > 0 {
		clause = " OPTIONS (" + strings.Join(kept, ", ") + ")"
	}
	return clause, redacted
}

// foreignServerStates classifies every foreign server once (used by the global
// collector, the foreign-table pass and the partition-child writer). A wrapper
// is "recognized" by PROVENANCE, never by name: it must be an extension member
// of the same-named postgres_fdw/file_fdw extension AND its handler must be
// too — a wrapper merely NAMED postgres_fdw is UNKNOWN and fully redacted.
func (d dialect) foreignServerStates(ctx context.Context, db *sql.DB) (map[string]foreignServerState, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT s.srvname, w.fdwname,
		       COALESCE(we.extname, ''),
		       COALESCE(he.extname, ''),
		       COALESCE(array_to_string(w.fdwoptions, E'\x1f'), ''),
		       EXISTS (SELECT 1 FROM pg_depend dep WHERE dep.classid = 'pg_foreign_data_wrapper'::regclass
		               AND dep.objid = w.oid AND dep.deptype = 'e')
		FROM pg_foreign_server s
		JOIN pg_foreign_data_wrapper w ON w.oid = s.srvfdw
		LEFT JOIN LATERAL (
		    SELECT e.extname FROM pg_depend dep JOIN pg_extension e ON e.oid = dep.refobjid
		    WHERE dep.classid = 'pg_foreign_data_wrapper'::regclass AND dep.objid = w.oid AND dep.deptype = 'e'
		    LIMIT 1) we ON true
		LEFT JOIN LATERAL (
		    SELECT e.extname FROM pg_depend dep JOIN pg_extension e ON e.oid = dep.refobjid
		    WHERE dep.classid = 'pg_proc'::regclass AND dep.objid = w.fdwhandler AND dep.deptype = 'e'
		    LIMIT 1) he ON true`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]foreignServerState{}
	for rows.Next() {
		var srv, fdw, wrapperExt, handlerExt, fdwOpts string
		var extMember bool
		if err := rows.Scan(&srv, &fdw, &wrapperExt, &handlerExt, &fdwOpts, &extMember); err != nil {
			return nil, err
		}
		st := foreignServerState{wrapper: fdw}
		recognized := wrapperExt == fdw && handlerExt == fdw &&
			(fdw == "postgres_fdw" || fdw == "file_fdw")
		switch {
		case recognized:
			st.state, st.kind = 'b', fdw // extension recreates the wrapper
		case extMember:
			st.state = 'b' // some other extension provides it — external prerequisite
		case fdwOpts != "":
			st.state = 'c' // unknown wrapper WITH (all-redacted) options: template
		default:
			st.state = 'a' // optionless hand-created wrapper: fully reproducible
		}
		out[srv] = st
	}
	return out, rows.Err()
}

// dumpForeignTables emits the schema's standalone foreign tables as
// STRUCTURE-ONLY relations (their rows live on the remote server; they never
// enter the data pass, listings, or CSV/JSON). Options follow the provenance
// allowlist; a table whose server is state (c), or a recognized file_fdw table
// whose validator-REQUIRED filename/program was redacted, cannot be emitted as
// executable DDL — it becomes an inert commented template and its dependents
// (triggers/comments/rules) are suppressed by removing it from the gate set.
// only restricts to a single relation (the table-scope foreign export);
// inTables nil skips the suppression bookkeeping.
func (d dialect) dumpForeignTables(ctx context.Context, db *sql.DB, schema, only string, r *dumpNodeResolver, plan *driver.DumpPlan) error {
	states, err := d.foreignServerStates(ctx, db)
	if err != nil {
		return err
	}
	var nameFilter any
	if only != "" {
		nameFilter = only
	}
	ftRows, err := db.QueryContext(ctx, `
		SELECT c.oid, c.relname, s.srvname,
		       COALESCE(array_to_string(ft.ftoptions, E'\x1f'), ''),
		       COALESCE(obj_description(c.oid, 'pg_class'), '')
		FROM pg_class c
		JOIN pg_foreign_table ft ON ft.ftrelid = c.oid
		JOIN pg_foreign_server s ON s.oid = ft.ftserver
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = $1 AND c.relkind = 'f' AND NOT c.relispartition
		  AND ($2::text IS NULL OR c.relname = $2)
		ORDER BY c.relname`, schema, nameFilter)
	if err != nil {
		return err
	}
	type ftRow struct {
		oid                            int64
		name, server, options, comment string
	}
	var fts []ftRow
	for ftRows.Next() {
		var f ftRow
		if err := ftRows.Scan(&f.oid, &f.name, &f.server, &f.options, &f.comment); err != nil {
			ftRows.Close()
			return err
		}
		fts = append(fts, f)
	}
	ftRows.Close()
	if err := ftRows.Err(); err != nil {
		return err
	}
	if len(fts) == 0 {
		return nil
	}

	type ftCol struct {
		name, typ, def, options, collSchema, collName string
		typOID                                        int64
		notnull                                       bool
	}
	cols := map[string][]ftCol{}
	colRows, err := db.QueryContext(ctx, `
		SELECT c.relname, a.attname, pg_catalog.format_type(a.atttypid, a.atttypmod), a.atttypid,
		       a.attnotnull, COALESCE(pg_get_expr(ad.adbin, ad.adrelid), ''),
		       COALESCE(array_to_string(a.attfdwoptions, E'\x1f'), ''),
		       COALESCE(cln.nspname, ''), COALESCE(cl.collname, '')
		FROM pg_attribute a
		JOIN pg_class c ON c.oid = a.attrelid
		JOIN pg_namespace n ON n.oid = c.relnamespace
		JOIN pg_type at ON at.oid = a.atttypid
		LEFT JOIN pg_attrdef ad ON ad.adrelid = a.attrelid AND ad.adnum = a.attnum
		LEFT JOIN pg_collation cl ON cl.oid = a.attcollation
		  AND a.attcollation <> 0 AND a.attcollation <> at.typcollation
		LEFT JOIN pg_namespace cln ON cln.oid = cl.collnamespace
		WHERE n.nspname = $1 AND c.relkind = 'f' AND NOT c.relispartition
		  AND a.attnum > 0 AND NOT a.attisdropped
		  AND ($2::text IS NULL OR c.relname = $2)
		ORDER BY c.relname, a.attnum`, schema, nameFilter)
	if err != nil {
		return err
	}
	for colRows.Next() {
		var tbl string
		var c ftCol
		if err := colRows.Scan(&tbl, &c.name, &c.typ, &c.typOID, &c.notnull, &c.def, &c.options, &c.collSchema, &c.collName); err != nil {
			colRows.Close()
			return err
		}
		cols[tbl] = append(cols[tbl], c)
	}
	colRows.Close()
	if err := colRows.Err(); err != nil {
		return err
	}

	// Ordinary INHERITS parents (a foreign table may inherit a local parent).
	parents := map[string][]string{}
	inhRows, err := db.QueryContext(ctx, `
		SELECT child.relname, pn.nspname, parent.relname
		FROM pg_inherits i
		JOIN pg_class child ON child.oid = i.inhrelid
		JOIN pg_namespace cn ON cn.oid = child.relnamespace
		JOIN pg_class parent ON parent.oid = i.inhparent
		JOIN pg_namespace pn ON pn.oid = parent.relnamespace
		WHERE cn.nspname = $1 AND child.relkind = 'f' AND NOT child.relispartition
		ORDER BY child.relname, i.inhseqno`, schema)
	if err != nil {
		return err
	}
	parentNodes := map[string][]string{}
	for inhRows.Next() {
		var child, pSchema, pName string
		if err := inhRows.Scan(&child, &pSchema, &pName); err != nil {
			inhRows.Close()
			return err
		}
		parents[child] = append(parents[child], d.QuoteIdent(pSchema)+"."+d.QuoteIdent(pName))
		parentNodes[child] = append(parentNodes[child], nodeID("relation", pSchema, pName))
	}
	inhRows.Close()
	if err := inhRows.Err(); err != nil {
		return err
	}

	for _, f := range fts {
		st := states[f.server]
		qname := d.QuoteIdent(schema) + "." + d.QuoteIdent(f.name)
		// Named NOT NULL constraints (PG18+) — inline with the NAME
		// preserved; a foreign-table contype='n' can never be NOT VALID (PG
		// forbids it), so no post-data form exists here. A disallowed state is
		// warned, never emitted as invalid DDL.
		nns, err := d.namedNotNulls(ctx, db, schema, f.name)
		if err != nil {
			return err
		}
		suppressNN := map[string]bool{}
		var nnLines, nnComments []string
		for _, nn := range nns {
			if !nn.islocal || nn.parentID != 0 {
				continue
			}
			if !nn.validated {
				plan.Warnings = append(plan.Warnings,
					"foreign table "+schema+"."+f.name+" has a NOT VALID named NOT NULL constraint "+nn.conname+", which PostgreSQL disallows; it is not emitted")
				continue
			}
			suppressNN[nn.attname] = true
			nnLines = append(nnLines, "  CONSTRAINT "+d.QuoteIdent(nn.conname)+" "+nn.def)
			if nn.comment != "" {
				nnComments = append(nnComments, "COMMENT ON CONSTRAINT "+d.QuoteIdent(nn.conname)+" ON "+qname+" IS "+d.QuoteString(nn.comment))
			}
		}
		var lines []string
		var deps []string
		var redactedAll []string
		for _, c := range cols[f.name] {
			line := "  " + d.QuoteIdent(c.name) + " " + c.typ
			if clause, redacted := d.foreignOptionsClause(st.kind, "column", c.options); clause != "" || len(redacted) > 0 {
				if clause != "" {
					line += clause
				}
				redactedAll = append(redactedAll, redacted...)
			}
			if c.collName != "" {
				line += " COLLATE " + d.QuoteIdent(c.collSchema) + "." + d.QuoteIdent(c.collName)
				deps = append(deps, nodeID("collation", c.collSchema, c.collName))
			}
			if c.notnull && !suppressNN[c.name] {
				line += " NOT NULL"
			}
			if c.def != "" {
				line += " DEFAULT " + c.def
			}
			lines = append(lines, line)
			if id := r.typ[c.typOID]; id != "" {
				deps = append(deps, id)
			}
		}
		// Validated CHECK constraints ride inline (foreign tables carry no
		// PK/UNIQUE/EXCLUDE); NOT VALID checks ride the shared post-data pass.
		extra, err := d.inlineConstraints(ctx, db, schema, f.name, false, nil)
		if err != nil {
			return err
		}
		lines = append(lines, extra...)
		lines = append(lines, nnLines...)
		sql := "CREATE FOREIGN TABLE " + qname + " (\n" + strings.Join(lines, ",\n") + "\n)"
		if p := parents[f.name]; len(p) > 0 {
			sql += " INHERITS (" + strings.Join(p, ", ") + ")"
			deps = append(deps, parentNodes[f.name]...)
		}
		sql += " SERVER " + d.QuoteIdent(f.server)
		clause, redacted := d.foreignOptionsClause(st.kind, "table", f.options)
		sql += clause
		redactedAll = append(redactedAll, redacted...)
		deps = append(deps, "server:"+f.server)

		// State (c): the server/wrapper could not be reproduced, or a
		// validator-REQUIRED option was redacted (file_fdw needs filename or
		// program) — emit only the inert template and suppress dependents.
		required := false
		if st.kind == "file_fdw" {
			for _, k := range redacted {
				if k == "filename" || k == "program" {
					required = true
				}
			}
		}
		if st.state == 'c' || required {
			plan.Warnings = append(plan.Warnings,
				"foreign table "+schema+"."+f.name+" is not dumped (its server/options cannot be reproduced under the redaction policy); template: "+sql+" -- complete the redacted OPTIONS manually; its triggers/comments/rules are suppressed with it")
			plan.SuppressedRelations = append(plan.SuppressedRelations, f.name)
			continue
		}
		if len(redactedAll) > 0 {
			plan.Warnings = append(plan.Warnings,
				"foreign table "+schema+"."+f.name+": options "+strings.Join(redactedAll, ", ")+" are redacted by policy and must be re-supplied after restore")
		}
		plan.ForeignData = append(plan.ForeignData, driver.DumpScript{
			Kind:      "foreign-table",
			Name:      nodeID("relation", schema, f.name),
			DependsOn: deps,
			Comment:   "Foreign table " + f.name,
			Drop:      "DROP FOREIGN TABLE IF EXISTS " + qname,
			SQL:       sql,
		})
		if f.comment != "" {
			plan.ForeignData = append(plan.ForeignData, driver.DumpScript{
				Kind:    "foreign-table",
				Comment: "Comment for foreign table " + f.name,
				SQL:     "COMMENT ON FOREIGN TABLE " + qname + " IS " + d.QuoteString(f.comment),
			})
		}
		for _, s := range nnComments {
			plan.ForeignData = append(plan.ForeignData, driver.DumpScript{
				Kind:    "foreign-table",
				Comment: "Constraint comment on foreign table " + f.name,
				SQL:     s,
			})
		}
	}
	return nil
}

// IsForeignTable (ForeignTableDumper) resolves a foreign table for the
// SQL-export-only path — foreign tables are deliberately absent from
// ListTables/ListTableNames (no browsing/CSV/JSON/data), so the export
// target-resolution 404s them without this.
func (dialect) IsForeignTable(ctx context.Context, db *sql.DB, scope driver.Scope, name string) (bool, error) {
	var found bool
	err := db.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM pg_class c
			JOIN pg_namespace n ON n.oid = c.relnamespace
			WHERE n.nspname = $1 AND c.relname = $2 AND c.relkind = 'f')`,
		schemaOfScope(scope), name).Scan(&found)
	return found, err
}

// DumpForeignTable (ForeignTableDumper) builds a single foreign table's
// STRUCTURE-ONLY plan: the CREATE FOREIGN TABLE under the option policy, its
// triggers/rules/comments, and the scoped-export prerequisite diagnostics —
// the server (and its wrapper/extension) must pre-exist in the target, plus
// the generic cast caveat (a user-defined cast records no catalog edge from
// its consumers, so a scoped export cannot NAME a required cast). No data pass
// exists on this path by construction.
func (d dialect) DumpForeignTable(ctx context.Context, db *sql.DB, scope driver.Scope, name string) (driver.DumpPlan, error) {
	schema := schemaOfScope(scope)
	plan := driver.DumpPlan{}
	resolver, err := d.buildNodeResolver(ctx, db)
	if err != nil {
		return plan, err
	}
	if err := d.dumpForeignTables(ctx, db, schema, name, resolver, &plan); err != nil {
		return plan, err
	}
	if err := d.dumpTriggers(ctx, db, schema, name, nil, nil, &plan); err != nil {
		return plan, err
	}
	if err := d.dumpRules(ctx, db, schema, name, nil, &plan); err != nil {
		return plan, err
	}
	plan.Warnings = append(plan.Warnings,
		"foreign table "+schema+"."+name+" is exported on its own: its SERVER (with its foreign-data wrapper/extension), referenced types/collations, and any user-defined cast its expressions rely on (casts record no catalog edge and cannot be named here) must already exist in the restore target")
	return plan, nil
}

// collectMixedTreeSplit adapts collectMixedTreeDataSplit to DumpObjects' pass
// table (whose run field takes only (ctx, db)). It runs whenever structure OR
// data is requested: the DataOnlyTables verdict is what stops a kept local
// leaf from getting a standalone CREATE next to the root's PARTITION OF
// emission, and the split's data halves matter whenever rows are read. Only
// the warnings are data-gated — a structure-only dump must not warn about
// rows it never reads.
func (o *objectDump) collectMixedTreeSplit(ctx context.Context, db *sql.DB) error {
	return o.d.collectMixedTreeDataSplit(ctx, db, o.schema, o.tables, o.data, &o.plan)
}

// collectMixedTreeDataSplit handles a partition tree containing a FOREIGN
// leaf: the root's structure still emits every child recursively, but its
// data scan cannot run — a plain FROM on the root would recurse into the
// foreign leaf and query the REMOTE server — so DumpDataTables splits the
// tree's data into per-local-leaf FROM ONLY reads. This pass emits the
// matching plan facts: DataOnlyTables (the local leaves — data yes, structure
// no, or their DDL would duplicate the root's recursive create; the verdict
// is needed by structure-only dumps too, which keep those leaves in the
// table list) and, when data is requested, honest warnings for the skipped
// foreign leaves and any cross-schema local leaf a per-schema data list
// cannot carry.
func (d dialect) collectMixedTreeDataSplit(ctx context.Context, db *sql.DB, schema string, tables []string, data bool, plan *driver.DumpPlan) error {
	inSet := driver.StringSet(tables)
	// No `NOT p.relispartition` pin — a TABLE-scope export can request a
	// MID-LEVEL partitioned child (kept standalone by the handler), and its
	// plain-FROM scan would recurse into a foreign leaf below it exactly like
	// a true root's; the inSet filter below keeps database scope unchanged
	// (folded children are never in the list).
	rows, err := db.QueryContext(ctx, `
		SELECT p.relname, cn.nspname, c.relname, c.relkind::text
		FROM pg_class p
		JOIN pg_namespace n ON n.oid = p.relnamespace
		CROSS JOIN LATERAL pg_partition_tree(p.oid) pt
		JOIN pg_class c ON c.oid = pt.relid
		JOIN pg_namespace cn ON cn.oid = c.relnamespace
		WHERE n.nspname = $1 AND p.relkind = 'p'
		  AND pt.isleaf
		  AND EXISTS (SELECT 1 FROM pg_partition_tree(p.oid) pt2
		      JOIN pg_class c2 ON c2.oid = pt2.relid WHERE c2.relkind = 'f')
		ORDER BY p.relname, cn.nspname, c.relname`, schema)
	if err != nil {
		return err
	}
	defer rows.Close()
	roots := map[string]bool{}
	for rows.Next() {
		var root, leafSchema, leaf, kind string
		if err := rows.Scan(&root, &leafSchema, &leaf, &kind); err != nil {
			return err
		}
		if !inSet[root] {
			continue
		}
		if !roots[root] {
			roots[root] = true
			plan.StructureOnlyTables = append(plan.StructureOnlyTables, root)
		}
		switch {
		case kind == "f":
			if data {
				plan.Warnings = append(plan.Warnings,
					"partition "+leafSchema+"."+leaf+" of "+schema+"."+root+" is a FOREIGN table; its rows live on the remote server and are not dumped")
			}
		case leafSchema != schema:
			if data {
				plan.Warnings = append(plan.Warnings,
					"partition "+leafSchema+"."+leaf+" of "+schema+"."+root+" lives in another schema; its rows are not dumped in this mixed local/foreign tree — export that schema too or move the partition")
			}
		default:
			plan.DataOnlyTables = append(plan.DataOnlyTables, leaf)
		}
	}
	return rows.Err()
}
