// Dump passes for the relation-attached objects: views and materialized views
// (dependency-ordered, with their column defaults as separate graph nodes),
// triggers and rules.

package postgres

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"github.com/tablexdev/tablex/internal/driver"
)

// dumpTriggers appends the schema's child-local triggers (CREATE TRIGGER, the
// trigger's comment, and its non-default enable state) to
// plan.PostData. only restricts to a single relation (the DumpView single-view
// path, inTables nil); empty scans the schema gated on inTables (DumpObjects).
// tgparentid = 0 keeps only child-LOCAL triggers (G11): a partition-cloned
// trigger re-clones via PARTITION OF, so re-emitting it fails — EXCEPT on a
// STANDALONE-materialized partition child (the cloned set), which has no
// parent to re-clone from: its cloned triggers are emitted as its own
// (pg_get_triggerdef of the clone already targets the child).
func (d dialect) dumpTriggers(ctx context.Context, db *sql.DB, schema, only string, inTables, cloned map[string]bool, plan *driver.DumpPlan) error {
	var nameFilter any
	if only != "" {
		nameFilter = only
	}
	trRows, err := db.QueryContext(ctx, `
		SELECT c.relname, c.relkind::text, t.tgname, pg_get_triggerdef(t.oid, true),
		       t.tgenabled::text, t.tgparentid,
		       COALESCE(obj_description(t.oid, 'pg_trigger'), '')
		FROM pg_trigger t
		JOIN pg_class c ON c.oid = t.tgrelid
		JOIN pg_namespace n ON n.oid = c.relnamespace
		-- A partition child's CLONED user trigger is flagged tgisinternal on
		-- PG13 but not on PG14+, so the internal test alone loses it on the
		-- floor (such a child is materialized WITH its triggers). Admitting a
		-- cloned row needs the tgconstraint guard: every referential-integrity
		-- trigger is internal AND cloned onto partitions too, and those must
		-- never surface as user triggers.
		WHERE n.nspname = $1
		  AND (NOT t.tgisinternal OR (t.tgparentid <> 0 AND t.tgconstraint = 0))
		  AND ($2::text IS NULL OR c.relname = $2)
		ORDER BY c.relname, t.tgname`, schema, nameFilter)
	if err != nil {
		return err
	}
	defer trRows.Close()
	for trRows.Next() {
		var table, relkind, name, def, enabled, comment string
		var parentID int64
		if err := trRows.Scan(&table, &relkind, &name, &def, &enabled, &parentID, &comment); err != nil {
			return err
		}
		if parentID != 0 && !cloned[table] {
			continue
		}
		if inTables != nil && !inTables[table] {
			continue
		}
		qtable := d.QuoteIdent(schema) + "." + d.QuoteIdent(table)
		plan.PostData = append(plan.PostData, driver.DumpScript{
			Kind:    "trigger",
			Comment: "Trigger " + name + " on " + table,
			Drop:    "DROP TRIGGER IF EXISTS " + d.QuoteIdent(name) + " ON " + qtable,
			SQL:     def,
		})
		// G3: a trigger comment rides post-data (Kind trigger-comment so a
		// data-only dump drops it) right after its trigger create.
		if comment != "" {
			plan.PostData = append(plan.PostData, driver.DumpScript{
				Kind:    "trigger-comment",
				Comment: "Comment for trigger " + name + " on " + table,
				SQL:     "COMMENT ON TRIGGER " + d.QuoteIdent(name) + " ON " + qtable + " IS " + d.QuoteString(comment),
			})
		}
		// Non-default enable state ('D' disabled, 'R' replica, 'A' always).
		// Without it a disabled trigger restores ENABLED — a silent behavior
		// change. Rank "trigger-state" (metadata) runs after every rank-1 create.
		if stmt := d.triggerStateSQL(qtable, name, relkind, enabled); stmt != "" {
			plan.PostData = append(plan.PostData, driver.DumpScript{
				Kind:    "trigger-state",
				Comment: "Enable state for trigger " + name + " on " + table,
				SQL:     stmt,
			})
		}
	}
	return trRows.Err()
}

// triggerStateSQL renders the ALTER statement restoring a non-default
// pg_trigger.tgenabled state; 'O' (enabled, fire on origin — the default) and
// unknown codes return "". The head is relkind-aware: a foreign table takes
// ALTER FOREIGN TABLE, while plain ALTER TABLE covers tables, partitioned
// tables and views (pg_dump parity — no ONLY, so a partitioned parent's state
// recurses into the just-recreated partition clones; a child's DIVERGENT state
// is a documented residual). Pure (unit-tested).
func (d dialect) triggerStateSQL(qualifiedTable, trigger, relkind, tgenabled string) string {
	var verb string
	switch tgenabled {
	case "D":
		verb = "DISABLE"
	case "R":
		verb = "ENABLE REPLICA"
	case "A":
		verb = "ENABLE ALWAYS"
	default:
		return ""
	}
	head := "ALTER TABLE "
	if relkind == "f" {
		head = "ALTER FOREIGN TABLE "
	}
	return head + qualifiedTable + " " + verb + " TRIGGER " + d.QuoteIdent(trigger)
}

// dumpRules appends the schema's user-defined non-SELECT rewrite rules
// (pg_rewrite, excluding every view's own '_RETURN' ON SELECT rule) to
// plan.PostData: the CREATE RULE via pg_get_ruledef, a COMMENT ON RULE, and a
// non-default ev_enabled state (ALTER TABLE … ENABLE/DISABLE … RULE — same
// state machine as triggers). Rules ride the default post-data CREATION rank
// (a deliberate choice: like triggers they must exist only after the data
// phase, and firing them during row restore would double-apply their actions);
// the state/comment ride the metadata rank. only/inTables mirror dumpTriggers:
// a single relation for the DumpView path, the gate set for DumpObjects.
func (d dialect) dumpRules(ctx context.Context, db *sql.DB, schema, only string, inTables map[string]bool, plan *driver.DumpPlan) error {
	var nameFilter any
	if only != "" {
		nameFilter = only
	}
	rows, err := db.QueryContext(ctx, `
		SELECT c.relname, r.rulename, pg_get_ruledef(r.oid, true), r.ev_enabled::text,
		       COALESCE(obj_description(r.oid, 'pg_rewrite'), '')
		FROM pg_rewrite r
		JOIN pg_class c ON c.oid = r.ev_class
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = $1 AND r.rulename <> '_RETURN'
		  AND ($2::text IS NULL OR c.relname = $2)
		ORDER BY c.relname, r.rulename`, schema, nameFilter)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var table, name, def, enabled, comment string
		if err := rows.Scan(&table, &name, &def, &enabled, &comment); err != nil {
			return err
		}
		if inTables != nil && !inTables[table] {
			continue
		}
		qtable := d.QuoteIdent(schema) + "." + d.QuoteIdent(table)
		plan.PostData = append(plan.PostData, driver.DumpScript{
			Kind:    "rule",
			Comment: "Rule " + name + " on " + table,
			Drop:    "DROP RULE IF EXISTS " + d.QuoteIdent(name) + " ON " + qtable,
			SQL:     def,
		})
		if comment != "" {
			plan.PostData = append(plan.PostData, driver.DumpScript{
				Kind:    "rule-comment",
				Comment: "Comment for rule " + name + " on " + table,
				SQL:     "COMMENT ON RULE " + d.QuoteIdent(name) + " ON " + qtable + " IS " + d.QuoteString(comment),
			})
		}
		var verb string
		switch enabled {
		case "D":
			verb = "DISABLE"
		case "R":
			verb = "ENABLE REPLICA"
		case "A":
			verb = "ENABLE ALWAYS"
		}
		if verb != "" {
			plan.PostData = append(plan.PostData, driver.DumpScript{
				Kind:    "rule-state",
				Comment: "Enable state for rule " + name + " on " + table,
				SQL:     "ALTER TABLE " + qtable + " " + verb + " RULE " + d.QuoteIdent(name),
			})
		}
	}
	return rows.Err()
}

// dumpViews appends view/matview DDL in dependency order, resolved through
// pg_depend: each view's rewrite rule depends on the relations it reads.
// dumpViews appends the view/matview CREATE + comment scripts for one schema to
// plan. When only is non-empty it restricts emission to that single relation
// (the V1 table-scope single-view export); empty dumps every view/matview in the
// schema, dependency-ordered. Each view carries its graph node id and its
// rewrite-rule edges (relations, routines, types — possibly cross-schema, via
// the resolver); a view-column default is its OWN node depending on the view
// AND its expression's references, so a view can precede a routine that reads
// it while the default follows that routine (breaking the view↔routine cycle
// without any staging).
func (d dialect) dumpViews(ctx context.Context, db *sql.DB, schema, only string, r *dumpNodeResolver, plan *driver.DumpPlan) error {
	// $2 is the optional single-relation filter: NULL (only == "") matches every
	// view/matview, a name restricts to that one. A parameter keeps both call
	// shapes on one query with no string-built predicate.
	var nameFilter any
	if only != "" {
		nameFilter = only
	}
	vrows, err := db.QueryContext(ctx, `
		SELECT c.relname, c.relkind::text, pg_get_viewdef(c.oid, true),
		       COALESCE(obj_description(c.oid, 'pg_class'), ''),
		       COALESCE(array_to_string(c.reloptions, E'\n'), ''),
		       COALESCE((SELECT amname FROM pg_am WHERE oid = c.relam), '')
		FROM pg_class c
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = $1 AND c.relkind IN ('v','m')
		  AND ($2::text IS NULL OR c.relname = $2)
		ORDER BY c.relname`, schema, nameFilter)
	if err != nil {
		return err
	}
	var names []string
	kinds := map[string]string{}
	defs := map[string]string{}
	comments := map[string]string{}
	// G9: a view's storage parameters carry its security_invoker/security_barrier/
	// check_option semantics (restored authorization can silently differ without
	// them); a matview's carry its access method + storage settings.
	reloptions := map[string]string{}
	amnames := map[string]string{}
	for vrows.Next() {
		var name, kind, def, comment, opts, am string
		if err := vrows.Scan(&name, &kind, &def, &comment, &opts, &am); err != nil {
			vrows.Close()
			return err
		}
		names = append(names, name)
		kinds[name] = kind
		defs[name] = def
		comments[name] = comment
		reloptions[name] = opts
		amnames[name] = am
	}
	vrows.Close()
	if err := vrows.Err(); err != nil {
		return err
	}
	if len(names) == 0 {
		return nil
	}

	// Column comments on views/matviews (col_description on the relation's
	// pg_attribute), grouped by relation — COMMENT ON COLUMN is legal on views.
	colComments := map[string][][2]string{} // relname -> [(col, comment)]
	ccRows, err := db.QueryContext(ctx, `
		SELECT c.relname, a.attname, col_description(c.oid, a.attnum)
		FROM pg_class c
		JOIN pg_namespace n ON n.oid = c.relnamespace
		JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped
		WHERE n.nspname = $1 AND c.relkind IN ('v','m')
		  AND ($2::text IS NULL OR c.relname = $2)
		  AND col_description(c.oid, a.attnum) IS NOT NULL
		ORDER BY c.relname, a.attnum`, schema, nameFilter)
	if err != nil {
		return err
	}
	for ccRows.Next() {
		var rel, col, comment string
		if err := ccRows.Scan(&rel, &col, &comment); err != nil {
			ccRows.Close()
			return err
		}
		colComments[rel] = append(colComments[rel], [2]string{col, comment})
	}
	ccRows.Close()
	if err := ccRows.Err(); err != nil {
		return err
	}

	// View-column DEFAULTs (pg_attrdef on a relkind 'v' relation — set via
	// ALTER VIEW … SET DEFAULT, applied by INSERTs through INSTEAD OF triggers /
	// auto-updatable views). Lost today. Matviews cannot carry column defaults.
	colDefaults := map[string][][2]string{} // relname -> [(col, default expr)]
	vdRows, err := db.QueryContext(ctx, `
		SELECT c.relname, a.attname, pg_get_expr(ad.adbin, ad.adrelid)
		FROM pg_attrdef ad
		JOIN pg_class c ON c.oid = ad.adrelid
		JOIN pg_namespace n ON n.oid = c.relnamespace
		JOIN pg_attribute a ON a.attrelid = ad.adrelid AND a.attnum = ad.adnum
		WHERE n.nspname = $1 AND c.relkind = 'v'
		  AND ($2::text IS NULL OR c.relname = $2)
		ORDER BY c.relname, a.attnum`, schema, nameFilter)
	if err != nil {
		return err
	}
	for vdRows.Next() {
		var rel, col, expr string
		if err := vdRows.Scan(&rel, &col, &expr); err != nil {
			vdRows.Close()
			return err
		}
		colDefaults[rel] = append(colDefaults[rel], [2]string{col, expr})
	}
	vdRows.Close()
	if err := vdRows.Err(); err != nil {
		return err
	}

	// Graph edges. Each view's rewrite-rule references (relations, routines,
	// types) become its node's DependsOn; a view-column default's expression
	// references become the default node's own deps.
	viewNodeDeps := map[string][]string{}
	vdefDeps := map[string][]string{} // relname+"\x00"+attname → deps
	if r != nil {
		refRows, err := db.QueryContext(ctx, `
			SELECT c.relname, dep.refclassid::regclass::text, dep.refobjid
			FROM pg_class c
			JOIN pg_rewrite rw ON rw.ev_class = c.oid
			JOIN pg_depend dep ON dep.classid = 'pg_rewrite'::regclass
			  AND dep.objid = rw.oid AND dep.deptype = 'n'
			JOIN pg_namespace n ON n.oid = c.relnamespace
			WHERE n.nspname = $1 AND c.relkind IN ('v','m')
			  AND dep.refclassid IN ('pg_class'::regclass, 'pg_proc'::regclass, 'pg_type'::regclass)
			  AND dep.refobjid <> c.oid
			  AND ($2::text IS NULL OR c.relname = $2)`, schema, nameFilter)
		if err != nil {
			return err
		}
		for refRows.Next() {
			var rel, refClass string
			var refOID int64
			if err := refRows.Scan(&rel, &refClass, &refOID); err != nil {
				refRows.Close()
				return err
			}
			if id := r.resolveRef(refClass, refOID); id != "" && id != nodeID("relation", schema, rel) {
				viewNodeDeps[rel] = append(viewNodeDeps[rel], id)
			}
		}
		refRows.Close()
		if err := refRows.Err(); err != nil {
			return err
		}
		vdRefRows, err := db.QueryContext(ctx, `
			SELECT c.relname, a.attname, dep.refclassid::regclass::text, dep.refobjid
			FROM pg_attrdef ad
			JOIN pg_class c ON c.oid = ad.adrelid
			JOIN pg_namespace n ON n.oid = c.relnamespace
			JOIN pg_attribute a ON a.attrelid = ad.adrelid AND a.attnum = ad.adnum
			JOIN pg_depend dep ON dep.classid = 'pg_attrdef'::regclass
			  AND dep.objid = ad.oid AND dep.deptype = 'n'
			WHERE n.nspname = $1 AND c.relkind = 'v'
			  AND dep.refclassid IN ('pg_class'::regclass, 'pg_proc'::regclass, 'pg_type'::regclass)
			  AND ($2::text IS NULL OR c.relname = $2)`, schema, nameFilter)
		if err != nil {
			return err
		}
		for vdRefRows.Next() {
			var rel, col, refClass string
			var refOID int64
			if err := vdRefRows.Scan(&rel, &col, &refClass, &refOID); err != nil {
				vdRefRows.Close()
				return err
			}
			if id := r.resolveRef(refClass, refOID); id != "" {
				key := rel + "\x00" + col
				vdefDeps[key] = append(vdefDeps[key], id)
			}
		}
		vdRefRows.Close()
		if err := vdRefRows.Err(); err != nil {
			return err
		}
	}

	// Local (same-schema) CREATE ordering, filtered from the DB-wide edge set —
	// cross-schema edges are the writer's global topo's job.
	deps := map[string][]string{}
	edges, err := d.viewDependencyEdges(ctx, db)
	if err != nil {
		return err
	}
	for _, e := range edges {
		fromSchema, fromName, ok1 := strings.Cut(e[0], "\x00")
		toSchema, toName, ok2 := strings.Cut(e[1], "\x00")
		if ok1 && ok2 && fromSchema == schema && toSchema == schema {
			deps[fromName] = append(deps[fromName], toName)
		}
	}

	for _, name := range driver.TopoOrder(names, deps) {
		qname := d.QuoteIdent(schema) + "." + d.QuoteIdent(name)
		def := strings.TrimRight(strings.TrimSpace(defs[name]), ";")
		matview := kinds[name] == "m"
		opts := d.reloptionsClause(reloptions[name])
		if matview {
			plan.Views = append(plan.Views, driver.DumpScript{
				Kind:      "matview",
				Name:      nodeID("relation", schema, name),
				DependsOn: viewNodeDeps[name],
				Comment:   "Materialized view " + name,
				Drop:      "DROP MATERIALIZED VIEW IF EXISTS " + qname,
				SQL:       "CREATE MATERIALIZED VIEW " + qname + d.usingClause(amnames[name]) + opts + " AS\n" + def + "\nWITH NO DATA",
			})
		} else {
			// A view has no access method (relam is 0); its reloptions carry the
			// security/check-option semantics.
			plan.Views = append(plan.Views, driver.DumpScript{
				Kind:      "view",
				Name:      nodeID("relation", schema, name),
				DependsOn: viewNodeDeps[name],
				Comment:   "View " + name,
				Drop:      "DROP VIEW IF EXISTS " + qname,
				DropForm:  driver.DropForm{Class: "VIEW", Ref: qname},
				SQL:       "CREATE OR REPLACE VIEW " + qname + opts + " AS\n" + def,
			})
		}
		// Object + column comments ride right after the CREATE (empty Drop, so
		// teardown skips them — a comment dies with its view).
		commentKw := "VIEW"
		if matview {
			commentKw = "MATERIALIZED VIEW"
		}
		if c := comments[name]; c != "" {
			plan.Views = append(plan.Views, driver.DumpScript{
				Kind:    kinds[name],
				Comment: "Comment for " + name,
				SQL:     "COMMENT ON " + commentKw + " " + qname + " IS " + d.QuoteString(c),
			})
		}
		for _, cc := range colComments[name] {
			plan.Views = append(plan.Views, driver.DumpScript{
				Kind:    kinds[name],
				Comment: "Comment for " + name + "." + cc[0],
				SQL:     "COMMENT ON COLUMN " + qname + "." + d.QuoteIdent(cc[0]) + " IS " + d.QuoteString(cc[1]),
			})
		}
		// A view's column DEFAULTs as their OWN graph nodes — depending
		// on the view AND the expression's references, so a routine reading the
		// view can be created between them (no view↔routine cycle).
		for _, cd := range colDefaults[name] {
			plan.Views = append(plan.Views, driver.DumpScript{
				Kind:      "view-default",
				Name:      "view-default:" + qualifiedKey(schema, name) + "\x00" + cd[0],
				DependsOn: append([]string{nodeID("relation", schema, name)}, vdefDeps[name+"\x00"+cd[0]]...),
				Comment:   "Default for " + name + "." + cd[0],
				SQL:       "ALTER VIEW " + qname + " ALTER COLUMN " + d.QuoteIdent(cd[0]) + " SET DEFAULT " + cd[1],
			})
		}
		if matview {
			// A matview's indexes (secondaryIndexDefs is relkind-agnostic; a
			// matview has no constraint-backing indexes, so every index is emitted —
			// incl. the UNIQUE index REFRESH … CONCURRENTLY requires) + their
			// comments. Collected HERE only: DumpView delegates to this function, so
			// the table-scope single-matview path emits each index exactly once too.
			// No Drop — DROP MATERIALIZED VIEW removes its indexes.
			idxDefs, err := d.secondaryIndexDefs(ctx, db, schema, name)
			if err != nil {
				return err
			}
			for _, def := range idxDefs {
				plan.Views = append(plan.Views, driver.DumpScript{
					Kind:    "index",
					Comment: "Index on materialized view " + name,
					SQL:     def,
				})
			}
			// Per-column physical settings (SET STORAGE / STATISTICS, and SET
			// COMPRESSION on PG14+) via the parameterized ALTER MATERIALIZED VIEW
			// head — previously a matview-only fidelity gap.
			settings, err := d.columnPhysicalSettings(ctx, db, schema, name, "ALTER MATERIALIZED VIEW "+qname)
			if err != nil {
				return err
			}
			for _, s := range settings {
				plan.Views = append(plan.Views, driver.DumpScript{
					Kind:    "matview",
					Comment: "Column settings for " + name,
					SQL:     s,
				})
			}
		}
	}
	return nil
}

// DumpView (ViewDumper) dumps a single view/matview's DDL for a table-scope SQL
// export whose target is a view — where the schema-wide dumpViews pass in
// DumpObjects does not run (that pass is dbScope-only). It reuses dumpViews
// filtered to the one relation (CREATE [MATERIALIZED] VIEW + object/column
// comments); for a POPULATED materialized view with withData set it appends a
// REFRESH, matching pg_dump's `-t matview` output. An unpopulated matview
// restores WITH NO DATA and gets no refresh. The export is not self-contained
// (the view's referenced tables/functions must exist in the target) — the
// caller emits that warning.
func (d dialect) DumpView(ctx context.Context, db *sql.DB, scope driver.Scope, name string, withData bool) (driver.DumpPlan, error) {
	schema := schemaOfScope(scope)
	plan := driver.DumpPlan{}
	resolver, err := d.buildNodeResolver(ctx, db)
	if err != nil {
		return plan, err
	}
	if err := d.dumpViews(ctx, db, schema, name, resolver, &plan); err != nil {
		return plan, err
	}
	// The view's own INSTEAD OF triggers (+ comments and enable state) so
	// a single-view export restores functionally — the trigger's function is an
	// external dependency covered by the not-self-contained warning. PostData
	// trigger kinds are structure-gated by the writer, so a data-only export
	// still drops them. Matviews cannot carry triggers (the pass finds none).
	if err := d.dumpTriggers(ctx, db, schema, name, nil, nil, &plan); err != nil {
		return plan, err
	}
	// The view's user rules (ON INSERT/UPDATE/DELETE DO … — the classic
	// updatable-view mechanism), same single-relation filter.
	if err := d.dumpRules(ctx, db, schema, name, nil, &plan); err != nil {
		return plan, err
	}
	if !withData {
		return plan, nil
	}
	var isMatview, populated bool
	switch err := db.QueryRowContext(ctx, `
		SELECT c.relkind = 'm', c.relispopulated
		FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = $1 AND c.relname = $2 AND c.relkind IN ('v','m')`,
		schema, name).Scan(&isMatview, &populated); {
	case errors.Is(err, sql.ErrNoRows):
		return plan, nil // not a view/matview after all (caller classified it; race)
	case err != nil:
		return plan, err
	}
	if isMatview && populated {
		plan.PostData = append(plan.PostData, driver.DumpScript{
			Kind:    "refresh",
			Comment: "Refresh materialized view " + name,
			SQL:     "REFRESH MATERIALIZED VIEW " + d.QuoteIdent(schema) + "." + d.QuoteIdent(name),
		})
	}
	return plan, nil
}

// dumpMatviewRefreshes emits the REFRESHes for the schema's materialized
// views. Matviews restore WITH NO DATA and are refreshed after the data; the
// refresh is a data-section item (pg_dump emits it in --data-only too), so this
// pass is gated on dbScope alone, not structure. A matview's query can read
// another matview (possibly transitively through a plain view), and PostgreSQL
// refuses to REFRESH a matview whose source matview is still unpopulated — so
// the REFRESHes come out in dependency order, using the same pg_rewrite/
// pg_depend graph dumpViews uses for the CREATE path, not alphabetically.
// The matview set, the edges and the blocked propagation are all
// DATABASE-WIDE (NUL-qualified keys) — a cross-schema matview chain must order
// and block across sections — while emission stays per-schema (each section
// emits its own refreshes; the writer topo-orders them across sections via
// plan.ViewEdges and the refresh node names).
//
// This lives here rather than in dumpViews because a data-only export skips
// dumpViews but still needs these REFRESHes.
func (o *objectDump) dumpMatviewRefreshes(ctx context.Context, db *sql.DB) error {
	d, schema, qualify := o.d, o.schema, o.qualify
	plan := &o.plan

	isMatview := map[string]bool{}
	populated := map[string]bool{}
	matSchema := map[string]string{}
	matName := map[string]string{}
	var names []string
	// ORDER BY so the topo sort (which is stable — ties keep input order)
	// emits independent matviews alphabetically, matching the CREATE path
	// (dumpViews) and the rest of this file's deterministic dump output.
	// relispopulated (G16): an unpopulated (WITH NO DATA) matview restores
	// unpopulated — emitting a REFRESH would wrongly populate it, and a REFRESH
	// of a matview that READS an unpopulated one fails mid-restore.
	mrows, err := db.QueryContext(ctx, `
		SELECT n.nspname, c.relname, c.relispopulated FROM pg_class c
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE c.relkind = 'm' AND `+notSystemSchema("n")+`
		ORDER BY n.nspname, c.relname`)
	if err != nil {
		return err
	}
	for mrows.Next() {
		var mvSchema, name string
		var isPop bool
		if err := mrows.Scan(&mvSchema, &name, &isPop); err != nil {
			mrows.Close()
			return err
		}
		key := qualifiedKey(mvSchema, name)
		populated[key] = isPop
		if !isMatview[key] {
			isMatview[key] = true
			matSchema[key] = mvSchema
			matName[key] = name
			names = append(names, key)
		}
	}
	mrows.Close()
	if err := mrows.Err(); err != nil {
		return err
	}

	// View/matview -> source edges. Plain views appearing on an edge are
	// pulled into the topo set (but never REFRESHed) so a matview -> view ->
	// matview chain still orders the source matview first.
	deps := map[string][]string{}
	seen := map[string]bool{}
	for _, n := range names {
		seen[n] = true
	}
	edges, err := d.viewDependencyEdges(ctx, db)
	if err != nil {
		return err
	}
	plan.ViewEdges = edges
	for _, e := range edges {
		from, to := e[0], e[1]
		deps[from] = append(deps[from], to)
		for _, n := range [...]string{from, to} {
			if !seen[n] {
				seen[n] = true
				names = append(names, n)
			}
		}
	}

	// A matview is "blocked" from refreshing if it is itself unpopulated (its
	// WITH NO DATA create restores it unpopulated — pg_dump parity) or if any
	// of its transitive dependencies (through plain views/matviews) is blocked.
	// Topo order guarantees each dep is resolved before its dependent.
	blocked := map[string]bool{}
	for _, key := range driver.TopoOrder(names, deps) {
		b := isMatview[key] && !populated[key]
		for _, dep := range deps[key] {
			if blocked[dep] {
				b = true
			}
		}
		blocked[key] = b
		if !isMatview[key] || matSchema[key] != schema {
			continue // a plain view, or another section's matview
		}
		if b {
			// A POPULATED matview blocked only because a source is unpopulated:
			// its REFRESH would fail mid-restore, so skip it with a warning. An
			// unpopulated matview is meant to stay unpopulated — skip silently.
			if populated[key] {
				plan.Warnings = append(plan.Warnings,
					"materialized view "+schema+"."+matName[key]+" is not refreshed because it reads an unpopulated materialized view; refresh it manually after populating the source")
			}
			continue
		}
		plan.PostData = append(plan.PostData, driver.DumpScript{
			Kind:    "refresh",
			Name:    "refresh:" + key,
			Comment: "Refresh materialized view " + matName[key],
			SQL:     "REFRESH MATERIALIZED VIEW " + qualify(matName[key]),
		})
	}
	return nil
}
