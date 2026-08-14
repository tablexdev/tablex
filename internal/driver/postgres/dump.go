// The dump entry points: value literals for the data stream, the script
// preamble/postamble, and DumpObjects - the per-schema collector that walks the
// catalog once and returns everything the writer needs to reproduce the schema.
// The individual object passes live in the dump_*.go files beside this one.

package postgres

import (
	"context"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io"
	"maps"
	"sort"
	"strings"

	"github.com/tablexdev/tablex/internal/driver"
)

// pgValueHooks: bytea spells '\x…', and a float8 can hold NaN/±Infinity —
// bare tokens are invalid as unquoted numeric literals, but PostgreSQL
// accepts them as the quoted special values.
var pgValueHooks = driver.ValueLiteralHooks{
	BinaryLiteral: func(b []byte) string { return "'\\x" + hex.EncodeToString(b) + "'" },
	NonFinite: func(class string) string {
		switch class {
		case "nan":
			return "'NaN'"
		case "+inf":
			return "'Infinity'"
		}
		return "'-Infinity'"
	},
}

// ValueLiteral renders a cell as a PostgreSQL dump literal (see pgValueHooks).
func (d dialect) ValueLiteral(col driver.ResultColumn, v driver.Value) string {
	return driver.RenderValueLiteral(d.QuoteString, pgValueHooks, col, v)
}

// ExportConnParams pins the export session's GUCs via the libpq `options`
// keyword, appended to any user-supplied options so a predefined server's own
// options compose. row_security=off makes a role that is SUBJECT to
// row-level-security policies FAIL VISIBLY (PostgreSQL raises an error) instead
// of silently exporting policy-filtered rows — a partial backup with no error.
// search_path= (empty, pg_dump parity) makes every pg_get_viewdef /
// pg_get_expr / pg_get_constraintdef deparse FULLY QUALIFY embedded references:
// without it a cross-schema (or even public) reference comes out unqualified
// and fails to resolve on a restore session with a different search_path.
// pg_catalog is always implicitly searched, so the driver's own catalog
// queries are unaffected. Both pins apply to every export format.
func (dialect) ExportConnParams(p driver.ConnParams) driver.ConnParams {
	params := make(map[string]string, len(p.Params)+1)
	maps.Copy(params, p.Params)
	const pin = "-c row_security=off -c search_path="
	if existing := strings.TrimSpace(params["options"]); existing != "" {
		params["options"] = existing + " " + pin
	} else {
		params["options"] = pin
	}
	p.Params = params
	return p
}

// DumpPreamble pins the session state a restore needs: check_function_bodies
// lets function bodies reference objects created later in the dump;
// standard_conforming_strings guards the dump's quote-doubled literals against
// servers configured otherwise; row_security=off (pg_dump parity) makes a
// restore into a target whose tables already carry RLS fail visibly instead of
// silently filtering or rejecting rows. FK constraints are post-data ALTERs, so
// no FK toggle is needed.
func (dialect) DumpPreamble(w io.Writer) {
	fmt.Fprint(w, "SET check_function_bodies = false;\nSET standard_conforming_strings = on;\nSET row_security = off;\n\n")
}

// DumpPostamble: the preamble SETs are session-scoped with no prior state to
// restore, so there is nothing to emit.
func (dialect) DumpPostamble(io.Writer) {}

// objectDump carries one DumpObjects run: the request, the plan being built,
// and the three pieces of state the passes hand to each other. The passes run
// in a fixed order (see DumpObjects) and each appends to plan; naming the
// coupling here is what lets them be separate methods instead of one
// 1,080-line function threading a dozen locals.
type objectDump struct {
	d         dialect
	scope     driver.Scope
	schema    string
	tables    []string
	dbScope   bool
	structure bool
	data      bool

	plan driver.DumpPlan

	// inTables gates every relation-attached pass. It starts as the requested
	// table list, is WIDENED by expandGateSet and NARROWED by the foreign-table
	// suppression in dumpPreData — so a pass must read this field, never
	// recompute the set from tables.
	inTables map[string]bool

	// resolver is the DB-wide OID -> node-id map behind every dependency edge
	// (edges cross schemas, so the maps must too). nil for a data-only dump,
	// which has no pre-data graph.
	resolver *dumpNodeResolver

	// standalone / partStandalone are classifyStandalone's output, read by the
	// object passes: tables materialized WITHOUT their inheritance or partition
	// link, which must therefore carry the inherited/cloned copies the linked
	// paths deliberately skip.
	standalone     map[string]bool
	partStandalone map[string]bool
}

// qualify renders a schema-qualified identifier for a relation in this run's
// schema.
func (o *objectDump) qualify(name string) string {
	return o.d.QuoteIdent(o.schema) + "." + o.d.QuoteIdent(name)
}

// DumpObjects collects routines (pg_get_functiondef), dependency-ordered views
// and materialized views (pg_depend through each view's rewrite rule),
// post-data constraints (FKs verbatim via pg_get_constraintdef — MATCH,
// DEFERRABLE, INITIALLY DEFERRED, NOT VALID and column-subset SET NULL/DEFAULT
// all survive — plus NOT VALID checks), triggers, matview refreshes, sequence
// DDL (CREATE SEQUENCE for serial/standalone sequences, ALTER SEQUENCE … OWNED
// BY linkage) and exact sequence synchronization (setval with the sequence's
// own last_value / is_called, what pg_dump does; MAX(col) is not equivalent).
//
// The passes run in this order and only in this order: the gate set must be
// widened before anything reads it, the pre-data pass narrows it again, and the
// object passes need classifyStandalone's verdict. Each appends to the shared
// plan; the first failure aborts with the partial plan, as before.
func (d dialect) DumpObjects(ctx context.Context, db *sql.DB, scope driver.Scope, tables []string, dbScope, structure, data bool) (driver.DumpPlan, error) {
	o := &objectDump{
		d: d, scope: scope, schema: schemaOfScope(scope), tables: tables,
		dbScope: dbScope, structure: structure, data: data,
		inTables:       driver.StringSet(tables),
		standalone:     map[string]bool{},
		partStandalone: map[string]bool{},
	}
	// Every pass takes (ctx, db) and reports only an error; the plan is o.plan.
	type pass struct {
		when bool
		run  func(context.Context, *sql.DB) error
	}
	for _, p := range []pass{
		{structure, o.buildGraph},
		// The gate set widens for any database-scope dump, structure or not:
		// the sequence pass runs unconditionally and gates on it, so a
		// data-only dump that skipped the widening emitted no setval for a
		// sequence owned by a partition CHILD (children are folded out of the
		// table list) — the restored table then reissues ids the rows already
		// hold. Every OTHER reader of the set is structure-gated, so at
		// data-only the widening reaches the sequence pass alone.
		{dbScope, o.expandGateSet},
		{dbScope && structure, o.dumpPreData},
		// The mixed local/foreign partition-tree split serves BOTH halves of a
		// dump, at ANY scope. Data: it keeps a tree's local rows from being
		// read twice (the root's recursive scan would also open a connection
		// to the REMOTE server). Structure: DumpDataTables keeps the tree's
		// local leaves in the effective table list, and only this split's
		// DataOnlyTables verdict stops each leaf from getting a standalone
		// CREATE alongside the root's own PARTITION OF emission — without it a
		// structure-only db/schema export creates every leaf twice and the
		// restore aborts on "relation already exists". Only its WARNINGS are
		// data-facing (rows not dumped), so those gate on data inside.
		{structure || data, o.collectMixedTreeSplit},
		{structure, o.warnExtensionMembers},
		{structure, o.classifyStandalone},
		{structure, o.dumpRelationObjects},
		{dbScope, o.dumpMatviewRefreshes},
		{true, o.dumpSequences},
	} {
		if !p.when {
			continue
		}
		if err := p.run(ctx, db); err != nil {
			return o.plan, err
		}
	}
	return o.plan, nil
}

// buildGraph loads the DB-wide OID -> node-id resolver behind every dependency
// edge and the tables' graph metadata — tables are not DumpScripts, the handler
// owns their emission, so their edges ride the plan.
func (o *objectDump) buildGraph(ctx context.Context, db *sql.DB) error {
	var err error
	if o.resolver, err = o.d.buildNodeResolver(ctx, db); err != nil {
		return err
	}
	o.plan.TableNodes, err = o.d.collectTableNodes(ctx, db, o.schema, o.tables, o.resolver)
	return err
}

// expandGateSet widens inTables for a database-scope dump, of either kind. The
// object passes (FKs, NOT VALID checks, triggers, RLS, replica identity,
// comments) gate on inTables, but partition CHILDREN are excluded from the
// table list — their DDL rides the parent's PARTITION OF — so a child's LOCAL
// objects would be silently dropped from the dump. Those passes are all
// structure-gated; the sequence pass is not, and it gates on this same set, so
// the widening also decides whether a partition child's serial/identity
// sequence gets its setval in a DATA-ONLY dump (it must: without it the
// restored table hands out ids the restored rows already hold). At db-scope
// every parent is exported, so the set gains every partition descendant; the
// parentid/conislocal filters in those passes then keep only child-LOCAL
// objects (the parent-cloned ones re-clone via PARTITION OF). The set also gains
// the schema's views and matviews (dumped by dumpViews, but absent from the
// handler's table list) so a view's INSTEAD OF triggers ride the trigger pass —
// they were silently dropped before; and foreign tables ('f' — they carry
// triggers, CHECKs and rules too). Views/matviews/foreign tables carry no
// policies or replica identity, and the RLS/replica passes filter relkind, so
// the wider set only affects the trigger/constraint/rule passes. Table-scope
// keeps today's set.
func (o *objectDump) expandGateSet(ctx context.Context, db *sql.DB) error {
	schema, inTables := o.schema, o.inTables

	prows, err := db.QueryContext(ctx, `
		SELECT c.relname FROM pg_class c
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = $1 AND (c.relispartition OR c.relkind IN ('v','m','f'))`, schema)
	if err != nil {
		return err
	}
	for prows.Next() {
		var name string
		if err := prows.Scan(&name); err != nil {
			prows.Close()
			return err
		}
		inTables[name] = true
	}
	prows.Close()
	if err := prows.Err(); err != nil {
		return err
	}
	return nil
}

// dumpPreData collects everything that must exist BEFORE any table is created:
// the schema comment, collations, user-defined types, routines, aggregates,
// operators, foreign tables, views and the inherited-DEFAULT deltas. The order
// inside is load-bearing and each step says why.
func (o *objectDump) dumpPreData(ctx context.Context, db *sql.DB) error {
	d, schema, scope := o.d, o.schema, o.scope
	tables, inTables, resolver := o.tables, o.inTables, o.resolver
	plan := &o.plan

	// G3: the schema's own comment (COMMENT ON SCHEMA), emitted independently of
	// CREATE SCHEMA by the writer (public/default sections write no CREATE
	// SCHEMA but a comment on them must still round-trip).
	if err := db.QueryRowContext(ctx,
		`SELECT COALESCE(obj_description(oid, 'pg_namespace'), '') FROM pg_namespace WHERE nspname = $1`,
		schema).Scan(&plan.SchemaComment); err != nil {
		return err
	}

	// User-defined collations FIRST — a domain, composite attribute or column
	// COLLATE below may reference one, and a restore into an empty server fails
	// without the CREATE COLLATION.
	if err := d.dumpCollations(ctx, db, schema, plan); err != nil {
		return err
	}

	// User-defined types (enum/domain/composite) next — routines and tables
	// below may reference them, and a restore into an empty server fails
	// without the CREATE TYPE/DOMAIN. Dependency-ordered so a domain over a
	// composite (or vice versa) restores.
	if err := d.dumpTypes(ctx, db, schema, resolver, plan); err != nil {
		return err
	}

	// Routines, plus the dependency edges the aggregate pass reuses.
	procDeps, err := o.dumpRoutines(ctx, db)
	if err != nil {
		return err
	}

	// Aggregates (prokind 'a'), reconstructed from the complete
	// pg_aggregate surface — pg_get_functiondef refuses them.
	if err := d.dumpAggregates(ctx, db, schema, procDeps, plan); err != nil {
		return err
	}

	// Operators, operator families and classes (schema-scoped).
	if err := d.dumpOperators(ctx, db, schema, resolver, plan); err != nil {
		return err
	}

	// Foreign tables (structure-only relations; their data lives on
	// the remote server). A state-(c) (template-only) foreign table's
	// dependents are suppressed by removing it from the gate set the
	// trigger/comment/rule passes use. The mixed local/foreign partition-tree
	// data split is NOT here: it is data planning, so it runs as its own
	// data-gated pass in DumpObjects.
	if err := d.dumpForeignTables(ctx, db, schema, "", resolver, plan); err != nil {
		return err
	}
	for _, name := range plan.SuppressedRelations {
		delete(inTables, name)
	}

	if err := d.dumpViews(ctx, db, schema, "", resolver, plan); err != nil {
		return err
	}

	// Divergent inherited/partition-child DEFAULTs and
	// the multi-parent conflict re-established through the deferred-DDL
	// carrier (linked restores only exist at database scope; a table-scope
	// standalone child materializes its own defaults inline).
	if err := d.collectInheritedDefaultDeltas(ctx, db, scope, tables, plan); err != nil {
		return err
	}
	return nil
}

// warnExtensionMembers records what a restore may conflict with, or silently
// lack, because of extension membership. This pass and every one after it is
// structure-only: a data-only dump discards post-data constraints and triggers
// (the writer keeps just sequence/refresh items in PostData), so it must not
// introspect them at all.
func (o *objectDump) warnExtensionMembers(ctx context.Context, db *sql.DB) error {
	schema, inTables, plan := o.schema, o.inTables, &o.plan

	// Extension-ATTACHED relations are deliberately kept LOOSE (dumped
	// like any table/view/matview — TableX emits no CREATE EXTENSION, cannot
	// tell which members the extension's install script would recreate, and
	// excluding one would silently lose its rows/definition). The honest,
	// inert notice below warns that a restore which ALSO runs CREATE
	// EXTENSION may conflict with the loose DDL and halt the import at that
	// statement — a visible, manually-reconcilable failure, never silent
	// loss. (Non-relation extension members — types, routines, collations,
	// sequences — stay EXCLUDED, the pre-existing posture.)
	extRows, err := db.QueryContext(ctx, `
		SELECT c.relname, e.extname
		FROM pg_depend dep
		JOIN pg_class c ON c.oid = dep.objid
		JOIN pg_namespace n ON n.oid = c.relnamespace
		JOIN pg_extension e ON e.oid = dep.refobjid
		WHERE dep.classid = 'pg_class'::regclass
		  AND dep.refclassid = 'pg_extension'::regclass
		  AND dep.deptype = 'e'
		  AND n.nspname = $1 AND c.relkind IN ('r','p','v','m','f')
		ORDER BY c.relname`, schema)
	if err != nil {
		return err
	}
	for extRows.Next() {
		var rel, ext string
		if err := extRows.Scan(&rel, &ext); err != nil {
			extRows.Close()
			return err
		}
		if !inTables[rel] {
			continue
		}
		plan.Warnings = append(plan.Warnings,
			"relation "+schema+"."+rel+" is attached to extension "+ext+" and is dumped as a loose object (its definition/rows are preserved); "+
				"a restore that also runs CREATE EXTENSION "+ext+" may conflict with this loose DDL and stop the import at that statement — "+
				"reconcile manually (do not pre-create the extension, or remove the conflicting statement); the extension-membership link itself is not restored")
	}
	extRows.Close()
	if err := extRows.Err(); err != nil {
		return err
	}

	// NAMED warnings for excluded extension-member NON-relation objects
	// (types, routines/aggregates, collations, sequences — previously
	// excluded silently; the newer object classes warn inline in their own
	// passes). A manually ALTER EXTENSION … ADD-attached object is excluded
	// yet NOT recreated by CREATE EXTENSION — the warning is the honest
	// record that nothing was dropped silently.
	extObjRows, err := db.QueryContext(ctx, `
		SELECT x.kind, x.name, e.extname FROM (
		  SELECT 'type' AS kind, t.typname AS name, dep.refobjid AS ext
		  FROM pg_type t
		  JOIN pg_namespace n ON n.oid = t.typnamespace
		  JOIN pg_depend dep ON dep.classid = 'pg_type'::regclass AND dep.objid = t.oid AND dep.deptype = 'e'
		  WHERE n.nspname = $1 AND t.typtype IN ('e','d','c','r','b')
		  UNION ALL
		  SELECT 'routine', p.proname, dep.refobjid
		  FROM pg_proc p
		  JOIN pg_namespace n ON n.oid = p.pronamespace
		  JOIN pg_depend dep ON dep.classid = 'pg_proc'::regclass AND dep.objid = p.oid AND dep.deptype = 'e'
		  WHERE n.nspname = $1
		  UNION ALL
		  SELECT 'collation', co.collname, dep.refobjid
		  FROM pg_collation co
		  JOIN pg_namespace n ON n.oid = co.collnamespace
		  JOIN pg_depend dep ON dep.classid = 'pg_collation'::regclass AND dep.objid = co.oid AND dep.deptype = 'e'
		  WHERE n.nspname = $1
		  UNION ALL
		  SELECT 'sequence', c.relname, dep.refobjid
		  FROM pg_class c
		  JOIN pg_namespace n ON n.oid = c.relnamespace
		  JOIN pg_depend dep ON dep.classid = 'pg_class'::regclass AND dep.objid = c.oid AND dep.deptype = 'e'
		  WHERE n.nspname = $1 AND c.relkind = 'S'
		) x
		JOIN pg_extension e ON e.oid = x.ext
		ORDER BY x.kind, x.name`, schema)
	if err != nil {
		return err
	}
	for extObjRows.Next() {
		var kind, name, ext string
		if err := extObjRows.Scan(&kind, &name, &ext); err != nil {
			extObjRows.Close()
			return err
		}
		plan.Warnings = append(plan.Warnings,
			kind+" "+schema+"."+name+" belongs to extension "+ext+" and is not dumped; CREATE EXTENSION "+ext+" in the target recreates it only if it is part of the extension's install script")
	}
	extObjRows.Close()
	if err := extObjRows.Err(); err != nil {
		return err
	}
	return nil
}

// classifyStandalone decides which dumped tables are materialized STANDALONE:
// their inheritance or partition link cannot restore, so the object passes must
// emit the inherited/cloned copies the linked paths deliberately skip. A
// partition child appears in the dump set only at table scope (the
// database-scope fold rides it with its parent); an ordinary INHERITS child is
// standalone when any parent is cross-schema or absent from the dump set
// (mirroring the handler's linked-create decision).
func (o *objectDump) classifyStandalone(ctx context.Context, db *sql.DB) error {
	schema, inTables, dbScope := o.schema, o.inTables, o.dbScope
	standalone, partStandalone, plan := o.standalone, o.partStandalone, &o.plan

	if !dbScope {
		pRows, err := db.QueryContext(ctx, `
			SELECT c.relname, COALESCE(pg_get_partition_constraintdef(c.oid), '')
			FROM pg_class c
			JOIN pg_namespace n ON n.oid = c.relnamespace
			WHERE n.nspname = $1 AND c.relispartition
			ORDER BY c.relname`, schema)
		if err != nil {
			return err
		}
		for pRows.Next() {
			var name, bound string
			if err := pRows.Scan(&name, &bound); err != nil {
				pRows.Close()
				return err
			}
			if !inTables[name] {
				continue
			}
			standalone[name] = true
			partStandalone[name] = true
			warn := "partition " + schema + "." + name + " is exported standalone: the partition link is not restored"
			if strings.Contains(bound, "satisfies_hash_partition(") {
				warn += "; its HASH bound cannot be reproduced portably (satisfies_hash_partition embeds the parent's OID), so bound enforcement is not restored"
			} else if bound != "" {
				warn += "; its bound is enforced by a synthesized CHECK constraint"
			}
			plan.Warnings = append(plan.Warnings, warn)
		}
		pRows.Close()
		if err := pRows.Err(); err != nil {
			return err
		}
	}
	inhRows, err := db.QueryContext(ctx, `
		SELECT child.relname, pn.nspname, parent.relname
		FROM pg_inherits i
		JOIN pg_class child ON child.oid = i.inhrelid
		JOIN pg_namespace cn ON cn.oid = child.relnamespace
		JOIN pg_class parent ON parent.oid = i.inhparent
		JOIN pg_namespace pn ON pn.oid = parent.relnamespace
		WHERE cn.nspname = $1 AND child.relkind = 'r' AND NOT child.relispartition
		ORDER BY child.relname, i.inhseqno`, schema)
	if err != nil {
		return err
	}
	crossSchema := map[string][]string{}
	for inhRows.Next() {
		var child, parentSchema, parentName string
		if err := inhRows.Scan(&child, &parentSchema, &parentName); err != nil {
			inhRows.Close()
			return err
		}
		if !inTables[child] {
			continue
		}
		if parentSchema != schema {
			standalone[child] = true
			crossSchema[child] = append(crossSchema[child], parentSchema+"."+parentName)
		} else if !inTables[parentName] {
			standalone[child] = true
		}
	}
	inhRows.Close()
	if err := inhRows.Err(); err != nil {
		return err
	}
	// The handler already warns for absent same-schema parents; the
	// cross-schema case was previously silent.
	crossNames := make([]string, 0, len(crossSchema))
	for child := range crossSchema {
		crossNames = append(crossNames, child)
	}
	sort.Strings(crossNames)
	for _, child := range crossNames {
		plan.Warnings = append(plan.Warnings,
			"table "+schema+"."+child+" inherits from "+strings.Join(crossSchema[child], ", ")+" in another schema; it is dumped standalone and the inheritance link is not restored")
	}
	return nil
}

// dumpRelationObjects emits the post-data objects attached to the dumped
// relations, in restore order: constraints, triggers, rules, row-level security
// and replica identity.
func (o *objectDump) dumpRelationObjects(ctx context.Context, db *sql.DB) error {
	d, schema, inTables := o.d, o.schema, o.inTables
	partStandalone, plan := o.partStandalone, &o.plan

	if err := o.dumpConstraints(ctx, db); err != nil {
		return err
	}

	// Triggers (after data so restored rows do not fire them), shared with the
	// single-view path (DumpView) so an INSTEAD OF trigger's dump shape cannot
	// drift between scopes. partStandalone additionally emits a
	// standalone-materialized partition child's CLONED triggers.
	if err := d.dumpTriggers(ctx, db, schema, "", inTables, partStandalone, plan); err != nil {
		return err
	}

	// User-defined non-SELECT rewrite rules (same gate set — a rule can
	// live on a table or a view).
	if err := d.dumpRules(ctx, db, schema, "", inTables, plan); err != nil {
		return err
	}

	if err := o.dumpRowSecurity(ctx, db); err != nil {
		return err
	}
	return o.dumpReplicaIdentity(ctx, db)
}

// dumpConstraints emits every FK plus the NOT VALID checks that are illegal
// inline, then the inherited named-NOT-NULL state that has to land in the same
// post-data creation rank.
func (o *objectDump) dumpConstraints(ctx context.Context, db *sql.DB) error {
	d, schema, scope := o.d, o.schema, o.scope
	tables, inTables, dbScope := o.tables, o.inTables, o.dbScope
	standalone, qualify, plan := o.standalone, o.qualify, &o.plan

	// PG18+: a NOT VALID named NOT NULL is illegal inline (NOT VALID
	// is ADD CONSTRAINT-only); its bare column clause was suppressed in the
	// CREATE, so the post-data ADD below is what re-establishes it. The
	// relkind <> 'f' guard is defensive: PostgreSQL permits NOT VALID on a
	// foreign table only for CHECK, never NOT NULL, so such a row cannot
	// exist — but emitting it would be invalid DDL.
	nnNotValid := ""
	if d.major >= 18 {
		nnNotValid = `
		    OR (con.contype = 'n' AND NOT con.convalidated AND c.relkind <> 'f')`
	}
	// Every FK, plus NOT VALID checks (illegal inline). The local/cloned
	// classification happens in Go: a partition-cloned FK (conparentid <> 0)
	// or inherited NOT VALID CHECK/NOT NULL normally re-arrives via the
	// parent's PARTITION OF / INHERITS — but a STANDALONE-materialized
	// child has no parent, so its cloned/inherited copies must be
	// emitted as its own.
	conRows, err := db.QueryContext(ctx, `
		SELECT c.relname, con.conname, con.contype::text, con.conislocal,
		       con.conparentid, pg_get_constraintdef(con.oid, true),
		       COALESCE(obj_description(con.oid, 'pg_constraint'), '')
		FROM pg_constraint con
		JOIN pg_class c ON c.oid = con.conrelid
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = $1
		  AND (con.contype = 'f'
		    OR (con.contype = 'c' AND NOT con.convalidated)`+nnNotValid+`)
		ORDER BY c.relname, con.conname`, schema)
	if err != nil {
		return err
	}
	for conRows.Next() {
		var table, name, contype, def, comment string
		var islocal bool
		var parentID int64
		if err := conRows.Scan(&table, &name, &contype, &islocal, &parentID, &def, &comment); err != nil {
			conRows.Close()
			return err
		}
		if !inTables[table] {
			continue
		}
		// G11: only child-LOCAL constraints for linked/riding children — a
		// partition-cloned FK re-clones via PARTITION OF, an inherited CHECK
		// is recreated by the parent, and re-emitting either duplicates it —
		// UNLESS the child is standalone-materialized (no parent on restore).
		keep := false
		switch contype {
		case "f":
			keep = parentID == 0 || standalone[table]
		case "c":
			keep = islocal || standalone[table]
		case "n":
			keep = (islocal && parentID == 0) || standalone[table]
		}
		if !keep {
			continue
		}
		plan.PostData = append(plan.PostData, driver.DumpScript{
			Kind:    "constraint",
			Comment: "Constraint " + name + " on " + table,
			Drop:    "ALTER TABLE IF EXISTS " + qualify(table) + " DROP CONSTRAINT IF EXISTS " + d.QuoteIdent(name),
			SQL:     "ALTER TABLE " + qualify(table) + " ADD CONSTRAINT " + d.QuoteIdent(name) + " " + def,
		})
		// G3: a comment on the constraint (restorable — the recreated constraint
		// keeps its name).
		if comment != "" {
			plan.PostData = append(plan.PostData, driver.DumpScript{
				Kind:    "constraint-comment",
				Comment: "Comment for constraint " + name + " on " + table,
				SQL:     "COMMENT ON CONSTRAINT " + d.QuoteIdent(name) + " ON " + qualify(table) + " IS " + d.QuoteString(comment),
			})
		}
	}
	conRows.Close()
	if err := conRows.Err(); err != nil {
		return err
	}

	// PG18+: the state a purely-inherited named NOT NULL copy still
	// owns (child-local comment; the parent-NOT-VALID/child-validated
	// VALIDATE fix-up). Appended after the constraint pass so a VALIDATE
	// lands after its parent's ADD CONSTRAINT … NOT VALID in the same
	// post-data creation rank.
	if err := d.dumpInheritedNotNullState(ctx, db, scope, tables, dbScope, plan); err != nil {
		return err
	}
	return nil
}

// dumpRowSecurity emits row-level security: the ENABLE/FORCE state and the
// policies.
func (o *objectDump) dumpRowSecurity(ctx context.Context, db *sql.DB) error {
	d, schema, inTables := o.d, o.schema, o.inTables
	qualify, plan := o.qualify, &o.plan

	// G14: row-level security. State (ENABLE/FORCE) and policies are structure,
	// gated on inTables like triggers. Both are Kind-ordered LAST in PostData
	// (rls-state after everything, policy in the creation group): FORCE ROW
	// LEVEL SECURITY subjects even the table owner, so engaging it before the
	// data phase or a matview refresh would filter/reject the restoring role's
	// own rows. The relkind filter is load-bearing — a matview has no REPLICA/
	// RLS statement form.
	rlsRows, err := db.QueryContext(ctx, `
		SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity
		FROM pg_class c
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = $1 AND c.relkind IN ('r','p')
		  AND (c.relrowsecurity OR c.relforcerowsecurity)
		ORDER BY c.relname`, schema)
	if err != nil {
		return err
	}
	for rlsRows.Next() {
		var table string
		var enabled, forced bool
		if err := rlsRows.Scan(&table, &enabled, &forced); err != nil {
			rlsRows.Close()
			return err
		}
		if !inTables[table] {
			continue
		}
		if enabled {
			plan.PostData = append(plan.PostData, driver.DumpScript{
				Kind:    "rls-state",
				Comment: "Enable RLS on " + table,
				SQL:     "ALTER TABLE " + qualify(table) + " ENABLE ROW LEVEL SECURITY",
			})
		}
		if forced {
			plan.PostData = append(plan.PostData, driver.DumpScript{
				Kind:    "rls-state",
				Comment: "Force RLS on " + table,
				SQL:     "ALTER TABLE " + qualify(table) + " FORCE ROW LEVEL SECURITY",
			})
		}
	}
	rlsRows.Close()
	if err := rlsRows.Err(); err != nil {
		return err
	}

	// Policies (CREATE POLICY … [AS RESTRICTIVE] FOR cmd TO roles USING/WITH
	// CHECK). Target roles must pre-exist in the restore target (pg_dump parity).
	polRows, err := db.QueryContext(ctx, `
		SELECT c.relname, pol.polname,
		       pol.polcmd, pol.polpermissive,
		       COALESCE(pg_get_expr(pol.polqual, pol.polrelid), ''),
		       COALESCE(pg_get_expr(pol.polwithcheck, pol.polrelid), ''),
		       CASE WHEN pol.polroles = '{0}' THEN 'PUBLIC'
		            ELSE (SELECT string_agg(quote_ident(rolname), ', ' ORDER BY rolname)
		                  FROM pg_roles WHERE oid = ANY(pol.polroles)) END,
		       COALESCE(obj_description(pol.oid, 'pg_policy'), '')
		FROM pg_policy pol
		JOIN pg_class c ON c.oid = pol.polrelid
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = $1
		ORDER BY c.relname, pol.polname`, schema)
	if err != nil {
		return err
	}
	polCmd := map[string]string{"r": "SELECT", "a": "INSERT", "w": "UPDATE", "d": "DELETE", "*": "ALL"}
	for polRows.Next() {
		var table, name, cmd, roles, using, withCheck, comment string
		var permissive bool
		if err := polRows.Scan(&table, &name, &cmd, &permissive, &using, &withCheck, &roles, &comment); err != nil {
			polRows.Close()
			return err
		}
		if !inTables[table] {
			continue
		}
		q := qualify(table)
		var b strings.Builder
		b.WriteString("CREATE POLICY " + d.QuoteIdent(name) + " ON " + q)
		if !permissive {
			b.WriteString(" AS RESTRICTIVE")
		}
		if c, ok := polCmd[cmd]; ok && cmd != "*" {
			b.WriteString(" FOR " + c)
		}
		if roles != "" {
			b.WriteString(" TO " + roles)
		}
		if using != "" {
			b.WriteString(" USING (" + using + ")")
		}
		if withCheck != "" {
			b.WriteString(" WITH CHECK (" + withCheck + ")")
		}
		plan.PostData = append(plan.PostData, driver.DumpScript{
			Kind:    "policy",
			Comment: "Policy " + name + " on " + table,
			SQL:     b.String(),
		})
		if comment != "" {
			plan.PostData = append(plan.PostData, driver.DumpScript{
				Kind:    "policy",
				Comment: "Comment for policy " + name + " on " + table,
				SQL:     "COMMENT ON POLICY " + d.QuoteIdent(name) + " ON " + q + " IS " + d.QuoteString(comment),
			})
		}
	}
	polRows.Close()
	if err := polRows.Err(); err != nil {
		return err
	}
	return nil
}

// dumpReplicaIdentity emits non-default REPLICA IDENTITY settings.
func (o *objectDump) dumpReplicaIdentity(ctx context.Context, db *sql.DB) error {
	d, schema, inTables := o.d, o.schema, o.inTables
	qualify, plan := o.qualify, &o.plan

	// G15(a): non-default REPLICA IDENTITY (relreplident <> 'd'), inTables-gated.
	// Ordered in the metadata group, AFTER index/constraint creation so a USING
	// INDEX target exists. relkind IN ('r','p') is load-bearing — a matview
	// defaults to relreplident 'n' but has no REPLICA IDENTITY statement form.
	riRows, err := db.QueryContext(ctx, `
		SELECT c.relname, c.relreplident, COALESCE(i.relname, '')
		FROM pg_class c
		JOIN pg_namespace n ON n.oid = c.relnamespace
		LEFT JOIN pg_index ix ON ix.indrelid = c.oid AND ix.indisreplident
		LEFT JOIN pg_class i ON i.oid = ix.indexrelid
		WHERE n.nspname = $1 AND c.relkind IN ('r','p') AND c.relreplident <> 'd'
		ORDER BY c.relname`, schema)
	if err != nil {
		return err
	}
	for riRows.Next() {
		var table, replident, idxName string
		if err := riRows.Scan(&table, &replident, &idxName); err != nil {
			riRows.Close()
			return err
		}
		if !inTables[table] {
			continue
		}
		var clause string
		switch replident {
		case "f":
			clause = "FULL"
		case "n":
			clause = "NOTHING"
		case "i":
			if idxName == "" {
				// The identity index was dropped; PostgreSQL then behaves as
				// NOTHING. Restoring the default would wrongly re-activate a PK
				// identity, so emit NOTHING with a warning.
				clause = "NOTHING"
				plan.Warnings = append(plan.Warnings,
					"table "+schema+"."+table+" has REPLICA IDENTITY USING INDEX but no surviving identity index; dumped as REPLICA IDENTITY NOTHING")
			} else {
				clause = "USING INDEX " + d.QuoteIdent(idxName)
			}
		default:
			continue
		}
		plan.PostData = append(plan.PostData, driver.DumpScript{
			Kind:    "replica-identity",
			Comment: "Replica identity for " + table,
			SQL:     "ALTER TABLE ONLY " + qualify(table) + " REPLICA IDENTITY " + clause,
		})
	}
	riRows.Close()
	if err := riRows.Err(); err != nil {
		return err
	}
	return nil
}
