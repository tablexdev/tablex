// Ordinary table inheritance for the dump path: which parents are in scope,
// the INHERITS-linked child CREATE, the divergent inherited DEFAULTs that must
// be re-established after restore, and inherited NOT NULL state (PG18+).

package postgres

import (
	"context"
	"database/sql"
	"slices"
	"sort"
	"strings"

	"github.com/tablexdev/tablex/internal/driver"
)

// localColumnSet returns the names of a table's LOCALLY-declared columns
// (attislocal) — an INHERITS child re-declares only these; inherited-only columns
// come from the parent.
func (d dialect) localColumnSet(ctx context.Context, db *sql.DB, schema, table string) (map[string]bool, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT a.attname
		FROM pg_attribute a
		JOIN pg_class c ON c.oid = a.attrelid
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname=$1 AND c.relname=$2 AND a.attnum>0 AND NOT a.attisdropped AND a.attislocal`,
		schema, table)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	set := map[string]bool{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		set[name] = true
	}
	return set, rows.Err()
}

// InheritanceParents (Inheritor, G10) returns, for each table in `tables` that is
// an ordinary (INHERITS, non-partition) inheritance CHILD whose EVERY parent is
// in the SAME schema, that child's parent bare-names ordered by inhseqno. A child
// with any cross-schema parent, or a partition child, is omitted — it dumps
// standalone. The handler uses this both to order parents before children and to
// decide the linked create.
func (d dialect) InheritanceParents(ctx context.Context, db *sql.DB, scope driver.Scope, tables []string) (map[string][]string, error) {
	schema := schemaOfScope(scope)
	inScope := driver.StringSet(tables)
	rows, err := db.QueryContext(ctx, `
		SELECT child.relname, pn.nspname, parent.relname, i.inhseqno
		FROM pg_inherits i
		JOIN pg_class child ON child.oid = i.inhrelid
		JOIN pg_namespace cn ON cn.oid = child.relnamespace
		JOIN pg_class parent ON parent.oid = i.inhparent
		JOIN pg_namespace pn ON pn.oid = parent.relnamespace
		WHERE cn.nspname = $1 AND child.relkind = 'r' AND NOT child.relispartition
		ORDER BY child.relname, i.inhseqno`, schema)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	parents := map[string][]string{}
	external := map[string]bool{}
	for rows.Next() {
		var child, parentSchema, parentName string
		var seq int
		if err := rows.Scan(&child, &parentSchema, &parentName, &seq); err != nil {
			return nil, err
		}
		if !inScope[child] {
			continue // not one of the tables being dumped
		}
		if parentSchema != schema {
			external[child] = true // cross-schema parent → dump standalone
			continue
		}
		parents[child] = append(parents[child], parentName)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// A child with ANY external parent cannot be partially linked.
	for child := range external {
		delete(parents, child)
	}
	return parents, nil
}

// DumpInheritsChildCreate (Inheritor, G10) emits an ordinary INHERITS child's
// CREATE TABLE with an INHERITS clause (parents qualified into the child's
// schema), local-only columns and local-only inline constraints.
func (d dialect) DumpInheritsChildCreate(ctx context.Context, db *sql.DB, t driver.TableRef, parents []string) (string, error) {
	qualified := make([]string, len(parents))
	for i, p := range parents {
		qualified[i] = d.QuoteIdent(schemaOf(t)) + "." + d.QuoteIdent(p)
	}
	return d.dumpTableCreate(ctx, db, t, qualified, nil, nil)
}

// collectInheritedDefaultDeltas reconciles inherited-column DEFAULTs a
// linked restore would silently change. A LINKED INHERITS child's CREATE omits
// inherited-only columns, so the child restores with its parents' create-time
// defaults; a partition child (PARTITION OF) restores with the ROOT's. The
// source can diverge from either (ALTER TABLE ONLY …), in both directions —
// each delta re-establishes the child's own state through the post-data
// deferred-DDL carrier (Kind "staged-default"; data INSERTs name every column
// explicitly, so restored rows are unaffected). The multi-parent CONFLICT case
// (parents disagree on one inherited column's default — CREATE … INHERITS
// fails before any staged DDL could run) suppresses the column's inline
// default across the whole affected hierarchy (DumpPlan.StagedDefaultColumns,
// rendered by the handler through DumpTableCreateStaged) and re-emits every
// member's own effective default the same way — attislocal/attinhcount stay
// untouched, exactly pg_dump's separate-default-statement strategy.
func (d dialect) collectInheritedDefaultDeltas(ctx context.Context, db *sql.DB, scope driver.Scope, tables []string, plan *driver.DumpPlan) error {
	schema := schemaOfScope(scope)
	inSet := driver.StringSet(tables)
	qualify := func(name string) string { return d.QuoteIdent(schema) + "." + d.QuoteIdent(name) }
	stage := func(table, col, def string) {
		s := driver.DumpScript{
			Kind:    "staged-default",
			Comment: "Deferred default for " + table + "." + col,
			SQL:     "ALTER TABLE ONLY " + qualify(table) + " ALTER COLUMN " + d.QuoteIdent(col) + " SET DEFAULT " + def,
		}
		if def == "" {
			s.Comment = "Dropped inherited default for " + table + "." + col
			s.SQL = "ALTER TABLE ONLY " + qualify(table) + " ALTER COLUMN " + d.QuoteIdent(col) + " DROP DEFAULT"
		}
		plan.PostData = append(plan.PostData, s)
	}

	// Linked children (same-schema parents, all in the dump set — mirrors the
	// handler's linked-create decision) and which tables have parents at all.
	parents, err := d.InheritanceParents(ctx, db, scope, tables)
	if err != nil {
		return err
	}
	linkedParents := map[string][]string{}
	for child, ps := range parents {
		ok := len(ps) > 0
		for _, p := range ps {
			if !inSet[p] {
				ok = false
				break
			}
		}
		if ok {
			linkedParents[child] = ps
		}
	}
	hasParents := map[string]bool{}
	hpRows, err := db.QueryContext(ctx, `
		SELECT DISTINCT child.relname
		FROM pg_inherits i
		JOIN pg_class child ON child.oid = i.inhrelid
		JOIN pg_namespace cn ON cn.oid = child.relnamespace
		WHERE cn.nspname = $1 AND child.relkind = 'r' AND NOT child.relispartition`, schema)
	if err != nil {
		return err
	}
	for hpRows.Next() {
		var name string
		if err := hpRows.Scan(&name); err != nil {
			hpRows.Close()
			return err
		}
		hasParents[name] = true
	}
	hpRows.Close()
	if err := hpRows.Err(); err != nil {
		return err
	}

	// Every ordinary-relation column's (attislocal, default) in the schema.
	type colState struct {
		islocal bool
		def     string // "" = no default
		has     bool   // false = the table lacks the column
	}
	cols := map[string]colState{}
	colNames := map[string][]string{}
	cRows, err := db.QueryContext(ctx, `
		SELECT c.relname, a.attname, a.attislocal,
		       COALESCE(pg_get_expr(ad.adbin, ad.adrelid), '')
		FROM pg_attribute a
		JOIN pg_class c ON c.oid = a.attrelid
		JOIN pg_namespace n ON n.oid = c.relnamespace
		LEFT JOIN pg_attrdef ad ON ad.adrelid = a.attrelid AND ad.adnum = a.attnum
		WHERE n.nspname = $1 AND c.relkind = 'r' AND NOT c.relispartition
		  AND a.attnum > 0 AND NOT a.attisdropped
		  AND a.attgenerated = '' AND a.attidentity = ''
		ORDER BY c.relname, a.attnum`, schema)
	if err != nil {
		return err
	}
	for cRows.Next() {
		var tbl, col string
		var islocal bool
		var def string
		if err := cRows.Scan(&tbl, &col, &islocal, &def); err != nil {
			cRows.Close()
			return err
		}
		cols[tbl+"\x00"+col] = colState{islocal: islocal, def: def, has: true}
		colNames[tbl] = append(colNames[tbl], col)
	}
	cRows.Close()
	if err := cRows.Err(); err != nil {
		return err
	}

	// eff(t, col): the default t carries AT A DEPENDENT'S CREATE TIME on
	// restore — its own inline default (root/standalone table, or a locally
	// re-declared column), or, for a linked child's inherited-only column, its
	// parents' create-time merge (the child's own staged ALTER runs post-data,
	// AFTER every dependent create). Suppressed inline defaults read as none.
	suppressed := map[string]bool{}
	// Initialised here as well as reset in parentMerge below: eff WRITES to it,
	// and a nil map panics on write. Today parentMerge always resets it before
	// any eff call, so this is latent rather than live — but eff is recursive and
	// called from two places, and "the only caller happens to initialise it
	// first" is not a property to leave a future caller to discover.
	memo := map[string]string{}
	var eff func(tbl, col string) string
	eff = func(tbl, col string) string {
		key := tbl + "\x00" + col
		if v, ok := memo[key]; ok {
			return v
		}
		st := cols[key]
		ps := linkedParents[tbl]
		v := ""
		switch {
		case suppressed[key]:
		case len(ps) == 0 || (st.has && st.islocal):
			v = st.def
		default:
			var distinct []string
			for _, p := range ps {
				if pv := eff(p, col); pv != "" && !slices.Contains(distinct, pv) {
					distinct = append(distinct, pv)
				}
			}
			if len(distinct) == 1 {
				v = distinct[0]
			}
			// >1 parents disagreeing: the conflict phase below resolves it;
			// treat as none here (matches the post-suppression state).
		}
		memo[key] = v
		return v
	}
	parentMerge := func(child, col string) (string, bool) {
		memo = map[string]string{}
		var distinct []string
		for _, p := range linkedParents[child] {
			if pv := eff(p, col); pv != "" && !slices.Contains(distinct, pv) {
				distinct = append(distinct, pv)
			}
		}
		if len(distinct) > 1 {
			return "", true
		}
		if len(distinct) == 1 {
			return distinct[0], false
		}
		return "", false
	}

	// Hierarchy components over the linked edges (for conflict suppression).
	adj := map[string][]string{}
	for child, ps := range linkedParents {
		for _, p := range ps {
			adj[child] = append(adj[child], p)
			adj[p] = append(adj[p], child)
		}
	}
	component := func(start string) []string {
		seen := map[string]bool{start: true}
		queue := []string{start}
		var out []string
		for len(queue) > 0 {
			cur := queue[0]
			queue = queue[1:]
			out = append(out, cur)
			for _, next := range adj[cur] {
				if !seen[next] {
					seen[next] = true
					queue = append(queue, next)
				}
			}
		}
		sort.Strings(out)
		return out
	}

	children := make([]string, 0, len(linkedParents))
	for child := range linkedParents {
		children = append(children, child)
	}
	sort.Strings(children)

	// Phase 1 — conflicts: suppress the column across the component, stage
	// every member's own default. A standalone-materialized member (unlinked
	// child) keeps its full inline create and is skipped.
	for _, child := range children {
		for _, col := range colNames[child] {
			key := child + "\x00" + col
			if cols[key].islocal || suppressed[key] {
				continue
			}
			if _, conflict := parentMerge(child, col); !conflict {
				continue
			}
			comp := component(child)
			var stagedMembers []string
			for _, m := range comp {
				mkey := m + "\x00" + col
				mst := cols[mkey]
				_, linked := linkedParents[m]
				if !linked && hasParents[m] {
					continue // standalone materialization carries its own inline default
				}
				if !mst.has || mst.def == "" || suppressed[mkey] {
					continue
				}
				suppressed[mkey] = true
				stagedMembers = append(stagedMembers, m)
				if !linked || mst.islocal {
					// The default is INLINE on this member — suppress it at
					// CREATE (the handler re-renders via DumpTableCreateStaged,
					// which also emits the staged SET DEFAULT).
					if plan.StagedDefaultColumns == nil {
						plan.StagedDefaultColumns = map[string][]string{}
					}
					plan.StagedDefaultColumns[m] = append(plan.StagedDefaultColumns[m], col)
				} else {
					// Inherited-only: nothing inline to suppress — just stage.
					stage(m, col, mst.def)
				}
			}
			plan.Warnings = append(plan.Warnings,
				"column "+col+" of the inheritance hierarchy around "+schema+"."+child+" has conflicting parent defaults (CREATE TABLE … INHERITS would fail); the defaults of "+strings.Join(stagedMembers, ", ")+" are re-established after the data phase instead of inline")
		}
	}

	// Phase 2 — plain divergences on linked children, both directions.
	for _, child := range children {
		for _, col := range colNames[child] {
			key := child + "\x00" + col
			st := cols[key]
			if st.islocal || suppressed[key] {
				continue
			}
			expected, _ := parentMerge(child, col)
			if st.def != expected {
				stage(child, col, st.def)
			}
		}
	}

	// Partition children: their creates (PARTITION OF, riding the root) carry
	// no defaults — each child copies the ROOT's inline default at create
	// time — so any child whose source default differs from the root's
	// re-establishes it post-data. Only children whose root is dumped IN THIS
	// SECTION are staged (the child's create provably rides it); a
	// cross-schema-rooted child stays the documented cross-schema residual.
	// Foreign leaves are skipped (ALTER TABLE does not address them).
	pdRows, err := db.QueryContext(ctx, `
		SELECT c.relname, rn.nspname, r.relname, a.attname,
		       COALESCE(pg_get_expr(ad.adbin, ad.adrelid), ''),
		       COALESCE(pg_get_expr(rad.adbin, rad.adrelid), '')
		FROM pg_class c
		JOIN pg_namespace cn ON cn.oid = c.relnamespace
		JOIN pg_class r ON r.oid = pg_partition_root(c.oid) AND r.oid <> c.oid
		JOIN pg_namespace rn ON rn.oid = r.relnamespace
		JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum > 0
		  AND NOT a.attisdropped AND a.attgenerated = '' AND a.attidentity = ''
		JOIN pg_attribute ra ON ra.attrelid = r.oid AND ra.attname = a.attname
		  AND NOT ra.attisdropped
		LEFT JOIN pg_attrdef ad ON ad.adrelid = c.oid AND ad.adnum = a.attnum
		LEFT JOIN pg_attrdef rad ON rad.adrelid = r.oid AND rad.adnum = ra.attnum
		WHERE cn.nspname = $1 AND c.relispartition AND c.relkind IN ('r','p')
		ORDER BY c.relname, a.attnum`, schema)
	if err != nil {
		return err
	}
	for pdRows.Next() {
		var child, rootSchema, rootName, col, childDef, rootDef string
		if err := pdRows.Scan(&child, &rootSchema, &rootName, &col, &childDef, &rootDef); err != nil {
			pdRows.Close()
			return err
		}
		if rootSchema == schema && inSet[rootName] && childDef != rootDef {
			stage(child, col, childDef)
		}
	}
	pdRows.Close()
	return pdRows.Err()
}

// dumpInheritedNotNullState (PG18+) emits the post-data statements a
// PURELY-INHERITED named NOT NULL copy (conislocal = false) still owns. Its
// DEFINITION is always suppressed — the constraint re-arrives via INHERITS or
// PARTITION OF — but a COMMENT is per-constraint-row (inlineConstraintComments
// never covers contype 'n'), and the copy's VALIDATION state can differ from
// its parent's: a child can be validated while the parent is NOT VALID, in
// which case the restored child inherits the parent's post-data NOT VALID
// state and needs an ALTER TABLE … VALIDATE CONSTRAINT fix-up (the pg_dump
// approach; validating an already-valid constraint is a no-op). Both are
// emitted ONLY when the recreated parent link actually exists: an ordinary
// INHERITS child LINKED to emitted parents (the same InheritanceParents/all-in
// decision the export handler makes) or a partition child at db-scope
// (recreated via PARTITION OF; NOT VALID NOT NULL is impossible on
// partitioned parents, so partitions need no VALIDATE). A STANDALONE child
// gets nothing here — no orphan DDL; its bare NOT NULL clause was kept.
func (d dialect) dumpInheritedNotNullState(ctx context.Context, db *sql.DB, scope driver.Scope, tables []string, dbScope bool, plan *driver.DumpPlan) error {
	if d.major < 18 {
		return nil
	}
	schema := schemaOfScope(scope)
	qualify := func(name string) string { return d.QuoteIdent(schema) + "." + d.QuoteIdent(name) }
	parents, err := d.InheritanceParents(ctx, db, scope, tables)
	if err != nil {
		return err
	}
	inSet := driver.StringSet(tables)
	linked := map[string]bool{}
	for child, ps := range parents {
		ok := len(ps) > 0
		for _, p := range ps {
			if !inSet[p] {
				ok = false
				break
			}
		}
		linked[child] = ok
	}

	// Every named NOT NULL's validity in the schema, keyed relname+"\x00"+attname.
	// The inherited copy has no parent-constraint link (conparentid is
	// partition-only), so the parent match is by column name.
	validity := map[string]bool{}
	vRows, err := db.QueryContext(ctx, `
		SELECT c.relname, a.attname, con.convalidated
		FROM pg_constraint con
		JOIN pg_class c ON c.oid = con.conrelid
		JOIN pg_namespace n ON n.oid = c.relnamespace
		JOIN pg_attribute a ON a.attrelid = con.conrelid AND a.attnum = con.conkey[1]
		WHERE n.nspname = $1 AND con.contype = 'n'`, schema)
	if err != nil {
		return err
	}
	for vRows.Next() {
		var rel, att string
		var valid bool
		if err := vRows.Scan(&rel, &att, &valid); err != nil {
			vRows.Close()
			return err
		}
		validity[rel+"\x00"+att] = valid
	}
	vRows.Close()
	if err := vRows.Err(); err != nil {
		return err
	}

	rows, err := db.QueryContext(ctx, `
		SELECT c.relname, c.relispartition, con.conname, con.convalidated, a.attname,
		       COALESCE(obj_description(con.oid, 'pg_constraint'), '')
		FROM pg_constraint con
		JOIN pg_class c ON c.oid = con.conrelid
		JOIN pg_namespace n ON n.oid = c.relnamespace
		JOIN pg_attribute a ON a.attrelid = con.conrelid AND a.attnum = con.conkey[1]
		WHERE n.nspname = $1 AND con.contype = 'n' AND NOT con.conislocal
		ORDER BY c.relname, con.conname`, schema)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var child, conname, attname, comment string
		var isPartition, validated bool
		if err := rows.Scan(&child, &isPartition, &conname, &validated, &attname, &comment); err != nil {
			return err
		}
		if !linked[child] && !(isPartition && dbScope) {
			continue // STANDALONE (or out-of-dump) child: no orphan DDL
		}
		if comment != "" {
			plan.PostData = append(plan.PostData, driver.DumpScript{
				Kind:    "constraint-comment",
				Comment: "Comment for constraint " + conname + " on " + child,
				SQL:     "COMMENT ON CONSTRAINT " + d.QuoteIdent(conname) + " ON " + qualify(child) + " IS " + d.QuoteString(comment),
			})
		}
		if validated && linked[child] {
			for _, p := range parents[child] {
				if valid, ok := validity[p+"\x00"+attname]; ok && !valid {
					plan.PostData = append(plan.PostData, driver.DumpScript{
						Kind:    "constraint",
						Comment: "Validate constraint " + conname + " on " + child,
						SQL:     "ALTER TABLE " + qualify(child) + " VALIDATE CONSTRAINT " + d.QuoteIdent(conname),
					})
					break
				}
			}
		}
	}
	return rows.Err()
}
