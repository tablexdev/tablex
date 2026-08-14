// The drop-first teardown audit: before a restore recreates a schema it
// drops what is there, and a DROP under RESTRICT fails when something outside
// the dump depends on the target. This pass warns about those survivors at dump
// time rather than letting the import stop halfway.

package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/tablexdev/tablex/internal/driver"
)

// teardownNode collapses a staged creation node id onto the ONE logical object
// the restored catalog holds — mirroring DumpScript.StageOf for ids that come
// from the resolver rather than from a script.
func teardownNode(id string) string {
	for _, stage := range [...]string{"type-shell:", "type-final:"} {
		if rest, ok := strings.CutPrefix(id, stage); ok {
			return "type:" + rest
		}
	}
	return id
}

// teardownAuditLimit caps how many blocked-drop advisories one database's audit
// emits: past a certain point the list stops informing and starts burying the
// dump's real content.
const teardownAuditLimit = 20

// AuditTeardown is the source-side, warn-only drop-first survivor audit.
// For every planned DROP it looks for pg_depend NORMAL dependents that this
// export does NOT itself drop — an external view over a dumped table, an
// out-of-scope default referencing a dumped sequence, an out-of-scope index
// using a dumped operator class — plus, via pg_inherits, out-of-scope
// inheritance and PARTITION children (partitioning layers 'P'/'S' dependencies
// that a pg_depend NORMAL scan alone would miss). A dependent is resolved to
// its OWNER first: an index, rule, constraint, default or trigger dies with its
// relation, so it blocks nothing when that relation is dropped too.
//
// It is advisory by construction. The export holds only the SOURCE connection,
// so a blocker that exists only in the restore target is unknowable, and a
// fresh target no-ops every `DROP … IF EXISTS` anyway. It never fails an
// export, never suppresses a drop, and never escalates one to CASCADE.
// Coverage is the classes whose OIDs the dump graph resolves (relations,
// types, routines, collations, operators, operator classes/families, casts,
// foreign-data wrappers and servers); user mappings have no dependents.
func (d dialect) AuditTeardown(ctx context.Context, db *sql.DB, planned []driver.TeardownDrop) ([]string, error) {
	if len(planned) == 0 {
		return nil, nil
	}
	stmt := make(map[string]string, len(planned))
	for _, p := range planned {
		if p.Node != "" {
			stmt[p.Node] = p.SQL
		}
	}
	r, err := d.buildNodeResolver(ctx, db)
	if err != nil {
		return nil, err
	}
	// pg_depend classid name → OID → node id, DB-wide. A node reachable through
	// several catalog rows (a standalone composite's pg_type and pg_class
	// entries, a type and its auto-array) is registered under each: a dependent
	// may reference any of them, and dropping the object drops them all.
	byClass := map[string]map[int64]string{}
	add := func(class string, oid int64, id string) {
		if id = teardownNode(id); id == "" {
			return
		}
		if byClass[class] == nil {
			byClass[class] = map[int64]string{}
		}
		byClass[class][oid] = id
	}
	for _, m := range []struct {
		class string
		ids   map[int64]string
	}{
		{"pg_class", r.rel}, {"pg_type", r.typ}, {"pg_proc", r.proc},
		{"pg_collation", r.coll}, {"pg_operator", r.op},
		{"pg_opclass", r.opc}, {"pg_opfamily", r.opf},
	} {
		for oid, id := range m.ids {
			add(m.class, oid, id)
		}
	}
	// Casts and the foreign-data globals are keyed by their own catalogs (the
	// node resolver covers only schema-owned classes). A cast's node id joins
	// its two type OIDs with NUL, which no PostgreSQL text value may carry — so
	// the id is assembled HERE, never in SQL.
	castRows, err := db.QueryContext(ctx, `SELECT oid, castsource::bigint, casttarget::bigint FROM pg_cast`)
	if err != nil {
		return nil, err
	}
	for castRows.Next() {
		var oid, src, tgt int64
		if err := castRows.Scan(&oid, &src, &tgt); err != nil {
			castRows.Close()
			return nil, err
		}
		add("pg_cast", oid, "cast:"+strconv.FormatInt(src, 10)+"\x00"+strconv.FormatInt(tgt, 10))
	}
	castRows.Close()
	if err := castRows.Err(); err != nil {
		return nil, err
	}
	for _, q := range []struct {
		class, sql string
	}{
		{"pg_foreign_data_wrapper", `SELECT oid, 'fdw:' || fdwname FROM pg_foreign_data_wrapper`},
		{"pg_foreign_server", `SELECT oid, 'server:' || srvname FROM pg_foreign_server`},
	} {
		rows, err := db.QueryContext(ctx, q.sql)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var oid int64
			var id string
			if err := rows.Scan(&oid, &id); err != nil {
				rows.Close()
				return nil, err
			}
			add(q.class, oid, id)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
	}

	// The planned (catalog, oid) pairs, as "catalog:oid" tokens. Catalog names
	// hold no ':' or ',' and every OID is numeric, so one parameter carries the
	// list without an array-binding round-trip.
	var toks []string
	var plannedRels []string
	for class, m := range byClass {
		for oid, id := range m {
			if stmt[id] == "" {
				continue
			}
			toks = append(toks, class+":"+strconv.FormatInt(oid, 10))
			if class == "pg_class" {
				plannedRels = append(plannedRels, strconv.FormatInt(oid, 10))
			}
		}
	}
	if len(toks) == 0 {
		return nil, nil
	}
	sort.Strings(toks)
	sort.Strings(plannedRels)

	var warnings []string
	seen := map[string]bool{}
	blocked := func(node, blockerNode, describe string) {
		if blockerNode != "" && (stmt[blockerNode] != "" || blockerNode == node) {
			return // dropped by this export too, or the object itself
		}
		key := node + "\x00" + describe
		if seen[key] {
			return
		}
		seen[key] = true
		if len(warnings) < teardownAuditLimit {
			warnings = append(warnings, "drop-first teardown: "+stmt[node]+
				" may be blocked by "+describe+", which this export does not drop (source-side audit; a fresh target is unaffected)")
		}
	}

	depRows, err := db.QueryContext(ctx, `
		WITH planned AS (
		  SELECT split_part(tok, ':', 1)::regclass AS cls, split_part(tok, ':', 2)::oid AS id
		  FROM unnest(string_to_array($1, ',')) AS tok
		),
		dep AS (
		  SELECT p.cls AS refcls, p.id AS refid, d.classid, d.objid, d.objsubid
		  FROM planned p
		  JOIN pg_depend d ON d.refclassid = p.cls AND d.refobjid = p.id AND d.deptype = 'n'
		)
		SELECT dep.refcls::regclass::text, dep.refid,
		       dep.classid::regclass::text, dep.objid,
		       COALESCE(rw.ev_class, cn.conrelid, ad.adrelid, tg.tgrelid, ix.indrelid, 0)::bigint,
		       pg_describe_object(dep.classid, dep.objid, dep.objsubid)
		FROM dep
		LEFT JOIN pg_rewrite    rw ON dep.classid = 'pg_rewrite'::regclass    AND rw.oid = dep.objid
		LEFT JOIN pg_constraint cn ON dep.classid = 'pg_constraint'::regclass AND cn.oid = dep.objid
		LEFT JOIN pg_attrdef    ad ON dep.classid = 'pg_attrdef'::regclass    AND ad.oid = dep.objid
		LEFT JOIN pg_trigger    tg ON dep.classid = 'pg_trigger'::regclass    AND tg.oid = dep.objid
		LEFT JOIN pg_index      ix ON dep.classid = 'pg_class'::regclass      AND ix.indexrelid = dep.objid
		ORDER BY 1, 2, 3, 4`, strings.Join(toks, ","))
	if err != nil {
		return nil, err
	}
	for depRows.Next() {
		var refCls, depCls, describe string
		var refID, objID, ownerRel int64
		if err := depRows.Scan(&refCls, &refID, &depCls, &objID, &ownerRel, &describe); err != nil {
			depRows.Close()
			return nil, err
		}
		node := byClass[refCls][refID]
		if node == "" || stmt[node] == "" {
			continue
		}
		blockerNode := ""
		if ownerRel != 0 {
			// The dependent dies with its relation: that relation is the blocker.
			blockerNode = byClass["pg_class"][ownerRel]
			if blockerNode == "" {
				// A relation outside the graph's classes (an index on an
				// out-of-scope table) — unknown node, so it cannot be planned.
				blockerNode = "\x00unknown"
			}
		} else {
			blockerNode = byClass[depCls][objID]
			if blockerNode == "" {
				blockerNode = "\x00unknown"
			}
		}
		blocked(node, blockerNode, describe)
	}
	depRows.Close()
	if err := depRows.Err(); err != nil {
		return nil, err
	}

	// Inheritance and partition children: ordinary INHERITS records a NORMAL
	// edge, but partitioning layers 'P'/'S' dependencies instead, and scoped
	// planning drops cross-schema parent links — so an emitted parent can have
	// an out-of-scope child that blocks its DROP.
	if len(plannedRels) > 0 {
		inhRows, err := db.QueryContext(ctx, `
			SELECT i.inhparent::bigint, i.inhrelid::bigint,
			       pg_describe_object('pg_class'::regclass, i.inhrelid, 0)
			FROM pg_inherits i
			WHERE i.inhparent = ANY (string_to_array($1, ',')::oid[])
			ORDER BY 1, 2`, strings.Join(plannedRels, ","))
		if err != nil {
			return nil, err
		}
		for inhRows.Next() {
			var parent, child int64
			var describe string
			if err := inhRows.Scan(&parent, &child, &describe); err != nil {
				inhRows.Close()
				return nil, err
			}
			node := byClass["pg_class"][parent]
			if node == "" || stmt[node] == "" {
				continue
			}
			childNode := byClass["pg_class"][child]
			if childNode == "" {
				childNode = "\x00unknown"
			}
			blocked(node, childNode, describe)
		}
		inhRows.Close()
		if err := inhRows.Err(); err != nil {
			return nil, err
		}
	}
	if len(seen) > len(warnings) {
		warnings = append(warnings, fmt.Sprintf("drop-first teardown: %d further blocked-drop advisories omitted", len(seen)-len(warnings)))
	}
	return warnings, nil
}
