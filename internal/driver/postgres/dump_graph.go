// The dump dependency graph: the database-wide OID -> node-id resolver
// every dependency edge is expressed through, and the table/view edge
// collectors that feed the writer's topological order and cycle staging.

package postgres

import (
	"context"
	"database/sql"
	"strconv"
	"strings"

	"github.com/tablexdev/tablex/internal/driver"
)

// nodeID builds a dump-graph node id: "<kind>:<schema>\x00<name>". The NUL
// separator keeps ids collision-free for names containing dots ("a.b"."c" vs
// "a"."b.c"); ids are internal to the planner and never emitted into a dump.
func nodeID(kind, schema, name string) string { return kind + ":" + schema + "\x00" + name }

// routineNodeID appends the identity arguments so overloads never collapse
// onto one node.
func routineNodeID(schema, name, identityArgs string) string {
	return "routine:" + schema + "\x00" + name + "\x00" + identityArgs
}

// qualifiedKey is the NUL-joined "schema\x00name" spelling ViewEdges and
// refresh node ids share with the writer's refresh-ordering graph.
func qualifiedKey(schema, name string) string { return schema + "\x00" + name }

// dumpNodeResolver maps catalog OIDs to graph node ids, DATABASE-WIDE (edges
// cross schemas). It implements the producer registry: every side-effect
// type OID is canonicalized to its ACTUAL producer — a standalone composite to
// its own type node, a relation ROW TYPE to the relation node (it has no
// separate create), an auto-ARRAY to its element's producer (a true array is
// identified exclusively by the reverse typarray relationship — neither
// typelem alone nor typcategory proves arrayness), a domain to itself (the
// domain IS the producer; its base type is the domain's own edge). Classes
// TableX does not (yet) dump — base/range/multirange types, indexes, TOAST —
// resolve to "" and the edge is dropped as a boundary reference. Misses
// resolve to "" too: pinned built-ins never appear in pg_depend, so a missing
// OID is an extension/system object, and genuine mid-export drift surfaces as
// a failed deparse (visible export error) rather than silent misordering.
type dumpNodeResolver struct {
	rel  map[int64]string // pg_class oid → node id ("" = known-undumped kind)
	typ  map[int64]string // pg_type oid → producer node id
	proc map[int64]string // pg_proc oid → routine node id
	coll map[int64]string // pg_collation oid → collation node id
	op   map[int64]string // pg_operator oid → operator node id
	opc  map[int64]string // pg_opclass oid → opclass node id
	opf  map[int64]string // pg_opfamily oid → opfamily node id
	// shellSelf marks the pg_type OIDs of the shell-staged (base/range) types
	// THEMSELVES: a routine SIGNATURE edge to one of these targets the
	// "type-shell:" stage (shell types are legal in signatures — the documented
	// bootstrap). A SIDE-EFFECT type resolved to the same final node — the
	// range's multirange, an auto-array — is NOT marked: it only exists once
	// the final CREATE ran, so even a signature edge must wait for the final.
	shellSelf map[int64]bool
}

// notSystemSchema renders the user-schema predicate for the DB-wide scans
// (mirrors ListSchemas' system classification), parameterized on the
// pg_namespace alias.
func notSystemSchema(alias string) string {
	return alias + `.nspname NOT LIKE 'pg\_%' AND ` + alias + `.nspname <> 'information_schema'`
}

// buildNodeResolver loads the DB-wide OID→node maps (four catalog scans over
// user schemas). Run once per DumpObjects pass; the maps are small (user
// objects only — pinned built-ins never appear in pg_depend edges).
func (d dialect) buildNodeResolver(ctx context.Context, db *sql.DB) (*dumpNodeResolver, error) {
	r := &dumpNodeResolver{
		rel:       map[int64]string{},
		typ:       map[int64]string{},
		proc:      map[int64]string{},
		coll:      map[int64]string{},
		op:        map[int64]string{},
		opc:       map[int64]string{},
		opf:       map[int64]string{},
		shellSelf: map[int64]bool{},
	}
	// Relations (any relkind — an unhandled kind maps to "" so a reference to
	// an index or TOAST relation is dropped, never mis-ordered).
	rows, err := db.QueryContext(ctx, `
		SELECT c.oid, n.nspname, c.relname, c.relkind::text
		FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE `+notSystemSchema("n"))
	if err != nil {
		return nil, err
	}
	type relRow struct {
		schema, name, kind string
	}
	rels := map[int64]relRow{}
	for rows.Next() {
		var oid int64
		var rr relRow
		if err := rows.Scan(&oid, &rr.schema, &rr.name, &rr.kind); err != nil {
			rows.Close()
			return nil, err
		}
		rels[oid] = rr
		switch rr.kind {
		case "r", "p", "v", "m", "S", "f":
			r.rel[oid] = nodeID("relation", rr.schema, rr.name)
		case "c":
			// A standalone composite's pg_class entry: its producer is the TYPE
			// node (resolved again below via pg_type, but a direct pg_class
			// reference to it must land on the same node).
			r.rel[oid] = nodeID("type", rr.schema, rr.name)
		default:
			r.rel[oid] = ""
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Types: two passes — load raw rows, then resolve recursively (arrays chain
	// to their element with cycle protection). The multirange → range map comes
	// from pg_range (rngmultitypid, PG14+ — read via to_jsonb so the PG13 floor
	// still parses).
	trows, err := db.QueryContext(ctx, `
		SELECT t.oid, n.nspname, t.typname, t.typtype::text, t.typelem, t.typarray, t.typrelid,
		       t.typisdefined
		FROM pg_type t JOIN pg_namespace n ON n.oid = t.typnamespace
		WHERE `+notSystemSchema("n"))
	if err != nil {
		return nil, err
	}
	type typRow struct {
		schema, name, typtype   string
		elem, arrayOf, typrelid int64
		defined                 bool
	}
	typs := map[int64]typRow{}
	for trows.Next() {
		var oid int64
		var tr typRow
		if err := trows.Scan(&oid, &tr.schema, &tr.name, &tr.typtype, &tr.elem, &tr.arrayOf, &tr.typrelid, &tr.defined); err != nil {
			trows.Close()
			return nil, err
		}
		typs[oid] = tr
	}
	trows.Close()
	if err := trows.Err(); err != nil {
		return nil, err
	}
	// multirange oid → its range oid (a multirange and its array are side
	// effects of the range's final CREATE — the producer registry).
	rangeOf := map[int64]int64{}
	mrRows, err := db.QueryContext(ctx, `
		SELECT rng.rngtypid, COALESCE((to_jsonb(rng)->>'rngmultitypid')::bigint, 0)
		FROM pg_range rng
		JOIN pg_type t ON t.oid = rng.rngtypid
		JOIN pg_namespace n ON n.oid = t.typnamespace
		WHERE `+notSystemSchema("n"))
	if err != nil {
		return nil, err
	}
	for mrRows.Next() {
		var rangeOID, multiOID int64
		if err := mrRows.Scan(&rangeOID, &multiOID); err != nil {
			mrRows.Close()
			return nil, err
		}
		if multiOID != 0 {
			rangeOf[multiOID] = rangeOID
		}
	}
	mrRows.Close()
	if err := mrRows.Err(); err != nil {
		return nil, err
	}
	var resolveType func(oid int64, depth int) string
	resolveType = func(oid int64, depth int) string {
		if depth > 8 {
			return "" // cycle/pathology guard
		}
		tr, ok := typs[oid]
		if !ok {
			return ""
		}
		// A never-completed shell type: its shell node IS the producer.
		if !tr.defined {
			return nodeID("type-shell", tr.schema, tr.name)
		}
		// True auto-array: this oid is its ELEMENT's typarray target — resolve
		// to the element's FINAL producer (the array is a side effect of it:
		// TypeShellMake leaves typarray = 0, so the array only exists once the
		// element's final CREATE ran).
		if tr.elem != 0 {
			if elem, ok := typs[tr.elem]; ok && elem.arrayOf == oid {
				return resolveType(tr.elem, depth+1)
			}
		}
		switch tr.typtype {
		case "e", "d":
			return nodeID("type", tr.schema, tr.name)
		case "c":
			if rr, ok := rels[tr.typrelid]; ok {
				if rr.kind == "c" {
					return nodeID("type", tr.schema, tr.name)
				}
				return r.rel[tr.typrelid] // relation row type → the relation node
			}
			return ""
		case "b", "r":
			// Base and range types are emitted via the shell → final
			// bootstrap; consumers wait for the FINAL stage. Only the DIRECT
			// oid (depth 0) is the staged type itself — a derived array or
			// multirange recursing here is a side effect of the final CREATE.
			if depth == 0 {
				r.shellSelf[oid] = true
			}
			return nodeID("type-final", tr.schema, tr.name)
		case "m":
			// A multirange is a side effect of its range's final CREATE.
			if rangeOID, ok := rangeOf[oid]; ok {
				return resolveType(rangeOID, depth+1)
			}
			return ""
		default:
			return "" // pseudo-types etc.: boundary by class
		}
	}
	for oid := range typs {
		r.typ[oid] = resolveType(oid, 0)
	}

	// Operators (real pg_depend edges exist for OpExpr consumers — unlike
	// casts, which record none and rely on class priority), operator classes
	// and families (a range's rngsubopc, cross-member family edges). Access
	// method is part of the identity.
	oprRows, err := db.QueryContext(ctx, `
		SELECT o.oid, n.nspname, o.oprname,
		       COALESCE(lt.oid, 0), COALESCE(rt.oid, 0)
		FROM pg_operator o
		JOIN pg_namespace n ON n.oid = o.oprnamespace
		LEFT JOIN pg_type lt ON lt.oid = o.oprleft
		LEFT JOIN pg_type rt ON rt.oid = o.oprright
		WHERE `+notSystemSchema("n"))
	if err != nil {
		return nil, err
	}
	for oprRows.Next() {
		var oid, l, rt int64
		var schema, name string
		if err := oprRows.Scan(&oid, &schema, &name, &l, &rt); err != nil {
			oprRows.Close()
			return nil, err
		}
		r.op[oid] = "operator:" + schema + "\x00" + name + "\x00" + strconv.FormatInt(l, 10) + "\x00" + strconv.FormatInt(rt, 10)
	}
	oprRows.Close()
	if err := oprRows.Err(); err != nil {
		return nil, err
	}
	for _, q := range []struct {
		table, kind string
		m           map[int64]string
	}{
		{"pg_opclass", "opclass", r.opc},
		{"pg_opfamily", "opfamily", r.opf},
	} {
		rows, err := db.QueryContext(ctx, `
			SELECT o.oid, am.amname, n.nspname, o.`+q.table[3:6]+`name
			FROM `+q.table+` o
			JOIN pg_am am ON am.oid = o.`+q.table[3:6]+`method
			JOIN pg_namespace n ON n.oid = o.`+q.table[3:6]+`namespace
			WHERE `+notSystemSchema("n"))
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var oid int64
			var am, schema, name string
			if err := rows.Scan(&oid, &am, &schema, &name); err != nil {
				rows.Close()
				return nil, err
			}
			q.m[oid] = q.kind + ":" + am + "\x00" + schema + "\x00" + name
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
	}

	// Routines, with identity arguments so overloads keep distinct nodes.
	prows, err := db.QueryContext(ctx, `
		SELECT p.oid, n.nspname, p.proname, pg_get_function_identity_arguments(p.oid)
		FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
		WHERE `+notSystemSchema("n"))
	if err != nil {
		return nil, err
	}
	for prows.Next() {
		var oid int64
		var schema, name, args string
		if err := prows.Scan(&oid, &schema, &name, &args); err != nil {
			prows.Close()
			return nil, err
		}
		r.proc[oid] = routineNodeID(schema, name, args)
	}
	prows.Close()
	if err := prows.Err(); err != nil {
		return nil, err
	}

	crows, err := db.QueryContext(ctx, `
		SELECT co.oid, n.nspname, co.collname
		FROM pg_collation co JOIN pg_namespace n ON n.oid = co.collnamespace
		WHERE `+notSystemSchema("n"))
	if err != nil {
		return nil, err
	}
	for crows.Next() {
		var oid int64
		var schema, name string
		if err := crows.Scan(&oid, &schema, &name); err != nil {
			crows.Close()
			return nil, err
		}
		r.coll[oid] = nodeID("collation", schema, name)
	}
	crows.Close()
	if err := crows.Err(); err != nil {
		return nil, err
	}
	return r, nil
}

// resolveRef maps one pg_depend (refclassid, refobjid) pair to a node id; ""
// drops the edge (boundary/undumped class).
func (r *dumpNodeResolver) resolveRef(refClass string, refOID int64) string {
	switch refClass {
	case "pg_class":
		return r.rel[refOID]
	case "pg_type":
		return r.typ[refOID]
	case "pg_proc":
		return r.proc[refOID]
	case "pg_collation":
		return r.coll[refOID]
	case "pg_operator":
		return r.op[refOID]
	case "pg_opclass":
		return r.opc[refOID]
	case "pg_opfamily":
		return r.opf[refOID]
	}
	return ""
}

// signatureTypeNode resolves a routine SIGNATURE type edge: the shell-staged
// (base/range) type ITSELF resolves to its "type-shell:" stage — shell types
// are legal in function signatures, which is exactly how the canonical/I-O
// support functions bootstrap — while every other type (including a
// side-effect multirange/auto-array that resolves to the same final node but
// only EXISTS after the final CREATE) keeps its consumer node.
func (r *dumpNodeResolver) signatureTypeNode(oid int64) string {
	id := r.typ[oid]
	if r.shellSelf[oid] {
		return "type-shell" + strings.TrimPrefix(id, "type-final")
	}
	return id
}

// collectTableNodes gathers each dumped table's dependency-graph metadata:
// hard edges (column types/collations — canonicalized through the producer
// registry, so a composite column orders the table after the type and a
// row-type column after its relation — the typed-table OF type, INHERITS
// parents incl. cross-schema ones, and generated-column expression references,
// which are NOT deferrable: a generated expression cannot be re-added by ALTER)
// plus the DEFERRABLE per-column DEFAULT and per-constraint (validated CHECK /
// EXCLUDE) expression edges the cycle resolver may cut and re-add post-data.
// nextval defaults ride the deferrable set too — their sequence edge normally
// just orders the sequence first (class priority already does), and a cut
// simply re-adds the DEFAULT after data, where every INSERT names its columns
// explicitly anyway.
func (d dialect) collectTableNodes(ctx context.Context, db *sql.DB, schema string, tables []string, r *dumpNodeResolver) (map[string]driver.DumpTableNode, error) {
	inSet := driver.StringSet(tables)
	nodes := map[string]*driver.DumpTableNode{}
	get := func(tbl string) *driver.DumpTableNode {
		n := nodes[tbl]
		if n == nil {
			n = &driver.DumpTableNode{
				Name:                  nodeID("relation", schema, tbl),
				DeferrableDefaults:    map[string][]string{},
				DeferrableConstraints: map[string][]string{},
			}
			nodes[tbl] = n
		}
		return n
	}
	addDep := func(n *driver.DumpTableNode, id string) {
		if id != "" && id != n.Name {
			n.Deps = append(n.Deps, id)
		}
	}

	// Column types + collations, the OF type of a typed table.
	colRows, err := db.QueryContext(ctx, `
		SELECT c.relname, a.atttypid, a.attcollation, c.reloftype
		FROM pg_attribute a
		JOIN pg_class c ON c.oid = a.attrelid
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = $1 AND c.relkind IN ('r','p')
		  AND a.attnum > 0 AND NOT a.attisdropped`, schema)
	if err != nil {
		return nil, err
	}
	for colRows.Next() {
		var tbl string
		var typOID, collOID, ofOID int64
		if err := colRows.Scan(&tbl, &typOID, &collOID, &ofOID); err != nil {
			colRows.Close()
			return nil, err
		}
		if !inSet[tbl] {
			continue
		}
		n := get(tbl)
		addDep(n, r.typ[typOID])
		addDep(n, r.coll[collOID])
		addDep(n, r.typ[ofOID])
	}
	colRows.Close()
	if err := colRows.Err(); err != nil {
		return nil, err
	}

	// INHERITS / partition parents: creation needs the parent first. Cross-
	// schema parents get an edge too — the child may dump standalone, but its
	// order relative to the parent stays right in a multi-schema dump.
	inhRows, err := db.QueryContext(ctx, `
		SELECT child.relname, i.inhparent
		FROM pg_inherits i
		JOIN pg_class child ON child.oid = i.inhrelid
		JOIN pg_namespace cn ON cn.oid = child.relnamespace
		WHERE cn.nspname = $1`, schema)
	if err != nil {
		return nil, err
	}
	for inhRows.Next() {
		var child string
		var parentOID int64
		if err := inhRows.Scan(&child, &parentOID); err != nil {
			inhRows.Close()
			return nil, err
		}
		if inSet[child] {
			addDep(get(child), r.rel[parentOID])
		}
	}
	inhRows.Close()
	if err := inhRows.Err(); err != nil {
		return nil, err
	}

	// Column DEFAULT / generated-expression references (pg_attrdef): plain
	// defaults are deferrable; generated expressions are hard edges.
	defRows, err := db.QueryContext(ctx, `
		SELECT c.relname, a.attname, a.attgenerated::text,
		       dep.refclassid::regclass::text, dep.refobjid
		FROM pg_attrdef ad
		JOIN pg_class c ON c.oid = ad.adrelid
		JOIN pg_namespace n ON n.oid = c.relnamespace
		JOIN pg_attribute a ON a.attrelid = ad.adrelid AND a.attnum = ad.adnum
		JOIN pg_depend dep ON dep.classid = 'pg_attrdef'::regclass
		  AND dep.objid = ad.oid AND dep.deptype = 'n'
		WHERE n.nspname = $1 AND c.relkind IN ('r','p')
		  AND dep.refclassid IN ('pg_class'::regclass, 'pg_proc'::regclass, 'pg_type'::regclass)`, schema)
	if err != nil {
		return nil, err
	}
	for defRows.Next() {
		var tbl, col, generated, refClass string
		var refOID int64
		if err := defRows.Scan(&tbl, &col, &generated, &refClass, &refOID); err != nil {
			defRows.Close()
			return nil, err
		}
		if !inSet[tbl] {
			continue
		}
		n := get(tbl)
		id := r.resolveRef(refClass, refOID)
		if id == "" || id == n.Name {
			continue
		}
		if generated != "" {
			addDep(n, id)
		} else {
			n.DeferrableDefaults[col] = append(n.DeferrableDefaults[col], id)
		}
	}
	defRows.Close()
	if err := defRows.Err(); err != nil {
		return nil, err
	}

	// Inline constraint expression references: validated CHECKs and EXCLUDE
	// constraints ride the CREATE, so their routine/type references are edges —
	// deferrable, since the resolver can move the whole constraint post-data
	// (where a re-added CHECK still validates the loaded rows). FKs and NOT
	// VALID checks are post-data already and need no pre-data edge.
	conRows, err := db.QueryContext(ctx, `
		SELECT c.relname, con.conname, dep.refclassid::regclass::text, dep.refobjid
		FROM pg_constraint con
		JOIN pg_class c ON c.oid = con.conrelid
		JOIN pg_namespace n ON n.oid = c.relnamespace
		JOIN pg_depend dep ON dep.classid = 'pg_constraint'::regclass
		  AND dep.objid = con.oid AND dep.deptype = 'n'
		WHERE n.nspname = $1
		  AND ((con.contype = 'c' AND con.convalidated) OR con.contype = 'x')
		  AND dep.refclassid IN ('pg_class'::regclass, 'pg_proc'::regclass, 'pg_type'::regclass)`, schema)
	if err != nil {
		return nil, err
	}
	for conRows.Next() {
		var tbl, con, refClass string
		var refOID int64
		if err := conRows.Scan(&tbl, &con, &refClass, &refOID); err != nil {
			conRows.Close()
			return nil, err
		}
		if !inSet[tbl] {
			continue
		}
		n := get(tbl)
		if id := r.resolveRef(refClass, refOID); id != "" && id != n.Name {
			n.DeferrableConstraints[con] = append(n.DeferrableConstraints[con], id)
		}
	}
	conRows.Close()
	if err := conRows.Err(); err != nil {
		return nil, err
	}

	out := make(map[string]driver.DumpTableNode, len(nodes))
	for name, n := range nodes {
		out[name] = *n
	}
	// Every dumped table gets a node (even an edge-less one) so the handler
	// always has its graph id.
	for _, t := range tables {
		if _, ok := out[t]; !ok {
			out[t] = driver.DumpTableNode{Name: nodeID("relation", schema, t)}
		}
	}
	return out, nil
}

// viewDependencyEdges returns the DATABASE-WIDE (dependent, source) edges
// among views and materialized views, resolved through each view's rewrite
// rule in pg_depend, as NUL-qualified "schema\x00name" pairs. The
// endpoints compare by relation OID (a bare relname comparison would collapse
// two same-named views in different schemas), the pg_rewrite classid filter
// keeps foreign pg_depend rows out, and both endpoints are restricted to user
// schemas rather than scanning every system/extension view. The per-schema
// CREATE ordering, the cross-schema matview-refresh ordering and the writer's
// ViewEdges all share this one query.
func (dialect) viewDependencyEdges(ctx context.Context, db *sql.DB) ([][2]string, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT DISTINCT dn.nspname, dep.relname, sn.nspname, src.relname
		FROM pg_depend pd
		JOIN pg_rewrite rw ON rw.oid = pd.objid
		JOIN pg_class dep ON dep.oid = rw.ev_class
		JOIN pg_class src ON src.oid = pd.refobjid
		JOIN pg_namespace dn ON dn.oid = dep.relnamespace
		JOIN pg_namespace sn ON sn.oid = src.relnamespace
		WHERE pd.classid = 'pg_rewrite'::regclass
		  AND pd.refclassid = 'pg_class'::regclass
		  AND dep.relkind IN ('v','m') AND src.relkind IN ('v','m')
		  AND dep.oid <> src.oid
		  AND `+notSystemSchema("dn")+`
		  AND `+notSystemSchema("sn"))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var edges [][2]string
	for rows.Next() {
		var fromSchema, from, toSchema, to string
		if err := rows.Scan(&fromSchema, &from, &toSchema, &to); err != nil {
			return nil, err
		}
		edges = append(edges, [2]string{qualifiedKey(fromSchema, from), qualifiedKey(toSchema, to)})
	}
	return edges, rows.Err()
}
