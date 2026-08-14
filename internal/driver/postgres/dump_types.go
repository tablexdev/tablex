// User-defined types and collations for the dump path: enums, domains,
// composites, ranges and base types, including the shell/final staging that
// bootstraps a base or range type whose I/O and canonical functions in turn
// reference the type itself.

package postgres

import (
	"context"
	"database/sql"
	"maps"
	"slices"
	"strconv"
	"strings"

	"github.com/tablexdev/tablex/internal/driver"
)

// typeDef holds one user-defined type's assembled CREATE plus its dependency
// edges (to other in-scope user types) for restore ordering.
type typeDef struct {
	name     string              // bare type name
	create   string              // CREATE TYPE/DOMAIN … base statement (no trailing ;)
	comment  string              // obj_description, or ""
	deps     []string            // SAME-SCHEMA user type names this one references (local topo)
	kind     byte                // 'e' enum, 'd' domain, 'c' composite
	nodeDeps []string            // dump-graph edges (node ids — may cross schemas)
	clauses  []driver.DumpClause // deferrable domain DEFAULT / CHECK clauses
}

// dumpCollations (G9) appends CREATE COLLATION scripts for the schema's
// user-defined collations to plan.Collations — emitted before types and tables
// (a domain, composite attribute or column COLLATE may reference one) and
// dropped after them. Extension-owned collations are excluded (the extension
// recreates them); only collations valid for the database encoding are dumped.
// The option set is provider-specific and version-aware (libc reads collcollate/
// collctype; ICU/builtin read the version-appropriate locale column via to_jsonb
// for the PG13 floor). A database-default provider collation cannot be
// reproduced (CREATE COLLATION … FROM "default" is rejected) and is skipped with
// a warning. ICU RULES (collicurules) are a documented residual.
func (d dialect) dumpCollations(ctx context.Context, db *sql.DB, schema string, plan *driver.DumpPlan) error {
	rows, err := db.QueryContext(ctx, `
		SELECT co.collname, co.collprovider::text, co.collisdeterministic,
		       COALESCE(to_jsonb(co)->>'collcollate',''),
		       COALESCE(to_jsonb(co)->>'collctype',''),
		       COALESCE(to_jsonb(co)->>'colllocale',''),
		       COALESCE(to_jsonb(co)->>'colliculocale',''),
		       -- ICU tailoring rules (PG16+; to_jsonb keeps the PG13 floor
		       -- parsing, and the column is simply absent below 16).
		       COALESCE(to_jsonb(co)->>'collicurules',''),
		       COALESCE(obj_description(co.oid,'pg_collation'),'')
		FROM pg_collation co
		JOIN pg_namespace n ON n.oid = co.collnamespace
		WHERE n.nspname = $1
		  AND co.collencoding IN (-1, (SELECT encoding FROM pg_database WHERE datname = current_database()))
		  AND NOT EXISTS (SELECT 1 FROM pg_depend dep
		                  WHERE dep.classid = 'pg_collation'::regclass AND dep.objid = co.oid AND dep.deptype = 'e')
		ORDER BY co.collname`, schema)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var name, provider, collcollate, collctype, colllocale, colliculocale, icurules, comment string
		var deterministic bool
		if err := rows.Scan(&name, &provider, &deterministic, &collcollate, &collctype,
			&colllocale, &colliculocale, &icurules, &comment); err != nil {
			return err
		}
		qname := d.QuoteIdent(schema) + "." + d.QuoteIdent(name)
		opts, ok := collationOptions(provider, deterministic, collcollate, collctype, colllocale, colliculocale, icurules)
		if !ok {
			plan.Warnings = append(plan.Warnings,
				"collation "+schema+"."+name+" uses the database-default provider and is not dumped; create it in the target before importing")
			continue
		}
		plan.Collations = append(plan.Collations, driver.DumpScript{
			Kind:    "collation",
			Name:    nodeID("collation", schema, name),
			Comment: "Collation " + name,
			Drop:    "DROP COLLATION IF EXISTS " + qname,
			SQL:     "CREATE COLLATION " + qname + " (" + opts + ")",
		})
		if comment != "" {
			plan.Collations = append(plan.Collations, driver.DumpScript{
				Kind:    "collation",
				Comment: "Comment for collation " + name,
				SQL:     "COMMENT ON COLLATION " + qname + " IS " + d.QuoteString(comment),
			})
		}
	}
	return rows.Err()
}

// collationOptions builds the parenthesized CREATE COLLATION option list from a
// pg_collation row. Provider-specific and version-aware: libc emits LOCALE (when
// collate == ctype) or LC_COLLATE/LC_CTYPE; ICU/builtin emit a single LOCALE from
// the first non-empty version-appropriate column (colllocale 17+, colliculocale
// 15-16, collcollate 13-14). ICU tailoring RULES (PG16+) ride the ICU branch —
// without them a rules-carrying collation restores with plain root-locale
// ordering, silently changing comparison results. ok is false for the
// database-default provider ('d'), which cannot be reproduced: PostgreSQL
// itself rejects CREATE COLLATION … FROM "default". Pure (unit-tested); string
// values are single-quote escaped.
func collationOptions(provider string, deterministic bool, collcollate, collctype, colllocale, colliculocale, icurules string) (string, bool) {
	q := func(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }
	var opts string
	switch provider {
	case "c": // libc
		if collcollate == collctype {
			opts = "LOCALE = " + q(collcollate)
		} else {
			opts = "LC_COLLATE = " + q(collcollate) + ", LC_CTYPE = " + q(collctype)
		}
		opts += ", PROVIDER = libc"
	case "i": // icu
		loc := colllocale
		if loc == "" {
			loc = colliculocale
		}
		if loc == "" {
			loc = collcollate
		}
		opts = "LOCALE = " + q(loc) + ", PROVIDER = icu"
		if icurules != "" {
			// The tailoring is part of the collation's identity — a
			// rules-carrying collation restored without them compares
			// differently. RULES landed in PG16, and only a PG16+ catalog can
			// report one, so the clause is self-gating.
			opts += ", RULES = " + q(icurules)
		}
	case "b": // builtin (PG17+)
		opts = "LOCALE = " + q(colllocale) + ", PROVIDER = builtin"
	default: // 'd' database-default (FROM "default" is rejected), or unknown
		return "", false
	}
	if !deterministic {
		opts += ", DETERMINISTIC = false"
	}
	return opts, true
}

// dumpTypes appends CREATE TYPE (enum/composite) and CREATE DOMAIN scripts for
// every non-extension user-defined type in the schema, dependency-ordered so a
// domain over a composite (or a composite with a user-type attribute) restores.
// Range/multirange and shell types are out of scope (their I/O functions cannot
// be reproduced) — a warning names any type skipped because it, or a type it
// depends on, is unsupported. Each type's DROP runs in teardown after the tables.
// Every script carries its graph node id and resolver-based (cross-schema)
// edges; a domain's DEFAULT and CHECK clauses are deferrable DumpClauses so
// the planner can cut one that closes a cycle (domain default calling a
// function returning that domain) and re-add it via ALTER DOMAIN in the
// pre-data finalizer lane. Domain-constraint comments ride post-data
// (rank-2 "constraint-comment") — valid on both the inline and deferred paths.
func (d dialect) dumpTypes(ctx context.Context, db *sql.DB, schema string, r *dumpNodeResolver, plan *driver.DumpPlan) error {
	qualify := func(name string) string { return d.QuoteIdent(schema) + "." + d.QuoteIdent(name) }

	// 1. Discover in-scope user types, OID→name, so the dependency edges below
	//    can be resolved to names. Extension-owned types are excluded (the
	//    classid predicate is required — objid alone is ambiguous across
	//    catalogs), as are auto-array types (side effects of their element —
	//    identified exclusively by the reverse typarray relationship). The staged pass
	//    widens the surface beyond enum/domain/composite: shells
	//    (typisdefined = false), range ('r') and base ('b') types route to the
	//    staged emission below; an EMPTY enum / zero-attribute composite gets
	//    its valid empty CREATE here so the label/attr loops merely overwrite it
	//    (both were previously dropped as "unsupported shape").
	oidName := map[int64]string{}
	defs := map[string]*typeDef{}
	var order []string // discovery order (typname) for a stable base
	var stagedNames []string
	stagedKind := map[string]string{} // name → 'r' / 'b' / shell ("s")
	stagedComment := map[string]string{}
	drows, err := db.QueryContext(ctx, `
		SELECT t.oid, t.typname, t.typtype, t.typisdefined,
		       COALESCE(obj_description(t.oid,'pg_type'),'')
		FROM pg_type t
		JOIN pg_namespace n ON n.oid = t.typnamespace
		WHERE n.nspname = $1
		  AND (t.typtype IN ('e','d','c','r','b') OR NOT t.typisdefined)
		  AND (t.typtype <> 'c' OR EXISTS (
		        SELECT 1 FROM pg_class c WHERE c.oid = t.typrelid AND c.relkind = 'c'))
		  AND NOT EXISTS (SELECT 1 FROM pg_type el
		      WHERE el.oid = t.typelem AND el.typarray = t.oid)
		  AND NOT EXISTS (SELECT 1 FROM pg_depend dep
		      WHERE dep.classid = 'pg_type'::regclass AND dep.objid = t.oid AND dep.deptype = 'e')
		ORDER BY t.typname`, schema)
	if err != nil {
		return err
	}
	for drows.Next() {
		var oid int64
		var name, comment string
		var typtype string
		var defined bool
		if err := drows.Scan(&oid, &name, &typtype, &defined, &comment); err != nil {
			drows.Close()
			return err
		}
		oidName[oid] = name
		switch {
		case !defined:
			stagedNames = append(stagedNames, name)
			stagedKind[name] = "s"
			stagedComment[name] = comment
		case typtype == "r" || typtype == "b":
			stagedNames = append(stagedNames, name)
			stagedKind[name] = typtype
			stagedComment[name] = comment
		default:
			def := &typeDef{name: name, comment: comment, kind: typtype[0]}
			switch typtype {
			case "e":
				def.create = "CREATE TYPE " + qualify(name) + " AS ENUM ()"
			case "c":
				def.create = "CREATE TYPE " + qualify(name) + " AS ()"
			}
			defs[name] = def
			order = append(order, name)
		}
	}
	drows.Close()
	if err := drows.Err(); err != nil {
		return err
	}
	if len(defs) == 0 && len(stagedNames) == 0 {
		return nil
	}

	// 2. Enum labels → CREATE TYPE … AS ENUM.
	erows, err := db.QueryContext(ctx, `
		SELECT t.typname, e.enumlabel
		FROM pg_type t
		JOIN pg_namespace n ON n.oid = t.typnamespace
		JOIN pg_enum e ON e.enumtypid = t.oid
		WHERE n.nspname = $1 AND t.typtype = 'e'
		ORDER BY t.typname, e.enumsortorder`, schema)
	if err != nil {
		return err
	}
	enumLabels := map[string][]string{}
	for erows.Next() {
		var name, label string
		if err := erows.Scan(&name, &label); err != nil {
			erows.Close()
			return err
		}
		enumLabels[name] = append(enumLabels[name], d.QuoteString(label))
	}
	erows.Close()
	if err := erows.Err(); err != nil {
		return err
	}
	for name, labels := range enumLabels {
		if def := defs[name]; def != nil {
			def.create = "CREATE TYPE " + qualify(name) + " AS ENUM (" + strings.Join(labels, ", ") + ")"
		}
	}

	// 3. Domains → CREATE DOMAIN … AS base [DEFAULT …] [NOT NULL] [CONSTRAINT …].
	//    The default comes from typdefaultbin (re-deparsed) so it round-trips
	//    under any search_path; a bare typdefault text falls back to a literal.
	// A domain's non-default COLLATE (typcollation differing from the
	// base type's own) was previously lost entirely.
	domRows, err := db.QueryContext(ctx, `
		SELECT t.typname, t.typbasetype,
		       pg_catalog.format_type(t.typbasetype, t.typtypmod),
		       t.typnotnull,
		       COALESCE(pg_get_expr(t.typdefaultbin, 0), ''),
		       COALESCE(t.typdefault, ''),
		       COALESCE(cn.nspname, ''), COALESCE(cl.collname, '')
		FROM pg_type t
		LEFT JOIN pg_type bt ON bt.oid = t.typbasetype
		LEFT JOIN pg_collation cl ON cl.oid = t.typcollation
		  AND t.typcollation <> 0 AND t.typcollation <> bt.typcollation
		LEFT JOIN pg_namespace cn ON cn.oid = cl.collnamespace
		JOIN pg_namespace n ON n.oid = t.typnamespace
		WHERE n.nspname = $1 AND t.typtype = 'd'
		ORDER BY t.typname`, schema)
	if err != nil {
		return err
	}
	type domInfo struct {
		base       string
		basetype   int64
		notnull    bool
		defbin     string
		deftext    string
		collSchema string
		collName   string
	}
	domains := map[string]domInfo{}
	for domRows.Next() {
		var name string
		var di domInfo
		if err := domRows.Scan(&name, &di.basetype, &di.base, &di.notnull, &di.defbin, &di.deftext, &di.collSchema, &di.collName); err != nil {
			domRows.Close()
			return err
		}
		domains[name] = di
	}
	domRows.Close()
	if err := domRows.Err(); err != nil {
		return err
	}
	// Domain constraints (CHECK / NOT NULL), keyed by the domain (contypid). On
	// PG17+ a domain's NOT NULL is stored as a NAMED contype='n' constraint AS
	// WELL AS typnotnull — emitting both a bare NOT NULL and the named constraint
	// is a "redundant NOT NULL constraint" error, so a domain with a named NOT
	// NULL suppresses the bare clause (the named constraint carries it).
	type domCon struct {
		name, contype, def, comment string
	}
	domConstraints := map[string][]domCon{}
	hasNamedNotNull := map[string]bool{}
	dcRows, err := db.QueryContext(ctx, `
		SELECT t.typname, con.conname, con.contype, pg_get_constraintdef(con.oid),
		       COALESCE(obj_description(con.oid, 'pg_constraint'), '')
		FROM pg_constraint con
		JOIN pg_type t ON t.oid = con.contypid
		JOIN pg_namespace n ON n.oid = t.typnamespace
		WHERE n.nspname = $1 AND con.contype IN ('c','n')
		ORDER BY t.typname, con.conname`, schema)
	if err != nil {
		return err
	}
	for dcRows.Next() {
		var tname string
		var c domCon
		if err := dcRows.Scan(&tname, &c.name, &c.contype, &c.def, &c.comment); err != nil {
			dcRows.Close()
			return err
		}
		if c.contype == "n" {
			hasNamedNotNull[tname] = true
		}
		domConstraints[tname] = append(domConstraints[tname], c)
	}
	dcRows.Close()
	if err := dcRows.Err(); err != nil {
		return err
	}

	// Expression edges. A domain's DEFAULT records its references on the
	// pg_type row itself (excluding the base-type edge, which is the domain's
	// own hard edge, and collation edges); a domain CHECK records its own on
	// the pg_constraint row. These become the deferrable clause deps below.
	domDefaultDeps := map[string][]string{}
	if r != nil {
		ddRows, err := db.QueryContext(ctx, `
			SELECT t.typname, dep.refclassid::regclass::text, dep.refobjid
			FROM pg_type t
			JOIN pg_namespace n ON n.oid = t.typnamespace
			JOIN pg_depend dep ON dep.classid = 'pg_type'::regclass
			  AND dep.objid = t.oid AND dep.deptype = 'n'
			WHERE n.nspname = $1 AND t.typtype = 'd'
			  AND NOT (dep.refclassid = 'pg_type'::regclass AND dep.refobjid = t.typbasetype)
			  AND dep.refclassid IN ('pg_proc'::regclass, 'pg_class'::regclass, 'pg_type'::regclass, 'pg_operator'::regclass)`, schema)
		if err != nil {
			return err
		}
		for ddRows.Next() {
			var tname, refClass string
			var refOID int64
			if err := ddRows.Scan(&tname, &refClass, &refOID); err != nil {
				ddRows.Close()
				return err
			}
			if id := r.resolveRef(refClass, refOID); id != "" {
				domDefaultDeps[tname] = append(domDefaultDeps[tname], id)
			}
		}
		ddRows.Close()
		if err := ddRows.Err(); err != nil {
			return err
		}
	}
	domConDeps := map[string]map[string][]string{} // domain → constraint → deps
	if r != nil {
		dcdRows, err := db.QueryContext(ctx, `
			SELECT t.typname, con.conname, dep.refclassid::regclass::text, dep.refobjid
			FROM pg_constraint con
			JOIN pg_type t ON t.oid = con.contypid
			JOIN pg_namespace n ON n.oid = t.typnamespace
			JOIN pg_depend dep ON dep.classid = 'pg_constraint'::regclass
			  AND dep.objid = con.oid AND dep.deptype = 'n'
			WHERE n.nspname = $1
			  AND NOT (dep.refclassid = 'pg_type'::regclass AND dep.refobjid = t.oid)
			  AND dep.refclassid IN ('pg_proc'::regclass, 'pg_class'::regclass, 'pg_type'::regclass, 'pg_operator'::regclass)`, schema)
		if err != nil {
			return err
		}
		for dcdRows.Next() {
			var tname, cname, refClass string
			var refOID int64
			if err := dcdRows.Scan(&tname, &cname, &refClass, &refOID); err != nil {
				dcdRows.Close()
				return err
			}
			if id := r.resolveRef(refClass, refOID); id != "" {
				if domConDeps[tname] == nil {
					domConDeps[tname] = map[string][]string{}
				}
				domConDeps[tname][cname] = append(domConDeps[tname][cname], id)
			}
		}
		dcdRows.Close()
		if err := dcdRows.Err(); err != nil {
			return err
		}
	}

	// Sorted, not map order: this loop appends constraint-comment entries to
	// plan.PostData, and the post-data sort is stable on rank — so equal-rank
	// entries keep INSERTION order. Ranging the map made two domains with
	// commented constraints emit in a random relative order, and two dumps of
	// the same database were not byte-identical. (The query is already ORDER BY
	// typname; sorting here keeps the guarantee visible at the point of use.)
	for _, name := range slices.Sorted(maps.Keys(domains)) {
		di := domains[name]
		def := defs[name]
		if def == nil {
			continue
		}
		q := qualify(name)
		def.create = "CREATE DOMAIN " + q + " AS " + di.base
		if di.collName != "" {
			def.create += " COLLATE " + d.QuoteIdent(di.collSchema) + "." + d.QuoteIdent(di.collName)
			def.nodeDeps = append(def.nodeDeps, nodeID("collation", di.collSchema, di.collName))
		}
		// The DEFAULT clause first (grammar: … [DEFAULT] [constraint …]), as a
		// deferrable clause: cut, it re-emerges as ALTER DOMAIN … SET DEFAULT in
		// the pre-data finalizer lane (before any consuming type/table and data).
		if di.defbin != "" || di.deftext != "" {
			expr := di.defbin
			if expr == "" {
				expr = d.QuoteString(di.deftext)
			}
			def.clauses = append(def.clauses, driver.DumpClause{
				Text: " DEFAULT " + expr,
				Deps: domDefaultDeps[name],
				Finalize: []driver.DumpScript{{
					Kind:    "type",
					Comment: "Deferred default for domain " + name,
					SQL:     "ALTER DOMAIN " + q + " SET DEFAULT " + expr,
				}},
				PreData: true,
			})
		}
		if di.notnull && !hasNamedNotNull[name] {
			def.clauses = append(def.clauses, driver.DumpClause{Text: " NOT NULL"})
		}
		for _, c := range domConstraints[name] {
			clause := driver.DumpClause{
				Text: " CONSTRAINT " + d.QuoteIdent(c.name) + " " + c.def,
			}
			if c.contype == "c" {
				clause.Deps = domConDeps[name][c.name]
				clause.Finalize = []driver.DumpScript{{
					Kind:    "type",
					Comment: "Deferred constraint " + c.name + " on domain " + name,
					SQL:     "ALTER DOMAIN " + q + " ADD CONSTRAINT " + d.QuoteIdent(c.name) + " " + c.def,
				}}
				clause.PreData = true
			}
			def.clauses = append(def.clauses, clause)
			// The constraint's comment (previously not collected at all): always
			// post-data rank 2 — the constraint exists by then on the inline AND
			// the deferred path alike.
			if c.comment != "" {
				plan.PostData = append(plan.PostData, driver.DumpScript{
					Kind:    "constraint-comment",
					Comment: "Comment for constraint " + c.name + " on domain " + name,
					SQL:     "COMMENT ON CONSTRAINT " + d.QuoteIdent(c.name) + " ON DOMAIN " + q + " IS " + d.QuoteString(c.comment),
				})
			}
		}
		if n, ok := oidName[di.basetype]; ok {
			def.deps = append(def.deps, n)
		}
		if r != nil {
			if id := r.typ[di.basetype]; id != "" {
				def.nodeDeps = append(def.nodeDeps, id)
			}
		}
	}

	// 4. Composites → CREATE TYPE … AS ( attr type, … ). An attribute's
	// non-default COLLATE (attcollation differing from the type's own) was
	// previously lost.
	compAttrs := map[string][]string{}
	compRows, err := db.QueryContext(ctx, `
		SELECT t.typname, a.attname, pg_catalog.format_type(a.atttypid, a.atttypmod), a.atttypid,
		       COALESCE(cln.nspname, ''), COALESCE(cl.collname, '')
		FROM pg_type t
		JOIN pg_namespace n ON n.oid = t.typnamespace
		JOIN pg_class c ON c.oid = t.typrelid AND c.relkind = 'c'
		JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped
		JOIN pg_type at ON at.oid = a.atttypid
		LEFT JOIN pg_collation cl ON cl.oid = a.attcollation
		  AND a.attcollation <> 0 AND a.attcollation <> at.typcollation
		LEFT JOIN pg_namespace cln ON cln.oid = cl.collnamespace
		WHERE n.nspname = $1 AND t.typtype = 'c'
		ORDER BY t.typname, a.attnum`, schema)
	if err != nil {
		return err
	}
	for compRows.Next() {
		var tname, aname, atype, collSchema, collName string
		var atypid int64
		if err := compRows.Scan(&tname, &aname, &atype, &atypid, &collSchema, &collName); err != nil {
			compRows.Close()
			return err
		}
		line := d.QuoteIdent(aname) + " " + atype
		if collName != "" {
			line += " COLLATE " + d.QuoteIdent(collSchema) + "." + d.QuoteIdent(collName)
		}
		compAttrs[tname] = append(compAttrs[tname], line)
		if def := defs[tname]; def != nil {
			if n, ok := oidName[atypid]; ok && n != tname {
				def.deps = append(def.deps, n)
			}
			if r != nil {
				if id := r.typ[atypid]; id != "" && id != nodeID("type", schema, tname) {
					def.nodeDeps = append(def.nodeDeps, id)
				}
			}
			if collName != "" {
				def.nodeDeps = append(def.nodeDeps, nodeID("collation", collSchema, collName))
			}
		}
	}
	compRows.Close()
	if err := compRows.Err(); err != nil {
		return err
	}
	for name, attrs := range compAttrs {
		if def := defs[name]; def != nil {
			def.create = "CREATE TYPE " + qualify(name) + " AS (" + strings.Join(attrs, ", ") + ")"
		}
	}

	// 5. Dependency-order the names and emit. A type whose CREATE stayed empty
	//    (an unsupported shape, e.g. a composite whose relkind row is missing)
	//    is skipped with a warning rather than emitting invalid DDL.
	deps := map[string][]string{}
	for _, def := range defs {
		deps[def.name] = def.deps
	}
	for _, name := range driver.TopoOrder(order, deps) {
		def := defs[name]
		if def == nil || def.create == "" {
			if def != nil {
				plan.Warnings = append(plan.Warnings,
					"type "+schema+"."+name+" was not dumped (unsupported shape); dependents may fail to restore")
			}
			continue
		}
		dropKw := "TYPE"
		if def.kind == 'd' {
			dropKw = "DOMAIN"
		}
		plan.Types = append(plan.Types, driver.DumpScript{
			Kind:      "type",
			Name:      nodeID("type", schema, name),
			DependsOn: def.nodeDeps,
			Clauses:   def.clauses,
			Comment:   "Type " + name,
			Drop:      "DROP " + dropKw + " IF EXISTS " + qualify(name),
			DropForm:  driver.DropForm{Class: dropKw, Ref: qualify(name)},
			SQL:       def.create,
		})
		if def.comment != "" {
			commentKw := "TYPE"
			if def.kind == 'd' {
				commentKw = "DOMAIN"
			}
			plan.Types = append(plan.Types, driver.DumpScript{
				Kind:    "type",
				Comment: "Comment for type " + name,
				SQL:     "COMMENT ON " + commentKw + " " + qualify(name) + " IS " + d.QuoteString(def.comment),
			})
		}
	}

	// Range / base / shell types via the type-shell → support-function →
	// type-final bootstrap.
	return d.dumpStagedTypes(ctx, db, schema, stagedNames, stagedKind, stagedComment, r, plan)
}

// multirangeNameClause renders the explicit MULTIRANGE_TYPE_NAME clause
// — ALWAYS emitted on PG14+ (the auto-derived name varies on collision) and
// NEVER below (PG13 has neither multiranges nor the clause; the version gate
// keeps generated SQL provably floor-correct and is unit-tested by driving
// major).
func (d dialect) multirangeNameClause(multiOID int64, schema, name string) string {
	if d.major < 14 || multiOID == 0 || name == "" {
		return ""
	}
	return "MULTIRANGE_TYPE_NAME = " + d.QuoteIdent(schema) + "." + d.QuoteIdent(name)
}

// subscriptClause renders a base type's SUBSCRIPT clause — PG14+ only
// (PG13 has neither the typsubscript column nor the grammar).
func (d dialect) subscriptClause(fn string) string {
	if d.major < 14 || fn == "" || fn == "-" {
		return ""
	}
	return "SUBSCRIPT = " + fn
}

// dumpStagedTypes emits range and base types through the SHELL → FINAL
// bootstrap the dependency-graph models: `CREATE TYPE q;` declares the shell (legal in
// the support functions' signatures — there is no function forward
// declaration), the support functions restore in between (their signature
// edges target the shell stage), and the completing CREATE finishes the type;
// consumers wait for the final stage. A never-completed catalog shell emits
// just the shell statement. Both classes are CONDITIONAL on an external
// artifact — their support functions are LANGUAGE C, so the restore target
// needs the same shared library (and, for base types, a compatible ABI:
// PASSEDBYVALUE depends on the target's Datum width) — which the emitted
// warning states honestly.
func (d dialect) dumpStagedTypes(ctx context.Context, db *sql.DB, schema string, names []string, kinds, comments map[string]string, r *dumpNodeResolver, plan *driver.DumpPlan) error {
	if len(names) == 0 {
		return nil
	}
	qualify := func(name string) string { return d.QuoteIdent(schema) + "." + d.QuoteIdent(name) }
	regprocText := func(s string) string {
		if s == "-" {
			return ""
		}
		return s
	}
	appendShell := func(name string) {
		plan.Types = append(plan.Types, driver.DumpScript{
			Kind: "type",
			Name: nodeID("type-shell", schema, name),
			// Both stages are the SAME restored object. Creation order needs
			// them apart (that is the bootstrap); the drop graph needs them
			// together, or the type↔support-function cycle the shell exists to
			// break stays invisible to the teardown that must not emit it.
			StageOf: nodeID("type", schema, name),
			Comment: "Shell for type " + name,
			SQL:     "CREATE TYPE " + qualify(name),
		})
	}
	appendFinal := func(name, create string, deps []string) {
		plan.Types = append(plan.Types, driver.DumpScript{
			Kind:      "type",
			Name:      nodeID("type-final", schema, name),
			StageOf:   nodeID("type", schema, name),
			DependsOn: append([]string{nodeID("type-shell", schema, name)}, deps...),
			Comment:   "Type " + name,
			Drop:      "DROP TYPE IF EXISTS " + qualify(name),
			DropForm:  driver.DropForm{Class: "TYPE", Ref: qualify(name)},
			SQL:       create,
		})
		if c := comments[name]; c != "" {
			plan.Types = append(plan.Types, driver.DumpScript{
				Kind:    "type",
				Comment: "Comment for type " + name,
				SQL:     "COMMENT ON TYPE " + qualify(name) + " IS " + d.QuoteString(c),
			})
		}
	}

	// Ranges: the full pg_range surface. rngmultitypid is PG14+ (to_jsonb keeps
	// the PG13 floor parsing); the ACTUAL multirange name is always emitted on
	// 14+ — the auto-derived name can differ on collision.
	rngRows, err := db.QueryContext(ctx, `
		SELECT t.typname,
		       pg_catalog.format_type(rng.rngsubtype, NULL), rng.rngsubtype,
		       CASE WHEN opc.opcdefault AND opc.opcintype = rng.rngsubtype THEN 0 ELSE rng.rngsubopc END,
		       COALESCE(opcn.nspname, ''), COALESCE(opc.opcname, ''),
		       rng.rngcollation, COALESCE(rcn.nspname, ''), COALESCE(rcl.collname, ''),
		       rng.rngcanonical::oid, CASE WHEN rng.rngcanonical = 0 THEN '' ELSE rng.rngcanonical::regproc::text END,
		       rng.rngsubdiff::oid, CASE WHEN rng.rngsubdiff = 0 THEN '' ELSE rng.rngsubdiff::regproc::text END,
		       COALESCE((to_jsonb(rng)->>'rngmultitypid')::bigint, 0),
		       COALESCE(mtn.nspname, ''), COALESCE(mt.typname, '')
		FROM pg_range rng
		JOIN pg_type t ON t.oid = rng.rngtypid
		JOIN pg_namespace n ON n.oid = t.typnamespace
		LEFT JOIN pg_opclass opc ON opc.oid = rng.rngsubopc
		LEFT JOIN pg_namespace opcn ON opcn.oid = opc.opcnamespace
		LEFT JOIN pg_type st ON st.oid = rng.rngsubtype
		LEFT JOIN pg_collation rcl ON rcl.oid = rng.rngcollation
		  AND rng.rngcollation <> 0 AND rng.rngcollation <> st.typcollation
		LEFT JOIN pg_namespace rcn ON rcn.oid = rcl.collnamespace
		LEFT JOIN pg_type mt ON mt.oid = COALESCE((to_jsonb(rng)->>'rngmultitypid')::bigint, 0)
		LEFT JOIN pg_namespace mtn ON mtn.oid = mt.typnamespace
		WHERE n.nspname = $1 AND t.typisdefined
		ORDER BY t.typname`, schema)
	if err != nil {
		return err
	}
	type rangeRow struct {
		name, subtype          string
		subtypeOID, opcOID     int64
		opcSchema, opcName     string
		collOID                int64
		collSchema, collName   string
		canonicalOID           int64
		canonical              string
		subdiffOID             int64
		subdiff                string
		multiOID               int64
		multiSchema, multiName string
	}
	var ranges []rangeRow
	for rngRows.Next() {
		var rr rangeRow
		if err := rngRows.Scan(&rr.name, &rr.subtype, &rr.subtypeOID, &rr.opcOID, &rr.opcSchema, &rr.opcName,
			&rr.collOID, &rr.collSchema, &rr.collName,
			&rr.canonicalOID, &rr.canonical, &rr.subdiffOID, &rr.subdiff,
			&rr.multiOID, &rr.multiSchema, &rr.multiName); err != nil {
			rngRows.Close()
			return err
		}
		ranges = append(ranges, rr)
	}
	rngRows.Close()
	if err := rngRows.Err(); err != nil {
		return err
	}

	// Base types: the complete CREATE TYPE physical surface from pg_type.
	// typsubscript is PG14+ (both the column and the SUBSCRIPT clause) — the
	// to_jsonb read tolerates the PG13 floor and the major gate keeps the
	// generated SQL version-correct.
	baseRows, err := db.QueryContext(ctx, `
		SELECT t.typname, t.typlen, t.typbyval, t.typalign::text, t.typstorage::text,
		       t.typcategory::text, t.typispreferred, t.typdelim::text,
		       t.typinput::regproc::text, t.typoutput::regproc::text,
		       CASE WHEN t.typreceive = 0 THEN '' ELSE t.typreceive::regproc::text END,
		       CASE WHEN t.typsend = 0 THEN '' ELSE t.typsend::regproc::text END,
		       CASE WHEN t.typmodin = 0 THEN '' ELSE t.typmodin::regproc::text END,
		       CASE WHEN t.typmodout = 0 THEN '' ELSE t.typmodout::regproc::text END,
		       CASE WHEN t.typanalyze = 0 THEN '' ELSE t.typanalyze::regproc::text END,
		       COALESCE(to_jsonb(t)->>'typsubscript', ''),
		       t.typelem, CASE WHEN t.typelem = 0 THEN '' ELSE pg_catalog.format_type(t.typelem, NULL) END,
		       t.typcollation <> 0,
		       COALESCE(pg_get_expr(t.typdefaultbin, 0), ''), COALESCE(t.typdefault, ''),
		       t.typinput::oid, t.typoutput::oid, t.typreceive::oid, t.typsend::oid,
		       t.typmodin::oid, t.typmodout::oid, t.typanalyze::oid
		FROM pg_type t
		JOIN pg_namespace n ON n.oid = t.typnamespace
		WHERE n.nspname = $1 AND t.typtype = 'b' AND t.typisdefined
		  AND NOT EXISTS (SELECT 1 FROM pg_type el WHERE el.oid = t.typelem AND el.typarray = t.oid)
		ORDER BY t.typname`, schema)
	if err != nil {
		return err
	}
	type baseRow struct {
		name                                                             string
		typlen                                                           int64
		byval                                                            bool
		align, storage, category                                         string
		preferred                                                        bool
		delim                                                            string
		input, output, receive, send, modin, modout, analyze, subscript  string
		elemOID                                                          int64
		elem                                                             string
		collatable                                                       bool
		defbin, deftext                                                  string
		inOID, outOID, recvOID, sendOID, modinOID, modoutOID, analyzeOID int64
	}
	var bases []baseRow
	for baseRows.Next() {
		var br baseRow
		if err := baseRows.Scan(&br.name, &br.typlen, &br.byval, &br.align, &br.storage,
			&br.category, &br.preferred, &br.delim,
			&br.input, &br.output, &br.receive, &br.send, &br.modin, &br.modout, &br.analyze,
			&br.subscript, &br.elemOID, &br.elem, &br.collatable, &br.defbin, &br.deftext,
			&br.inOID, &br.outOID, &br.recvOID, &br.sendOID, &br.modinOID, &br.modoutOID, &br.analyzeOID); err != nil {
			baseRows.Close()
			return err
		}
		bases = append(bases, br)
	}
	baseRows.Close()
	if err := baseRows.Err(); err != nil {
		return err
	}

	for _, name := range names {
		switch kinds[name] {
		case "s":
			// A never-completed shell: the bare declaration is the whole object.
			plan.Types = append(plan.Types, driver.DumpScript{
				Kind:     "type",
				Name:     nodeID("type-shell", schema, name),
				StageOf:  nodeID("type", schema, name),
				Comment:  "Shell type " + name,
				Drop:     "DROP TYPE IF EXISTS " + qualify(name),
				DropForm: driver.DropForm{Class: "TYPE", Ref: qualify(name)},
				SQL:      "CREATE TYPE " + qualify(name),
			})
		case "r":
			for _, rr := range ranges {
				if rr.name != name {
					continue
				}
				var opts []string
				var deps []string
				opts = append(opts, "SUBTYPE = "+rr.subtype)
				if r != nil {
					if id := r.typ[rr.subtypeOID]; id != "" {
						deps = append(deps, id)
					}
				}
				if rr.opcOID != 0 && rr.opcName != "" {
					opts = append(opts, "SUBTYPE_OPCLASS = "+d.QuoteIdent(rr.opcSchema)+"."+d.QuoteIdent(rr.opcName))
					if r != nil {
						if id := r.opc[rr.opcOID]; id != "" {
							deps = append(deps, id)
						}
					}
				}
				if rr.collName != "" {
					opts = append(opts, "COLLATION = "+d.QuoteIdent(rr.collSchema)+"."+d.QuoteIdent(rr.collName))
					deps = append(deps, nodeID("collation", rr.collSchema, rr.collName))
				}
				if fn := regprocText(rr.canonical); fn != "" {
					opts = append(opts, "CANONICAL = "+fn)
					if r != nil {
						if id := r.proc[rr.canonicalOID]; id != "" {
							deps = append(deps, id)
						}
					}
				}
				if fn := regprocText(rr.subdiff); fn != "" {
					opts = append(opts, "SUBTYPE_DIFF = "+fn)
					if r != nil {
						if id := r.proc[rr.subdiffOID]; id != "" {
							deps = append(deps, id)
						}
					}
				}
				if clause := d.multirangeNameClause(rr.multiOID, rr.multiSchema, rr.multiName); clause != "" {
					opts = append(opts, clause)
				}
				appendShell(name)
				appendFinal(name, "CREATE TYPE "+qualify(name)+" AS RANGE ("+strings.Join(opts, ", ")+")", deps)
				if rr.canonicalOID != 0 {
					plan.Warnings = append(plan.Warnings,
						"range type "+schema+"."+name+" has a CANONICAL function; restoring it requires that (C-language) function's shared library in the target")
				}
			}
		case "b":
			for _, br := range bases {
				if br.name != name {
					continue
				}
				var opts []string
				var deps []string
				addFn := func(kw, fn string, oid int64) {
					if fn == "" || fn == "-" {
						return
					}
					opts = append(opts, kw+" = "+fn)
					if r != nil && oid != 0 {
						if id := r.proc[oid]; id != "" {
							deps = append(deps, id)
						}
					}
				}
				addFn("INPUT", br.input, br.inOID)
				addFn("OUTPUT", br.output, br.outOID)
				addFn("RECEIVE", br.receive, br.recvOID)
				addFn("SEND", br.send, br.sendOID)
				addFn("TYPMOD_IN", br.modin, br.modinOID)
				addFn("TYPMOD_OUT", br.modout, br.modoutOID)
				addFn("ANALYZE", br.analyze, br.analyzeOID)
				if clause := d.subscriptClause(br.subscript); clause != "" {
					opts = append(opts, clause)
				}
				if br.typlen == -1 {
					opts = append(opts, "INTERNALLENGTH = VARIABLE")
				} else if br.typlen > 0 {
					opts = append(opts, "INTERNALLENGTH = "+strconv.FormatInt(br.typlen, 10))
				}
				if br.byval {
					opts = append(opts, "PASSEDBYVALUE")
				}
				switch br.align {
				case "c":
					opts = append(opts, "ALIGNMENT = char")
				case "s":
					opts = append(opts, "ALIGNMENT = int2")
				case "i":
					opts = append(opts, "ALIGNMENT = int4")
				case "d":
					opts = append(opts, "ALIGNMENT = double")
				}
				if kw := storageKeyword(br.storage); kw != "" {
					opts = append(opts, "STORAGE = "+kw)
				}
				if br.category != "U" && br.category != "" {
					opts = append(opts, "CATEGORY = "+d.QuoteString(br.category))
				}
				if br.preferred {
					opts = append(opts, "PREFERRED = true")
				}
				// DEFAULT: an expression tree deparses as SQL; a bare typdefault is
				// the external TEXT VALUE and must be a quoted literal, never raw SQL
				// (an embedded quote/comma would corrupt the clause).
				if br.defbin != "" {
					opts = append(opts, "DEFAULT = "+br.defbin)
				} else if br.deftext != "" {
					opts = append(opts, "DEFAULT = "+d.QuoteString(br.deftext))
				}
				if br.elemOID != 0 && br.elem != "" {
					opts = append(opts, "ELEMENT = "+br.elem)
					if r != nil {
						if id := r.typ[br.elemOID]; id != "" {
							deps = append(deps, id)
						}
					}
				}
				if br.delim != "," && br.delim != "" {
					opts = append(opts, "DELIMITER = "+d.QuoteString(br.delim))
				}
				if br.collatable {
					opts = append(opts, "COLLATABLE = true")
				}
				appendShell(name)
				appendFinal(name, "CREATE TYPE "+qualify(name)+" ("+strings.Join(opts, ", ")+")", deps)
				plan.Warnings = append(plan.Warnings,
					"base type "+schema+"."+name+" is dumped best-effort; restoring it requires its (C-language) I/O functions' shared library AND a binary-compatible target (PASSEDBYVALUE/alignment depend on the platform ABI)")
			}
		}
	}
	return nil
}
