// Catalog introspection: the read side of the PostgreSQL dialect. Server info,
// the database/schema/table/view/routine/trigger/user listings, columns,
// indexes and foreign keys (single and bulk), row estimates, the live
// CREATE TABLE reconstruction and the server monitor (status, variables,
// processes). Nothing here emits restore DDL - that is the dump_*.go set.

package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/tablexdev/tablex/internal/driver"
	"github.com/tablexdev/tablex/internal/model"
)

func (dialect) ServerInfo(ctx context.Context, db *sql.DB) (driver.ServerInfo, error) {
	var version, user, database string
	var encoding, collate sql.NullString
	err := db.QueryRowContext(ctx, `
		SELECT version(), current_user, current_database(),
		       (SELECT pg_catalog.pg_encoding_to_char(encoding) FROM pg_database WHERE datname = current_database()),
		       (SELECT datcollate FROM pg_database WHERE datname = current_database())`).
		Scan(&version, &user, &database, &encoding, &collate)
	if err != nil {
		return driver.ServerInfo{}, err
	}
	short := version
	if f := strings.Fields(version); len(f) >= 2 {
		short = f[1]
	}
	return driver.ServerInfo{
		Engine:    "postgres",
		Flavor:    "PostgreSQL",
		Version:   short,
		User:      user,
		Database:  database,
		Charset:   encoding.String,
		Collation: collate.String,
	}, nil
}

func (dialect) ListDatabases(ctx context.Context, db *sql.DB) ([]model.Database, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT d.datname, d.datcollate
		FROM pg_catalog.pg_database d
		WHERE d.datistemplate = false AND d.datallowconn = true
		ORDER BY d.datname`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Database
	for rows.Next() {
		var dbm model.Database
		var coll sql.NullString
		if err := rows.Scan(&dbm.Name, &coll); err != nil {
			return nil, err
		}
		dbm.Collation = coll.String
		dbm.TableCount = -1
		dbm.Size = -1
		out = append(out, dbm)
	}
	return out, rows.Err()
}

func (dialect) ListSchemas(ctx context.Context, db *sql.DB, _ string) ([]model.Schema, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT n.nspname, pg_catalog.pg_get_userbyid(n.nspowner)
		FROM pg_catalog.pg_namespace n
		WHERE n.nspname NOT LIKE 'pg_temp_%' AND n.nspname NOT LIKE 'pg_toast%'
		ORDER BY n.nspname`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Schema
	for rows.Next() {
		var s model.Schema
		var owner sql.NullString
		if err := rows.Scan(&s.Name, &owner); err != nil {
			return nil, err
		}
		s.Owner = owner.String
		s.IsSystem = s.Name == "information_schema" || strings.HasPrefix(s.Name, "pg_")
		out = append(out, s)
	}
	return out, rows.Err()
}

func (dialect) ListTables(ctx context.Context, db *sql.DB, scope driver.Scope) ([]model.Table, error) {
	schema := schemaOfScope(scope)
	// A partitioned parent (relkind 'p') keeps no rows or storage of its own —
	// reltuples and pg_*_size report ~0 because the data lives in the leaf
	// partitions. Roll the leaves up via pg_partition_tree (PostgreSQL 12+; the
	// documented feature floor is now 13 for DROP DATABASE ... WITH (FORCE)) so
	// the listing shows real totals instead of zero; every
	// other relkind keeps its direct stats.
	rows, err := db.QueryContext(ctx, `
		SELECT c.relname,
		       CASE c.relkind WHEN 'v' THEN 'view' WHEN 'm' THEN 'matview' ELSE 'table' END,
		       CASE WHEN c.relkind = 'p'
		            THEN COALESCE((SELECT SUM(GREATEST(pc.reltuples,0))::bigint
		                           FROM pg_partition_tree(c.oid) pt
		                           JOIN pg_catalog.pg_class pc ON pc.oid = pt.relid
		                           WHERE pt.isleaf), 0)
		            ELSE COALESCE(c.reltuples,-1)::bigint END,
		       CASE WHEN c.relkind = 'p'
		            THEN COALESCE((SELECT SUM(pg_catalog.pg_total_relation_size(pt.relid))::bigint
		                           FROM pg_partition_tree(c.oid) pt WHERE pt.isleaf), 0)
		            ELSE pg_catalog.pg_total_relation_size(c.oid) END,
		       CASE WHEN c.relkind = 'p'
		            THEN COALESCE((SELECT SUM(pg_catalog.pg_relation_size(pt.relid))::bigint
		                           FROM pg_partition_tree(c.oid) pt WHERE pt.isleaf), 0)
		            ELSE pg_catalog.pg_relation_size(c.oid) END,
		       CASE WHEN c.relkind = 'p'
		            THEN COALESCE((SELECT SUM(pg_catalog.pg_indexes_size(pt.relid))::bigint
		                           FROM pg_partition_tree(c.oid) pt WHERE pt.isleaf), 0)
		            ELSE pg_catalog.pg_indexes_size(c.oid) END,
		       COALESCE(obj_description(c.oid),'')
		FROM pg_catalog.pg_class c
		JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = $1 AND c.relkind IN ('r','v','m','p')
		ORDER BY c.relname`, schema)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Table
	for rows.Next() {
		var t model.Table
		var kind, comment string
		var reltuples, total, rel, idx int64
		if err := rows.Scan(&t.Name, &kind, &reltuples, &total, &rel, &idx, &comment); err != nil {
			return nil, err
		}
		t.Schema = schema
		switch kind {
		case "view":
			t.Type = model.TableView
		case "matview":
			t.Type = model.TableMatView
		default:
			t.Type = model.TableBase
		}
		if reltuples < 0 {
			t.Rows = -1
		} else {
			t.Rows = reltuples
		}
		t.Size = total
		t.DataSize = rel
		t.IndexSize = idx
		t.Comment = comment
		out = append(out, t)
	}
	return out, rows.Err()
}

// SearchExpr text-casts a column for LIKE matching (driver.SearchCaster):
// PostgreSQL's LIKE takes text only, so uuid/json/bool/enum/inet/array columns
// would otherwise error out — failing table search and silently dropping whole
// tables from database search.
func (dialect) SearchExpr(quotedIdent string) string {
	return quotedIdent + "::text"
}

// ListDatabaseNames delegates to ListDatabases, which is already identity-only
// (pg_database carries no sizes; per-database sizes would need pg_database_size
// calls, which the full listing deliberately avoids too).
func (d dialect) ListDatabaseNames(ctx context.Context, db *sql.DB) ([]model.Database, error) {
	return d.ListDatabases(ctx, db)
}

// ListTableNames lists relation names and kinds only. Unlike ListTables it
// skips pg_total_relation_size/pg_indexes_size, which stat the relation's disk
// files — measurable per call and O(tables) per navigation render.
func (dialect) ListTableNames(ctx context.Context, db *sql.DB, scope driver.Scope) ([]model.Table, error) {
	schema := schemaOfScope(scope)
	rows, err := db.QueryContext(ctx, `
		SELECT c.relname,
		       CASE c.relkind WHEN 'v' THEN 'view' WHEN 'm' THEN 'matview' ELSE 'table' END
		FROM pg_catalog.pg_class c
		JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = $1 AND c.relkind IN ('r','v','m','p')
		ORDER BY c.relname`, schema)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Table
	for rows.Next() {
		var t model.Table
		var kind string
		if err := rows.Scan(&t.Name, &kind); err != nil {
			return nil, err
		}
		t.Schema = schema
		switch kind {
		case "view":
			t.Type = model.TableView
		case "matview":
			t.Type = model.TableMatView
		default:
			t.Type = model.TableBase
		}
		t.Rows, t.Size, t.DataSize, t.IndexSize = -1, -1, -1, -1
		out = append(out, t)
	}
	return out, rows.Err()
}

// EstimateRows returns the planner's reltuples estimate, scaled by the ratio of
// current pages to the pages seen at the last ANALYZE — the same correction the
// planner applies, so a table that grew since its last ANALYZE is not
// undercounted. A relation that was never vacuumed or analyzed reports -1 (PG
// 14+), which the caller treats as "no estimate" and counts exactly. Views are
// excluded by relkind.
func (dialect) EstimateRows(ctx context.Context, db *sql.DB, t driver.TableRef) (int64, error) {
	schema := schemaOf(t)
	var n int64
	err := db.QueryRowContext(ctx, `
		SELECT CASE
		         WHEN c.reltuples < 0 THEN -1::bigint
		         WHEN c.relpages <= 0 THEN c.reltuples::bigint
		         ELSE (c.reltuples
		               * (pg_catalog.pg_relation_size(c.oid) / current_setting('block_size')::bigint)
		               / c.relpages)::bigint
		       END
		FROM pg_catalog.pg_class c
		JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = $1 AND c.relname = $2 AND c.relkind IN ('r','m','p')`,
		schema, t.Table).Scan(&n)
	if errors.Is(err, sql.ErrNoRows) {
		return -1, nil
	}
	if err != nil {
		return 0, err
	}
	return n, nil
}

// bulkPrimaryKeyColumns returns each table's primary-key column set — one
// table when table is non-empty, the whole schema otherwise. Only the first
// indnkeyatts entries of indkey are key columns; the rest are INCLUDE
// (covering) payload columns, which are NOT part of the primary key. Bounding
// by seq <= indnkeyatts keeps a payload column out of the PK set (else it is
// forced NOT NULL, weakens uniqueness on restore, and corrupts row-identity
// WHERE clauses).
func (dialect) bulkPrimaryKeyColumns(ctx context.Context, db *sql.DB, schema, table string) (map[string]map[string]bool, error) {
	query := `
		SELECT c.relname, a.attname
		FROM pg_index i
		JOIN pg_class c ON c.oid = i.indrelid
		JOIN pg_namespace n ON n.oid = c.relnamespace
		JOIN LATERAL unnest(string_to_array(i.indkey::text,' ')::int[]) WITH ORDINALITY AS ord(attnum, seq) ON true
		JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum = ord.attnum
		WHERE n.nspname = $1 AND i.indisprimary AND ord.seq <= i.indnkeyatts`
	args := []any{schema}
	if table != "" {
		query += ` AND c.relname = $2`
		args = append(args, table)
	}
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	pk := map[string]map[string]bool{}
	for rows.Next() {
		var tbl, name string
		if err := rows.Scan(&tbl, &name); err != nil {
			return nil, err
		}
		if pk[tbl] == nil {
			pk[tbl] = map[string]bool{}
		}
		pk[tbl][name] = true
	}
	return pk, rows.Err()
}

// canonicalBaseType maps a PostgreSQL internal type name (pg_type.typname) to the
// canonical SQL spelling used by ColumnTypes() and the modify-column form. Without
// it BaseType would carry aliases (int4/int8/bool/bpchar/float4/float8) that never
// appear in the ColumnTypes allowlist, so the form's <option> sync would silently
// select the first entry (smallint) and a comment-only edit would rewrite the
// column's type. timetz/bit/varbit are deliberately left un-normalized: they are
// their own canonical spellings in ColumnTypes() (mapping to a name absent from the
// allowlist would re-trip the same unmatched-select bug).
func canonicalBaseType(typname string) string {
	switch typname {
	case "int2":
		return "smallint"
	case "int4":
		return "integer"
	case "int8":
		return "bigint"
	case "float4":
		return "real"
	case "float8":
		return "double precision"
	case "bool":
		return "boolean"
	case "bpchar":
		return "char"
	default:
		return typname
	}
}

func (d dialect) Columns(ctx context.Context, db *sql.DB, t driver.TableRef) ([]model.Column, error) {
	m, err := d.bulkColumns(ctx, db, schemaOf(t), t.Table)
	if err != nil {
		return nil, err
	}
	return m[t.Table], nil
}

// BulkColumns returns the columns of every table/view in the scope's schema
// with one catalog query (driver.BulkIntrospector) — the designer /
// export-preflight fast path that replaces a per-table N+1.
func (d dialect) BulkColumns(ctx context.Context, db *sql.DB, scope driver.Scope) (map[string][]model.Column, error) {
	schema := schemaOfScope(scope)
	return d.bulkColumns(ctx, db, schema, "")
}

// bulkColumns is the single column-introspection scan: one relation when table
// is non-empty (the SQL still filters, so a structure page never reads the
// whole schema), the entire schema otherwise. The relkind filter matters only
// on the bulk path — pg_attribute also holds rows for indexes, sequences and
// composite types, which a per-table call never named but a schema-wide scan
// would sweep in. Its relkind set ('r','p','v','m') deliberately matches
// ListTables/ListTableNames, so Columns answers for exactly the relations the
// app surfaces. One shared query/scan keeps the two paths from drifting.
func (d dialect) bulkColumns(ctx context.Context, db *sql.DB, schema, table string) (map[string][]model.Column, error) {
	pk, err := d.bulkPrimaryKeyColumns(ctx, db, schema, table)
	if err != nil {
		return nil, err
	}
	query := `
		SELECT c.relname, a.attname, a.attnum,
		       pg_catalog.format_type(a.atttypid, a.atttypmod),
		       t.typname,
		       a.attnotnull,
		       pg_catalog.pg_get_expr(ad.adbin, ad.adrelid),
		       a.attidentity,
		       a.attgenerated,
		       COALESCE(col_description(a.attrelid, a.attnum),''),
		       -- Non-default collation only (attcollation differing from the type's
		       -- own collation); the column DDL then emits COLLATE.
		       COALESCE(cl.collname,''), COALESCE(cn.nspname,'')
		FROM pg_catalog.pg_attribute a
		JOIN pg_catalog.pg_class c ON c.oid = a.attrelid
		JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
		JOIN pg_catalog.pg_type t ON t.oid = a.atttypid
		LEFT JOIN pg_catalog.pg_attrdef ad ON ad.adrelid = a.attrelid AND ad.adnum = a.attnum
		LEFT JOIN pg_catalog.pg_collation cl ON cl.oid = a.attcollation
		      AND a.attcollation <> 0 AND a.attcollation <> t.typcollation
		LEFT JOIN pg_catalog.pg_namespace cn ON cn.oid = cl.collnamespace
		WHERE n.nspname = $1 AND a.attnum > 0 AND NOT a.attisdropped
		  AND c.relkind IN ('r','p','v','m')`
	args := []any{schema}
	if table != "" {
		query += ` AND c.relname = $2`
		args = append(args, table)
	}
	query += ` ORDER BY c.relname, a.attnum`
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]model.Column{}
	for rows.Next() {
		var tbl string
		var c model.Column
		var dataType, baseType, comment string
		var notnull bool
		var def sql.NullString
		var identity, generated string
		if err := rows.Scan(&tbl, &c.Name, &c.Position, &dataType, &baseType, &notnull, &def, &identity, &generated, &comment, &c.Collation, &c.CollationSchema); err != nil {
			return nil, err
		}
		c.DataType = dataType
		c.BaseType = canonicalBaseType(strings.ToLower(baseType))
		c.Nullable = !notnull
		c.IsGenerated = generated != ""
		if def.Valid {
			// For a generated column pg_attrdef holds the GENERATION expression,
			// not a DEFAULT; carry it in GeneratedExpr (not Default) so display and
			// columnLine read one dedicated field instead of smuggling it through
			// Default. For an ordinary column pg_get_expr always renders an
			// expression — even a literal default appears as 'x'::text — so the
			// default is carried verbatim, never re-quoted as a string literal.
			if c.IsGenerated {
				c.GeneratedExpr = def.String
			} else {
				v := def.String
				c.Default = &v
				c.DefaultIsExpr = true
			}
		}
		c.IsPrimaryKey = pk[tbl][c.Name]
		c.IsAutoIncrement = identity != "" || (def.Valid && strings.HasPrefix(def.String, "nextval("))
		// attgenerated: 's' = STORED, 'v' = VIRTUAL (PG18+ default), '' = none.
		// Preserve the kind so columnLine reconstructs the correct storage clause
		// instead of unconditionally emitting STORED.
		switch generated {
		case "s":
			c.GeneratedKind = "stored"
		case "v":
			c.GeneratedKind = "virtual"
		}
		// attidentity: 'a' = GENERATED ALWAYS, 'd' = GENERATED BY DEFAULT. Preserve
		// the mode so CreateSQL reconstructs the correct IDENTITY clause.
		switch identity {
		case "a":
			c.Identity = model.IdentityAlways
		case "d":
			c.Identity = model.IdentityByDefault
		}
		c.Comment = comment
		// attnum is a catalog slot number, not an ordinal: it keeps its gaps
		// after a DROP COLUMN, and the structure page renders Position raw. The
		// query orders by attnum within each relation, so the running length is
		// the contiguous position every other engine reports.
		c.Position = len(out[tbl]) + 1
		out[tbl] = append(out[tbl], c)
	}
	return out, rows.Err()
}

// Indexes lists a table's indexes. As in bulkPrimaryKeyColumns, only the
// first indnkeyatts entries of indkey are key columns; the rest are INCLUDE
// (covering) payload columns, which are excluded here so they are not
// misreported as part of the key.
func (d dialect) Indexes(ctx context.Context, db *sql.DB, t driver.TableRef) ([]model.Index, error) {
	schema := schemaOf(t)
	rows, err := db.QueryContext(ctx, `
		SELECT ic.relname, i.indisunique, i.indisprimary, am.amname, a.attname,
		       pg_get_indexdef(i.indexrelid, ord.seq::int, true),
		       (string_to_array(i.indoption::text,' ')::int[])[ord.seq] & 1,
		       pg_get_expr(i.indpred, i.indrelid)
		FROM pg_index i
		JOIN pg_class c ON c.oid = i.indrelid
		JOIN pg_class ic ON ic.oid = i.indexrelid
		JOIN pg_namespace n ON n.oid = c.relnamespace
		JOIN pg_am am ON am.oid = ic.relam
		JOIN LATERAL unnest(string_to_array(i.indkey::text,' ')::int[]) WITH ORDINALITY AS ord(attnum, seq) ON true
		LEFT JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum = ord.attnum
		WHERE n.nspname = $1 AND c.relname = $2 AND ord.seq <= i.indnkeyatts
		ORDER BY i.indisprimary DESC, ic.relname, ord.seq`, schema, t.Table)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	g := driver.NewGrouper[string, model.Index]()
	for rows.Next() {
		var name, am string
		var unique, primary bool
		var col, coldef, predicate sql.NullString
		var descOpt sql.NullInt64
		if err := rows.Scan(&name, &unique, &primary, &am, &col, &coldef, &descOpt, &predicate); err != nil {
			return nil, err
		}
		idx := g.GetOrAdd(name, func() model.Index {
			// pg_get_expr returns NULL for a non-partial index; carry the WHERE
			// predicate (e.g. "active") so a partial index round-trips visibly.
			return model.Index{Name: name, Unique: unique, Primary: primary, Type: strings.ToUpper(am), Predicate: predicate.String}
		})
		var ic model.IndexColumn
		switch {
		case col.Valid:
			ic.Name = col.String
		case coldef.Valid && coldef.String != "":
			// An expression index column (attnum 0): recover the real expression
			// (e.g. "lower(email)") via pg_get_indexdef rather than a placeholder.
			ic.Expr = coldef.String
		default:
			ic.Expr = "(expression)"
		}
		// indoption bit 0 (INDOPTION_DESC) marks a DESC-sorted key column.
		ic.Descending = descOpt.Int64&1 == 1
		idx.Columns = append(idx.Columns, ic)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return g.Slice(), nil
}

func (d dialect) ForeignKeys(ctx context.Context, db *sql.DB, t driver.TableRef) ([]model.ForeignKey, error) {
	m, err := d.bulkForeignKeys(ctx, db, schemaOf(t), t.Table)
	if err != nil {
		return nil, err
	}
	return m[t.Table], nil
}

// BulkForeignKeys returns the foreign keys of every table in the scope's
// schema with one catalog query (driver.BulkIntrospector).
func (d dialect) BulkForeignKeys(ctx context.Context, db *sql.DB, scope driver.Scope) (map[string][]model.ForeignKey, error) {
	schema := schemaOfScope(scope)
	return d.bulkForeignKeys(ctx, db, schema, "")
}

// bulkForeignKeys is the single FK-introspection scan (see bulkColumns for the
// shared-query rationale). Constraints are grouped per (table, name) — a
// PostgreSQL constraint name is only unique within its table, so two tables
// may each carry an identically-named FK.
func (dialect) bulkForeignKeys(ctx context.Context, db *sql.DB, schema, table string) (map[string][]model.ForeignKey, error) {
	query := `
		SELECT c.relname, con.conname, att.attname, nf.nspname, cf.relname, attf.attname,
		       con.confupdtype, con.confdeltype, ord.seq
		FROM pg_constraint con
		JOIN pg_class c ON c.oid = con.conrelid
		JOIN pg_namespace n ON n.oid = c.relnamespace
		JOIN pg_class cf ON cf.oid = con.confrelid
		JOIN pg_namespace nf ON nf.oid = cf.relnamespace
		JOIN LATERAL unnest(con.conkey) WITH ORDINALITY AS ord(attnum, seq) ON true
		JOIN pg_attribute att ON att.attrelid = c.oid AND att.attnum = ord.attnum
		JOIN LATERAL unnest(con.confkey) WITH ORDINALITY AS ordf(attnum, seq) ON ordf.seq = ord.seq
		JOIN pg_attribute attf ON attf.attrelid = cf.oid AND attf.attnum = ordf.attnum
		WHERE n.nspname = $1 AND con.contype = 'f'`
	args := []any{schema}
	if table != "" {
		query += ` AND c.relname = $2`
		args = append(args, table)
	}
	query += ` ORDER BY c.relname, con.conname, ord.seq`
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	g := driver.NewNestedGrouper[string, string, model.ForeignKey]()
	for rows.Next() {
		var tbl, name, col, refSchema, refTable, refCol string
		var upd, del string
		var seq int
		if err := rows.Scan(&tbl, &name, &col, &refSchema, &refTable, &refCol, &upd, &del, &seq); err != nil {
			return nil, err
		}
		fk := g.GetOrAdd(tbl, name, func() model.ForeignKey {
			return model.ForeignKey{
				Name:      name,
				RefSchema: refSchema,
				RefTable:  refTable,
				OnUpdate:  fkAction(upd),
				OnDelete:  fkAction(del),
			}
		})
		fk.Columns = append(fk.Columns, col)
		fk.RefColumns = append(fk.RefColumns, refCol)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return g.Map(), nil
}

func fkAction(c string) string {
	switch c {
	case "a":
		return "NO ACTION"
	case "r":
		return "RESTRICT"
	case "c":
		return "CASCADE"
	case "n":
		return "SET NULL"
	case "d":
		return "SET DEFAULT"
	}
	return ""
}

// columnLine renders one column's "  name type [NOT NULL] [generated | default]"
// line for a CREATE TABLE body. Shared by CreateSQL (display) and
// DumpTableCreate (restore); identityOpts carries a native identity column's
// sequence options (START WITH … etc.) on the restore path and is "" for display.
func (d dialect) columnLine(c model.Column, identityOpts string) string {
	line := "  " + d.QuoteIdent(c.Name) + " " + c.DataType
	// G9: a non-default collation (COLLATE comes right after the type, before the
	// column constraints). Qualified so it resolves without a search_path pin; a
	// user-defined collation is created by the CREATE COLLATION pass.
	if c.Collation != "" {
		if c.CollationSchema != "" {
			line += " COLLATE " + d.QuoteIdent(c.CollationSchema) + "." + d.QuoteIdent(c.Collation)
		} else {
			line += " COLLATE " + d.QuoteIdent(c.Collation)
		}
	}
	if !c.Nullable {
		line += " NOT NULL"
	}
	switch {
	case c.IsGenerated && c.GeneratedExpr != "":
		// Generated column: the expression is in pg_attrdef (rendered via
		// pg_get_expr into c.GeneratedExpr for both kinds). Preserve the storage
		// kind — a VIRTUAL column (PG18+ default) must NOT restore as STORED, which
		// would change storage semantics. Emit no DEFAULT clause for either kind.
		line += " GENERATED ALWAYS AS (" + c.GeneratedExpr + ")"
		if c.GeneratedKind == "virtual" {
			line += " VIRTUAL"
		} else {
			line += " STORED"
		}
	case c.Identity != "":
		// Native identity column; preserve ALWAYS vs BY DEFAULT.
		if c.Identity == model.IdentityAlways {
			line += " GENERATED ALWAYS AS IDENTITY"
		} else {
			line += " GENERATED BY DEFAULT AS IDENTITY"
		}
		if identityOpts != "" {
			line += " (" + identityOpts + ")"
		}
	case c.Default != nil:
		// Keep ordinary defaults and legacy serial's DEFAULT nextval(...).
		line += " DEFAULT " + *c.Default
	}
	return line
}

// CreateSQL reconstructs DDL from the catalog (PostgreSQL has no SHOW CREATE).
// unloggedPrefix returns "UNLOGGED " when pg_class.relpersistence is 'u', so an
// UNLOGGED table is reconstructed as one rather than silently becoming a normal
// (logged) table on restore.
func unloggedPrefix(relpersistence string) string {
	if relpersistence == "u" {
		return "UNLOGGED "
	}
	return ""
}

func (d dialect) CreateSQL(ctx context.Context, db *sql.DB, t driver.TableRef) (string, error) {
	schema := schemaOf(t)
	var relkind, relpersistence, tableComment string
	err := db.QueryRowContext(ctx, `
		SELECT c.relkind, c.relpersistence, COALESCE(obj_description(c.oid, 'pg_class'), '')
		FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
		WHERE n.nspname=$1 AND c.relname=$2`, schema, t.Table).Scan(&relkind, &relpersistence, &tableComment)
	if err != nil {
		return "", err
	}
	qname := d.QualifyTable(t)
	if relkind == "v" || relkind == "m" {
		var def string
		if err := db.QueryRowContext(ctx, `SELECT pg_get_viewdef(($1||'.'||$2)::regclass, true)`, d.QuoteIdent(schema), d.QuoteIdent(t.Table)).Scan(&def); err != nil {
			return "", err
		}
		kw := "VIEW"
		if relkind == "m" {
			kw = "MATERIALIZED VIEW"
		}
		return fmt.Sprintf("CREATE %s %s AS\n%s", kw, qname, def), nil
	}

	cols, err := d.Columns(ctx, db, t)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "CREATE %sTABLE %s (\n", unloggedPrefix(relpersistence), qname)
	lines := make([]string, 0, len(cols)+4)
	for _, c := range cols {
		lines = append(lines, d.columnLine(c, "")) // display path: no identity options
	}
	// Foreign keys.
	fks, err := d.ForeignKeys(ctx, db, t)
	if err != nil {
		return "", err
	}
	for _, fk := range fks {
		cols := driver.QuoteEach(d, fk.Columns)
		refCols := driver.QuoteEach(d, fk.RefColumns)
		ref := d.QuoteIdent(fk.RefSchema) + "." + d.QuoteIdent(fk.RefTable)
		line := fmt.Sprintf("  CONSTRAINT %s FOREIGN KEY (%s) REFERENCES %s (%s)",
			d.QuoteIdent(fk.Name), strings.Join(cols, ", "), ref, strings.Join(refCols, ", "))
		if fk.OnUpdate != "" && fk.OnUpdate != "NO ACTION" {
			line += " ON UPDATE " + fk.OnUpdate
		}
		if fk.OnDelete != "" && fk.OnDelete != "NO ACTION" {
			line += " ON DELETE " + fk.OnDelete
		}
		lines = append(lines, line)
	}
	// PRIMARY KEY / CHECK / UNIQUE / EXCLUDE constraints, inline with their names.
	// Best-effort on the display path: a query failure drops them rather than
	// failing the whole reconstruction (DumpTableCreate, the restore path,
	// propagates).
	extra, _ := d.inlineConstraints(ctx, db, schema, t.Table, false, nil)
	lines = append(lines, extra...)
	b.WriteString(strings.Join(lines, ",\n"))
	b.WriteString("\n)")
	if relkind == "p" {
		// A partitioned table's CREATE is invalid without its PARTITION BY, so
		// this read propagates (not best-effort like the constraint reads above).
		partKey, err := d.partKeyDef(ctx, db, schema, t.Table)
		if err != nil {
			return "", err
		}
		if partKey != "" {
			b.WriteString(" PARTITION BY " + partKey)
		}
	}
	b.WriteString(";\n")
	// Table + column comments (kept after the table so the DDL round-trips).
	if tableComment != "" {
		fmt.Fprintf(&b, "COMMENT ON TABLE %s IS %s;\n", qname, d.QuoteString(tableComment))
	}
	for _, c := range cols {
		if c.Comment != "" {
			fmt.Fprintf(&b, "COMMENT ON COLUMN %s.%s IS %s;\n", qname, d.QuoteIdent(c.Name), d.QuoteString(c.Comment))
		}
	}

	// Secondary indexes via pg_get_indexdef (constraint-backing indexes excluded
	// — they appear as the inline PRIMARY KEY / UNIQUE / EXCLUDE constraints
	// above). Best-effort: append whatever was read and flag (rather than
	// silently drop) an incomplete list so the DDL doesn't look complete.
	idxDefs, idxErr := d.secondaryIndexDefs(ctx, db, schema, t.Table)
	for _, def := range idxDefs {
		b.WriteString(def)
		b.WriteString(";\n")
	}
	if idxErr != nil {
		b.WriteString("-- note: secondary index list may be incomplete\n")
	}
	if relkind == "p" {
		// Partition children (recursive, like the dump path) so the displayed DDL
		// shows the full tree rather than a parent with no partitions.
		if err := d.writePartitionChildren(ctx, db, &b, schema, t.Table, nil); err != nil {
			return "", err
		}
	}
	return b.String(), nil
}

func (d dialect) ListViews(ctx context.Context, db *sql.DB, scope driver.Scope) ([]model.View, error) {
	schema := schemaOfScope(scope)
	rows, err := db.QueryContext(ctx, `
		SELECT c.relname, pg_get_viewdef(c.oid, true)
		FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
		WHERE n.nspname=$1 AND c.relkind IN ('v','m') ORDER BY c.relname`, schema)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.View
	for rows.Next() {
		var v model.View
		if err := rows.Scan(&v.Name, &v.Definition); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (dialect) ListRoutines(ctx context.Context, db *sql.DB, scope driver.Scope) ([]model.Routine, error) {
	schema := schemaOfScope(scope)
	rows, err := db.QueryContext(ctx, `
		SELECT p.proname,
		       CASE p.prokind WHEN 'p' THEN 'PROCEDURE' ELSE 'FUNCTION' END,
		       pg_catalog.pg_get_function_result(p.oid),
		       l.lanname,
		       COALESCE(pg_catalog.pg_get_functiondef(p.oid),''),
		       COALESCE(obj_description(p.oid, 'pg_proc'),''),
		       -- Identity arguments, not the full argument list: this is what
		       -- DROP FUNCTION/PROCEDURE needs to name an overload (see
		       -- DropRoutineSQL). Empty for a zero-argument routine.
		       pg_catalog.pg_get_function_identity_arguments(p.oid)
		FROM pg_proc p
		JOIN pg_namespace n ON n.oid = p.pronamespace
		JOIN pg_language l ON l.oid = p.prolang
		WHERE n.nspname = $1 AND p.prokind IN ('f','p') AND l.lanname NOT IN ('internal','c')
		-- The identity arguments are part of the sort key, not decoration:
		-- proname alone TIES for overloaded functions, and the callers that
		-- address a routine by its position in this list (the definition panel
		-- and the drop action) need the order to be total and repeatable.
		ORDER BY p.proname, pg_catalog.pg_get_function_identity_arguments(p.oid)`, schema)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Routine
	for rows.Next() {
		var r model.Routine
		var ret, lang, def, args sql.NullString
		if err := rows.Scan(&r.Name, &r.Type, &ret, &lang, &def, &r.Comment, &args); err != nil {
			return nil, err
		}
		r.ReturnType = ret.String
		r.Language = lang.String
		r.Definition = def.String
		r.ArgSignature = args.String
		out = append(out, r)
	}
	return out, rows.Err()
}

func (dialect) ListTriggers(ctx context.Context, db *sql.DB, scope driver.Scope) ([]model.Trigger, error) {
	schema := schemaOfScope(scope)
	rows, err := db.QueryContext(ctx, `
		SELECT t.tgname, c.relname, pg_get_triggerdef(t.oid, true), t.tgtype::int
		FROM pg_trigger t
		JOIN pg_class c ON c.oid = t.tgrelid
		JOIN pg_namespace n ON n.oid = c.relnamespace
		-- Same version split the dump pass handles: a partition child's CLONED
		-- user trigger is flagged tgisinternal on PG13 but not on PG14+. It DOES
		-- fire on that child, so the internal test alone makes the floor report
		-- "no triggers" for a table that has one. The tgconstraint guard keeps
		-- referential-integrity triggers out — they are internal AND cloned onto
		-- partitions too.
		WHERE n.nspname = $1
		  AND (NOT t.tgisinternal OR (t.tgparentid <> 0 AND t.tgconstraint = 0))
		-- Trigger names are unique per TABLE, not per schema, so tgname alone
		-- ties whenever two tables carry the same trigger name; the table breaks
		-- it, keeping this list's positions stable for the callers that address
		-- a trigger by index.
		ORDER BY t.tgname, c.relname`, schema)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Trigger
	for rows.Next() {
		var tr model.Trigger
		var tgtype int
		if err := rows.Scan(&tr.Name, &tr.Table, &tr.Definition, &tgtype); err != nil {
			return nil, err
		}
		// Decode the timing/event from the pg_trigger.tgtype bitmask, not the
		// rendered DDL: a quoted trigger name or the EXECUTE FUNCTION name can embed
		// " ON " or keywords like "update"/"insert" and mislabel a text scan.
		tr.Timing, tr.Event = decodeTriggerType(tgtype)
		out = append(out, tr)
	}
	return out, rows.Err()
}

// decodeTriggerType maps the pg_trigger.tgtype bitmask to the display timing and
// comma-joined event list. Bit positions are from PostgreSQL's
// catalog/pg_trigger.h (TRIGGER_TYPE_*).
func decodeTriggerType(tgtype int) (timing, event string) {
	const (
		tgBefore   = 1 << 1
		tgInsert   = 1 << 2
		tgDelete   = 1 << 3
		tgUpdate   = 1 << 4
		tgTruncate = 1 << 5
		tgInstead  = 1 << 6
	)
	switch {
	case tgtype&tgInstead != 0:
		timing = "INSTEAD OF"
	case tgtype&tgBefore != 0:
		timing = "BEFORE"
	default:
		timing = "AFTER"
	}
	var events []string
	if tgtype&tgInsert != 0 {
		events = append(events, "INSERT")
	}
	if tgtype&tgUpdate != 0 {
		events = append(events, "UPDATE")
	}
	if tgtype&tgDelete != 0 {
		events = append(events, "DELETE")
	}
	if tgtype&tgTruncate != 0 {
		events = append(events, "TRUNCATE")
	}
	return timing, strings.Join(events, ", ")
}

func (dialect) ListEvents(context.Context, *sql.DB, driver.Scope) ([]model.Event, error) {
	return nil, nil
}

func (dialect) ListUsers(ctx context.Context, db *sql.DB) ([]model.User, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT rolname, rolcanlogin, rolsuper, rolcreatedb, rolcreaterole
		FROM pg_catalog.pg_roles ORDER BY rolname`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.User
	for rows.Next() {
		var u model.User
		var super, createdb, createrole bool
		if err := rows.Scan(&u.Name, &u.CanLogin, &super, &createdb, &createrole); err != nil {
			return nil, err
		}
		u.IsSuper = super
		var attrs []string
		if super {
			attrs = append(attrs, "Superuser")
		}
		if createdb {
			attrs = append(attrs, "Create DB")
		}
		if createrole {
			attrs = append(attrs, "Create role")
		}
		u.Attributes = strings.Join(attrs, ", ")
		out = append(out, u)
	}
	return out, rows.Err()
}

// Privileges lists the direct ACL grants on the connected database (ref.Table
// == "") or on a single table, via aclexplode over pg_database.datacl /
// pg_class.relacl — the grants a REVOKE can actually remove, unlike effective-
// privilege views (has_database_privilege, role_table_grants), which fold in
// PUBLIC and role membership. A NULL ACL means built-in defaults; acldefault
// renders those so the page never shows an empty list for a fresh object.
// Grantee OID 0 is the PUBLIC pseudo-role — a fully grant/revoke-able target —
// surfaced as User "PUBLIC". The grantee is otherwise a role name (PostgreSQL
// has no host part). The database ACL is a database-scoped object, so the DB
// branch ignores ref.Schema entirely; PostgreSQL binds one database per
// connection, so it also keys on current_database() rather than ref.Database.
func (d dialect) Privileges(ctx context.Context, db *sql.DB, ref driver.TableRef) ([]model.Privilege, error) {
	var (
		rows   *sql.Rows
		err    error
		object string
	)
	if ref.Table != "" {
		object = schemaOf(ref) + "." + ref.Table
		// The second leg lists column grants (pg_attribute.attacl). It has no
		// acldefault companion on purpose: a NULL attacl means "no column-level
		// entry", i.e. the column is covered by the table ACL alone — rendering
		// a default there would invent grants that no REVOKE can remove. A
		// column grant is its own ACL entry, so it must be listed to be
		// revokable at all.
		rows, err = db.QueryContext(ctx, `
			SELECT COALESCE(r.rolname, 'PUBLIC'), a.privilege_type, a.is_grantable, ''::text
			FROM pg_catalog.pg_class c
			JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
			CROSS JOIN LATERAL aclexplode(coalesce(c.relacl, acldefault('r', c.relowner))) a
			LEFT JOIN pg_catalog.pg_roles r ON r.oid = a.grantee
			WHERE n.nspname = $1 AND c.relname = $2
			UNION ALL
			SELECT COALESCE(r.rolname, 'PUBLIC'), a.privilege_type, a.is_grantable, att.attname
			FROM pg_catalog.pg_attribute att
			JOIN pg_catalog.pg_class c ON c.oid = att.attrelid
			JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
			CROSS JOIN LATERAL aclexplode(att.attacl) a
			LEFT JOIN pg_catalog.pg_roles r ON r.oid = a.grantee
			WHERE n.nspname = $1 AND c.relname = $2
			  AND att.attnum > 0 AND NOT att.attisdropped AND att.attacl IS NOT NULL
			ORDER BY 1, 4, 2`, schemaOf(ref), ref.Table)
	} else {
		rows, err = db.QueryContext(ctx, `
			SELECT COALESCE(r.rolname, 'PUBLIC'), a.privilege_type, a.is_grantable, d.datname
			FROM pg_catalog.pg_database d
			CROSS JOIN LATERAL aclexplode(coalesce(d.datacl, acldefault('d', d.datdba))) a
			LEFT JOIN pg_catalog.pg_roles r ON r.oid = a.grantee
			WHERE d.datname = current_database()
			ORDER BY 1, 2`)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Privilege
	for rows.Next() {
		var p model.Privilege
		dest := []any{&p.User, &p.Privilege, &p.Grantable}
		if ref.Table != "" {
			p.Object = object
			dest = append(dest, &p.Column) // attname, '' on the table-ACL leg
		} else {
			dest = append(dest, &p.Object) // datname: Object is the database name
		}
		if err := rows.Scan(dest...); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (dialect) Status(ctx context.Context, db *sql.DB) ([]model.Variable, error) {
	var backends, commit, rollback, blksRead, blksHit, tupReturned, tupFetched, tupIns, tupUpd, tupDel sql.NullInt64
	err := db.QueryRowContext(ctx, `
		SELECT numbackends, xact_commit, xact_rollback, blks_read, blks_hit,
		       tup_returned, tup_fetched, tup_inserted, tup_updated, tup_deleted
		FROM pg_stat_database WHERE datname = current_database()`).
		Scan(&backends, &commit, &rollback, &blksRead, &blksHit, &tupReturned, &tupFetched, &tupIns, &tupUpd, &tupDel)
	if err != nil {
		return nil, err
	}
	kv := func(n string, v sql.NullInt64) model.Variable {
		return model.Variable{Name: n, Value: strconv.FormatInt(v.Int64, 10)}
	}
	return []model.Variable{
		kv("Active connections", backends),
		kv("Transactions committed", commit),
		kv("Transactions rolled back", rollback),
		kv("Blocks read (disk)", blksRead),
		kv("Blocks hit (cache)", blksHit),
		kv("Tuples returned", tupReturned),
		kv("Tuples fetched", tupFetched),
		kv("Tuples inserted", tupIns),
		kv("Tuples updated", tupUpd),
		kv("Tuples deleted", tupDel),
	}, nil
}

func (dialect) Variables(ctx context.Context, db *sql.DB) ([]model.Variable, error) {
	rows, err := db.QueryContext(ctx, "SELECT name, setting FROM pg_settings ORDER BY name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Variable
	for rows.Next() {
		var v model.Variable
		if err := rows.Scan(&v.Name, &v.Value); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// ProcessIDColumn is pg_stat_activity's backend pid.
func (dialect) ProcessIDColumn() string { return "pid" }

// KillProcessSQL terminates the backend. pg_terminate_backend, not
// pg_cancel_backend: cancelling only aborts the running statement and leaves
// the session connected, which is not what a "kill" button promises.
//
// It is a SELECT because that is the only form PostgreSQL has for this; the
// returned boolean is discarded, so a pid that vanished between the listing and
// the click reports success rather than an error — the session is gone either
// way, which is what was asked for.
func (dialect) KillProcessSQL(id int64) string {
	return "SELECT pg_catalog.pg_terminate_backend(" + strconv.FormatInt(id, 10) + ")"
}

func (dialect) Processes(ctx context.Context, db *sql.DB) (*driver.ResultSet, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT pid, usename, datname, state, wait_event_type, left(query, 200) AS query
		FROM pg_stat_activity ORDER BY pid`)
	if err != nil {
		return nil, err
	}
	return driver.ScanResult(rows, 1000)
}
