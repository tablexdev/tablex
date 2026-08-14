package postgres

import (
	"context"
	"database/sql"
	"strconv"

	"github.com/tablexdev/tablex/internal/driver"
)

// This file holds the SCHEMA-WIDE, memoized catalog reads for the table-dump
// preflight. dumpTableCreate runs once per table, and several of its catalog
// reads are pure schema+table filters — read once for the whole schema and
// indexed by table, they amortize from N round trips to one across a dump of N
// tables (driver.MemoizedDump, the same seam identityOptions uses). With no memo
// attached (the single-table DISPLAY path never carries one) every lookup misses
// and computes the schema-wide value once, so the results are identical either
// way — only the query COUNT changes.
//
// Only the DUMP-ONLY reads live here. inlineConstraints and secondaryIndexDefs
// are deliberately NOT amortized: they are shared with the display path
// (introspect.go's CreateSQL), where a schema-wide scan for one table would be a
// latency REGRESSION, and Columns is the shared introspection method with its
// own semantics. Those stay per-table.

// preflightOnly returns the single relation a preflight read should be
// narrowed to, or "" for the schema-wide read.
//
// The planner attaches a dump memo only when a dump has SEVERAL tables to
// amortize a schema-wide read across (dump.BuildPlan). Without one — a
// table-scope export, or the display path — reading the whole schema to answer
// for one relation is not an amortization at all, it is a scan whose cost
// grows with the schema while the answer stays one row: exporting a single
// table from a 5 000-table schema transferred every table's pg_class row and
// every column's physical settings to build one CREATE TABLE.
//
// Narrowing changes only the width and count of the queries, never their
// results — the same contract driver.DumpMemo keeps, and the reason this is
// safe as an optimization rather than a second code path. The memo key carries
// the scope too, so a narrow result can never be served to a schema-wide
// caller.
func preflightOnly(ctx context.Context, table string) string {
	if driver.HasDumpMemo(ctx) {
		return ""
	}
	return table
}

// onlyClause is the relname predicate for a narrowed read, or "" for the
// schema-wide one. n is the placeholder index ($2 in every query here).
func onlyClause(only string, n int) string {
	if only == "" {
		return ""
	}
	return " AND c.relname = $" + strconv.Itoa(n)
}

// scopeArgs pairs onlyClause with its arguments.
func scopeArgs(schema, only string) []any {
	if only == "" {
		return []any{schema}
	}
	return []any{schema, only}
}

// pgTableMeta is one relation's dump-relevant pg_class facts.
type pgTableMeta struct {
	relkind, relpersistence, tableComment, reloptions, amname string
	ofTypeSchema, ofTypeName                                  string
	isPartition                                               bool
	partBound                                                 string
}

// tableMeta returns one table's pg_class facts, from the memoized schema-wide
// read. A name with no row is sql.ErrNoRows, exactly as the old per-table
// QueryRow reported it.
func (d dialect) tableMeta(ctx context.Context, db *sql.DB, schema, table string) (pgTableMeta, error) {
	all, err := d.tableMetaBySchema(ctx, db, schema, preflightOnly(ctx, table))
	if err != nil {
		return pgTableMeta{}, err
	}
	m, ok := all[table]
	if !ok {
		return pgTableMeta{}, sql.ErrNoRows
	}
	return m, nil
}

func (d dialect) tableMetaBySchema(ctx context.Context, db *sql.DB, schema, only string) (map[string]pgTableMeta, error) {
	v, err := driver.MemoizedDump(ctx, "pg:table-meta:"+schema+":"+only, func() (any, error) {
		rows, err := db.QueryContext(ctx, `
			SELECT c.relname, c.relkind, c.relpersistence,
			       COALESCE(obj_description(c.oid, 'pg_class'), ''),
			       COALESCE(array_to_string(c.reloptions, E'\n'), ''),
			       COALESCE((SELECT amname FROM pg_am WHERE oid = c.relam), ''),
			       COALESCE((SELECT tn.nspname FROM pg_type ty
			                 JOIN pg_namespace tn ON tn.oid = ty.typnamespace
			                 WHERE ty.oid = c.reloftype), ''),
			       COALESCE((SELECT ty.typname FROM pg_type ty WHERE ty.oid = c.reloftype), ''),
			       c.relispartition, COALESCE(pg_get_partition_constraintdef(c.oid), '')
			FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
			WHERE n.nspname = $1`+onlyClause(only, 2), scopeArgs(schema, only)...)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		out := map[string]pgTableMeta{}
		for rows.Next() {
			var name string
			var m pgTableMeta
			if err := rows.Scan(&name, &m.relkind, &m.relpersistence, &m.tableComment,
				&m.reloptions, &m.amname, &m.ofTypeSchema, &m.ofTypeName, &m.isPartition, &m.partBound); err != nil {
				return nil, err
			}
			out[name] = m
		}
		return out, rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return v.(map[string]pgTableMeta), nil
}

// namedNotNullsBySchema reads every PG18+ table NOT NULL constraint in the
// schema, grouped by table. The major-version gate stays in the per-table
// wrapper, so below 18 no query runs at all.
func (d dialect) namedNotNullsBySchema(ctx context.Context, db *sql.DB, schema, only string) (map[string][]namedNotNull, error) {
	v, err := driver.MemoizedDump(ctx, "pg:named-not-nulls:"+schema+":"+only, func() (any, error) {
		rows, err := db.QueryContext(ctx, `
			SELECT c.relname, con.conname, pg_get_constraintdef(con.oid, true), a.attname,
			       con.convalidated, con.conislocal, con.coninhcount, con.conparentid,
			       COALESCE(obj_description(con.oid, 'pg_constraint'), '')
			FROM pg_constraint con
			JOIN pg_class c ON c.oid = con.conrelid
			JOIN pg_namespace n ON n.oid = c.relnamespace
			JOIN pg_attribute a ON a.attrelid = con.conrelid AND a.attnum = con.conkey[1]
			WHERE n.nspname = $1 AND con.contype = 'n'`+onlyClause(only, 2)+`
			ORDER BY c.relname, con.conname`, scopeArgs(schema, only)...)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		out := map[string][]namedNotNull{}
		for rows.Next() {
			var tbl string
			var nn namedNotNull
			if err := rows.Scan(&tbl, &nn.conname, &nn.def, &nn.attname, &nn.validated,
				&nn.islocal, &nn.inhcount, &nn.parentID, &nn.comment); err != nil {
				return nil, err
			}
			out[tbl] = append(out[tbl], nn)
		}
		return out, rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return v.(map[string][]namedNotNull), nil
}

// conCommentRow is one inline-constraint comment (name + comment text); the
// per-table wrapper builds the COMMENT statement, since it needs the table's
// qualified name and the deferred-constraint skip set.
type conCommentRow struct {
	name    string
	comment string
}

func (d dialect) inlineConstraintCommentsBySchema(ctx context.Context, db *sql.DB, schema, only string) (map[string][]conCommentRow, error) {
	v, err := driver.MemoizedDump(ctx, "pg:inline-constraint-comments:"+schema+":"+only, func() (any, error) {
		rows, err := db.QueryContext(ctx, `
			SELECT c.relname, con.conname, obj_description(con.oid, 'pg_constraint')
			FROM pg_constraint con
			JOIN pg_class c ON c.oid = con.conrelid
			JOIN pg_namespace n ON n.oid = c.relnamespace
			WHERE n.nspname=$1
			  AND ((con.contype='c' AND con.convalidated) OR con.contype IN ('p','u','x'))
			  AND obj_description(con.oid, 'pg_constraint') IS NOT NULL`+onlyClause(only, 2)+`
			ORDER BY c.relname, con.conname`, scopeArgs(schema, only)...)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		out := map[string][]conCommentRow{}
		for rows.Next() {
			var tbl string
			var r conCommentRow
			if err := rows.Scan(&tbl, &r.name, &r.comment); err != nil {
				return nil, err
			}
			out[tbl] = append(out[tbl], r)
		}
		return out, rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return v.(map[string][]conCommentRow), nil
}

// physColRow is one column's raw physical-setting catalog values; the per-table
// wrapper renders them through physicalSettingLines, which needs the caller's
// alterHead (ALTER TABLE vs ALTER MATERIALIZED VIEW).
type physColRow struct {
	name, storage, typStorage, compression string
	statTarget                             sql.NullString
}

func (d dialect) columnPhysicalSettingsBySchema(ctx context.Context, db *sql.DB, schema, only string) (map[string][]physColRow, error) {
	v, err := driver.MemoizedDump(ctx, "pg:column-physical:"+schema+":"+only, func() (any, error) {
		rows, err := db.QueryContext(ctx, `
			SELECT c.relname, a.attname, a.attstorage::text, t.typstorage::text,
			       COALESCE(to_jsonb(a)->>'attcompression', ''), to_jsonb(a)->>'attstattarget'
			FROM pg_attribute a
			JOIN pg_class c ON c.oid = a.attrelid
			JOIN pg_namespace n ON n.oid = c.relnamespace
			JOIN pg_type t ON t.oid = a.atttypid
			WHERE n.nspname=$1 AND a.attnum > 0 AND NOT a.attisdropped`+onlyClause(only, 2)+`
			ORDER BY c.relname, a.attnum`, scopeArgs(schema, only)...)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		out := map[string][]physColRow{}
		for rows.Next() {
			var tbl string
			var pc physColRow
			if err := rows.Scan(&tbl, &pc.name, &pc.storage, &pc.typStorage, &pc.compression, &pc.statTarget); err != nil {
				return nil, err
			}
			out[tbl] = append(out[tbl], pc)
		}
		return out, rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return v.(map[string][]physColRow), nil
}
