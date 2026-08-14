package postgres

// The partition-tree writers for the dump and display CREATE
// reconstructions: CREATE TABLE ... PARTITION OF for every child (with the
// foreign-leaf redaction/suppression policy), the dump-only child objects
// (comments, child-only indexes), and their batched catalog readers. Split
// from dump_table.go by role (the file-size ratchet keeps it that way).

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/tablexdev/tablex/internal/driver"
)

// partKeyDef returns a partitioned table's PARTITION BY definition. A query
// failure propagates (the CREATE is invalid without the clause), but a NULL
// partkeydef degrades to "" and the callers omit the clause — the same
// COALESCE-and-guard shape writePartitionChildren uses for sub-partitioned
// children, so the parent and child paths cannot drift. (A relkind 'p'
// relation always has a partkeydef; the guard is defensive symmetry.)
func (dialect) partKeyDef(ctx context.Context, db *sql.DB, schema, table string) (string, error) {
	var partKey string
	err := db.QueryRowContext(ctx, `
		SELECT COALESCE(pg_get_partkeydef(c.oid), '') FROM pg_class c
		JOIN pg_namespace n ON n.oid=c.relnamespace
		WHERE n.nspname=$1 AND c.relname=$2`, schema, table).Scan(&partKey)
	return partKey, err
}

// writePartitionChildren emits CREATE TABLE … PARTITION OF for every child of
// (schema, parent), recursing into sub-partitioned children so a multi-level
// partition tree reconstructs completely: a child that is itself partitioned
// (relkind 'p') keeps its own PARTITION BY clause and its grandchildren follow
// it. A child may live in a different schema from its parent, so each child is
// qualified — and recursed into — with its OWN namespace. Shared by the dump
// and display CREATE reconstructions so the two cannot drift.
//
// suppressed, when non-nil, collects the qualifiedKeys of foreign leaves whose
// CREATE was withheld (an unreproducible server, or a validator-REQUIRED
// option redacted) so writePartitionChildObjects can suppress every dependent
// object with them — the same policy the standalone foreign path applies via
// SuppressedRelations. The display caller passes nil: it emits the same inert
// template but has no second phase to inform.
func (d dialect) writePartitionChildren(ctx context.Context, db *sql.DB, b *strings.Builder, schema, parent string, suppressed map[string]bool) error {
	rows, err := db.QueryContext(ctx, `
		SELECT cn.nspname, c.relname, pg_get_expr(c.relpartbound, c.oid, true),
		       c.relkind, COALESCE(pg_get_partkeydef(c.oid), ''),
		       COALESCE(fs.srvname, ''),
		       COALESCE(array_to_string(ft.ftoptions, E'\x1f'), '')
		FROM pg_inherits i
		JOIN pg_class c ON c.oid = i.inhrelid
		JOIN pg_namespace cn ON cn.oid = c.relnamespace
		JOIN pg_class p ON p.oid = i.inhparent
		JOIN pg_namespace n ON n.oid = p.relnamespace
		LEFT JOIN pg_foreign_table ft ON ft.ftrelid = c.oid
		LEFT JOIN pg_foreign_server fs ON fs.oid = ft.ftserver
		WHERE n.nspname=$1 AND p.relname=$2 AND c.relispartition
		ORDER BY c.relname`, schema, parent)
	if err != nil {
		return err
	}
	type childPart struct{ schema, name, bound, kind, partKey, server, ftOptions string }
	var children []childPart
	hasForeign := false
	for rows.Next() {
		var c childPart
		if err := rows.Scan(&c.schema, &c.name, &c.bound, &c.kind, &c.partKey, &c.server, &c.ftOptions); err != nil {
			rows.Close()
			return err
		}
		if c.kind == "f" {
			hasForeign = true
		}
		children = append(children, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	// A FOREIGN partition leaf must emit CREATE FOREIGN TABLE … PARTITION
	// OF … SERVER … OPTIONS under the provenance/redaction policy — a plain
	// CREATE TABLE would silently lose the server, options and foreign-ness.
	var states map[string]foreignServerState
	if hasForeign {
		if states, err = d.foreignServerStates(ctx, db); err != nil {
			return err
		}
	}
	qparent := d.QuoteIdent(schema) + "." + d.QuoteIdent(parent)
	for _, c := range children {
		qchild := d.QuoteIdent(c.schema) + "." + d.QuoteIdent(c.name)
		if c.kind == "f" {
			st := states[c.server]
			stmt := "CREATE FOREIGN TABLE " + qchild + " PARTITION OF " + qparent + " " + c.bound +
				" SERVER " + d.QuoteIdent(c.server)
			clause, redacted := d.foreignOptionsClause(st.kind, "table", c.ftOptions)
			stmt += clause
			// A validator-REQUIRED option that was redacted leaves a CREATE the
			// server would refuse (file_fdw needs filename or program) — the
			// same test the standalone foreign path applies before templating.
			required := false
			if st.kind == "file_fdw" {
				for _, k := range redacted {
					if k == "filename" || k == "program" {
						required = true
					}
				}
			}
			if st.state == 'c' || required {
				// The leaf rides only as an inert template — the tree restores
				// without this partition, and its dependent objects (comments,
				// indexes) are suppressed with it in the second phase.
				if suppressed != nil {
					suppressed[qualifiedKey(c.schema, c.name)] = true
				}
				fmt.Fprintf(b, "-- WARNING: foreign partition %s is not dumped (its server or a required option cannot be reproduced under the redaction policy); template: %s\n",
					driver.CommentSafe(c.schema+"."+c.name), driver.CommentSafe(stmt))
				continue
			}
			fmt.Fprintf(b, "%s;\n", stmt)
			continue
		}
		fmt.Fprintf(b, "CREATE TABLE %s PARTITION OF %s %s", qchild, qparent, c.bound)
		if c.kind == "p" && c.partKey != "" {
			b.WriteString(" PARTITION BY " + c.partKey)
		}
		b.WriteString(";\n")
		if c.kind == "p" {
			if err := d.writePartitionChildren(ctx, db, b, c.schema, c.name, suppressed); err != nil {
				return err
			}
		}
	}
	return nil
}

// writePartitionChildObjects (G11) emits the DUMP-only objects that ride with a
// partition child's create but are NOT part of the shared PARTITION OF DDL: the
// child's table/column COMMENTs and its child-only secondary indexes (excluding
// indexes cloned from a parent partitioned index, which auto-attach). Called
// ONLY from DumpTableCreate — the display CreateSQL path keeps writePartition-
// Children's plain output. Recurses like writePartitionChildren so a multi-level
// tree's grandchildren are covered. (Child-local FKs, NOT VALID checks, triggers,
// RLS and replica identity ride the inTables-gated PostData passes instead.)
//
// suppressed is the first phase's verdict: a leaf whose CREATE was withheld
// contributes NO dependent objects — a COMMENT or CREATE INDEX on a table the
// restore never creates is a guaranteed error. A foreign leaf that WAS emitted
// takes COMMENT ON FOREIGN TABLE (COMMENT ON TABLE errors with "is not a
// table"), the same verb split the standalone foreign path uses.
func (d dialect) writePartitionChildObjects(ctx context.Context, db *sql.DB, b *strings.Builder, schema, parent string, suppressed map[string]bool) error {
	rows, err := db.QueryContext(ctx, `
		SELECT cn.nspname, c.relname, c.relkind,
		       COALESCE(obj_description(c.oid, 'pg_class'), '')
		FROM pg_inherits i
		JOIN pg_class c ON c.oid = i.inhrelid
		JOIN pg_namespace cn ON cn.oid = c.relnamespace
		JOIN pg_class p ON p.oid = i.inhparent
		JOIN pg_namespace n ON n.oid = p.relnamespace
		WHERE n.nspname=$1 AND p.relname=$2 AND c.relispartition
		ORDER BY c.relname`, schema, parent)
	if err != nil {
		return err
	}
	type childRel struct{ schema, name, kind, comment string }
	var children []childRel
	for rows.Next() {
		var c childRel
		if err := rows.Scan(&c.schema, &c.name, &c.kind, &c.comment); err != nil {
			rows.Close()
			return err
		}
		children = append(children, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	// The two per-child reads below are issued ONCE for this whole level and
	// grouped in Go, so a 50-partition table costs two queries here instead of a
	// hundred. Emission still walks `children` in its original order and each
	// group keeps its query's ORDER BY, so the bytes written are unchanged.
	schemas := make([]string, len(children))
	names := make([]string, len(children))
	for i, c := range children {
		schemas[i], names[i] = c.schema, c.name
	}
	colComments, err := d.childColumnComments(ctx, db, schemas, names)
	if err != nil {
		return err
	}
	childIndexes, err := d.childIndexes(ctx, db, schemas, names)
	if err != nil {
		return err
	}

	for _, c := range children {
		key := qualifiedKey(c.schema, c.name)
		if suppressed[key] {
			// The first phase withheld this leaf's CREATE; every dependent
			// object rides with it or the restore errors on a missing relation.
			continue
		}
		q := d.QuoteIdent(c.schema) + "." + d.QuoteIdent(c.name)
		if c.comment != "" {
			verb := "TABLE"
			if c.kind == "f" {
				verb = "FOREIGN TABLE"
			}
			fmt.Fprintf(b, "COMMENT ON %s %s IS %s;\n", verb, q, d.QuoteString(c.comment))
		}
		for _, cc := range colComments[key] {
			fmt.Fprintf(b, "COMMENT ON COLUMN %s.%s IS %s;\n", q, d.QuoteIdent(cc.name), d.QuoteString(cc.comment))
		}
		for _, ix := range childIndexes[key] {
			fmt.Fprintf(b, "%s;\n", ix.def)
			if ix.comment != "" {
				fmt.Fprintf(b, "COMMENT ON INDEX %s.%s IS %s;\n",
					d.QuoteIdent(c.schema), d.QuoteIdent(ix.name), d.QuoteString(ix.comment))
			}
		}
		if c.kind == "p" {
			if err := d.writePartitionChildObjects(ctx, db, b, c.schema, c.name, suppressed); err != nil {
				return err
			}
		}
	}
	return nil
}

// namedComment is one column's comment; childIndex is one secondary index's
// definition, name and comment. Both are keyed by qualifiedKey(schema, table).
type namedComment struct{ name, comment string }

type childIndex struct{ def, name, comment string }

// childColumnComments reads the column comments of every named relation in one
// query. The (schema, name) pairs are matched row-wise through unnest, so a
// same-named relation in another schema cannot be picked up.
func (d dialect) childColumnComments(ctx context.Context, db *sql.DB, schemas, names []string) (map[string][]namedComment, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT n.nspname, c.relname, a.attname, col_description(c.oid, a.attnum)
		FROM pg_class c
		JOIN pg_namespace n ON n.oid = c.relnamespace
		JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped
		WHERE (n.nspname, c.relname) IN (SELECT * FROM unnest($1::text[], $2::text[]))
		  AND col_description(c.oid, a.attnum) IS NOT NULL
		ORDER BY n.nspname, c.relname, a.attnum`, schemas, names)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]namedComment{}
	for rows.Next() {
		var schema, table string
		var cc namedComment
		if err := rows.Scan(&schema, &table, &cc.name, &cc.comment); err != nil {
			return nil, err
		}
		key := qualifiedKey(schema, table)
		out[key] = append(out[key], cc)
	}
	return out, rows.Err()
}

// childIndexes reads the child-only secondary indexes of every named relation
// in one query: constraint-backing indexes are excluded (they ride their
// constraints) and so are indexes attached to a parent partitioned index
// (pg_inherits), which re-attach automatically when the child is created.
func (d dialect) childIndexes(ctx context.Context, db *sql.DB, schemas, names []string) (map[string][]childIndex, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT n.nspname, rel.relname,
		       pg_get_indexdef(i.indexrelid, 0, true), ic.relname,
		       COALESCE(obj_description(i.indexrelid, 'pg_class'), '')
		FROM pg_index i
		JOIN pg_class rel ON rel.oid = i.indrelid
		JOIN pg_class ic ON ic.oid = i.indexrelid
		JOIN pg_namespace n ON n.oid = rel.relnamespace
		WHERE (n.nspname, rel.relname) IN (SELECT * FROM unnest($1::text[], $2::text[]))
		  AND NOT i.indisprimary
		  AND (i.indisvalid OR rel.relkind='p') AND i.indisready
		  AND NOT EXISTS (SELECT 1 FROM pg_constraint cc
		    WHERE cc.conindid = i.indexrelid AND cc.conrelid = i.indrelid AND cc.contype IN ('p','u','x'))
		  AND NOT EXISTS (SELECT 1 FROM pg_inherits pi WHERE pi.inhrelid = i.indexrelid)
		ORDER BY n.nspname, rel.relname, ic.relname`, schemas, names)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]childIndex{}
	for rows.Next() {
		var schema, table string
		var ix childIndex
		if err := rows.Scan(&schema, &table, &ix.def, &ix.name, &ix.comment); err != nil {
			return nil, err
		}
		key := qualifiedKey(schema, table)
		out[key] = append(out[key], ix)
	}
	return out, rows.Err()
}
