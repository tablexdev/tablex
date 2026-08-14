// Table structure for the dump path: the restore-oriented CREATE TABLE
// reconstruction (inline constraints, physical column settings, reloptions,
// access method), the partition-tree writers, and the data-scan classification
// that decides which relations are scanned for rows.

package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/tablexdev/tablex/internal/driver"
)

// DataSelectOnly (G10): an ordinary relkind='r' table's data SELECT uses FROM
// ONLY so an INHERITS parent scans only its OWN rows — its ordinary children are
// dumped separately (they are NOT filtered from the data list, unlike partition
// children), so a plain FROM would return every child row through the parent
// scan AND through the child's own scan, duplicating it. A partitioned parent
// (relkind='p') returns false (plain FROM): its descendants are excluded from the
// data list, so the parent scan is the only place their rows appear.
func (dialect) DataSelectOnly(ctx context.Context, db *sql.DB, scope driver.Scope, tables []string) (map[string]bool, error) {
	schema := schemaOfScope(scope)
	rows, err := db.QueryContext(ctx, `
		SELECT c.relname FROM pg_class c
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = $1 AND c.relkind = 'r'`, schema)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	inList := driver.StringSet(tables)
	out := map[string]bool{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		if inList[name] {
			out[name] = true
		}
	}
	return out, rows.Err()
}

// DumpDataTables excludes partition children: their structure rides with the
// parent (DumpTableCreate emits CREATE TABLE ... PARTITION OF) and a SELECT on
// the parent already returns their rows — dumping both would duplicate every
// row. Foreign-leaf exception — a tree containing a FOREIGN leaf: the root's plain
// FROM scan would recurse into the foreign leaf and query the REMOTE server,
// so the root is dropped from the data list and its same-schema LOCAL leaves
// are kept instead (each read FROM ONLY — exactly-once rows). An all-local
// tree keeps the single recursive root scan unchanged.
func (dialect) DumpDataTables(ctx context.Context, db *sql.DB, scope driver.Scope, tables []string) ([]string, error) {
	schema := schemaOfScope(scope)
	rows, err := db.QueryContext(ctx, `
		SELECT c.relname FROM pg_class c
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = $1 AND c.relispartition`, schema)
	if err != nil {
		return nil, err
	}
	children := map[string]bool{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			rows.Close()
			return nil, err
		}
		children[name] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	keepLeaf := map[string]bool{}
	mixRows, err := db.QueryContext(ctx, `
		SELECT cn.nspname, c.relname, c.relkind::text
		FROM pg_class p
		JOIN pg_namespace n ON n.oid = p.relnamespace
		CROSS JOIN LATERAL pg_partition_tree(p.oid) pt
		JOIN pg_class c ON c.oid = pt.relid
		JOIN pg_namespace cn ON cn.oid = c.relnamespace
		WHERE n.nspname = $1 AND p.relkind = 'p' AND NOT p.relispartition
		  AND pt.isleaf
		  AND EXISTS (SELECT 1 FROM pg_partition_tree(p.oid) pt2
		      JOIN pg_class c2 ON c2.oid = pt2.relid WHERE c2.relkind = 'f')`, schema)
	if err != nil {
		return nil, err
	}
	for mixRows.Next() {
		var leafSchema, leaf, kind string
		if err := mixRows.Scan(&leafSchema, &leaf, &kind); err != nil {
			mixRows.Close()
			return nil, err
		}
		if kind == "r" && leafSchema == schema {
			keepLeaf[leaf] = true
		}
	}
	mixRows.Close()
	if err := mixRows.Err(); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(tables))
	for _, t := range tables {
		// A mixed root STAYS in the list — its structure entry still owns the
		// whole tree's DDL; DumpObjects marks it StructureOnly so the handler
		// skips its data scan, while the kept local leaves are its data source.
		if !children[t] || keepLeaf[t] {
			out = append(out, t)
		}
	}
	return out, nil
}

// DumpTableCreate reconstructs restore-oriented DDL: foreign keys are stripped
// (they return as post-data ALTERs, the only way cyclic / self-referencing
// schemas restore), CHECK constraints keep their names (NOT VALID ones move to
// post-data — they are not legal inline), PARTITION BY is preserved and the
// partition children are created with the parent.
func (d dialect) DumpTableCreate(ctx context.Context, db *sql.DB, t driver.TableRef) (string, error) {
	return d.dumpTableCreate(ctx, db, t, nil, nil, nil)
}

// DumpTableCreateStaged (StagedTableDumper) re-renders a table's create
// with the named columns' DEFAULT clauses and the named inline constraints
// OMITTED — the cycle resolver's cut — and returns the deferred post-data
// scripts re-adding them: ALTER … SET DEFAULT (Kind "staged-default"; data
// INSERTs name every column explicitly, so restored rows are unaffected) and
// ALTER … ADD CONSTRAINT (Kind "constraint"; a re-added CHECK validates the
// loaded rows), with a moved COMMENT ON CONSTRAINT where one exists (the
// create no longer declares the constraint, so its inline comment slot is
// gone).
func (d dialect) DumpTableCreateStaged(ctx context.Context, db *sql.DB, t driver.TableRef, parents []string, stripDefaults, stripConstraints []string) (string, []driver.DumpScript, error) {
	var qualifiedParents []string
	if len(parents) > 0 {
		qualifiedParents = make([]string, len(parents))
		for i, p := range parents {
			qualifiedParents[i] = d.QuoteIdent(schemaOf(t)) + "." + d.QuoteIdent(p)
		}
	}
	create, err := d.dumpTableCreate(ctx, db, t, qualifiedParents,
		driver.StringSet(stripDefaults), driver.StringSet(stripConstraints))
	if err != nil {
		return "", nil, err
	}
	schema := schemaOf(t)
	qname := d.QualifyTable(t)
	var out []driver.DumpScript
	for _, col := range stripDefaults {
		var expr string
		if err := db.QueryRowContext(ctx, `
			SELECT pg_get_expr(ad.adbin, ad.adrelid)
			FROM pg_attrdef ad
			JOIN pg_class c ON c.oid = ad.adrelid
			JOIN pg_namespace n ON n.oid = c.relnamespace
			JOIN pg_attribute a ON a.attrelid = ad.adrelid AND a.attnum = ad.adnum
			WHERE n.nspname = $1 AND c.relname = $2 AND a.attname = $3`,
			schema, t.Table, col).Scan(&expr); err != nil {
			return "", nil, err
		}
		out = append(out, driver.DumpScript{
			Kind:    "staged-default",
			Comment: "Deferred default for " + t.Table + "." + col,
			SQL:     "ALTER TABLE ONLY " + qname + " ALTER COLUMN " + d.QuoteIdent(col) + " SET DEFAULT " + expr,
		})
	}
	for _, con := range stripConstraints {
		var def, comment string
		if err := db.QueryRowContext(ctx, `
			SELECT pg_get_constraintdef(con.oid, true),
			       COALESCE(obj_description(con.oid, 'pg_constraint'), '')
			FROM pg_constraint con
			JOIN pg_class c ON c.oid = con.conrelid
			JOIN pg_namespace n ON n.oid = c.relnamespace
			WHERE n.nspname = $1 AND c.relname = $2 AND con.conname = $3`,
			schema, t.Table, con).Scan(&def, &comment); err != nil {
			return "", nil, err
		}
		out = append(out, driver.DumpScript{
			Kind:    "constraint",
			Comment: "Deferred constraint " + con + " on " + t.Table,
			Drop:    "ALTER TABLE IF EXISTS " + qname + " DROP CONSTRAINT IF EXISTS " + d.QuoteIdent(con),
			SQL:     "ALTER TABLE " + qname + " ADD CONSTRAINT " + d.QuoteIdent(con) + " " + def,
		})
		if comment != "" {
			out = append(out, driver.DumpScript{
				Kind:    "constraint-comment",
				Comment: "Comment for constraint " + con + " on " + t.Table,
				SQL:     "COMMENT ON CONSTRAINT " + d.QuoteIdent(con) + " ON " + qname + " IS " + d.QuoteString(comment),
			})
		}
	}
	return create, out, nil
}

// dumpTableCreate is the shared core. inheritsParents is non-nil for an ordinary
// (INHERITS, non-partition) child that links to an emitted parent: the CREATE
// gains an INHERITS clause, the column list is filtered to LOCAL columns
// (inherited ones come from the parent) and inline constraints to conislocal, so
// provenance round-trips instead of every inherited definition becoming local.
// The parents are already schema-qualified. nil dumps a standalone table.
// stripDefaults/stripConstraints (nil normally) omit the named columns'
// DEFAULT clauses / the named inline constraints — the cycle resolver's staged
// re-render, which re-adds them post-data.
func (d dialect) dumpTableCreate(ctx context.Context, db *sql.DB, t driver.TableRef, inheritsParents []string, stripDefaults, stripConstraints map[string]bool) (string, error) {
	schema := schemaOf(t)
	// pg_class facts, from the schema-wide memoized read (dump_preflight.go) so a
	// whole-schema dump makes one query here instead of one per table.
	meta, err := d.tableMeta(ctx, db, schema, t.Table)
	if err != nil {
		return "", err
	}
	relkind, relpersistence, tableComment := meta.relkind, meta.relpersistence, meta.tableComment
	reloptions, amname := meta.reloptions, meta.amname
	ofTypeSchema, ofTypeName := meta.ofTypeSchema, meta.ofTypeName
	isPartition, partBound := meta.isPartition, meta.partBound
	qname := d.QualifyTable(t)

	cols, err := d.Columns(ctx, db, t)
	if err != nil {
		return "", err
	}
	identityOpts, err := d.identityOptions(ctx, db, schema, t.Table)
	if err != nil {
		return "", err
	}
	// G10: an INHERITS child re-declares only its LOCAL columns; inherited columns
	// come from the parent (re-declaring one flips attislocal on restore).
	var localCols map[string]bool
	if inheritsParents != nil {
		if localCols, err = d.localColumnSet(ctx, db, schema, t.Table); err != nil {
			return "", err
		}
	}
	// PG18+ (namedNotNulls returns nil below 18): named table NOT NULL
	// constraints. A VALIDATED local constraint emits inline (named, via
	// pg_get_constraintdef — NO INHERIT survives) and suppresses that column's
	// bare NOT NULL clause per column (suppressing table-wide would strip
	// unrelated columns' NOT NULL, and NOT suppressing makes the named form a
	// silent no-op that loses the name/comment). A NOT VALID local constraint
	// is illegal inline: only the suppression happens here (the column loads
	// nullable) and the ADD CONSTRAINT … NOT VALID rides the post-data
	// constraint pass. A PURELY-INHERITED copy on a LINKED child suppresses too
	// (the constraint re-arrives via INHERITS; re-declaring flips conislocal),
	// while on a STANDALONE table it keeps the bare clause — the named form is
	// unemittable without the parent, and a nullable column would be an
	// integrity regression. Partition-cloned copies (conparentid != 0) re-clone
	// via PARTITION OF and keep the bare clause on the (unreachable) direct path.
	nns, err := d.namedNotNulls(ctx, db, schema, t.Table)
	if err != nil {
		return "", err
	}
	suppressNN := map[string]bool{}
	var nnLines, nnComments []string
	for _, nn := range nns {
		switch {
		case nn.islocal && nn.parentID == 0 && nn.validated:
			suppressNN[nn.attname] = true
			nnLines = append(nnLines, "  CONSTRAINT "+d.QuoteIdent(nn.conname)+" "+nn.def)
			if nn.comment != "" {
				nnComments = append(nnComments, "COMMENT ON CONSTRAINT "+d.QuoteIdent(nn.conname)+" ON "+qname+" IS "+d.QuoteString(nn.comment))
			}
		case nn.islocal && nn.parentID == 0:
			suppressNN[nn.attname] = true // NOT VALID: post-data ADD CONSTRAINT
		case inheritsParents != nil:
			suppressNN[nn.attname] = true // LINKED child: INHERITS re-creates it
		case nn.validated:
			// STANDALONE materialization — the inherited/partition-cloned
			// copy has no parent to re-arrive from on restore, so the named form
			// (and its comment) is materialized as the child's own constraint.
			suppressNN[nn.attname] = true
			nnLines = append(nnLines, "  CONSTRAINT "+d.QuoteIdent(nn.conname)+" "+nn.def)
			if nn.comment != "" {
				nnComments = append(nnComments, "COMMENT ON CONSTRAINT "+d.QuoteIdent(nn.conname)+" ON "+qname+" IS "+d.QuoteString(nn.comment))
			}
		default:
			// A NOT VALID inherited copy on a standalone child cannot go
			// inline; the post-data constraint pass adds it (with its comment).
			suppressNN[nn.attname] = true
		}
	}
	// A TYPED table (CREATE TABLE … OF type). Its columns come from the
	// composite type and cannot be re-declared — only per-column deviations
	// (`col WITH OPTIONS [NOT NULL] [DEFAULT …]`) and table constraints are
	// legal in the body. Identity/generated columns cannot exist on one, and a
	// typed table cannot INHERITS or be partitioned, so the plain-column loop
	// is skipped entirely. The type itself restores via the CREATE TYPE pass
	// (types are emitted before tables).
	ofClause := ""
	if ofTypeName != "" {
		ofClause = " OF " + d.QuoteIdent(ofTypeSchema) + "." + d.QuoteIdent(ofTypeName)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "CREATE %sTABLE %s%s (\n", unloggedPrefix(relpersistence), qname, ofClause)
	lines := make([]string, 0, len(cols)+4)
	for _, c := range cols {
		if stripDefaults[c.Name] && !c.IsGenerated {
			c.Default = nil // deferred — re-added post-data as SET DEFAULT
		}
		if ofTypeName != "" {
			var opts []string
			if !c.Nullable && !suppressNN[c.Name] {
				opts = append(opts, "NOT NULL")
			}
			if c.Default != nil && !c.IsGenerated {
				opts = append(opts, "DEFAULT "+*c.Default)
			}
			if len(opts) > 0 {
				lines = append(lines, "  "+d.QuoteIdent(c.Name)+" WITH OPTIONS "+strings.Join(opts, " "))
			}
			continue
		}
		if localCols != nil && !localCols[c.Name] {
			continue // inherited-only column: comes from the parent
		}
		if suppressNN[c.Name] {
			c.Nullable = true // the named NOT NULL constraint carries it instead
		}
		lines = append(lines, d.columnLine(c, identityOpts[c.Name]))
	}
	// PRIMARY KEY, validated CHECK, UNIQUE and EXCLUDE constraints, inline with
	// their names via pg_get_constraintdef (restore equivalence compares that
	// output before/after, so an auto name and any INCLUDE / DEFERRABLE clause
	// must survive too). NOT VALID checks and all FKs are post-data ALTERs.
	extra, err := d.inlineConstraints(ctx, db, schema, t.Table, inheritsParents != nil, stripConstraints)
	if err != nil {
		return "", err
	}
	lines = append(lines, extra...)
	lines = append(lines, nnLines...)
	// A partition child materialized STANDALONE loses its implicit
	// partition-bound constraint — synthesize a plain CHECK from
	// pg_get_partition_constraintdef (NOT pg_get_expr(relpartbound), which
	// yields the FOR VALUES fragment the untouched PARTITION OF path uses). A
	// HASH bound embeds the non-portable parent OID via
	// satisfies_hash_partition('NNNN'::oid, …), so it is dropped — DumpObjects
	// warns about the enforcement loss — rather than emitted unstable.
	if isPartition && inheritsParents == nil && partBound != "" &&
		!strings.Contains(partBound, "satisfies_hash_partition(") {
		lines = append(lines, "  CHECK ("+partBound+")")
	}
	// An INHERITS child with only inherited columns and no local constraints has
	// an empty body — emit `()` rather than `(\n\n)`. A typed table with no
	// deviations drops the parens entirely (`OF type ()` is not valid grammar).
	if len(lines) == 0 {
		b.Reset()
		if ofTypeName != "" {
			fmt.Fprintf(&b, "CREATE %sTABLE %s%s", unloggedPrefix(relpersistence), qname, ofClause)
		} else {
			fmt.Fprintf(&b, "CREATE %sTABLE %s ()", unloggedPrefix(relpersistence), qname)
		}
	} else {
		b.WriteString(strings.Join(lines, ",\n"))
		b.WriteString("\n)")
	}
	if len(inheritsParents) > 0 {
		b.WriteString(" INHERITS (" + strings.Join(inheritsParents, ", ") + ")")
	}
	if relkind == "p" {
		partKey, err := d.partKeyDef(ctx, db, schema, t.Table)
		if err != nil {
			return "", err
		}
		if partKey != "" {
			b.WriteString(" PARTITION BY " + partKey)
		}
	}
	// G9: access method (non-default only) then storage parameters, in grammar
	// order (… [INHERITS] [PARTITION BY] [USING method] [WITH (…)]).
	b.WriteString(d.usingClause(amname))
	b.WriteString(d.reloptionsClause(reloptions))
	b.WriteString(";\n")
	// A LINKED child's inherited-only (attislocal = false) generated
	// column with a DIVERGENT expression. The child CREATE deliberately omits
	// inherited-only columns (re-declaring one flips attislocal/attinhcount),
	// so the child restores with the parent's expression; PG17+ SET EXPRESSION
	// re-establishes the child's own — pre-data, before any row computes. The
	// state is UNREACHABLE below 17 (SET EXPRESSION is the only way to diverge
	// an inherited-only generated column), so the gate loses nothing.
	if inheritsParents != nil && d.major >= 17 {
		genRows, err := db.QueryContext(ctx, `
			SELECT a.attname, pg_get_expr(ad.adbin, ad.adrelid),
			       COALESCE((SELECT pg_get_expr(pad.adbin, pad.adrelid)
			                 FROM pg_inherits i
			                 JOIN pg_attribute pa ON pa.attrelid = i.inhparent
			                   AND pa.attname = a.attname AND NOT pa.attisdropped
			                 LEFT JOIN pg_attrdef pad ON pad.adrelid = i.inhparent
			                   AND pad.adnum = pa.attnum
			                 WHERE i.inhrelid = c.oid
			                 ORDER BY i.inhseqno LIMIT 1), '')
			FROM pg_attribute a
			JOIN pg_class c ON c.oid = a.attrelid
			JOIN pg_namespace n ON n.oid = c.relnamespace
			JOIN pg_attrdef ad ON ad.adrelid = a.attrelid AND ad.adnum = a.attnum
			WHERE n.nspname = $1 AND c.relname = $2 AND a.attnum > 0
			  AND NOT a.attisdropped AND a.attgenerated <> '' AND NOT a.attislocal
			ORDER BY a.attnum`, schema, t.Table)
		if err != nil {
			return "", err
		}
		for genRows.Next() {
			var col, childExpr, parentExpr string
			if err := genRows.Scan(&col, &childExpr, &parentExpr); err != nil {
				genRows.Close()
				return "", err
			}
			if childExpr != parentExpr {
				fmt.Fprintf(&b, "ALTER TABLE ONLY %s ALTER COLUMN %s SET EXPRESSION AS (%s);\n",
					qname, d.QuoteIdent(col), childExpr)
			}
		}
		genRows.Close()
		if err := genRows.Err(); err != nil {
			return "", err
		}
	}
	if tableComment != "" {
		fmt.Fprintf(&b, "COMMENT ON TABLE %s IS %s;\n", qname, d.QuoteString(tableComment))
	}
	for _, c := range cols {
		if c.Comment != "" {
			fmt.Fprintf(&b, "COMMENT ON COLUMN %s.%s IS %s;\n", qname, d.QuoteIdent(c.Name), d.QuoteString(c.Comment))
		}
	}
	// G3: comments on the INLINE constraints (PK/UNIQUE/EXCLUDE/validated CHECK)
	// emitted just above by inlineConstraints — which is shared with the display
	// path and cannot carry them. FK and NOT VALID check comments ride the
	// PostData constraint pass instead.
	conComments, err := d.inlineConstraintComments(ctx, db, schema, t.Table, qname, stripConstraints)
	if err != nil {
		return "", err
	}
	for _, s := range conComments {
		b.WriteString(s)
		b.WriteString(";\n")
	}
	// Comments on the inline NAMED NOT NULL constraints emitted above
	// (inlineConstraintComments does not cover contype 'n'). Restorable because
	// the inline constraint keeps its name. NOT VALID named NOT NULL comments
	// ride the post-data constraint pass; purely-inherited copies' child-local
	// comments ride dumpInheritedNotNullState.
	for _, s := range nnComments {
		b.WriteString(s)
		b.WriteString(";\n")
	}
	// G15(b): per-column physical settings (SET STORAGE / COMPRESSION /
	// STATISTICS) the CREATE TABLE column line does not carry. Emitted BEFORE the
	// partition children below so a child created via PARTITION OF copies the
	// parent's (just-set) storage — a partition child's DIVERGENT settings remain
	// the documented §8 residual.
	settings, err := d.columnPhysicalSettings(ctx, db, schema, t.Table, "ALTER TABLE ONLY "+qname)
	if err != nil {
		return "", err
	}
	for _, s := range settings {
		b.WriteString(s)
		b.WriteString(";\n")
	}
	// Secondary indexes (parent only; partition children inherit them on
	// CREATE ... PARTITION OF, which is why children come after the indexes).
	// Constraint-backing indexes are skipped — they restore via the inline
	// PRIMARY KEY / UNIQUE / EXCLUDE constraints above.
	idxDefs, err := d.secondaryIndexDefs(ctx, db, schema, t.Table)
	if err != nil {
		return "", err
	}
	for _, def := range idxDefs {
		b.WriteString(def)
		b.WriteString(";\n")
	}
	if relkind == "p" {
		// Recursive: a sub-partitioned child keeps its own PARTITION BY and its
		// grandchildren follow — a multi-level tree restores completely.
		// suppressed carries the first phase's withheld foreign leaves into the
		// second, so an uncreated leaf contributes no dependent objects.
		suppressed := map[string]bool{}
		if err := d.writePartitionChildren(ctx, db, &b, schema, t.Table, suppressed); err != nil {
			return "", err
		}
		// G11: the children's dump-only objects (comments, child-only indexes)
		// after the whole hierarchy exists. The display path (CreateSQL) does NOT
		// call this — it keeps writePartitionChildren's plain output.
		if err := d.writePartitionChildObjects(ctx, db, &b, schema, t.Table, suppressed); err != nil {
			return "", err
		}
	}
	// Return self-contained DDL with its trailing ';' intact rather than relying
	// on the caller to re-append exactly one (the body already ends with ';\n').
	return strings.TrimRight(b.String(), "\n"), nil
}

// namedNotNull is one PG18+ catalogued table NOT NULL constraint (pg_constraint
// contype 'n' with a conrelid). PG13–17 store table NOT NULL only in
// pg_attribute.attnotnull, so those versions never build these.
type namedNotNull struct {
	conname   string
	def       string // pg_get_constraintdef: NOT NULL <col> [NO INHERIT] [NOT VALID]
	attname   string // the single conkey column
	validated bool
	islocal   bool
	inhcount  int
	parentID  int64 // conparentid: != 0 for a partition-cloned copy
	comment   string
}

// namedNotNulls returns the table's named NOT NULL constraints, or nil
// below PostgreSQL 18 — the collection query is the ONLY PG18-gated part;
// PG13–17 keep the bare attnotnull-derived column clause.
func (d dialect) namedNotNulls(ctx context.Context, db *sql.DB, schema, table string) ([]namedNotNull, error) {
	if d.major < 18 {
		return nil, nil
	}
	all, err := d.namedNotNullsBySchema(ctx, db, schema, preflightOnly(ctx, table))
	if err != nil {
		return nil, err
	}
	return all[table], nil
}

// inlineConstraints returns the table-level PRIMARY KEY, CHECK (validated only),
// UNIQUE and EXCLUDE constraint lines for a CREATE TABLE body, each formatted as
// "  CONSTRAINT <name> <def>" from pg_get_constraintdef (so the constraint name,
// NULLS NOT DISTINCT, INCLUDE covering columns, DEFERRABLE / INITIALLY DEFERRED
// and EXCLUDE … USING all survive verbatim). Routing the PK through
// pg_get_constraintdef (rather than a hand-assembled clause) keeps INCLUDE
// payload columns out of the key and preserves the constraint name / DEFERRABLE.
// NOT VALID CHECKs and every FK are post-data ALTERs, not inline. Shared by
// DumpTableCreate (restore path) and CreateSQL (display path) so the two cannot
// drift; the caller decides the error policy.
func (d dialect) inlineConstraints(ctx context.Context, db *sql.DB, schema, table string, localOnly bool, skip map[string]bool) ([]string, error) {
	// localOnly (G10): for an ordinary INHERITS child, re-declaring an inherited
	// constraint would mark it local on restore; only conislocal constraints are
	// emitted, the inherited ones re-merge from the parent via INHERITS.
	// skip (nil normally): constraints the cycle resolver deferred to
	// post-data — omitted from the inline list.
	localFilter := ""
	if localOnly {
		localFilter = " AND con.conislocal"
	}
	rows, err := db.QueryContext(ctx, `
		SELECT con.conname, pg_get_constraintdef(con.oid, true)
		FROM pg_constraint con
		JOIN pg_class c ON c.oid = con.conrelid
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname=$1 AND c.relname=$2
		  AND ((con.contype='c' AND con.convalidated) OR con.contype IN ('p','u','x'))`+localFilter+`
		ORDER BY con.contype, con.conname`, schema, table)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var name, def string
		if err := rows.Scan(&name, &def); err != nil {
			return out, err
		}
		if skip[name] {
			continue
		}
		out = append(out, "  CONSTRAINT "+d.QuoteIdent(name)+" "+def)
	}
	return out, rows.Err()
}

// inlineConstraintComments (G3) returns COMMENT ON CONSTRAINT statements for the
// table's INLINE constraints (PK, UNIQUE, EXCLUDE and validated CHECK) that carry
// a comment. inlineConstraints emits the definitions but is shared with the
// display path and cannot carry the comments, so these restore-only statements
// live here (DumpTableCreate only). Restorable because the inline constraint
// keeps its name. FK and NOT VALID check comments are emitted by the PostData
// constraint pass instead (disjoint contype sets, so no double-emit).
func (d dialect) inlineConstraintComments(ctx context.Context, db *sql.DB, schema, table, qname string, skip map[string]bool) ([]string, error) {
	all, err := d.inlineConstraintCommentsBySchema(ctx, db, schema, preflightOnly(ctx, table))
	if err != nil {
		return nil, err
	}
	var out []string
	for _, c := range all[table] {
		if skip[c.name] {
			continue // the comment moves with its deferred constraint
		}
		out = append(out, "COMMENT ON CONSTRAINT "+d.QuoteIdent(c.name)+" ON "+qname+" IS "+d.QuoteString(c.comment))
	}
	return out, nil
}

// secondaryIndexDefs returns pg_get_indexdef statements for the table's
// secondary indexes, EXCLUDING constraint-backing indexes (primary, unique,
// exclusion) — those restore via the inline constraints inlineConstraints
// emits, so re-emitting their CREATE INDEX would duplicate enforcement. The
// conrelid guard is essential: an FK's conindid points at the *referenced*
// table's unique index, so matching on conindid alone would wrongly drop a
// plain unique index that another table's FK references.
func (d dialect) secondaryIndexDefs(ctx context.Context, db *sql.DB, schema, table string) ([]string, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT pg_get_indexdef(i.indexrelid, 0, true), ic.relname,
		       COALESCE(obj_description(i.indexrelid, 'pg_class'), '')
		FROM pg_index i
		JOIN pg_class c ON c.oid = i.indrelid
		JOIN pg_class ic ON ic.oid = i.indexrelid
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname=$1 AND c.relname=$2 AND NOT i.indisprimary
		  -- G17: skip a failed concurrent build. An invalid/unready leaf index
		  -- would restore as VALID (a broken unique index can even fail the
		  -- restore); pg_dump's shape keeps an invalid-but-ready PARTITIONED
		  -- PARENT index (ON ONLY, valid once every child attaches).
		  AND (i.indisvalid OR c.relkind = 'p') AND i.indisready
		  AND NOT EXISTS (
		    SELECT 1 FROM pg_constraint cc
		    WHERE cc.conindid = i.indexrelid AND cc.conrelid = i.indrelid
		      AND cc.contype IN ('p','u','x'))
		ORDER BY ic.relname`, schema, table)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var def, idxName, comment string
		if err := rows.Scan(&def, &idxName, &comment); err != nil {
			return out, err
		}
		out = append(out, def)
		// G3: a comment on a secondary index (restorable because the recreated
		// index keeps its name).
		if comment != "" {
			out = append(out, "COMMENT ON INDEX "+d.QuoteIdent(schema)+"."+d.QuoteIdent(idxName)+" IS "+d.QuoteString(comment))
		}
	}
	return out, rows.Err()
}

// columnPhysicalSettings (G15b) returns the per-column ALTER statements that
// restore a column's non-default physical attributes the CREATE column line
// never carries: SET STORAGE (attstorage differing from the type default),
// SET COMPRESSION (attcompression, PG14+) and SET STATISTICS (attstattarget).
// The version-dependent columns are read through to_jsonb so the PG13 floor (no
// attcompression) and PG17+ (nullable attstattarget) shapes both parse.
// alterHead parameterizes the statement head — "ALTER TABLE ONLY <q>" for
// tables (pg_dump parity; emitted BEFORE the partition children so a child
// created via PARTITION OF copies the parent's just-set storage — a child's
// DIVERGENT settings are a documented §8 residual) and
// "ALTER MATERIALIZED VIEW <q>" for matviews.
func (d dialect) columnPhysicalSettings(ctx context.Context, db *sql.DB, schema, table, alterHead string) ([]string, error) {
	all, err := d.columnPhysicalSettingsBySchema(ctx, db, schema, preflightOnly(ctx, table))
	if err != nil {
		return nil, err
	}
	var out []string
	for _, pc := range all[table] {
		out = append(out, d.physicalSettingLines(alterHead, pc.name, pc.storage, pc.typStorage, pc.compression, pc.statTarget)...)
	}
	return out, nil
}

// physicalSettingLines renders one column's SET STORAGE / COMPRESSION /
// STATISTICS statements. Pure (unit-tested with a driven major). SET
// COMPRESSION is version-gated on major >= 14: both attcompression and the
// ALTER … SET COMPRESSION grammar exist only from PostgreSQL 14, so a
// 13-floor dump must never carry it (the catalog cannot report one there, but
// the gate keeps the generated SQL provably version-correct).
func (d dialect) physicalSettingLines(alterHead, column, storage, typStorage, compression string, statTarget sql.NullString) []string {
	var out []string
	prefix := alterHead + " ALTER COLUMN " + d.QuoteIdent(column) + " SET "
	if storage != typStorage {
		if kw := storageKeyword(storage); kw != "" {
			out = append(out, prefix+"STORAGE "+kw)
		}
	}
	if d.major >= 14 {
		if kw := compressionKeyword(compression); kw != "" {
			out = append(out, prefix+"COMPRESSION "+kw)
		}
	}
	// attstattarget: NULL (PG17+) or -1 (pre-17) is the default; any other
	// value — including an explicit 0 (collect no statistics) — is emitted.
	if statTarget.Valid && statTarget.String != "-1" {
		out = append(out, prefix+"STATISTICS "+statTarget.String)
	}
	return out
}

// storageKeyword maps a pg_attribute.attstorage code to its SET STORAGE keyword.
func storageKeyword(code string) string {
	switch code {
	case "p":
		return "PLAIN"
	case "e":
		return "EXTERNAL"
	case "m":
		return "MAIN"
	case "x":
		return "EXTENDED"
	}
	return ""
}

// compressionKeyword maps a pg_attribute.attcompression code to its SET
// COMPRESSION method. The empty/default code emits nothing.
func compressionKeyword(code string) string {
	switch code {
	case "p":
		return "pglz"
	case "l":
		return "lz4"
	}
	return ""
}

// safeReloptionName reports whether s is a valid storage-parameter name — one
// or two dot-separated segments of [a-z_][a-z0-9_]* (the namespaced `toast.`
// form, e.g. `toast.autovacuum_enabled`). A catalog value is already constrained
// by PostgreSQL, but the clause is executable SQL, so an unmatched name is
// skipped rather than concatenated.
func safeReloptionName(s string) bool {
	seg := func(x string) bool {
		if x == "" {
			return false
		}
		for i := 0; i < len(x); i++ {
			c := x[i]
			ok := c == '_' || (c >= 'a' && c <= 'z') || (i > 0 && c >= '0' && c <= '9')
			if !ok {
				return false
			}
		}
		return true
	}
	if a, b, ok := strings.Cut(s, "."); ok {
		return seg(a) && seg(b)
	}
	return seg(s)
}

// reloptionsClause (G9) builds a ` WITH (name = 'value', …)` clause from a
// pg_class.reloptions array joined on newlines (empty → ""). Each element is
// name=value split at the FIRST '='; the value is emitted through QuoteString
// (PostgreSQL accepts a quoted storage-parameter value and coerces it) so a
// value containing a comma or quote cannot corrupt the clause, and the name is
// validated so a hostile catalog value cannot inject SQL. Shared by tables,
// views and matviews (a view's security_invoker/security_barrier/check_option
// all live here as reloptions). Mirrors pg_dump's appendReloptionsArray.
func (d dialect) reloptionsClause(joined string) string {
	if joined == "" {
		return ""
	}
	var opts []string
	for opt := range strings.SplitSeq(joined, "\n") {
		name, value, ok := strings.Cut(opt, "=")
		if !ok || !safeReloptionName(name) {
			continue // a valueless option (none exist) or an unsafe name — skip
		}
		opts = append(opts, name+" = "+d.QuoteString(value))
	}
	if len(opts) == 0 {
		return ""
	}
	return " WITH (" + strings.Join(opts, ", ") + ")"
}

// usingClause (G9) returns a ` USING "method"` clause for a relation whose access
// method is non-default (anything but heap). The default is left implicit — the
// common case, and every seed relation — so the vast majority of CREATE TABLEs
// are unchanged; a non-heap AM needs an extension present in the target anyway.
// A target with a non-default default_table_access_method could therefore change
// a heap source relation's method — a documented §8 caveat.
func (d dialect) usingClause(amname string) string {
	if amname == "" || amname == "heap" {
		return ""
	}
	return " USING " + d.QuoteIdent(amname)
}
