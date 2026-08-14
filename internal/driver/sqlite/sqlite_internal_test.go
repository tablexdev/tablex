package sqlite

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	"github.com/tablexdev/tablex/internal/driver"
)

// TestColumnsAutoIncrementDetection exercises the full L4/L5 chain through
// Columns against a real in-memory SQLite DB: a plain INTEGER PRIMARY KEY is the
// auto-incrementing rowid alias, but a WITHOUT ROWID table (L5) and an inline
// INTEGER PRIMARY KEY DESC (L4) are not.
func TestColumnsAutoIncrementDetection(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()
	d := dialect{}
	ctx := context.Background()
	cases := []struct {
		table, ddl string
		want       bool
	}{
		{"t1", `CREATE TABLE t1 (id INTEGER PRIMARY KEY, v TEXT)`, true},
		{"t2", `CREATE TABLE t2 (id INTEGER PRIMARY KEY, v TEXT) WITHOUT ROWID`, false},
		{"t3", `CREATE TABLE t3 (id INTEGER PRIMARY KEY DESC, v TEXT)`, false},
	}
	for _, c := range cases {
		if _, err := db.ExecContext(ctx, c.ddl); err != nil {
			t.Fatalf("%s: create: %v", c.table, err)
		}
	}
	for _, c := range cases {
		cols, err := d.Columns(ctx, db, driver.TableRef{Database: "main", Table: c.table})
		if err != nil {
			t.Fatalf("%s: Columns: %v", c.table, err)
		}
		var got bool
		for _, col := range cols {
			if col.Name == "id" {
				got = col.IsAutoIncrement
			}
		}
		if got != c.want {
			t.Errorf("%s: id IsAutoIncrement = %v, want %v", c.table, got, c.want)
		}
	}
}

// TestIndexesDescendingAndPartial covers the Theme-H index fidelity: a DESC key
// column is flagged Descending, and a partial index carries its WHERE predicate
// (recovered from sqlite_master, since PRAGMA does not expose it).
func TestIndexesDescendingAndPartial(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()
	ctx := context.Background()
	for _, ddl := range []string{
		`CREATE TABLE t (id INTEGER PRIMARY KEY, a INT, b INT)`,
		`CREATE INDEX ix_desc ON t (a DESC, b ASC)`,
		`CREATE INDEX ix_partial ON t (a) WHERE b > 0`,
	} {
		if _, err := db.ExecContext(ctx, ddl); err != nil {
			t.Fatalf("exec %q: %v", ddl, err)
		}
	}
	idxs, err := dialect{}.Indexes(ctx, db, driver.TableRef{Database: "main", Table: "t"})
	if err != nil {
		t.Fatalf("Indexes: %v", err)
	}
	var descOK, partialOK bool
	for _, ix := range idxs {
		switch ix.Name {
		case "ix_desc":
			if len(ix.Columns) == 2 && ix.Columns[0].Descending && !ix.Columns[1].Descending {
				descOK = true
			}
		case "ix_partial":
			// SQLite normalizes the predicate; assert it names the column and is non-empty.
			if ix.Predicate != "" {
				partialOK = true
			}
		}
	}
	if !descOK {
		t.Errorf("ix_desc: expected first column DESC, second ASC; got %+v", idxs)
	}
	if !partialOK {
		t.Errorf("ix_partial: expected a non-empty WHERE predicate; got %+v", idxs)
	}
}

func ptr(s string) *string { return &s }

func TestBaseType(t *testing.T) {
	cases := map[string]string{
		"VARCHAR(255)": "varchar",
		"INTEGER":      "integer",
		"NUMERIC(8,2)": "numeric",
		"  TEXT  ":     "text",
	}
	for in, want := range cases {
		if got := driver.BaseTypeName(in); got != want {
			t.Errorf("BaseTypeName(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestSQLiteCreateTableSQL pins the CREATE TABLE builder and — the R2 point —
// that it accepts column shapes AddColumnSQL must reject: CURRENT_TIMESTAMP
// defaults and NOT NULL without a default are ALTER-TABLE-only restrictions,
// both legal in a CREATE TABLE column list.
func TestSQLiteCreateTableSQL(t *testing.T) {
	d := dialect{}
	tr := driver.TableRef{Database: "main", Table: "orders"}
	got, err := d.CreateTableSQL(tr, []driver.ColumnSpec{
		{Name: "id", Type: "INTEGER"},
		{Name: "made", Type: "DATETIME", Default: ptr("CURRENT_TIMESTAMP")},
	}, []string{"id"})
	if err != nil {
		t.Fatalf("CreateTableSQL: %v", err)
	}
	want := "CREATE TABLE \"orders\" (\n  \"id\" INTEGER NOT NULL,\n  \"made\" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,\n  PRIMARY KEY (\"id\")\n)"
	if len(got) != 1 || got[0] != want {
		t.Errorf("CreateTableSQL:\n got %q\nwant %q", got, want)
	}
	// The same column must be rejected by the ALTER-TABLE path.
	if _, err := d.AddColumnSQL(tr, driver.ColumnSpec{Name: "made", Type: "DATETIME", Default: ptr("CURRENT_TIMESTAMP")}); err == nil {
		t.Error("AddColumnSQL must reject a CURRENT_* default (ALTER TABLE restriction)")
	}
	if _, err := d.CreateTableSQL(tr, nil, nil); err == nil {
		t.Error("empty column list should error")
	}
	if _, err := d.CreateTableSQL(tr, []driver.ColumnSpec{{Name: "id", Type: "INTEGER"}}, []string{"ghost"}); err == nil {
		t.Error("pk entry not among the columns should error")
	}
}

func TestParseTriggerDef(t *testing.T) {
	timing, event := parseTriggerDef("CREATE TRIGGER t AFTER INSERT ON x BEGIN END")
	if timing != "AFTER" || event != "INSERT" {
		t.Errorf("parseTriggerDef = %q/%q, want AFTER/INSERT", timing, event)
	}
	timing, event = parseTriggerDef("CREATE TRIGGER t BEFORE UPDATE ON x BEGIN END")
	if timing != "BEFORE" || event != "UPDATE" {
		t.Errorf("parseTriggerDef = %q/%q, want BEFORE/UPDATE", timing, event)
	}
	// The body must not be scanned: an INSERT trigger whose body UPDATEs/DELETEs
	// must still report INSERT.
	timing, event = parseTriggerDef("CREATE TRIGGER t AFTER INSERT ON x BEGIN UPDATE y SET a=1; DELETE FROM z; END")
	if timing != "AFTER" || event != "INSERT" {
		t.Errorf("parseTriggerDef body bled through = %q/%q, want AFTER/INSERT", timing, event)
	}
	// INSTEAD OF on a view.
	timing, event = parseTriggerDef("CREATE TRIGGER t INSTEAD OF DELETE ON v BEGIN END")
	if timing != "INSTEAD OF" || event != "DELETE" {
		t.Errorf("parseTriggerDef = %q/%q, want INSTEAD OF/DELETE", timing, event)
	}
	// A quoted trigger name containing " ON " and an event keyword must not
	// truncate the header early or masquerade as the clause.
	timing, event = parseTriggerDef(`CREATE TRIGGER "audit ON update" AFTER INSERT ON "t" BEGIN END`)
	if timing != "AFTER" || event != "INSERT" {
		t.Errorf("parseTriggerDef quoted-name = %q/%q, want AFTER/INSERT", timing, event)
	}
	// A quoted table name containing " ON ".
	timing, event = parseTriggerDef(`CREATE TRIGGER t BEFORE DELETE ON "orders ON hold" BEGIN END`)
	if timing != "BEFORE" || event != "DELETE" {
		t.Errorf("parseTriggerDef quoted-table = %q/%q, want BEFORE/DELETE", timing, event)
	}
	// SQLite defaults the timing to BEFORE when the clause is omitted.
	timing, event = parseTriggerDef("CREATE TRIGGER t DELETE ON x BEGIN END")
	if timing != "BEFORE" || event != "DELETE" {
		t.Errorf("parseTriggerDef default-timing = %q/%q, want BEFORE/DELETE", timing, event)
	}
}

// TestDDLIsWithoutRowid covers: WITHOUT ROWID must be detected from the
// table-options clause only, never a literal in a default/CHECK (false positive)
// and still found when followed by another option like STRICT (false negative).
func TestDDLIsWithoutRowid(t *testing.T) {
	cases := []struct {
		ddl  string
		want bool
	}{
		{`CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT) WITHOUT ROWID`, true},
		{`CREATE TABLE t (a INT, b INT, PRIMARY KEY (a, b)) WITHOUT ROWID, STRICT`, true},
		{`CREATE TABLE t (a INT, b INT, PRIMARY KEY (a, b)) STRICT, WITHOUT ROWID`, true},
		{"CREATE TABLE t (id INTEGER PRIMARY KEY)\n  WITHOUT\n  ROWID", true},
		{`CREATE TABLE t (id INTEGER PRIMARY KEY, note TEXT DEFAULT 'WITHOUT ROWID')`, false},
		{`CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT CHECK (v <> 'WITHOUT ROWID'))`, false},
		// Theme H: a "WITHOUT ROWID" token inside a comment must not false-trip.
		{"CREATE TABLE t (id INTEGER PRIMARY KEY /* WITHOUT ROWID */)", false},
		{"CREATE TABLE t (id INTEGER PRIMARY KEY -- WITHOUT ROWID\n)", false},
		// 1.3: a comment TRAILING the column list (in the options tail) must
		// not false-trip either — the tail gets the same comment elision.
		{"CREATE TABLE t (id INTEGER PRIMARY KEY) /* WITHOUT ROWID */", false},
		{"CREATE TABLE t (id INTEGER PRIMARY KEY) -- WITHOUT ROWID", false},
		// ...while a real option still matches with a comment alongside.
		{"CREATE TABLE t (id INTEGER PRIMARY KEY) /* c */ WITHOUT ROWID", true},
		{`CREATE TABLE t (id INTEGER PRIMARY KEY)`, false},
		{``, false},
	}
	for _, c := range cases {
		if got := ddlIsWithoutRowid(c.ddl); got != c.want {
			t.Errorf("ddlIsWithoutRowid(%q) = %v, want %v", c.ddl, got, c.want)
		}
	}
}

// TestDDLHasInlinePKDesc covers: an inline "INTEGER PRIMARY KEY DESC" is not a
// rowid alias, while a table-level "PRIMARY KEY (col DESC)" is unaffected.
func TestDDLHasInlinePKDesc(t *testing.T) {
	cases := []struct {
		ddl  string
		want bool
	}{
		{`CREATE TABLE t (id INTEGER PRIMARY KEY DESC)`, true},
		{"CREATE TABLE t (id INTEGER PRIMARY  KEY\tDESC, v TEXT)", true},
		{`CREATE TABLE t (id INTEGER PRIMARY KEY)`, false},
		{`CREATE TABLE t (a INT, b INT, PRIMARY KEY (a DESC, b))`, false},
		{`CREATE TABLE t (id INTEGER PRIMARY KEY ASC)`, false},
		// False positives that the whole-DDL match used to trip on:
		{`CREATE TABLE t (id INTEGER PRIMARY KEY, note TEXT DEFAULT 'PRIMARY KEY DESC')`, false},   // literal default
		{`CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT CHECK (v <> 'PRIMARY KEY DESC'))`, false}, // CHECK literal
		{`CREATE TABLE "PRIMARY KEY DESCRIPTION" (id INTEGER PRIMARY KEY)`, false},                 // quoted table name
		{`CREATE TABLE t ("PRIMARY KEY DESC" INTEGER PRIMARY KEY)`, false},                         // quoted column name
		{`CREATE TABLE t (id INTEGER PRIMARY KEY DESCENDING)`, false},                              // DESC must be whole word
		// Theme H: a "PRIMARY KEY DESC" token inside a comment must not false-trip.
		{"CREATE TABLE t (id INTEGER PRIMARY KEY /* PRIMARY KEY DESC */, v TEXT)", false},
		{"CREATE TABLE t (id INTEGER PRIMARY KEY, -- PRIMARY KEY DESC\n v TEXT)", false},
	}
	for _, c := range cases {
		if got := ddlHasInlinePKDesc(c.ddl); got != c.want {
			t.Errorf("ddlHasInlinePKDesc(%q) = %v, want %v", c.ddl, got, c.want)
		}
	}
}

func TestSchemaPrefix(t *testing.T) {
	d := dialect{}
	if d.schemaPrefix("main") != "" || d.schemaPrefix("") != "" {
		t.Error("main/empty should have no prefix")
	}
	if d.schemaPrefix("attached") != `"attached".` {
		t.Errorf("schemaPrefix(attached) = %q", d.schemaPrefix("attached"))
	}
}

func TestSQLiteSchemaEditorSQL(t *testing.T) {
	d := dialect{}
	tr := driver.TableRef{Database: "main", Table: "items"}

	one := func(got []string, err error) string {
		t.Helper()
		if err != nil {
			t.Fatalf("builder error: %v", err)
		}
		if len(got) != 1 {
			t.Fatalf("expected 1 statement, got %d: %v", len(got), got)
		}
		return got[0]
	}

	cases := []struct{ name, got, want string }{
		{"add nullable", one(d.AddColumnSQL(tr, driver.ColumnSpec{Name: "note", Type: "TEXT", Nullable: true})),
			`ALTER TABLE "items" ADD COLUMN "note" TEXT`},
		{"add not null default", one(d.AddColumnSQL(tr, driver.ColumnSpec{Name: "n", Type: "INTEGER", Default: ptr("0")})),
			`ALTER TABLE "items" ADD COLUMN "n" INTEGER NOT NULL DEFAULT 0`},
		{"drop column", one(d.DropColumnSQL(tr, "note")),
			`ALTER TABLE "items" DROP COLUMN "note"`},
		{"add index", one(d.AddIndexSQL(tr, driver.IndexSpec{
			Name: "idx_ab", Columns: []driver.IndexColumn{{Name: "a"}, {Name: "b"}}})),
			`CREATE INDEX "idx_ab" ON "items" ("a", "b")`},
		{"add unique index", one(d.AddIndexSQL(tr, driver.IndexSpec{
			Name: "u", Columns: []driver.IndexColumn{{Name: "a"}}, Unique: true})),
			`CREATE UNIQUE INDEX "u" ON "items" ("a")`},
		// SQLite has DESC key parts and partial indexes, but no prefix lengths
		// and no access-method choice.
		{"add partial index desc", one(d.AddIndexSQL(tr, driver.IndexSpec{
			Name: "idx_w", Columns: []driver.IndexColumn{{Name: "a", Desc: true}}, Where: "a IS NOT NULL"})),
			`CREATE INDEX "idx_w" ON "items" ("a" DESC) WHERE a IS NOT NULL`},
		{"drop index", one(d.DropIndexSQL(tr, "idx_ab")),
			`DROP INDEX "idx_ab"`},
		// Adversarial identifier is quoted (double-quote doubled), not rejected.
		{"adversarial", one(d.DropColumnSQL(tr, `a"b`)),
			`ALTER TABLE "items" DROP COLUMN "a""b"`},
		// M6: DROP routes to DROP TABLE / DROP VIEW; RENAME uses ALTER TABLE for
		// both (SQLite renames views via ALTER TABLE ... RENAME TO, >=3.25).
		{"drop table", one(d.DropObjectSQL(tr, driver.ObjectTable)),
			`DROP TABLE "items"`},
		{"drop view", one(d.DropObjectSQL(tr, driver.ObjectView)),
			`DROP VIEW "items"`},
		{"rename view", one(d.RenameObjectSQL(tr, "renamed", driver.ObjectView)),
			`ALTER TABLE "items" RENAME TO "renamed"`},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s:\n got %q\nwant %q", c.name, c.got, c.want)
		}
	}
}

// TestSQLiteSchemaEditorUnsupported pins: column modification and
// foreign-key editing are absent from SQLite, and the way to say so is to not
// implement the interface. It used to say so with three methods that only ever
// returned an error, which duplicated what Capabilities already declares and
// meant every future engine had to carry the same stubs.
//
// The capability flag and the interface must agree in both directions, or the
// handler's gate and its type assertion would disagree about the same engine.
func TestSQLiteSchemaEditorUnsupported(t *testing.T) {
	var d driver.Dialect = dialect{}

	if _, ok := d.(driver.ColumnModifier); ok {
		t.Error("SQLite must not implement ColumnModifier: ALTER TABLE cannot redefine a column")
	}
	if _, ok := d.(driver.ForeignKeyEditor); ok {
		t.Error("SQLite must not implement ForeignKeyEditor: ALTER TABLE cannot add or drop a constraint")
	}
	caps := d.Capabilities()
	if caps.SupportsColumnModify {
		t.Error("SupportsColumnModify must stay false while ColumnModifier is unimplemented")
	}
	if caps.SupportsForeignKeyDDL {
		t.Error("SupportsForeignKeyDDL must stay false while ForeignKeyEditor is unimplemented")
	}
	// The rest of the editor is still there — this is a split, not a removal.
	if _, ok := d.(driver.SchemaEditor); !ok {
		t.Error("SQLite must still implement SchemaEditor")
	}
}

// TestSQLiteAddColumnGuards covers the value-only guards SQLite imposes on ADD
// COLUMN: a CURRENT_*/expression default and a NOT NULL column without a
// non-NULL default are both rejected by the (stateless) builder.
func TestSQLiteAddColumnGuards(t *testing.T) {
	d := dialect{}
	tr := driver.TableRef{Database: "main", Table: "items"}

	if _, err := d.AddColumnSQL(tr, driver.ColumnSpec{Name: "ts", Type: "DATETIME", Nullable: true, Default: ptr("CURRENT_TIMESTAMP")}); err == nil {
		t.Error("CURRENT_TIMESTAMP default should be rejected for ADD COLUMN")
	}
	if _, err := d.AddColumnSQL(tr, driver.ColumnSpec{Name: "e", Type: "TEXT", Nullable: true, Default: ptr("(1+1)")}); err == nil {
		t.Error("expression default should be rejected for ADD COLUMN")
	}
	if _, err := d.AddColumnSQL(tr, driver.ColumnSpec{Name: "x", Type: "TEXT", Nullable: false}); err == nil {
		t.Error("NOT NULL without a default should be rejected for ADD COLUMN")
	}
	if _, err := d.AddColumnSQL(tr, driver.ColumnSpec{Name: "x", Type: "TEXT", Nullable: false, Default: ptr("NULL")}); err == nil {
		t.Error("NOT NULL with a NULL default should be rejected for ADD COLUMN")
	}
}

// TestParseGeneratedExprs pins the DDL parser that recovers generated-column
// expressions PRAGMA table_xinfo does not expose: quoted identifiers, bracket
// names, nested parens and string literals containing commas/parens must all be
// handled, and a non-generated column must not appear.
func TestParseGeneratedExprs(t *testing.T) {
	ddl := `CREATE TABLE t(
		a INTEGER PRIMARY KEY,
		b INT,
		full_name TEXT GENERATED ALWAYS AS (a || ' ' || b) STORED,
		"weird,name" TEXT AS (substr(b, 1, 3)) VIRTUAL,
		[brk] TEXT AS (CASE WHEN a > 0 THEN 'x, (y)' ELSE b END),
		nested REAL GENERATED ALWAYS AS ((a + (b * 2)) / 3) VIRTUAL,
		plain TEXT DEFAULT 'AS (not a formula)'
	)`
	got := parseGeneratedExprs(ddl)
	want := map[string]string{
		"full_name":  "a || ' ' || b",
		"weird,name": "substr(b, 1, 3)",
		"brk":        "CASE WHEN a > 0 THEN 'x, (y)' ELSE b END",
		"nested":     "(a + (b * 2)) / 3",
	}
	if len(got) != len(want) {
		t.Fatalf("parseGeneratedExprs count = %d (%v), want %d", len(got), got, len(want))
	}
	for name, exp := range want {
		if got[name] != exp {
			t.Errorf("expr[%q] = %q, want %q", name, got[name], exp)
		}
	}
	if _, ok := got["plain"]; ok {
		t.Error("non-generated 'plain' column must not be reported as generated")
	}
}

// TestPartialIndexPredicate pins the WHERE-clause extraction for partial indexes:
// it must skip past the (possibly nested-paren) column list, return "" when no
// WHERE follows, and treat a ')' inside a string literal as data, not a paren
// close (blankSQLiteQuoted neutralizes quoted spans before the paren scan while
// the returned predicate is sliced from the ORIGINAL DDL).
func TestPartialIndexPredicate(t *testing.T) {
	cases := []struct{ ddl, want string }{
		{`CREATE INDEX i ON t (a, b) WHERE a > 0`, "a > 0"},
		{`CREATE INDEX i ON t (a) WHERE b IS NOT NULL AND c = 1`, "b IS NOT NULL AND c = 1"},
		{`CREATE INDEX i ON t (a)`, ""},                                          // no predicate
		{`CREATE UNIQUE INDEX i ON t (lower(name)) WHERE active`, "active"},      // nested parens in the column list
		{`CREATE INDEX i ON t (a) WHERE x = 'has ) paren'`, "x = 'has ) paren'"}, // ')' inside a literal is data
	}
	for _, c := range cases {
		if got := partialIndexPredicate(c.ddl); got != c.want {
			t.Errorf("partialIndexPredicate(%q) = %q, want %q", c.ddl, got, c.want)
		}
	}
}

// TestPartialIndexPredicateComments is the offset-desync half. The scan used to
// search an strings.ToUpper'd copy and then slice the ORIGINAL at the index it
// found, which only lines up while every byte folds to the same width — and
// comments were not neutralized at all, so the copy could carry a WHERE the
// statement does not have.
//
// The `want` column is what each case must return NOW. What each did BEFORE is
// in the comment beside it: those are the behaviours that had to stop, and no
// fixture covered any of them.
func TestPartialIndexPredicateComments(t *testing.T) {
	const head = `CREATE INDEX ix ON t(a) `
	for _, c := range []struct{ name, tail, want string }{
		// ToUpper GREW the copy (U+0250 → U+2C6F, 2 bytes → 3, five times), so
		// the computed start ran one byte past the end of the original: a panic.
		{"folding that grows", "/*ɐɐɐɐɐ*/ WHERE a>0", "a>0"},
		// ToUpper SHRANK it (U+017F → 'S', 2 bytes → 1, five times — exactly
		// len("WHERE")), so the start landed on the keyword and returned it as
		// part of the predicate. One 'ſ' returns "E a>0": wrong, but not this.
		{"folding that shrinks", "/*ſſſſſ*/ WHERE a>0", "a>0"},
		// The keyword was found INSIDE the word "somewhere", with no identifier
		// boundary required on either side.
		{"keyword inside a longer word", "/*somewhere*/ WHERE a>0", "a>0"},
		// An apostrophe in a comment opened a "string" that ran to end of input,
		// so the whole tail was blanked and the predicate vanished.
		{"apostrophe in a comment", "/* don't */ WHERE a>0", "a>0"},
		// The comment's own WHERE was found first, because comments were never
		// neutralized.
		{"keyword inside a comment", "/* WHERE x */ WHERE a>0", "a>0"},
		{"line comment before the clause", "-- note\n WHERE a>0", "a>0"},
		// Boundaries on BOTH sides: neither of these is the clause.
		{"no clause, only lookalikes", "/* x */ NOWHERE WHERECLAUSE", ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := partialIndexPredicate(head + c.tail); got != c.want {
				t.Errorf("partialIndexPredicate(%q) = %q, want %q", head+c.tail, got, c.want)
			}
		})
	}

	// The trap in the obvious fix: neutralizing comments in a pass of their own,
	// BEFORE quoted spans, elides from the `--` inside this literal to end of
	// input. That destroys the `))`, leaves no top-level close-paren, and returns
	// "" — a silent regression on a case that works today. The two must interleave.
	const inLiteral = `CREATE INDEX ix ON t(lower('a--b')) WHERE y > 0`
	if got := partialIndexPredicate(inLiteral); got != "y > 0" {
		t.Errorf("partialIndexPredicate(%q) = %q, want %q", inLiteral, got, "y > 0")
	}
	// And the mirror: a quote inside a block comment is comment text, not a
	// literal opener, so the `)` after it still closes the column list.
	const inComment = `CREATE INDEX ix ON t(a /* it's */) WHERE z = 1`
	if got := partialIndexPredicate(inComment); got != "z = 1" {
		t.Errorf("partialIndexPredicate(%q) = %q, want %q", inComment, got, "z = 1")
	}
}

// TestForeignKeysSyntheticName covers: PRAGMA foreign_key_list has no name
// column, so the dialect invents one for display and grouping. It exists
// nowhere in the schema, and presenting it like a real constraint name misled —
// Synthetic marks it so the UI can say so, and so nothing emits it into SQL.
func TestForeignKeysSyntheticName(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()
	ctx := context.Background()
	for _, s := range []string{
		`CREATE TABLE parent (id INTEGER PRIMARY KEY, code TEXT)`,
		`CREATE TABLE child (
			id INTEGER PRIMARY KEY,
			pid INTEGER REFERENCES parent(id) ON DELETE CASCADE,
			qid INTEGER REFERENCES parent(id)
		)`,
	} {
		if _, err := db.ExecContext(ctx, s); err != nil {
			t.Fatalf("seed %q: %v", s, err)
		}
	}

	fks, err := dialect{}.ForeignKeys(ctx, db, driver.TableRef{Table: "child"})
	if err != nil {
		t.Fatalf("ForeignKeys: %v", err)
	}
	if len(fks) != 2 {
		t.Fatalf("got %d foreign keys, want 2", len(fks))
	}
	for _, fk := range fks {
		if !fk.Synthetic {
			t.Errorf("foreign key %q is not marked synthetic, but SQLite never named it", fk.Name)
		}
		if fk.Name == "" {
			t.Error("a synthetic name is still needed for display and grouping")
		}
	}
}

// TestVariablesReportsUnreadablePragma covers the other half of: a PRAGMA
// this build does not implement returns NO ROW and is correctly omitted, but a
// read that FAILS used to be dropped just as silently — leaving no way to tell
// "no such setting" from "TableX could not read it".
func TestVariablesReportsUnreadablePragma(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	ctx := context.Background()
	vars, err := dialect{}.Variables(ctx, db)
	if err != nil {
		t.Fatalf("Variables: %v", err)
	}
	if len(vars) == 0 {
		t.Fatal("Variables returned nothing on a healthy database")
	}
	for _, v := range vars {
		if strings.HasPrefix(v.Value, "(unavailable") {
			t.Errorf("healthy database reported %s as unavailable: %s", v.Name, v.Value)
		}
	}

	// A closed pool makes every PRAGMA fail with a real error (not ErrNoRows),
	// which must now be reported rather than silently omitted.
	db.Close()
	vars, err = dialect{}.Variables(ctx, db)
	if err != nil {
		t.Fatalf("Variables on a closed pool: %v", err)
	}
	if len(vars) == 0 {
		t.Fatal("every failed PRAGMA was dropped silently")
	}
	for _, v := range vars {
		if !strings.HasPrefix(v.Value, "(unavailable") {
			t.Errorf("%s = %q on a closed pool, want an explicit unavailable marker", v.Name, v.Value)
		}
	}
}
