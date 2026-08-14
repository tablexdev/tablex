package driver_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tablexdev/tablex/internal/driver"
	_ "github.com/tablexdev/tablex/internal/driver/sqlite"
)

// openTempSQLite spins up a real, pure-Go SQLite database in a temp file and
// seeds a couple of related tables. SQLite needs no Docker, so this exercises
// the full Connection + Dialect + result-scanning path in a unit test.
func openTempSQLite(t *testing.T) *driver.Connection {
	t.Helper()
	d, ok := driver.Get("sqlite")
	if !ok {
		t.Fatal("sqlite dialect not registered")
	}
	path := filepath.Join(t.TempDir(), "tablex_test.db")
	// BuildDSN no longer auto-creates a missing database file; pre-create an
	// empty one (a zero-byte file is a valid empty SQLite database).
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("create temp db file: %v", err)
	}
	conn, err := driver.Open(context.Background(), d, driver.ConnParams{FilePath: path})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	ctx := context.Background()
	stmts := []string{
		`CREATE TABLE authors (
			id INTEGER PRIMARY KEY,
			name TEXT NOT NULL,
			email TEXT
		)`,
		`CREATE TABLE books (
			id INTEGER PRIMARY KEY,
			title TEXT NOT NULL,
			author_id INTEGER NOT NULL REFERENCES authors(id) ON DELETE CASCADE,
			price NUMERIC(8,2) DEFAULT 0
		)`,
		`CREATE INDEX idx_books_author ON books(author_id)`,
		`INSERT INTO authors (name, email) VALUES ('Ada Lovelace', 'ada@example.com')`,
		`INSERT INTO authors (name, email) VALUES ('Alan Turing', NULL)`,
		`INSERT INTO books (title, author_id, price) VALUES ('Notes', 1, 9.99)`,
	}
	for _, s := range stmts {
		if _, err := conn.Exec(ctx, s); err != nil {
			t.Fatalf("seed exec %q: %v", s, err)
		}
	}
	return conn
}

func TestSQLiteServerInfo(t *testing.T) {
	conn := openTempSQLite(t)
	info := conn.Info()
	if info.Engine != "sqlite" || info.Flavor != "SQLite" {
		t.Errorf("unexpected server info: %+v", info)
	}
	if info.Version == "" {
		t.Error("expected a non-empty sqlite version")
	}
}

func TestSQLiteListTablesAndColumns(t *testing.T) {
	conn := openTempSQLite(t)
	ctx := context.Background()

	tables, err := conn.ListTables(ctx, driver.Scope{Database: "main"})
	if err != nil {
		t.Fatalf("list tables: %v", err)
	}
	if len(tables) != 2 {
		t.Fatalf("expected 2 tables, got %d (%+v)", len(tables), tables)
	}

	cols, err := conn.Columns(ctx, driver.TableRef{Database: "main", Table: "books"})
	if err != nil {
		t.Fatalf("columns: %v", err)
	}
	if len(cols) != 4 {
		t.Fatalf("expected 4 columns, got %d", len(cols))
	}
	if !cols[0].IsPrimaryKey || !cols[0].IsAutoIncrement {
		t.Errorf("books.id should be PK + autoincrement rowid: %+v", cols[0])
	}
	if cols[1].Nullable {
		t.Errorf("books.title should be NOT NULL")
	}
	if !cols[3].IsNumeric() {
		t.Errorf("books.price should be numeric, base type %q", cols[3].BaseType)
	}
}

func TestSQLiteIndexesAndForeignKeys(t *testing.T) {
	conn := openTempSQLite(t)
	ctx := context.Background()
	ref := driver.TableRef{Database: "main", Table: "books"}

	idx, err := conn.Indexes(ctx, ref)
	if err != nil {
		t.Fatalf("indexes: %v", err)
	}
	var havePrimary, haveAuthorIdx bool
	for _, i := range idx {
		if i.Primary {
			havePrimary = true
		}
		if i.Name == "idx_books_author" {
			haveAuthorIdx = true
		}
	}
	if !havePrimary {
		t.Error("expected a synthesized PRIMARY index")
	}
	if !haveAuthorIdx {
		t.Error("expected idx_books_author index")
	}

	fks, err := conn.ForeignKeys(ctx, ref)
	if err != nil {
		t.Fatalf("fks: %v", err)
	}
	if len(fks) != 1 {
		t.Fatalf("expected 1 FK, got %d", len(fks))
	}
	if fks[0].RefTable != "authors" || fks[0].OnDelete != "CASCADE" {
		t.Errorf("unexpected FK: %+v", fks[0])
	}
}

func TestSQLiteBrowseAndCount(t *testing.T) {
	conn := openTempSQLite(t)
	ctx := context.Background()
	ref := driver.TableRef{Database: "main", Table: "authors"}

	n, err := conn.CountRows(ctx, ref)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 2 {
		t.Fatalf("expected 2 authors, got %d", n)
	}

	rs, err := conn.Browse(ctx, ref, driver.Pagination{Limit: 10}, []driver.Sort{{Column: "name", Descending: false}})
	if err != nil {
		t.Fatalf("browse: %v", err)
	}
	if len(rs.Rows) != 2 {
		t.Fatalf("expected 2 rows, got %d", len(rs.Rows))
	}
	// Sorted ascending by name: "Ada Lovelace" first.
	if rs.Rows[0][1].Str != "Ada Lovelace" {
		t.Errorf("expected Ada first, got %q", rs.Rows[0][1].Str)
	}
	// Turing's email is NULL.
	if !rs.Rows[1][2].Null {
		t.Errorf("expected NULL email for second author, got %+v", rs.Rows[1][2])
	}
}

// TestSQLiteEstimateRows covers the Theme K estimator: -1 before ANALYZE (no
// sqlite_stat1), then the statistics-based estimate afterward.
func TestSQLiteEstimateRows(t *testing.T) {
	conn := openTempSQLite(t)
	ctx := context.Background()
	ref := driver.TableRef{Database: "main", Table: "authors"}

	// No sqlite_stat1 yet → -1 (caller falls back to an exact count).
	if n, err := conn.EstimateRows(ctx, ref); err != nil || n != -1 {
		t.Fatalf("pre-ANALYZE EstimateRows = %d,%v; want -1,nil", n, err)
	}
	if _, err := conn.Exec(ctx, "ANALYZE"); err != nil {
		t.Fatalf("ANALYZE: %v", err)
	}
	if n, err := conn.EstimateRows(ctx, ref); err != nil || n != 2 {
		t.Errorf("post-ANALYZE EstimateRows = %d,%v; want 2,nil", n, err)
	}
}

// TestSQLiteEstimateRowsIgnoresAPartialIndexCount: sqlite_stat1 holds one row
// per INDEX, and a PARTIAL index's row counts only the rows its WHERE matches.
// Reading whichever row came first therefore reported the partial index's count
// as the table's — and a small estimate is precisely what makes the caller run
// the exact COUNT(*) this estimator exists to avoid, on every render.
//
// Both index creation orders are covered because ANALYZE decides the physical
// order of those rows, not this test: it currently writes them in REVERSE
// creation order, so only the table whose partial index was created LAST puts
// the misleading row first today. Pinning one order would leave the test
// passing for the wrong reason the moment SQLite changed that, which is exactly
// what a first draft of this test did.
func TestSQLiteEstimateRowsIgnoresAPartialIndexCount(t *testing.T) {
	conn := openTempSQLite(t)
	ctx := context.Background()

	// 40 rows per table, of which 3 are flagged.
	var values []string
	for i := range 40 {
		flagged := 0
		if i < 3 {
			flagged = 1
		}
		values = append(values, fmt.Sprintf("(%d, 'row')", flagged))
	}
	rows := strings.Join(values, ",")

	for _, tc := range []struct{ name, table, first, second string }{
		{"partial index created first", "readings_pf",
			`CREATE INDEX pf_flagged ON readings_pf (v) WHERE flagged = 1`,
			`CREATE INDEX pf_all ON readings_pf (v)`},
		{"partial index created last", "readings_pl",
			`CREATE INDEX pl_all ON readings_pl (v)`,
			`CREATE INDEX pl_flagged ON readings_pl (v) WHERE flagged = 1`},
	} {
		for _, stmt := range []string{
			`CREATE TABLE ` + tc.table + ` (id INTEGER PRIMARY KEY, flagged INTEGER NOT NULL, v TEXT)`,
			tc.first, tc.second,
			`INSERT INTO ` + tc.table + ` (flagged, v) VALUES ` + rows,
		} {
			if _, err := conn.Exec(ctx, stmt); err != nil {
				t.Fatalf("%s: seed %q: %v", tc.name, stmt, err)
			}
		}
	}
	if _, err := conn.Exec(ctx, "ANALYZE"); err != nil {
		t.Fatalf("ANALYZE: %v", err)
	}

	for _, tc := range []struct{ name, table string }{
		{"partial index created first", "readings_pf"},
		{"partial index created last", "readings_pl"},
	} {
		n, err := conn.EstimateRows(ctx, driver.TableRef{Database: "main", Table: tc.table})
		if err != nil {
			t.Fatalf("%s: EstimateRows: %v", tc.name, err)
		}
		if n != 40 {
			t.Errorf("%s: EstimateRows = %d, want 40 — the partial index covers only 3 rows and must not stand in for the table's count", tc.name, n)
		}
	}
}

func TestSQLiteCreateSQL(t *testing.T) {
	conn := openTempSQLite(t)
	ctx := context.Background()
	ddl, err := conn.CreateSQL(ctx, driver.TableRef{Database: "main", Table: "authors"})
	if err != nil {
		t.Fatalf("create sql: %v", err)
	}
	if ddl == "" {
		t.Fatal("expected non-empty DDL")
	}
}

// TestSeedDemoDB writes a persistent demo database to $TABLEX_TEST_SEED_DB
// when set, for manual/smoke testing of the running server. It is a no-op
// (skip) in normal test runs. The TABLEX_TEST_ prefix keeps it inside the
// unknown-variable sweep's test carve-out, so leaving it exported does not
// stop a real binary from starting.
func TestSeedDemoDB(t *testing.T) {
	path := os.Getenv("TABLEX_TEST_SEED_DB")
	if path == "" {
		t.Skip("set TABLEX_TEST_SEED_DB to seed a demo database")
	}
	d, _ := driver.Get("sqlite")
	// Ensure the file exists without truncating an existing demo database
	// (BuildDSN no longer auto-creates a missing file).
	if f, err := os.OpenFile(path, os.O_CREATE, 0o600); err != nil {
		t.Fatalf("touch seed db: %v", err)
	} else {
		f.Close()
	}
	conn, err := driver.Open(context.Background(), d, driver.ConnParams{FilePath: path})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer conn.Close()
	ctx := context.Background()
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS authors (id INTEGER PRIMARY KEY, name TEXT NOT NULL, email TEXT, born INTEGER)`,
		`CREATE TABLE IF NOT EXISTS books (id INTEGER PRIMARY KEY, title TEXT NOT NULL,
			author_id INTEGER NOT NULL REFERENCES authors(id) ON DELETE CASCADE,
			price NUMERIC(8,2) DEFAULT 0, published TEXT)`,
		`CREATE INDEX IF NOT EXISTS idx_books_author ON books(author_id)`,
		`CREATE VIEW IF NOT EXISTS pricey AS SELECT title, price FROM books WHERE price > 10`,
	}
	for _, s := range stmts {
		if _, err := conn.Exec(ctx, s); err != nil {
			t.Fatalf("seed %q: %v", s, err)
		}
	}
	db := conn.DB()
	for _, s := range []string{
		`DELETE FROM books`,
		`DELETE FROM authors`,
		`INSERT INTO authors (id, name, email, born) VALUES (1,'Ada Lovelace','ada@example.com',1815)`,
		`INSERT INTO authors (id, name, email, born) VALUES (2,'Alan Turing',NULL,1912)`,
		`INSERT INTO authors (id, name, email, born) VALUES (3,'Grace Hopper','grace@example.com',1906)`,
	} {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("seed %q: %v", s, err)
		}
	}
	for i := 1; i <= 60; i++ {
		if _, err := db.Exec(`INSERT INTO books (title, author_id, price, published) VALUES (?, ?, ?, ?)`,
			fmt.Sprintf("Sample Book %02d", i), (i%3)+1, float64(i)*1.25, fmt.Sprintf("20%02d-01-15", i%30)); err != nil {
			t.Fatalf("insert book: %v", err)
		}
	}
	t.Logf("seeded demo database at %s", path)
}

func TestSQLiteRejectsBadSortColumn(t *testing.T) {
	conn := openTempSQLite(t)
	ctx := context.Background()
	// The DEL case pins the 4.3 hardening: sort columns share
	// HasUnsafeIdentifierRune's reject set and now refuse 0x7f too.
	for _, col := range []string{"name; DROP TABLE authors", "name\x7f"} {
		_, err := conn.Browse(ctx, driver.TableRef{Database: "main", Table: "authors"},
			driver.Pagination{Limit: 10}, []driver.Sort{{Column: col}})
		if err == nil {
			t.Fatalf("expected Browse to reject unsafe sort column %q", col)
		}
	}
}

// TestExecCommentOnlyNoPanic pins the nil-result guard: modernc.org/sqlite
// returns a nil driver.Result for input that compiles to no statement (a
// comment-only script), and database/sql's wrapper panics in RowsAffected /
// LastInsertId on it. Connection.Exec must absorb that, not crash the handler.
func TestExecCommentOnlyNoPanic(t *testing.T) {
	conn := openTempSQLite(t)
	ctx := context.Background()
	reached := 0
	for _, stmt := range []string{"-- nothing here", "/* still nothing */", "  "} {
		res, err := conn.Exec(ctx, stmt)
		if err != nil {
			// An engine rejecting empty input with an error is fine; panicking is not.
			continue
		}
		reached++
		if res.RowsAffected != 0 {
			t.Errorf("Exec(%q) = %+v, want zero ExecResult", stmt, res)
		}
	}
	// At least one comment-only input must reach the nil-result guard, or the
	// zero-ExecResult assertion above never actually ran (vacuous pass).
	if reached == 0 {
		t.Fatal("no comment-only input reached the nil-result guard")
	}
}

// TestPinnedSessionStateSticks proves the Pinned contract: every statement
// runs on the same physical connection, so connection-scoped state (a TEMP
// table here, standing in for SET/PRAGMA import preambles) is visible to
// later statements and disappears when the Pinned connection is closed.
func TestPinnedSessionStateSticks(t *testing.T) {
	d, ok := driver.Get("sqlite")
	if !ok {
		t.Fatal("sqlite dialect not registered")
	}
	file := filepath.Join(t.TempDir(), "pinned_test.db")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatalf("create db file: %v", err)
	}
	ctx := context.Background()
	pinned, err := driver.OpenPinned(ctx, d, driver.ConnParams{FilePath: file})
	if err != nil {
		t.Fatalf("open pinned: %v", err)
	}
	if pinned.Engine() != "sqlite" {
		t.Errorf("Engine() = %q, want sqlite", pinned.Engine())
	}
	if _, err := pinned.Exec(ctx, "CREATE TEMP TABLE scratch (x INT)"); err != nil {
		t.Fatalf("create temp: %v", err)
	}
	if _, err := pinned.Exec(ctx, "INSERT INTO scratch VALUES (1)"); err != nil {
		t.Fatalf("insert temp: %v", err)
	}
	rs, err := pinned.Query(ctx, "SELECT COUNT(*) FROM scratch", 1)
	if err != nil {
		t.Fatalf("query temp: %v", err)
	}
	if rs.Rows[0][0].Str != "1" {
		t.Errorf("temp table not visible on pinned connection: %+v", rs.Rows)
	}
	if err := pinned.Close(); err != nil {
		t.Fatalf("close pinned: %v", err)
	}

	// After Close the session (and its temp state) is gone: a fresh connection
	// must not see the temp table.
	fresh, err := driver.Open(ctx, d, driver.ConnParams{FilePath: file})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer fresh.Close()
	if _, err := fresh.Query(ctx, "SELECT COUNT(*) FROM scratch", 1); err == nil {
		t.Error("temp table leaked past Pinned.Close into a fresh connection")
	}
}

// TestSQLiteTableCountCountsViews is a regression test for
// model.Database.TableCount. SQLite's ListTables returns tables AND views, but
// its ListDatabases counted only type='table' — so a database with a view
// reported a smaller number on the databases page than the number of rows its
// structure page went on to show.
func TestSQLiteTableCountCountsViews(t *testing.T) {
	conn := openTempSQLite(t)
	ctx := context.Background()
	if _, err := conn.Exec(ctx, `CREATE VIEW author_names AS SELECT name FROM authors`); err != nil {
		t.Fatalf("create view: %v", err)
	}

	tables, err := conn.ListTables(ctx, driver.Scope{Database: "main"})
	if err != nil {
		t.Fatalf("ListTables: %v", err)
	}
	listed := 0
	views := 0
	for _, tb := range tables {
		if tb.IsSequence() {
			continue // the structure page skips these
		}
		listed++
		if tb.IsView() {
			views++
		}
	}
	if views == 0 {
		t.Fatal("no view in the listing; this test no longer discriminates")
	}

	dbs, err := conn.ListDatabases(ctx)
	if err != nil {
		t.Fatalf("ListDatabases: %v", err)
	}
	for _, d := range dbs {
		if d.Name != "main" {
			continue
		}
		if d.TableCount != listed {
			t.Fatalf("TableCount = %d but the structure page lists %d relations (%d of them views)",
				d.TableCount, listed, views)
		}
		return
	}
	t.Fatal(`"main" is not in ListDatabases`)
}
