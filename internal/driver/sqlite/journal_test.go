package sqlite

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tablexdev/tablex/internal/driver"
)

// openViaDialect dials a fresh temp database file through the dialect's own
// BuildDSN, so the test exercises exactly the DSN production builds.
func openViaDialect(t *testing.T, params map[string]string) *sql.DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "journal.db")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("create temp db file: %v", err)
	}
	dsn, err := dialect{}.BuildDSN(driver.ConnParams{FilePath: path, Params: params})
	if err != nil {
		t.Fatalf("BuildDSN: %v", err)
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func journalMode(t *testing.T, db *sql.DB) string {
	t.Helper()
	var mode string
	if err := db.QueryRowContext(context.Background(), "PRAGMA journal_mode").Scan(&mode); err != nil {
		t.Fatalf("PRAGMA journal_mode: %v", err)
	}
	return strings.ToLower(mode)
}

// TestSQLiteJournalModeWAL covers: TableX serves many concurrent requests
// against one SQLite file, and under the default rollback journal a writer
// blocks every reader — so a browse running alongside an import surfaces
// "database is locked" even with busy_timeout waiting. WAL is the mode that
// workload needs.
func TestSQLiteJournalModeWAL(t *testing.T) {
	db := openViaDialect(t, nil)
	if got := journalMode(t, db); got != "wal" {
		t.Errorf("journal_mode = %q, want wal", got)
	}
}

// TestSQLiteJournalModeOverride pins the escape hatch: journal_mode is persisted
// in the database header, so an operator must be able to decline WAL. The
// operator's value wins because BuildDSN SUPPRESSES its own default when the
// params carry a journal_mode (hasJournalModePragma) — so only the operator's is
// emitted. It does NOT rely on ordering: modernc sorts the _pragma list, and
// "wal" would otherwise sort last and win (see TestSQLitePragmaOrderIsSorted).
func TestSQLiteJournalModeOverride(t *testing.T) {
	db := openViaDialect(t, map[string]string{"_pragma": "journal_mode(DELETE)"})
	if got := journalMode(t, db); got != "delete" {
		t.Errorf("journal_mode with an operator override = %q, want delete", got)
	}
}

// TestSQLitePragmaOrderIsSorted pins the modernc v1.56.0 behavior BuildDSN's WAL
// default relies on. The driver does NOT apply repeated _pragma values in DSN
// order — neither the first nor the last in the DSN wins. It SORTS the _pragma
// list (busy_timeout first, then case-insensitive lexicographic) and executes in
// that order, so for a repeated journal_mode the lexicographically-LARGEST value
// wins. "wal" is the largest standard mode, so an emitted default WAL would
// override ANY operator journal_mode — which is exactly why BuildDSN must
// SUPPRESS its default when the operator set one (hasJournalModePragma) rather
// than rely on ordering. Both DSN orders below therefore resolve to WAL; a
// first-wins driver would give delete then wal, a last-wins driver wal then
// delete — this test fails under either of those models.
func TestSQLitePragmaOrderIsSorted(t *testing.T) {
	for i, dsnPragmas := range []string{
		"_pragma=journal_mode(delete)&_pragma=journal_mode(wal)",
		"_pragma=journal_mode(wal)&_pragma=journal_mode(delete)",
	} {
		// A distinct file per case: journal_mode WAL persists in the database
		// header, so reusing one file would carry the first case's mode into the
		// second and mask a real ordering difference.
		path := filepath.Join(t.TempDir(), "order.db")
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatalf("create db file: %v", err)
		}
		db, err := sql.Open("sqlite", path+"?"+dsnPragmas)
		if err != nil {
			t.Fatalf("open %d: %v", i, err)
		}
		mode := journalMode(t, db)
		db.Close()
		if mode != "wal" {
			t.Errorf("DSN order %q → journal_mode=%q; modernc sorts _pragma values, so wal must win regardless of DSN order", dsnPragmas, mode)
		}
	}
}

// TestSQLiteMemoryDSNSkipsWAL: an in-memory database has no journal to switch,
// and the pragma must not appear in a DSN whose path already carries a query
// string.
func TestSQLiteMemoryDSNSkipsWAL(t *testing.T) {
	dsn, err := dialect{}.BuildDSN(driver.ConnParams{FilePath: ":memory:"})
	if err != nil {
		t.Fatalf("BuildDSN(:memory:): %v", err)
	}
	if strings.Contains(dsn, "journal_mode") {
		t.Errorf("in-memory DSN carries a journal_mode pragma: %s", dsn)
	}
	// The two session pragmas are still there.
	for _, want := range []string{"busy_timeout", "foreign_keys"} {
		if !strings.Contains(dsn, want) {
			t.Errorf("in-memory DSN lost the %s pragma: %s", want, dsn)
		}
	}
}

// TestSQLiteConcurrentReadDuringWrite is the behavioural half: with WAL a
// reader must succeed while another connection holds a write transaction. Under
// the old rollback journal this returned SQLITE_BUSY once busy_timeout expired.
func TestSQLiteConcurrentReadDuringWrite(t *testing.T) {
	db := openViaDialect(t, nil)
	ctx := context.Background()
	if _, err := db.ExecContext(ctx, "CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)"); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := db.ExecContext(ctx, "INSERT INTO t VALUES (1, 'a')"); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// Hold an open write transaction on one connection...
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, "INSERT INTO t VALUES (2, 'b')"); err != nil {
		t.Fatalf("write in tx: %v", err)
	}

	// ...and read from another. Same file, same pool, different connection.
	var n int
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM t").Scan(&n); err != nil {
		t.Fatalf("concurrent read during an open write transaction: %v", err)
	}
	if n != 1 {
		t.Errorf("reader saw %d rows, want 1 (the uncommitted row must not be visible)", n)
	}
}
