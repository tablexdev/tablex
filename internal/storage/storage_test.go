package storage_test

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tablexdev/tablex/internal/driver"
	"github.com/tablexdev/tablex/internal/storage"

	// The metadata store resolves its engine through the driver registry, so the
	// engines have to be registered — exactly as package main does.
	_ "github.com/tablexdev/tablex/internal/driver/mysql"
	_ "github.com/tablexdev/tablex/internal/driver/postgres"
	_ "github.com/tablexdev/tablex/internal/driver/sqlite"
)

// openTemp opens a metadata store on a fresh SQLite file under t.TempDir and
// returns it with the path, so a test can close and reopen the same database to
// stand in for a restart.
func openTemp(t *testing.T) (*storage.Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "meta.db")
	st := openAt(t, path)
	return st, path
}

func openAt(t *testing.T, path string) *storage.Store {
	t.Helper()
	st, err := storage.Open(context.Background(), storage.Config{Engine: "sqlite", FilePath: path})
	if err != nil {
		t.Fatalf("storage.Open(%s): %v", path, err)
	}
	// Closed with a defer-equivalent rather than left to the process: the SQLite
	// file lives under t.TempDir, whose cleanup cannot remove a file the pool
	// still holds open on Windows.
	t.Cleanup(func() { st.Close() })
	return st
}

// TestOpenCreatesTheFileAndSchema covers the whole first-run path: TableX is
// pointed at a path that does not exist, and comes back with a usable schema.
func TestOpenCreatesTheFileAndSchema(t *testing.T) {
	st, path := openTemp(t)

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("the metadata database was not created: %v", err)
	}
	if got := st.SchemaVersion(); got != 1 {
		t.Errorf("schema version = %d, want 1", got)
	}
	// The sessions table has to be real, not merely recorded as migrated.
	if _, err := st.DB().Exec("INSERT INTO " + st.Table(storage.SessionsTable) +
		" (" + st.Col("id") + ", " + st.Col("csrf") + ", " + st.Col("created") + ", " + st.Col("last_seen") + ")" +
		" VALUES ('a', 'b', 1, 2)"); err != nil {
		t.Errorf("the sessions table is not usable: %v", err)
	}
	if !strings.Contains(st.Describe(), "schema v1") {
		t.Errorf("Describe() = %q, want it to name the schema version", st.Describe())
	}
}

// TestOpenIsIdempotent is the restart case: the second Open must find the schema
// already there, leave the data alone, and not re-run anything.
func TestOpenIsIdempotent(t *testing.T) {
	st, path := openTemp(t)
	insert(t, st, "keep-me", "csrf", time.Now(), time.Now())
	if err := st.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	again := openAt(t, path)
	if got := again.SchemaVersion(); got != 1 {
		t.Errorf("schema version after reopen = %d, want 1", got)
	}
	if n := countSessions(t, again); n != 1 {
		t.Errorf("sessions after reopen = %d, want the row to have survived", n)
	}
}

// TestOpenRejectsAnAlienDatabase guards against being pointed at the wrong
// database. A bookkeeping table whose version is not a number means this is
// somebody else's schema, and silently "migrating" it would be destructive.
func TestOpenRejectsAnAlienDatabase(t *testing.T) {
	st, path := openTemp(t)
	if _, err := st.DB().Exec("UPDATE " + st.Table("meta") + " SET " + st.Col("v") + " = 'not-a-version'"); err != nil {
		t.Fatalf("corrupt the version row: %v", err)
	}
	st.Close()

	_, err := storage.Open(context.Background(), storage.Config{Engine: "sqlite", FilePath: path})
	if err == nil {
		t.Fatal("Open accepted a database whose schema version is not a version")
	}
	if !strings.Contains(err.Error(), "not a version number") {
		t.Errorf("error = %v, want it to explain that the version is unreadable", err)
	}
}

func TestOpenRejectsAnEngineThatCannotHostIt(t *testing.T) {
	_, err := storage.Open(context.Background(), storage.Config{Engine: "nosuchengine"})
	if err == nil || !strings.Contains(err.Error(), "unknown engine") {
		t.Errorf("unknown engine: err = %v, want it named as unknown", err)
	}
	// A missing parent directory stays a configuration error: TableX creates its
	// own file but never guesses where an operator meant to put it.
	_, err = storage.Open(context.Background(), storage.Config{
		Engine:   "sqlite",
		FilePath: filepath.Join(t.TempDir(), "no", "such", "dir", "meta.db"),
	})
	if err == nil {
		t.Error("Open created a metadata database inside a directory that does not exist")
	}
}

// TestEveryEngineCanTypeTheSchema is the reason driver.StorageHost exists: the
// schema must be expressible on every engine, not just the one the unit tests
// use. It checks the type vocabulary rather than executing DDL, so it runs
// without a live MySQL or PostgreSQL.
func TestEveryEngineCanTypeTheSchema(t *testing.T) {
	for _, d := range driver.All() {
		h, ok := d.(driver.StorageHost)
		if !ok {
			continue // an engine may decline to host the store
		}
		ddl := h.StorageDDL()
		for name, val := range map[string]string{"ID": ddl.ID, "Text": ddl.Text, "Int64": ddl.Int64} {
			if strings.TrimSpace(val) == "" {
				t.Errorf("%s: StorageDDL().%s is empty", d.Name(), name)
			}
		}
		// The options string is concatenated straight after the closing paren of
		// a CREATE TABLE, so a non-empty value that does not start with a space
		// would produce "…)ENGINE=InnoDB".
		if o := ddl.TableOptions; o != "" && !strings.HasPrefix(o, " ") {
			t.Errorf("%s: StorageDDL().TableOptions = %q, which must begin with a space", d.Name(), o)
		}
	}
}

func TestValidTablePrefix(t *testing.T) {
	for _, c := range []struct {
		in, want string
		ok       bool
	}{
		{"", storage.DefaultTablePrefix, true},
		{"tablex_", "tablex_", true},
		{"  tx_  ", "tx_", true},
		{"_private", "_private", true},
		{"Mixed9_", "Mixed9_", true},
		{"9leading", "", false},
		{`"; DROP TABLE x; --`, "", false},
		{"has space", "", false},
		{"back`tick", "", false},
		{"dot.ted", "", false},
		{strings.Repeat("x", 33), "", false},
	} {
		got, err := storage.ValidTablePrefix(c.in)
		if c.ok && err != nil {
			t.Errorf("ValidTablePrefix(%q) = error %v, want %q", c.in, err, c.want)
			continue
		}
		if !c.ok {
			if err == nil {
				t.Errorf("ValidTablePrefix(%q) = %q, want it refused", c.in, got)
			}
			continue
		}
		if got != c.want {
			t.Errorf("ValidTablePrefix(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestTablePrefixIsHonoured is the point of the setting: two stores on the same
// database must not collide.
func TestTablePrefixIsHonoured(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shared.db")
	one, err := storage.Open(context.Background(), storage.Config{Engine: "sqlite", FilePath: path, TablePrefix: "one_"})
	if err != nil {
		t.Fatalf("open one: %v", err)
	}
	defer one.Close()
	two, err := storage.Open(context.Background(), storage.Config{Engine: "sqlite", FilePath: path, TablePrefix: "two_"})
	if err != nil {
		t.Fatalf("open two: %v", err)
	}
	defer two.Close()

	if one.Table(storage.SessionsTable) == two.Table(storage.SessionsTable) {
		t.Fatal("both prefixes resolved to the same table name")
	}
	insert(t, one, "only-in-one", "c", time.Now(), time.Now())
	if n := countSessions(t, one); n != 1 {
		t.Errorf("prefix one_ sessions = %d, want 1", n)
	}
	if n := countSessions(t, two); n != 0 {
		t.Errorf("prefix two_ sessions = %d, want 0 — the prefixes are sharing a table", n)
	}
}

func TestMicrosRoundTrip(t *testing.T) {
	// Deliberately not a whole second, and deliberately with a nanosecond
	// remainder: the schema stores microseconds, so the round trip must keep the
	// microseconds and drop only what it says it drops.
	in := time.Date(2026, 7, 30, 14, 3, 2, 123456789, time.UTC)
	got := storage.FromMicros(storage.Micros(in))
	if want := in.Truncate(time.Microsecond); !got.Equal(want) {
		t.Errorf("round trip = %v, want %v", got, want)
	}
	if got.Location() != time.UTC {
		t.Errorf("round trip location = %v, want UTC", got.Location())
	}
	// An instant read back through the database, not just through the helpers.
	st, _ := openTemp(t)
	insert(t, st, "id", "csrf", in, in)
	var created int64
	if err := st.DB().QueryRow("SELECT " + st.Col("created") + " FROM " + st.Table(storage.SessionsTable)).Scan(&created); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !storage.FromMicros(created).Equal(in.Truncate(time.Microsecond)) {
		t.Errorf("stored instant = %v, want %v", storage.FromMicros(created), in)
	}
}

// --- helpers ------------------------------------------------------------------

func insert(t *testing.T, st *storage.Store, id, csrf string, created, lastSeen time.Time) {
	t.Helper()
	_, err := st.DB().Exec("INSERT INTO "+st.Table(storage.SessionsTable)+
		" ("+st.Col("id")+", "+st.Col("csrf")+", "+st.Col("created")+", "+st.Col("last_seen")+")"+
		" VALUES ("+st.Placeholder(1)+", "+st.Placeholder(2)+", "+st.Placeholder(3)+", "+st.Placeholder(4)+")",
		id, csrf, storage.Micros(created), storage.Micros(lastSeen))
	if err != nil {
		t.Fatalf("insert %s: %v", id, err)
	}
}

func countSessions(t *testing.T, st *storage.Store) int {
	t.Helper()
	var n int
	if err := st.DB().QueryRow("SELECT COUNT(*) FROM " + st.Table(storage.SessionsTable)).Scan(&n); err != nil {
		if err == sql.ErrNoRows {
			return 0
		}
		t.Fatalf("count: %v", err)
	}
	return n
}
