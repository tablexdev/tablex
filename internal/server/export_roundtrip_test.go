package server_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/tablexdev/tablex/internal/driver"
)

// TestSQLDumpRoundTrip is the WS-2 restore-equivalence acceptance test, run on
// SQLite (the engine the harness exercises without Docker; MySQL/PostgreSQL
// run the same flow in CI against live services). It builds a schema covering
// the known dump hazards — a cyclic FK pair, a self-referencing
// FK, a generated column, a view depending on another view, a trigger whose
// body holds multiple semicolon-separated statements and a CASE expression,
// unique/secondary indexes, BLOBs, and an AUTOINCREMENT counter ahead of its
// data — then exports a SQL dump, drops everything, re-imports the dump
// through the import endpoint, and asserts schema and data equality.
func TestSQLDumpRoundTrip(t *testing.T) {
	ts, client, dbPath := newTestServer(t)

	seedConn := inspectConn(t, dbPath)
	ctx := context.Background()
	for _, stmt := range []string{
		// Cyclic FK pair (a→b, b→a) — only restorable with FKs off — plus an
		// expression DEFAULT.
		`CREATE TABLE a (id INTEGER PRIMARY KEY, b_id INTEGER REFERENCES b(id), note TEXT DEFAULT ('n/a'))`,
		`CREATE TABLE b (id INTEGER PRIMARY KEY, a_id INTEGER REFERENCES a(id))`,
		// Self-referencing FK + STORED generated column + BLOB + AUTOINCREMENT.
		`CREATE TABLE emp (id INTEGER PRIMARY KEY AUTOINCREMENT, boss INTEGER REFERENCES emp(id),
			name TEXT NOT NULL, upper_name TEXT GENERATED ALWAYS AS (upper(name)) STORED, photo BLOB)`,
		`CREATE UNIQUE INDEX emp_name_u ON emp(name)`,
		`CREATE INDEX emp_boss_i ON emp(boss)`,
		`CREATE TABLE log (id INTEGER PRIMARY KEY, msg TEXT)`,
		// Trigger body with internal semicolons and a CASE ... END expression.
		`CREATE TRIGGER emp_audit AFTER INSERT ON emp BEGIN
			INSERT INTO log (msg) VALUES ('hired: ' || new.name);
			UPDATE log SET msg = msg || CASE WHEN new.boss IS NULL THEN ' (boss)' ELSE '' END
				WHERE id = (SELECT MAX(id) FROM log);
		END`,
		`CREATE VIEW v_emp AS SELECT id, name, upper_name FROM emp`,
		`CREATE VIEW v_emp2 AS SELECT name FROM v_emp WHERE id > 0`,
		// Data: FK-safe insertion order for the cycle (the dump itself need not
		// be order-safe — its preamble disables FK enforcement).
		`INSERT INTO a (id, b_id) VALUES (1, NULL)`,
		`INSERT INTO b (id, a_id) VALUES (1, 1)`,
		`UPDATE a SET b_id = 1 WHERE id = 1`,
		`INSERT INTO emp (boss, name, photo) VALUES (NULL, 'alice', X'00FF10')`,
		`INSERT INTO emp (boss, name, photo) VALUES (1, 'bob', NULL)`,
		// Push the AUTOINCREMENT counter ahead of the data.
		`INSERT INTO emp (boss, name) VALUES (1, 'temp')`,
		`DELETE FROM emp WHERE name = 'temp'`,
	} {
		if _, err := seedConn.Exec(ctx, stmt); err != nil {
			t.Fatalf("seed %q: %v", stmt, err)
		}
	}

	before := snapshotSchema(t, dbPath)
	beforeData := snapshotData(t, dbPath)
	if beforeData["sqlite_sequence"] == "" || !strings.Contains(beforeData["sqlite_sequence"], "emp|3") {
		t.Fatalf("seed expectation: emp AUTOINCREMENT counter should be 3 (ahead of max id 2), got %q", beforeData["sqlite_sequence"])
	}
	// Guard against a vacuous pass (L10): a swallowed query error in snapshotData
	// would drop a table from beforeData, which the comparison loop then never
	// checks. Require the seeded rows to actually be present before the round-trip.
	if !strings.Contains(beforeData["emp"], "alice") || !strings.Contains(beforeData["emp"], "bob") {
		t.Fatalf("before-snapshot missing seeded emp rows: %q", beforeData["emp"])
	}
	if !strings.Contains(beforeData["log"], "hired: alice") {
		t.Fatalf("before-snapshot missing seeded log rows: %q", beforeData["log"])
	}
	if beforeData["a"] == "" || beforeData["b"] == "" {
		t.Fatalf("before-snapshot missing seeded a/b rows: a=%q b=%q", beforeData["a"], beforeData["b"])
	}

	login(t, client, ts.URL)
	csrf := csrfFrom(t, client, ts.URL+"/")

	resp, err := client.PostForm(ts.URL+"/db/main/export", url.Values{
		"csrf_token": {csrf}, "format": {"sql"}, "structure": {"on"}, "data": {"on"}, "drop": {"on"},
	})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	dumpBytes, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("export status = %d: %s", resp.StatusCode, dumpBytes)
	}
	dump := string(dumpBytes)

	// Phase sanity: preamble, post-data triggers/indexes after the row data,
	// counter sync, and hex BLOBs.
	for _, want := range []string{
		"PRAGMA foreign_keys=OFF;",
		"CREATE TRIGGER emp_audit",
		"CREATE UNIQUE INDEX emp_name_u",
		"CREATE VIEW v_emp",
		"INSERT INTO sqlite_sequence (name, seq) VALUES ('emp', 3)",
		"X'00ff10'",
	} {
		if !strings.Contains(dump, want) {
			t.Fatalf("dump is missing %q:\n%s", want, dump)
		}
	}
	// Guard the anchors explicitly: a missing INSERT would make strings.Index
	// return -1 and the ordering check pass vacuously.
	ti, di := strings.Index(dump, "CREATE TRIGGER emp_audit"), strings.Index(dump, `INSERT INTO "emp"`)
	if ti < 0 || di < 0 {
		t.Fatalf("ordering anchors not found (trigger idx=%d, data idx=%d):\n%s", ti, di, dump)
	}
	if ti < di {
		t.Fatalf("trigger DDL must come after the data phase (or restored inserts re-fire it):\n%s", dump)
	}

	dropAll(t, dbPath)
	if left := snapshotSchema(t, dbPath); len(left) != 0 {
		t.Fatalf("teardown incomplete, %d objects remain: %v", len(left), left)
	}

	resp, err = client.PostForm(ts.URL+"/db/main/import", url.Values{
		"csrf_token": {csrf}, "format": {"sql"}, "sql_script": {dump},
	})
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	importBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("import status = %d", resp.StatusCode)
	}
	if strings.Contains(string(importBody), "tx-alert-error") {
		t.Fatalf("import reported statement errors:\n%s\n--- dump was ---\n%s", importBody, dump)
	}

	after := snapshotSchema(t, dbPath)
	for key, sql := range before {
		if after[key] != sql {
			t.Errorf("schema mismatch for %s:\n before %q\n after  %q", key, sql, after[key])
		}
	}
	for key := range after {
		if _, ok := before[key]; !ok {
			t.Errorf("unexpected object after restore: %s", key)
		}
	}
	afterData := snapshotData(t, dbPath)
	for table, rows := range beforeData {
		if afterData[table] != rows {
			t.Errorf("data mismatch in %s:\n before %q\n after  %q", table, rows, afterData[table])
		}
	}

	// The restored AUTOINCREMENT counter must continue ahead of the data: the
	// next hire gets id 3 (not a reused 3 from max(id)+1 == 3 ... which here
	// coincides; the sqlite_sequence assertion above is the strict check).
	if !strings.Contains(afterData["sqlite_sequence"], "emp|3") {
		t.Errorf("AUTOINCREMENT counter not restored: %q", afterData["sqlite_sequence"])
	}
}

// snapshotSchema returns the user-visible sqlite_master entries keyed by
// "type|name", with whitespace-normalized DDL as the value.
func snapshotSchema(t *testing.T, dbPath string) map[string]string {
	t.Helper()
	conn := inspectConn(t, dbPath)
	rs, err := conn.Query(context.Background(),
		`SELECT type, name, COALESCE(sql,'') FROM sqlite_master
		 WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name`, 1000)
	if err != nil {
		t.Fatalf("schema snapshot: %v", err)
	}
	out := make(map[string]string, len(rs.Rows))
	for _, row := range rs.Rows {
		out[row[0].Str+"|"+row[1].Str] = strings.Join(strings.Fields(row[2].Str), " ")
	}
	return out
}

// snapshotData renders each table's rows (ordered by id) plus the
// sqlite_sequence counters into comparable strings.
func snapshotData(t *testing.T, dbPath string) map[string]string {
	t.Helper()
	conn := inspectConn(t, dbPath)
	ctx := context.Background()
	out := map[string]string{}
	for _, table := range []string{"a", "b", "emp", "log", "widgets"} {
		var b strings.Builder
		// Stream (not Query): only the streaming path carries BLOB bytes, and the
		// snapshot must compare actual binary content, not the size placeholder.
		err := conn.Stream(ctx, fmt.Sprintf("SELECT * FROM %q ORDER BY id", table),
			func(_ []driver.ResultColumn, row []driver.Value) error {
				for i, v := range row {
					if i > 0 {
						b.WriteByte('|')
					}
					switch {
					case v.Null:
						b.WriteString("<null>")
					case v.Binary:
						fmt.Fprintf(&b, "blob:%x", v.Bytes)
					default:
						b.WriteString(v.Str)
					}
				}
				b.WriteByte('\n')
				return nil
			})
		if err != nil {
			// Tolerate a table that simply isn't present (defensive — a caller could
			// snapshot a partially-built DB), but never let a real query/scan failure
			// masquerade as "absent": that is how a vacuous pass hides. In this test
			// every listed table exists in both snapshots, so this continue is a
			// guard, not an expected path — the positive content check on the
			// before-snapshot (below) is what actually defeats a vacuous pass.
			if strings.Contains(err.Error(), "no such table") {
				continue
			}
			t.Fatalf("snapshot %s: %v", table, err)
		}
		out[table] = b.String()
	}
	if rs, err := conn.Query(ctx, "SELECT name, seq FROM sqlite_sequence ORDER BY name", 100); err == nil {
		var b strings.Builder
		for _, row := range rs.Rows {
			fmt.Fprintf(&b, "%s|%s\n", row[0].Str, row[1].Str)
		}
		out["sqlite_sequence"] = b.String()
	}
	return out
}

// dropAll removes every user object (triggers, views, tables) from the file.
// It runs on a single pinned connection so PRAGMA foreign_keys=OFF reliably
// applies to every DROP — the cyclic FK pair cannot be torn down otherwise.
func dropAll(t *testing.T, dbPath string) {
	t.Helper()
	d, _ := driver.Get("sqlite")
	ctx := context.Background()
	conn, err := driver.OpenPinned(ctx, d, driver.ConnParams{FilePath: dbPath})
	if err != nil {
		t.Fatalf("teardown open: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Exec(ctx, "PRAGMA foreign_keys=OFF"); err != nil {
		t.Fatalf("teardown pragma: %v", err)
	}
	for _, kind := range []string{"trigger", "view", "table"} {
		rs, err := conn.Query(ctx,
			"SELECT name FROM sqlite_master WHERE type = '"+kind+"' AND name NOT LIKE 'sqlite_%'", 1000)
		if err != nil {
			t.Fatalf("list %ss: %v", kind, err)
		}
		for _, row := range rs.Rows {
			if _, err := conn.Exec(ctx, fmt.Sprintf("DROP %s IF EXISTS %q", strings.ToUpper(kind), row[0].Str)); err != nil {
				t.Fatalf("drop %s %s: %v", kind, row[0].Str, err)
			}
		}
	}
}
