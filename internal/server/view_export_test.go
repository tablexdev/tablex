package server_test

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// TestTableScopeViewExportEmitsViewDDL pins V1: a table-scope SQL export whose
// target is a VIEW must emit the view's own CREATE VIEW (plus a DROP VIEW on a
// drop-first export and its INSTEAD OF trigger), NOT a physical CREATE TABLE
// snapshot with row INSERTs. Before the fix SQLite's DumpTableCreate errored on
// the view; PostgreSQL emitted a table snapshot with INSERTs.
func TestTableScopeViewExportEmitsViewDDL(t *testing.T) {
	ts, client, dbPath := newTestServer(t)
	login(t, client, ts.URL)
	csrf := csrfFrom(t, client, ts.URL+"/")

	ctx := context.Background()
	conn := inspectConn(t, dbPath)
	for _, stmt := range []string{
		`CREATE TABLE base (id INTEGER PRIMARY KEY, name TEXT)`,
		`INSERT INTO base (id, name) VALUES (1, 'alpha'), (2, 'beta')`,
		`CREATE VIEW v_names AS SELECT id, name FROM base`,
		// An INSTEAD OF trigger makes the view updatable; it must survive the dump
		// (its tbl_name is the view, so a plain table scan would miss it).
		`CREATE TRIGGER v_ins INSTEAD OF INSERT ON v_names BEGIN INSERT INTO base(id,name) VALUES (NEW.id, NEW.name); END`,
	} {
		if _, err := conn.Exec(ctx, stmt); err != nil {
			t.Fatalf("seed %q: %v", stmt, err)
		}
	}

	resp, err := client.PostForm(ts.URL+"/db/main/table/v_names/export", url.Values{
		"csrf_token": {csrf}, "format": {"sql"}, "structure": {"1"}, "data": {"1"}, "drop": {"1"},
	})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("export = %d:\n%s", resp.StatusCode, body)
	}
	dump := string(body)

	if !strings.Contains(dump, "CREATE VIEW") || !strings.Contains(dump, "v_names") {
		t.Errorf("dump missing CREATE VIEW v_names:\n%s", dump)
	}
	// The view must NOT be dumped as a physical table, and its rows must NOT be
	// INSERTed (a view has no rows of its own).
	if strings.Contains(dump, "CREATE TABLE") {
		t.Errorf("view export wrongly emitted a physical CREATE TABLE:\n%s", dump)
	}
	if strings.Contains(dump, "INSERT INTO") && strings.Contains(dump, "v_names") &&
		strings.Contains(dump, "INSERT INTO \"v_names\"") {
		t.Errorf("view export wrongly emitted row INSERTs into the view:\n%s", dump)
	}
	// drop-first must tear the view down as a view.
	if !strings.Contains(dump, "DROP VIEW IF EXISTS") {
		t.Errorf("drop-first view export missing DROP VIEW IF EXISTS:\n%s", dump)
	}
	if strings.Contains(dump, "DROP TABLE IF EXISTS \"v_names\"") {
		t.Errorf("view export wrongly emitted DROP TABLE for the view:\n%s", dump)
	}
	// The view's INSTEAD OF trigger rides along so the restored view stays updatable.
	if !strings.Contains(dump, "v_ins") {
		t.Errorf("view export dropped the view's INSTEAD OF trigger:\n%s", dump)
	}
	// A not-self-contained advisory is emitted (the base table must exist in the
	// target).
	if !strings.Contains(dump, "-- WARNING:") {
		t.Errorf("view export missing the not-self-contained warning:\n%s", dump)
	}
}

// TestTableScopeViewExportStructureOnly pins the mode gate: a structure-only
// view export emits the CREATE VIEW and no data section.
func TestTableScopeViewExportStructureOnly(t *testing.T) {
	ts, client, dbPath := newTestServer(t)
	login(t, client, ts.URL)
	csrf := csrfFrom(t, client, ts.URL+"/")

	ctx := context.Background()
	conn := inspectConn(t, dbPath)
	for _, stmt := range []string{
		`CREATE TABLE base2 (id INTEGER PRIMARY KEY)`,
		`INSERT INTO base2 (id) VALUES (1)`,
		`CREATE VIEW v2 AS SELECT id FROM base2`,
	} {
		if _, err := conn.Exec(ctx, stmt); err != nil {
			t.Fatalf("seed %q: %v", stmt, err)
		}
	}

	resp, err := client.PostForm(ts.URL+"/db/main/table/v2/export", url.Values{
		"csrf_token": {csrf}, "format": {"sql"}, "structure": {"1"},
	})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("export = %d:\n%s", resp.StatusCode, body)
	}
	dump := string(body)
	if !strings.Contains(dump, "CREATE VIEW") {
		t.Errorf("structure-only view export missing CREATE VIEW:\n%s", dump)
	}
	if strings.Contains(dump, "-- Data:") || strings.Contains(dump, "INSERT INTO") {
		t.Errorf("structure-only view export wrongly emitted data:\n%s", dump)
	}
}
