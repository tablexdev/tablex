package server_test

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/tablexdev/tablex/internal/config"
	"github.com/tablexdev/tablex/internal/driver"
)

// The restricted-mode policy used to be inferred from a request's LAST PATH
// SEGMENT, which cannot tell a route verb from a {db} or {table} value the user
// chose. These are the two things that cost, and the two the per-route table in
// router.go fixes.

// TestATableNamedLikeARouteVerbIsStillBrowsable: with the console disabled, a
// table called "import" used to answer "Running SQL directly is disabled" on a
// plain browse, because /db/main/table/import ENDS in "import".
//
// SQLite is what makes this expressible as a unit test: a DATABASE named "sql"
// cannot be constructed here (the dialect hard-codes "main"), so that half lives
// in live_restrict_test.go, but a TABLE can be named anything.
func TestATableNamedLikeARouteVerbIsStillBrowsable(t *testing.T) {
	ts, client, path := newTestServerWith(t, func(cfg *config.Config) {
		cfg.Restrict.AllowConsole = false
		cfg.Restrict.AllowDDL = true
	})
	seedTables(t, path,
		`CREATE TABLE "import" (id INTEGER PRIMARY KEY, note TEXT)`,
		`INSERT INTO "import" (note) VALUES ('a row')`,
		`CREATE TABLE "sql" (id INTEGER PRIMARY KEY)`,
	)
	login(t, client, ts.URL)

	for _, name := range []string{"import", "sql"} {
		code, body := getBody(t, client, ts.URL+"/db/main/table/"+name)
		if code != http.StatusOK {
			t.Errorf("browsing a table named %q with allow_console = false = %d, want 200\n%.300s", name, code, body)
			continue
		}
		if strings.Contains(body, "Running SQL directly is disabled") {
			t.Errorf("browsing a table named %q rendered the console refusal:\n%.300s", name, body)
		}
	}
	// The console itself is still closed — otherwise the assertions above would
	// pass simply because nothing is restricted.
	if code, _ := getBody(t, client, ts.URL+"/db/main/table/import/sql"); code != http.StatusForbidden {
		t.Errorf("the console on that table = %d, want 403 — the restriction is not in force", code)
	}
}

// TestSavingAStoredProgramNeedsTheConsole is the gap the route table cannot
// close on its own: save and drop share one POST endpoint and are told apart by
// a form field, so the route's need is the DDL one and saveProgram checks the
// console half itself.
//
// It matters because a stored program's BODY is unconstrained SQL running on the
// server — validateProgramDDL only constrains the outermost statement to be a
// CREATE of the page's kind. Under allow_console = false that was an open door.
func TestSavingAStoredProgramNeedsTheConsole(t *testing.T) {
	ts, client, path := newTestServerWith(t, func(cfg *config.Config) {
		cfg.Restrict.AllowConsole = false
		cfg.Restrict.AllowDDL = true
	})
	seedSQLiteTriggers(t, path)
	login(t, client, ts.URL)
	csrf := csrfFrom(t, client, ts.URL+"/")

	resp := postForm(t, client, ts.URL+"/db/main/triggers", url.Values{
		"csrf_token": {csrf}, "action": {"save"},
		"definition": {`CREATE TRIGGER trg_new_guard BEFORE UPDATE ON widgets
FOR EACH ROW WHEN NEW.qty < 0
BEGIN SELECT RAISE(ABORT, 'no negatives'); END`},
	})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("saving a trigger with allow_console = false = %d, want 403", resp.StatusCode)
	}
	// And it really was not created — a 403 that ran the statement first would be
	// the worst of both.
	_, body := getBody(t, client, ts.URL+"/db/main/triggers")
	if listsTrigger(body, "trg_new_guard") {
		t.Errorf("the trigger was created despite the refusal:\n%s", body)
	}
	// The editor is not offered either: a form the server will refuse is worse
	// than no form. The drop control on the same page still is — see the
	// companion test.
	if strings.Contains(body, "New trigger") {
		t.Errorf("the triggers page still offers the editor under allow_console = false:\n%s", body)
	}
	if !strings.Contains(body, `value="drop"`) {
		t.Errorf("hiding the editor also hid the drop control, which still works:\n%s", body)
	}
}

// TestDroppingAStoredProgramStillWorksWithoutTheConsole is the other half, and
// the reason the route's need could not simply be tightened to console: dropping
// a trigger is ordinary DDL and must keep working.
func TestDroppingAStoredProgramStillWorksWithoutTheConsole(t *testing.T) {
	ts, client, path := newTestServerWith(t, func(cfg *config.Config) {
		cfg.Restrict.AllowConsole = false
		cfg.Restrict.AllowDDL = true
	})
	seedSQLiteTriggers(t, path)
	login(t, client, ts.URL)
	csrf := csrfFrom(t, client, ts.URL+"/")

	resp := postForm(t, client, ts.URL+"/db/main/triggers", url.Values{
		"csrf_token": {csrf}, "action": {"drop"},
		"name": {"trg_widget_guard"}, "i": {"1"}, "tx_confirm": {"1"},
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("dropping a trigger with allow_console = false = %d, want 303", resp.StatusCode)
	}
	_, body := getBody(t, client, ts.URL+"/db/main/triggers")
	if listsTrigger(body, "trg_widget_guard") {
		t.Errorf("the trigger survived the drop:\n%s", body)
	}
	// The drop control is still offered, so the UI has not hidden what still works.
	if !strings.Contains(body, `value="drop"`) {
		t.Errorf("the triggers page no longer offers a drop control:\n%s", body)
	}
}

// TestHTMXRefusalRendersInPanel pins the arm every other restricted-mode test
// misses. refuse() has no method branch; renderError branches on whether the
// request is htmx. So a hand-typed GET gets a real 403, while an htmx request
// gets wire 200 with HX-Retarget and the refusal in the panel — because an htmx
// swap discards a non-2xx body, and a 403 would leave the page silently
// unchanged.
//
// Every refusal test before this one used the plain helpers, which send no HX
// headers, so the 200-with-panel behaviour was entirely unasserted.
func TestHTMXRefusalRendersInPanel(t *testing.T) {
	base, client := restrictedServer(t, func(rc *config.RestrictConfig) {
		rc.AllowConsole = false
		rc.AllowDDL = true
	})
	login(t, client, base)

	req, err := http.NewRequest(http.MethodGet, base+"/db/main/sql", nil)
	if err != nil {
		t.Fatalf("building the request: %v", err)
	}
	req.Header.Set("HX-Request", "true")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET /db/main/sql as htmx: %v", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading the refusal body: %v", err)
	}
	body := string(raw)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("an htmx refusal answered %d, want wire 200 — htmx discards a non-2xx body and the panel would not update", resp.StatusCode)
	}
	if got := resp.Header.Get("HX-Retarget"); got != "#page_content" {
		t.Errorf("HX-Retarget = %q, want %q", got, "#page_content")
	}
	if !strings.Contains(body, "Running SQL directly is disabled") {
		t.Errorf("the refusal message is not in the panel:\n%.500s", body)
	}

	// The same request WITHOUT the header is a real 403. Both arms in one test,
	// because the discriminator is htmx-vs-full-page and not the method.
	if code, _ := getBody(t, client, base+"/db/main/sql"); code != http.StatusForbidden {
		t.Errorf("a non-htmx refusal answered %d, want 403", code)
	}
}

// seedTables applies extra DDL to the seeded SQLite file. The server reads the
// same file live, so this may run after it has started.
func seedTables(t *testing.T, path string, ddl ...string) {
	t.Helper()
	d, _ := driver.Get("sqlite")
	conn, err := driver.Open(context.Background(), d, driver.ConnParams{FilePath: path})
	if err != nil {
		t.Fatalf("seed open: %v", err)
	}
	defer conn.Close()
	for _, s := range ddl {
		if _, err := conn.Exec(context.Background(), s); err != nil {
			t.Fatalf("seed %q: %v", s, err)
		}
	}
}

// TestPartialIndexPredicateNeedsTheConsole is the structure-editor twin of the
// stored-program gap above, and the same shape: the POST route carries several
// actions, so its need is the DDL one and the handler takes the console check
// where the action and its fields are finally known.
//
// It matters because the predicate is user-WRITTEN SQL appended to the CREATE
// INDEX — an expression no placeholder can carry. The route is need{write, ddl},
// so under allow_console = false with DDL still on, the field was reachable.
func TestPartialIndexPredicateNeedsTheConsole(t *testing.T) {
	ts, client, path := newTestServerWith(t, func(cfg *config.Config) {
		cfg.Restrict.AllowConsole = false
		cfg.Restrict.AllowDDL = true
	})
	login(t, client, ts.URL)

	code, body := postStructureOp(t, client, ts.URL, url.Values{
		"action": {"add_index"}, "index_name": {"idx_partial_guard"},
		"index_columns": {"name"}, "index_where": {"qty > 0"},
	})
	if code != http.StatusForbidden {
		t.Fatalf("a partial index with allow_console = false = %d, want 403:\n%.600s", code, body)
	}
	// A 403 that built the index first would be the worst of both.
	if _, ok := findIndex(sqliteIndexes(t, path, "widgets"), "idx_partial_guard"); ok {
		t.Error("the index was created despite the refusal")
	}
	// The field is not offered either — the rest of the index form still is.
	_, page := getBody(t, client, ts.URL+structureURL)
	if strings.Contains(page, `name="index_where"`) {
		t.Error("the structure page still offers the predicate under allow_console = false")
	}
	if !strings.Contains(page, `value="add_index"`) {
		t.Error("hiding the predicate also hid index creation, which still works")
	}
}

// TestStructureEditingStillWorksWithoutTheConsole is the other half, and the
// reason the check is scoped to one FIELD of one action rather than to the
// route or even to add_index: everything else on this endpoint is ordinary DDL
// and must keep working. Without this, over-refusal would ship untested.
func TestStructureEditingStillWorksWithoutTheConsole(t *testing.T) {
	ts, client, path := newTestServerWith(t, func(cfg *config.Config) {
		cfg.Restrict.AllowConsole = false
		cfg.Restrict.AllowDDL = true
	})
	login(t, client, ts.URL)

	// An index with no predicate at all.
	if code, body := postStructureOp(t, client, ts.URL, url.Values{
		"action": {"add_index"}, "index_name": {"idx_plain_ok"}, "index_columns": {"name"},
	}); code != http.StatusSeeOther {
		t.Fatalf("a plain index = %d, want 303:\n%.600s", code, body)
	}
	if _, ok := findIndex(sqliteIndexes(t, path, "widgets"), "idx_plain_ok"); !ok {
		t.Error("a plain index was refused under allow_console = false")
	}
	// An empty predicate field is what the no-JS form submits when the control
	// is hidden, so it must not be read as "a predicate was supplied".
	if code, body := postStructureOp(t, client, ts.URL, url.Values{
		"action": {"add_index"}, "index_name": {"idx_blank_ok"},
		"index_columns": {"qty"}, "index_where": {"   "},
	}); code != http.StatusSeeOther {
		t.Fatalf("a blank predicate = %d, want 303:\n%.600s", code, body)
	}
	// And a different action on the same endpoint.
	if code, body := postStructureOp(t, client, ts.URL, url.Values{
		"action": {"add_column"}, "col_name": {"note"}, "col_type": {"TEXT"}, "col_nullable": {"1"},
	}); code != http.StatusSeeOther {
		t.Fatalf("add_column = %d, want 303:\n%.600s", code, body)
	}
}
