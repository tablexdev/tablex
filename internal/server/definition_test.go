package server_test

// The definition viewer. Two things need proving and only a live server can
// prove the second:
//
//   - the pages render a lazy panel per object, and the fragment it loads
//     returns that object's statement (SQLite, in every run);
//   - MySQL's panel shows a REPLAYABLE definition. information_schema stores a
//     routine body without its signature, so rendering the listed value would
//     have shown a bare "SET hi = lo + 1" — no CREATE, no parameters, no
//     DEFINER. That is the whole reason DefinitionViewer exists, and it is
//     invisible to the SQLite harness.

import (
	"context"
	"database/sql"
	"html"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/tablexdev/tablex/internal/config"
	"github.com/tablexdev/tablex/internal/driver"
)

var defURLRE = regexp.MustCompile(`hx-get="([^"]*/definition\?[^"]*)"`)

// seedSQLiteTriggers adds two triggers on two tables, writing through a second
// connection rather than extending the shared fixture so no existing test's
// object counts move.
//
// The names are chosen so the database-wide list orders trg_alpha_guard FIRST
// and trg_widget_guard second. The per-table page for `widgets` therefore shows
// trg_widget_guard at position 0 of its FILTERED list while it sits at position
// 1 of the unfiltered one — which is what makes the filtered-index test below
// able to fail.
func seedSQLiteTriggers(t *testing.T, path string) {
	t.Helper()
	d, _ := driver.Get("sqlite")
	conn, err := driver.Open(context.Background(), d, driver.ConnParams{FilePath: path})
	if err != nil {
		t.Fatalf("seed open: %v", err)
	}
	defer conn.Close()
	for _, ddl := range []string{
		`CREATE TABLE alpha (id INTEGER PRIMARY KEY, tag TEXT)`,
		`CREATE TRIGGER trg_alpha_guard BEFORE INSERT ON alpha
FOR EACH ROW WHEN NEW.tag IS NULL
BEGIN SELECT RAISE(ABORT, 'alpha needs a tag'); END`,
		// The abort message carries markup on purpose: a definition is arbitrary
		// user-authored SQL rendered straight into a page, so the panel is an
		// injection sink if it is ever emitted unescaped.
		`CREATE TRIGGER trg_widget_guard BEFORE INSERT ON widgets
FOR EACH ROW WHEN NEW.qty < 0
BEGIN SELECT RAISE(ABORT, 'negative qty <script>alert(1)</script>'); END`,
	} {
		if _, err := conn.Exec(context.Background(), ddl); err != nil {
			t.Fatalf("seed %q: %v", ddl, err)
		}
	}
}

// TestDefinitionPanelRendersAndLoads walks the whole feature the way a user
// does: open the triggers page, follow the panel's own hx-get, read the
// statement. Before this, the page truncated the definition at 80 characters
// and there was no way to see the rest.
func TestDefinitionPanelRendersAndLoads(t *testing.T) {
	ts, client, path := newTestServer(t)
	seedSQLiteTriggers(t, path)
	login(t, client, ts.URL)

	code, body := getBody(t, client, ts.URL+"/db/main/triggers")
	if code != http.StatusOK {
		t.Fatalf("triggers page = %d, want 200", code)
	}
	if !strings.Contains(body, "trg_widget_guard") {
		t.Fatalf("seeded trigger is not listed:\n%s", body)
	}
	panels := defURLRE.FindAllStringSubmatch(body, -1)
	if len(panels) != 2 {
		t.Fatalf("want one definition panel per trigger (2), got %d:\n%s", len(panels), body)
	}
	// The panel must load lazily; no statement may be inlined into the list.
	if strings.Contains(body, "RAISE(ABORT") {
		t.Error("a trigger body was inlined into the list; panels are supposed to fetch on demand")
	}
	var url string
	for _, p := range panels {
		if u := html.UnescapeString(p[1]); strings.Contains(u, "name=trg_widget_guard") {
			url = u
		}
	}
	if url == "" {
		t.Fatalf("no panel addresses trg_widget_guard:\n%s", body)
	}

	code, frag := getBody(t, client, ts.URL+url)
	if code != http.StatusOK {
		t.Fatalf("definition fragment = %d, want 200", code)
	}
	// html/template escapes '<' and quotes, so compare content against the
	// unescaped text — then assert separately that the escaping really happened.
	shown := html.UnescapeString(frag)
	for _, want := range []string{"CREATE TRIGGER", "trg_widget_guard", "RAISE(ABORT", "negative qty"} {
		if !strings.Contains(shown, want) {
			t.Errorf("definition fragment is missing %q:\n%s", want, frag)
		}
	}
	// A definition is arbitrary user-authored SQL rendered into a page. The
	// seeded trigger hides a <script> in its abort message; it must arrive
	// escaped, or the panel is a stored-XSS sink for anyone who can create a
	// trigger.
	if strings.Contains(frag, "<script>") {
		t.Errorf("the definition panel emitted raw <script>:\n%s", frag)
	}
	if !strings.Contains(frag, "&lt;script&gt;") {
		t.Errorf("expected the script tag to render escaped:\n%s", frag)
	}
	// A fragment is a bare panel, never a whole page.
	if strings.Contains(frag, "<body") {
		t.Error("the definition fragment rendered a full page")
	}
}

// TestTableTriggerDefinitionUsesFilteredIndex covers the per-table triggers
// page, whose list is filtered to one table. Its rows are positions in that
// FILTERED slice, so the fragment endpoint has to reapply the same filter
// before indexing. Without that, `widgets`' only trigger — position 0 of the
// filtered list, position 1 of the database-wide one — would resolve to the
// trigger on `alpha` and the panel would show the wrong object's SQL.
func TestTableTriggerDefinitionUsesFilteredIndex(t *testing.T) {
	ts, client, path := newTestServer(t)
	seedSQLiteTriggers(t, path)
	login(t, client, ts.URL)

	code, body := getBody(t, client, ts.URL+"/db/main/table/widgets/triggers")
	if code != http.StatusOK {
		t.Fatalf("table triggers page = %d, want 200", code)
	}
	if strings.Contains(body, "trg_alpha_guard") {
		t.Fatal("the per-table page is no longer filtered; this test would not discriminate")
	}
	m := defURLRE.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no definition panel on the table triggers page:\n%s", body)
	}
	url := html.UnescapeString(m[1])
	if !strings.Contains(url, "table=widgets") {
		t.Errorf("panel URL does not carry the table filter, so the index is ambiguous: %s", url)
	}
	code, frag := getBody(t, client, ts.URL+url)
	if code != http.StatusOK {
		t.Fatalf("definition fragment = %d, want 200", code)
	}
	if !strings.Contains(frag, "trg_widget_guard") || !strings.Contains(frag, "negative qty") {
		t.Errorf("panel did not return this table's trigger:\n%s", frag)
	}
	if strings.Contains(frag, "alpha") {
		t.Errorf("panel returned the OTHER table's trigger:\n%s", frag)
	}
}

// TestDefinitionRejectsStaleOrBogusRequests pins the addressing rule: an object
// is identified by list position AND name, so a page left open after someone
// drops a trigger cannot silently open whatever now sits in that slot.
func TestDefinitionRejectsStaleOrBogusRequests(t *testing.T) {
	ts, client, path := newTestServer(t)
	seedSQLiteTriggers(t, path)
	login(t, client, ts.URL)

	for _, tc := range []struct {
		name, query string
		wantCode    int
		wantBody    string
	}{
		{"index past the end", "?kind=trigger&name=trg_widget_guard&i=99", http.StatusOK, "no longer exists"},
		{"name does not match the slot", "?kind=trigger&name=someone_else&i=0", http.StatusOK, "no longer exists"},
		{"unknown kind", "?kind=teapot&name=trg_widget_guard&i=0", http.StatusOK, "unknown object kind"},
		{"missing name", "?kind=trigger&i=0", http.StatusBadRequest, ""},
		{"non-numeric index", "?kind=trigger&name=trg_widget_guard&i=x", http.StatusBadRequest, ""},
		{"negative index", "?kind=trigger&name=trg_widget_guard&i=-1", http.StatusBadRequest, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, body := getBody(t, client, ts.URL+"/db/main/definition"+tc.query)
			if code != tc.wantCode {
				t.Fatalf("= %d, want %d (%s)", code, tc.wantCode, body)
			}
			if tc.wantBody != "" && !strings.Contains(body, tc.wantBody) {
				t.Errorf("body does not mention %q:\n%s", tc.wantBody, body)
			}
			// Whatever happens, no object's SQL leaks out.
			if strings.Contains(body, "RAISE(ABORT") {
				t.Errorf("a rejected request still returned a definition:\n%s", body)
			}
		})
	}
}

// TestDefinitionRequiresAuth — the fragment endpoint reads schema objects, so an
// unauthenticated caller must be turned away before any of them is touched. The
// middleware does that ahead of the handler, in the two shapes it uses
// everywhere: a plain GET is redirected, an htmx GET gets HX-Redirect + 401 so
// the client navigates rather than swapping a login page into a panel.
func TestDefinitionRequiresAuth(t *testing.T) {
	ts, client, _ := newTestServer(t)
	const path = "/db/main/definition?kind=trigger&name=x&i=0"

	code, body := getBody(t, client, ts.URL+path)
	if code != http.StatusSeeOther {
		t.Errorf("unauthenticated definition fetch = %d, want 303", code)
	}
	if strings.Contains(body, "CREATE") {
		t.Errorf("a definition leaked to an unauthenticated caller:\n%s", body)
	}

	req, err := http.NewRequest(http.MethodGet, ts.URL+path, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("HX-Request", "true")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("htmx definition fetch: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("unauthenticated htmx definition fetch = %d, want 401", resp.StatusCode)
	}
	if got := resp.Header.Get("HX-Redirect"); got != "/login" {
		t.Errorf("HX-Redirect = %q, want %q", got, "/login")
	}
}

func TestLiveMySQLObjectDefinition(t *testing.T) {
	liveObjectDefinition(t, liveEnvFor(t, "MYSQL", "mysql", 3306, "root"))
}

func TestLiveMariaDBObjectDefinition(t *testing.T) {
	liveObjectDefinition(t, liveEnvFor(t, "MARIADB", "mysql", 3306, "root"))
}

// liveObjectDefinition proves the MySQL-family DefinitionViewer returns a
// statement that could be replayed, and that Routine.Language is no longer
// permanently blank.
func liveObjectDefinition(t *testing.T, env liveEnv) {
	ctx := context.Background()
	d, ok := driver.Get(env.engine)
	if !ok {
		t.Fatalf("dialect %s not registered", env.engine)
	}
	adminParams := driver.ConnParams{Host: env.host, Port: env.port, User: env.user, Password: env.pass}
	admin, err := driver.Open(ctx, d, adminParams)
	if err != nil {
		t.Fatalf("connect %s at %s:%d: %v", env.label, env.host, env.port, err)
	}
	defer admin.Close()
	liveDropDB(t, admin, env.engine)
	liveCreateDB(t, admin)
	defer liveDropDB(t, admin, env.engine)

	dbParams := adminParams
	dbParams.Database = liveDB
	conn, err := driver.Open(ctx, d, dbParams)
	if err != nil {
		t.Fatalf("connect to %s: %v", liveDB, err)
	}
	defer conn.Close()

	// Single-statement bodies: a BEGIN…END body would need a DELIMITER change,
	// which is a client concept the driver has no reason to carry.
	for _, s := range []string{
		`CREATE TABLE audit_log (id INT AUTO_INCREMENT PRIMARY KEY, note VARCHAR(64))`,
		`CREATE PROCEDURE bump(IN lo INT, OUT hi INT) COMMENT 'demo' SET hi = lo + 1`,
		`CREATE FUNCTION dbl(a INT) RETURNS INT DETERMINISTIC RETURN a * 2`,
		`CREATE TRIGGER trg_audit BEFORE INSERT ON audit_log FOR EACH ROW SET NEW.note = CONCAT('t:', NEW.note)`,
	} {
		if _, err := conn.Exec(ctx, s); err != nil {
			t.Fatalf("seed %q: %v", s, err)
		}
	}

	scope := driver.Scope{Database: liveDB}
	routines, err := conn.ListRoutines(ctx, scope)
	if err != nil {
		t.Fatalf("ListRoutines: %v", err)
	}
	if len(routines) != 2 {
		t.Fatalf("ListRoutines returned %d routines, want 2", len(routines))
	}
	for _, r := range routines {
		// B-side of the fix: this column rendered a permanent "—" because MySQL
		// never selected a language at all, and MariaDB reports NULL for
		// EXTERNAL_LANGUAGE even on 11.4.
		if r.Language == "" {
			t.Errorf("routine %s has an empty Language; the column would render as %q", r.Name, "—")
		}
		// Pin WHY DefinitionViewer exists: the listed value is a bare body.
		if strings.Contains(strings.ToUpper(r.Definition), "CREATE ") {
			t.Errorf("routine %s: information_schema now returns a full statement (%q) — "+
				"the body-only premise behind DefinitionViewer no longer holds", r.Name, r.Definition)
		}

		kind := driver.ProgramFunction
		if strings.EqualFold(r.Type, "PROCEDURE") {
			kind = driver.ProgramProcedure
		}
		def, supported, err := conn.ObjectDefinition(ctx, scope, kind, r.Name)
		if err != nil {
			t.Fatalf("ObjectDefinition(%s): %v", r.Name, err)
		}
		if !supported {
			t.Fatalf("%s reports no DefinitionViewer; the panel would fall back to the body-only value", env.label)
		}
		for _, want := range []string{"CREATE", strings.ToUpper(r.Type), r.Name} {
			if !strings.Contains(strings.ToUpper(def), strings.ToUpper(want)) {
				t.Errorf("ObjectDefinition(%s) is missing %q:\n%s", r.Name, want, def)
			}
		}
	}

	// The parameter list is the part information_schema drops entirely, so it is
	// the sharpest single assertion that the panel shows the real statement.
	def, _, err := conn.ObjectDefinition(ctx, scope, driver.ProgramProcedure, "bump")
	if err != nil {
		t.Fatalf("ObjectDefinition(bump): %v", err)
	}
	for _, want := range []string{"IN lo", "OUT hi"} {
		if !strings.Contains(def, want) {
			t.Errorf("procedure definition lost its signature (%q missing):\n%s", want, def)
		}
	}

	triggers, err := conn.ListTriggers(ctx, scope)
	if err != nil {
		t.Fatalf("ListTriggers: %v", err)
	}
	if len(triggers) != 1 {
		t.Fatalf("ListTriggers returned %d triggers, want 1", len(triggers))
	}
	tdef, supported, err := conn.ObjectDefinition(ctx, scope, driver.ProgramTrigger, triggers[0].Name)
	if err != nil {
		t.Fatalf("ObjectDefinition(trigger): %v", err)
	}
	if !supported {
		t.Fatal("trigger definitions report unsupported")
	}
	for _, want := range []string{"CREATE", "TRIGGER", "trg_audit", "audit_log"} {
		if !strings.Contains(tdef, want) {
			t.Errorf("trigger definition is missing %q:\n%s", want, tdef)
		}
	}

	// An object that does not exist must surface as an error, never as an empty
	// panel that reads like "this routine has no body".
	if _, _, err := conn.ObjectDefinition(ctx, scope, driver.ProgramProcedure, "no_such_routine"); err == nil {
		t.Error("ObjectDefinition on a missing routine returned no error")
	} else if err != sql.ErrNoRows && !strings.Contains(strings.ToLower(err.Error()), "does not exist") {
		t.Logf("missing-routine error (informational): %v", err)
	}
}

// TestLiveMySQLRoutinesPageShowsDefinition is the end-to-end pass for the one
// page the SQLite harness cannot reach at all: SQLite has no routines, so
// db_routines.html is rendered here for the first time with real content. It
// walks the user's path — open the page, expand a panel, read the procedure.
func TestLiveMySQLRoutinesPageShowsDefinition(t *testing.T) {
	env := liveEnvFor(t, "MYSQL", "mysql", 3306, "root")
	ctx := context.Background()
	d, _ := driver.Get(env.engine)
	adminParams := driver.ConnParams{Host: env.host, Port: env.port, User: env.user, Password: env.pass}
	admin, err := driver.Open(ctx, d, adminParams)
	if err != nil {
		t.Fatalf("connect %s: %v", env.label, err)
	}
	defer admin.Close()
	liveDropDB(t, admin, env.engine)
	liveCreateDB(t, admin)
	defer liveDropDB(t, admin, env.engine)

	dbParams := adminParams
	dbParams.Database = liveDB
	seed, err := driver.Open(ctx, d, dbParams)
	if err != nil {
		t.Fatalf("connect to %s: %v", liveDB, err)
	}
	for _, stmt := range []string{
		`CREATE PROCEDURE bump(IN lo INT, OUT hi INT) COMMENT 'demo' SET hi = lo + 1`,
	} {
		if _, err := seed.Exec(ctx, stmt); err != nil {
			seed.Close()
			t.Fatalf("seed %q: %v", stmt, err)
		}
	}
	seed.Close()

	ts, client, _ := newTestServerWith(t, func(c *config.Config) {
		c.Servers = append(c.Servers, config.ServerConfig{
			Name: "live", Engine: env.engine, Host: env.host, Port: env.port,
		})
	})
	csrf := csrfFrom(t, client, ts.URL+"/login")
	resp, err := client.PostForm(ts.URL+"/login", url.Values{
		"csrf_token": {csrf}, "server": {"live"},
		"username": {env.user}, "password": {env.pass},
	})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("live login = %d, want 303", resp.StatusCode)
	}

	code, page := getBody(t, client, ts.URL+"/db/"+liveDB+"/routines")
	if code != http.StatusOK {
		t.Fatalf("routines page = %d, want 200:\n%.2000s", code, page)
	}
	if !strings.Contains(page, "bump") || !strings.Contains(page, "PROCEDURE") {
		t.Fatalf("the routine is not listed:\n%.3000s", page)
	}
	// The Language column rendered a permanent em dash before the COALESCE fix.
	if !strings.Contains(page, ">SQL<") {
		t.Errorf("Language column does not show SQL:\n%.3000s", page)
	}
	m := defURLRE.FindStringSubmatch(page)
	if m == nil {
		t.Fatalf("no definition panel on the routines page:\n%.3000s", page)
	}
	code, frag := getBody(t, client, ts.URL+html.UnescapeString(m[1]))
	if code != http.StatusOK {
		t.Fatalf("definition fragment = %d, want 200:\n%s", code, frag)
	}
	// Compare against the unescaped text: html/template renders '+' as &#43; and
	// "'" as &#39;, which is correct output, not missing content.
	shown := html.UnescapeString(frag)
	// The whole point: a statement someone could replay, not a bare body.
	for _, want := range []string{"CREATE", "PROCEDURE", "bump", "IN lo", "OUT hi", "COMMENT 'demo'", "SET hi = lo + 1"} {
		if !strings.Contains(shown, want) {
			t.Errorf("routine panel is missing %q:\n%s", want, frag)
		}
	}
}

// TestLivePostgresDefinitionIsSelfContained pins the other half of the contract:
// PostgreSQL deliberately implements NO DefinitionViewer, which is only correct
// while its listings keep returning complete CREATE statements.
func TestLivePostgresDefinitionIsSelfContained(t *testing.T) {
	env := liveEnvFor(t, "POSTGRES", "postgres", 5432, "postgres")
	ctx := context.Background()
	d, ok := driver.Get(env.engine)
	if !ok {
		t.Fatalf("dialect %s not registered", env.engine)
	}
	adminParams := driver.ConnParams{Host: env.host, Port: env.port, User: env.user, Password: env.pass}
	admin, err := driver.Open(ctx, d, adminParams)
	if err != nil {
		t.Fatalf("connect %s: %v", env.label, err)
	}
	defer admin.Close()
	liveDropDB(t, admin, env.engine)
	liveCreateDB(t, admin)
	defer liveDropDB(t, admin, env.engine)

	dbParams := adminParams
	dbParams.Database = liveDB
	conn, err := driver.Open(ctx, d, dbParams)
	if err != nil {
		t.Fatalf("connect to %s: %v", liveDB, err)
	}
	defer conn.Close()

	for _, s := range []string{
		`CREATE FUNCTION dbl(a int) RETURNS int LANGUAGE sql AS $$ SELECT a * 2 $$`,
	} {
		if _, err := conn.Exec(ctx, s); err != nil {
			t.Fatalf("seed %q: %v", s, err)
		}
	}
	scope := driver.Scope{Database: liveDB, Schema: "public"}
	routines, err := conn.ListRoutines(ctx, scope)
	if err != nil {
		t.Fatalf("ListRoutines: %v", err)
	}
	if len(routines) != 1 {
		t.Fatalf("ListRoutines returned %d routines, want 1", len(routines))
	}
	// No capability, so the panel falls back to the listed definition — which
	// therefore has to be the whole statement, signature included.
	if _, supported, err := conn.ObjectDefinition(ctx, scope, driver.ProgramFunction, "dbl"); err != nil {
		t.Fatalf("ObjectDefinition: %v", err)
	} else if supported {
		t.Fatal("PostgreSQL now implements DefinitionViewer; the fallback below no longer describes the code")
	}
	for _, want := range []string{"CREATE", "FUNCTION", "dbl(a integer)", "RETURNS integer"} {
		if !strings.Contains(routines[0].Definition, want) {
			t.Errorf("listed PostgreSQL definition is missing %q:\n%s", want, routines[0].Definition)
		}
	}
}
