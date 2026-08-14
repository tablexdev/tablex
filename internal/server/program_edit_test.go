package server_test

// The stored-program definition editor: open it, save a new object, redefine an
// existing one — and, on an engine without transactional DDL, survive a rejected
// redefinition without destroying what was there.

import (
	"context"
	"html"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/tablexdev/tablex/internal/config"
	"github.com/tablexdev/tablex/internal/driver"
)

// readBody drains and closes a response, returning its body.
func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return string(b)
}

// TestProgramEditorOpens covers both entry points: a new object gets the
// dialect's skeleton, an existing one gets its real definition.
func TestProgramEditorOpens(t *testing.T) {
	ts, client, path := newTestServer(t)
	seedSQLiteTriggers(t, path)
	login(t, client, ts.URL)

	t.Run("new", func(t *testing.T) {
		code, body := getBody(t, client, ts.URL+"/db/main/triggers/edit")
		if code != http.StatusOK {
			t.Fatalf("new-trigger editor = %d, want 200", code)
		}
		shown := html.UnescapeString(body)
		for _, want := range []string{"CREATE TRIGGER", "BEFORE INSERT ON", "END"} {
			if !strings.Contains(shown, want) {
				t.Errorf("skeleton is missing %q:\n%s", want, body)
			}
		}
		// Creating posts no name, which is how the handler tells create from edit.
		if strings.Contains(body, `name="name" value=`) {
			t.Error("the new-object editor pre-set a name; it would try to redefine something")
		}
		if !strings.Contains(body, "codemirror") {
			t.Error("the editor page did not request CodeMirror (Page.NeedsEditor)")
		}
	})

	t.Run("edit", func(t *testing.T) {
		code, body := getBody(t, client, ts.URL+"/db/main/triggers/edit?name=trg_widget_guard&i=1")
		if code != http.StatusOK {
			t.Fatalf("edit editor = %d, want 200", code)
		}
		shown := html.UnescapeString(body)
		if !strings.Contains(shown, "trg_widget_guard") || !strings.Contains(shown, "negative qty") {
			t.Errorf("editor was not pre-filled with the current definition:\n%s", body)
		}
		for _, want := range []string{`name="name" value="trg_widget_guard"`, `name="i" value="1"`} {
			if !strings.Contains(body, want) {
				t.Errorf("edit form is missing %q so it would create instead of replace", want)
			}
		}
	})

	t.Run("stale reference", func(t *testing.T) {
		code, _ := getBody(t, client, ts.URL+"/db/main/triggers/edit?name=trg_widget_guard&i=99")
		if code != http.StatusConflict {
			t.Errorf("editor for a vanished object = %d, want 409", code)
		}
	})
}

// TestProgramEditorRefusesRoutinesOnSQLite — the editor is capability-gated, so
// an engine with no routines cannot open one even by typing the URL.
func TestProgramEditorRefusesRoutinesOnSQLite(t *testing.T) {
	ts, client, _ := newTestServer(t)
	login(t, client, ts.URL)
	code, body := getBody(t, client, ts.URL+"/db/main/routines/edit")
	if code != http.StatusBadRequest {
		t.Errorf("routine editor on SQLite = %d, want 400 (%s)", code, body)
	}
}

// TestSaveNewProgram creates a trigger through the editor.
func TestSaveNewProgram(t *testing.T) {
	ts, client, path := newTestServer(t)
	seedSQLiteTriggers(t, path)
	login(t, client, ts.URL)
	csrf := csrfFrom(t, client, ts.URL+"/")

	resp, err := client.PostForm(ts.URL+"/db/main/triggers", url.Values{
		"csrf_token": {csrf}, "action": {"save"},
		"definition": {`CREATE TRIGGER trg_new_guard BEFORE UPDATE ON widgets
FOR EACH ROW WHEN NEW.qty < 0
BEGIN SELECT RAISE(ABORT, 'no negatives'); END`},
	})
	if err != nil {
		t.Fatalf("save POST: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("save = %d, want 303", resp.StatusCode)
	}
	_, body := getBody(t, client, ts.URL+"/db/main/triggers")
	if !listsTrigger(body, "trg_new_guard") {
		t.Errorf("the new trigger was not created:\n%s", body)
	}
}

// TestSaveReplacesExistingProgram redefines a trigger in place.
func TestSaveReplacesExistingProgram(t *testing.T) {
	ts, client, path := newTestServer(t)
	seedSQLiteTriggers(t, path)
	login(t, client, ts.URL)
	csrf := csrfFrom(t, client, ts.URL+"/")

	resp, err := client.PostForm(ts.URL+"/db/main/triggers", url.Values{
		"csrf_token": {csrf}, "action": {"save"},
		"name": {"trg_widget_guard"}, "i": {"1"},
		"definition": {`CREATE TRIGGER trg_widget_guard BEFORE INSERT ON widgets
FOR EACH ROW WHEN NEW.qty > 1000
BEGIN SELECT RAISE(ABORT, 'too many'); END`},
	})
	if err != nil {
		t.Fatalf("save POST: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("save = %d, want 303", resp.StatusCode)
	}

	// Still exactly one trigger of that name, now with the new body.
	_, body := getBody(t, client, ts.URL+"/db/main/triggers")
	if !listsTrigger(body, "trg_widget_guard") {
		t.Fatalf("the trigger disappeared instead of being replaced:\n%s", body)
	}
	if strings.Count(body, `<td class="tx-tbl-name">trg_widget_guard</td>`) != 1 {
		t.Error("the replaced trigger is listed more than once")
	}
	code, frag := getBody(t, client, ts.URL+"/db/main/definition?kind=trigger&name=trg_widget_guard&i=1")
	if code != http.StatusOK {
		t.Fatalf("definition = %d", code)
	}
	shown := html.UnescapeString(frag)
	if !strings.Contains(shown, "too many") {
		t.Errorf("the definition was not replaced:\n%s", frag)
	}
	if strings.Contains(shown, "negative qty") {
		t.Errorf("the old definition is still in place:\n%s", frag)
	}
}

// TestSaveRejectsBadDefinitions pins the checks that run before anything is sent
// to the server. The definition is the user's own DDL — the same bargain as the
// SQL console — but it must be ONE statement creating the kind of object the
// page administers, so a "save this trigger" cannot carry a second statement or
// quietly create something else.
func TestSaveRejectsBadDefinitions(t *testing.T) {
	ts, client, path := newTestServer(t)
	seedSQLiteTriggers(t, path)
	login(t, client, ts.URL)
	csrf := csrfFrom(t, client, ts.URL+"/")

	for _, tc := range []struct {
		name, definition, wantMsg string
	}{
		{"not a CREATE at all", `DROP TABLE widgets`, "does not look like a CREATE"},
		{"creates the wrong kind", `CREATE VIEW v AS SELECT 1`, "does not look like a CREATE"},
		{"a second statement rides along",
			`CREATE TRIGGER t2 AFTER INSERT ON widgets BEGIN SELECT 1; END; DROP TABLE widgets`,
			"single CREATE statement"},
		{"empty", "   ", "empty"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := client.PostForm(ts.URL+"/db/main/triggers", url.Values{
				"csrf_token": {csrf}, "action": {"save"}, "definition": {tc.definition},
			})
			if err != nil {
				t.Fatalf("POST: %v", err)
			}
			body := readBody(t, resp)
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("= %d, want 400:\n%s", resp.StatusCode, body)
			}
			if !strings.Contains(body, tc.wantMsg) {
				t.Errorf("message does not mention %q:\n%s", tc.wantMsg, body)
			}
		})
	}

	// Nothing above may have run: widgets must still be there, with its trigger.
	if code, _ := getBody(t, client, ts.URL+"/db/main/table/widgets"); code != http.StatusOK {
		t.Fatalf("widgets browse = %d — a rejected definition still executed", code)
	}
	_, list := getBody(t, client, ts.URL+"/db/main/triggers")
	if !listsTrigger(list, "trg_widget_guard") {
		t.Error("a rejected definition disturbed the existing trigger")
	}
	if listsTrigger(list, "t2") {
		t.Error("the multi-statement definition created its first statement anyway")
	}
}

// TestLiveMySQLReplaceRestoresOnFailure is the one that matters for data safety.
//
// MySQL commits every DDL statement on its own, so redefining a routine is a
// DROP followed by a CREATE with no transaction around them. A CREATE the server
// rejects would otherwise leave the routine simply gone — a typo in an editor
// destroying a stored procedure. The previous definition must come back.
func TestLiveMySQLReplaceRestoresOnFailure(t *testing.T) {
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
	if _, err := seed.Exec(ctx, `CREATE PROCEDURE bump(IN lo INT, OUT hi INT) SET hi = lo + 1`); err != nil {
		seed.Close()
		t.Fatalf("seed: %v", err)
	}
	seed.Close()

	// This engine is exactly the one the restore path exists for.
	if admin.Capabilities().SupportsTransactionalDDL {
		t.Fatal("MySQL now reports transactional DDL; this test no longer covers the restore path")
	}

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
	csrf = csrfFrom(t, client, ts.URL+"/")

	// A definition that passes the editor's checks (one statement, CREATE
	// PROCEDURE) but the server rejects: NOSUCHTYPE is not a type.
	resp, err = client.PostForm(ts.URL+"/db/"+liveDB+"/routines", url.Values{
		"csrf_token": {csrf}, "action": {"save"},
		"name": {"bump"}, "i": {"0"},
		"definition": {`CREATE PROCEDURE bump(IN lo NOSUCHTYPE) SET @x = 1`},
	})
	if err != nil {
		t.Fatalf("save POST: %v", err)
	}
	body := readBody(t, resp)
	if resp.StatusCode == http.StatusSeeOther {
		t.Fatalf("an invalid definition was accepted")
	}
	if !strings.Contains(body, "restored") {
		t.Errorf("the failure did not report restoring the previous definition:\n%.1500s", body)
	}

	// The whole point: the procedure is still there, and still the original.
	check, err := driver.Open(ctx, d, dbParams)
	if err != nil {
		t.Fatalf("verify connect: %v", err)
	}
	defer check.Close()
	routines, err := check.ListRoutines(ctx, driver.Scope{Database: liveDB})
	if err != nil {
		t.Fatalf("ListRoutines: %v", err)
	}
	if len(routines) != 1 || routines[0].Name != "bump" {
		t.Fatalf("the procedure was destroyed by a failed edit: %+v", routines)
	}
	def, _, err := check.ObjectDefinition(ctx, driver.Scope{Database: liveDB}, driver.ProgramProcedure, "bump")
	if err != nil {
		t.Fatalf("ObjectDefinition: %v", err)
	}
	if !strings.Contains(def, "IN lo INT") {
		t.Errorf("the restored definition is not the original:\n%s", def)
	}
}

// TestLiveMySQLEditRoutineRoundTrip is the success path of the same flow.
func TestLiveMySQLEditRoutineRoundTrip(t *testing.T) {
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
		t.Fatalf("connect: %v", err)
	}
	if _, err := seed.Exec(ctx, `CREATE PROCEDURE bump(IN lo INT, OUT hi INT) SET hi = lo + 1`); err != nil {
		seed.Close()
		t.Fatalf("seed: %v", err)
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

	// The editor must open pre-filled with a REPLAYABLE definition — the whole
	// reason DefinitionViewer exists. A body-only pre-fill would be unsaveable.
	code, page := getBody(t, client, ts.URL+"/db/"+liveDB+"/routines/edit?name=bump&i=0")
	if code != http.StatusOK {
		t.Fatalf("editor = %d, want 200", code)
	}
	shown := html.UnescapeString(page)
	for _, want := range []string{"CREATE", "PROCEDURE", "bump", "IN lo INT"} {
		if !strings.Contains(shown, want) {
			t.Errorf("editor pre-fill is missing %q — it would not save as-is:\n%.1500s", want, page)
		}
	}

	csrf = csrfFrom(t, client, ts.URL+"/")
	resp, err = client.PostForm(ts.URL+"/db/"+liveDB+"/routines", url.Values{
		"csrf_token": {csrf}, "action": {"save"},
		"name": {"bump"}, "i": {"0"},
		"definition": {`CREATE PROCEDURE bump(IN lo INT, OUT hi INT) SET hi = lo + 100`},
	})
	if err != nil {
		t.Fatalf("save POST: %v", err)
	}
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("save = %d, want 303:\n%.1500s", resp.StatusCode, body)
	}

	check, err := driver.Open(ctx, d, dbParams)
	if err != nil {
		t.Fatalf("verify connect: %v", err)
	}
	defer check.Close()
	def, _, err := check.ObjectDefinition(ctx, driver.Scope{Database: liveDB}, driver.ProgramProcedure, "bump")
	if err != nil {
		t.Fatalf("ObjectDefinition: %v", err)
	}
	if !strings.Contains(def, "lo + 100") {
		t.Errorf("the routine was not redefined:\n%s", def)
	}
}
