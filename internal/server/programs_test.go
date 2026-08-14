package server_test

// Dropping stored programs. The interesting cases are the ones where a name is
// not enough to identify the object: PostgreSQL overloads a function name, and
// trigger names are unique per table rather than per schema. Both are addressed
// by list position plus name, which only works while those listings are totally
// ordered — so that is asserted too.

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/tablexdev/tablex/internal/driver"
)

var dropFormRE = regexp.MustCompile(`(?s)<form method="post"[^>]*hx-confirm="([^"]*)"[^>]*>(.*?)</form>`)

// TestDropTriggerFromList is the end-to-end drop: the list renders a form, the
// form posts, the trigger is gone.
func TestDropTriggerFromList(t *testing.T) {
	ts, client, path := newTestServer(t)
	seedSQLiteTriggers(t, path)
	login(t, client, ts.URL)

	code, body := getBody(t, client, ts.URL+"/db/main/triggers")
	if code != http.StatusOK {
		t.Fatalf("triggers page = %d, want 200", code)
	}
	var form string
	for _, m := range dropFormRE.FindAllStringSubmatch(body, -1) {
		if strings.Contains(m[2], `name="name" value="trg_widget_guard"`) {
			form = m[0]
		}
	}
	if form == "" {
		t.Fatalf("no drop form for trg_widget_guard:\n%s", body)
	}
	for _, want := range []string{`name="action" value="drop"`, `name="i" value="1"`, `name="csrf_token"`} {
		if !strings.Contains(form, want) {
			t.Errorf("drop form is missing %q:\n%s", want, form)
		}
	}

	csrf := csrfFrom(t, client, ts.URL+"/")
	resp, err := client.PostForm(ts.URL+"/db/main/triggers", url.Values{
		"csrf_token": {csrf}, "action": {"drop"},
		"name": {"trg_widget_guard"}, "i": {"1"}, "tx_confirm": {"1"},
	})
	if err != nil {
		t.Fatalf("drop POST: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("drop POST = %d, want 303", resp.StatusCode)
	}

	code, body = getBody(t, client, ts.URL+"/db/main/triggers")
	if code != http.StatusOK {
		t.Fatalf("triggers page after drop = %d", code)
	}
	// Match the NAME CELL, not the page. The success flash reads
	// `Trigger "trg_widget_guard" dropped.`, so a bare Contains over the whole
	// body finds the confirmation OF the drop and reports it as a surviving row.
	if listsTrigger(body, "trg_widget_guard") {
		t.Error("the trigger is still listed after the drop")
	}
	// The OTHER trigger must survive: a drop that took the whole list with it
	// would also make the assertion above pass.
	if !listsTrigger(body, "trg_alpha_guard") {
		t.Errorf("the drop removed an unrelated trigger too:\n%s", body)
	}
}

// listsTrigger reports whether name appears as a row in the triggers table,
// rather than anywhere on the page (flash text included).
func listsTrigger(page, name string) bool {
	return strings.Contains(page, `<td class="tx-tbl-name">`+name+`</td>`)
}

// TestDropProgramRejectsStaleRequests: the drop reuses the definition panel's
// addressing rule, so a stale page must not be able to drop the wrong object.
func TestDropProgramRejectsStaleRequests(t *testing.T) {
	ts, client, path := newTestServer(t)
	seedSQLiteTriggers(t, path)
	login(t, client, ts.URL)
	csrf := csrfFrom(t, client, ts.URL+"/")

	for _, tc := range []struct {
		name     string
		form     url.Values
		wantCode int
	}{
		{"name does not match the slot",
			url.Values{"action": {"drop"}, "name": {"trg_alpha_guard"}, "i": {"1"}}, http.StatusConflict},
		{"index past the end",
			url.Values{"action": {"drop"}, "name": {"trg_widget_guard"}, "i": {"99"}}, http.StatusConflict},
		{"unknown action",
			url.Values{"action": {"vaporize"}, "name": {"trg_widget_guard"}, "i": {"1"}}, http.StatusBadRequest},
		{"missing index",
			url.Values{"action": {"drop"}, "name": {"trg_widget_guard"}}, http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := url.Values{"csrf_token": {csrf}}
			for k, v := range tc.form {
				f[k] = v
			}
			resp, err := client.PostForm(ts.URL+"/db/main/triggers", f)
			if err != nil {
				t.Fatalf("POST: %v", err)
			}
			resp.Body.Close()
			if resp.StatusCode != tc.wantCode {
				t.Errorf("= %d, want %d", resp.StatusCode, tc.wantCode)
			}
		})
	}

	// Nothing above may have dropped anything.
	_, body := getBody(t, client, ts.URL+"/db/main/triggers")
	for _, want := range []string{"trg_alpha_guard", "trg_widget_guard"} {
		if !listsTrigger(body, want) {
			t.Errorf("a rejected request still dropped %s", want)
		}
	}
}

// TestDropProgramRequiresCSRF — a destructive route, so the token is mandatory.
func TestDropProgramRequiresCSRF(t *testing.T) {
	ts, client, path := newTestServer(t)
	seedSQLiteTriggers(t, path)
	login(t, client, ts.URL)

	resp, err := client.PostForm(ts.URL+"/db/main/triggers", url.Values{
		"action": {"drop"}, "name": {"trg_widget_guard"}, "i": {"1"},
	})
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("drop without a CSRF token = %d, want 403", resp.StatusCode)
	}
	if _, body := getBody(t, client, ts.URL+"/db/main/triggers"); !listsTrigger(body, "trg_widget_guard") {
		t.Error("the tokenless drop went through")
	}
}

// TestLivePostgresDropOverloadedRoutine is the case model.Routine.ArgSignature
// exists for. Two functions share a name; DROP FUNCTION f fails outright with
// "is not unique", so the drop has to name the one it means by its identity
// arguments — and the listing has to order the two stably, or the row the user
// clicked is not the row the server resolves.
func TestLivePostgresDropOverloadedRoutine(t *testing.T) {
	env := liveEnvFor(t, "POSTGRES", "postgres", 5432, "postgres")
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
	conn, err := driver.Open(ctx, d, dbParams)
	if err != nil {
		t.Fatalf("connect to %s: %v", liveDB, err)
	}
	defer conn.Close()

	for _, s := range []string{
		// text BEFORE integer, deliberately. proname ties for the two twins, so
		// without a tiebreaker PostgreSQL returns them in creation (oid) order and
		// the listing would read text-then-integer. The sorted order is the
		// reverse, so this seeding is what makes the ordering assertion below able
		// to fail — seeded the other way round, oid order and sorted order agree
		// and a missing ORDER BY key is invisible.
		`CREATE FUNCTION twin(a text) RETURNS text LANGUAGE sql AS $$ SELECT a $$`,
		`CREATE FUNCTION twin(a integer) RETURNS integer LANGUAGE sql AS $$ SELECT a $$`,
		`CREATE FUNCTION solo() RETURNS integer LANGUAGE sql AS $$ SELECT 1 $$`,
	} {
		if _, err := conn.Exec(ctx, s); err != nil {
			t.Fatalf("seed %q: %v", s, err)
		}
	}
	scope := driver.Scope{Database: liveDB, Schema: "public"}

	first, err := conn.ListRoutines(ctx, scope)
	if err != nil {
		t.Fatalf("ListRoutines: %v", err)
	}
	if len(first) != 3 {
		t.Fatalf("ListRoutines returned %d routines, want 3", len(first))
	}

	// Identify the two overloads and drop exactly the text one.
	textTwin, intTwin := -1, -1
	for i, r := range first {
		if r.Name != "twin" {
			continue
		}
		switch r.ArgSignature {
		case "a text":
			textTwin = i
		case "a integer":
			intTwin = i
		}
	}
	if textTwin < 0 || intTwin < 0 {
		t.Fatalf("did not find both overloads; got %+v", first)
	}
	// The listing must be TOTALLY ordered, or a row index does not identify a
	// row: the user clicks position 1 and the server resolves whatever position 1
	// happens to be on the next query. "a integer" sorts before "a text", but
	// they were created the other way round, so this fails on proname alone.
	if intTwin > textTwin {
		t.Errorf("overloads are ordered by creation, not by signature: got %s(%s) at %d before %s(%s) at %d — "+
			"row indexes are not stable, so the definition panel and the drop can resolve different objects",
			first[textTwin].Name, first[textTwin].ArgSignature, textTwin,
			first[intTwin].Name, first[intTwin].ArgSignature, intTwin)
	}
	if err := conn.DropRoutine(ctx, scope, first[textTwin]); err != nil {
		t.Fatalf("DropRoutine(twin(text)): %v", err)
	}

	after, err := conn.ListRoutines(ctx, scope)
	if err != nil {
		t.Fatalf("ListRoutines after drop: %v", err)
	}
	var names []string
	for _, r := range after {
		names = append(names, r.Name+"("+r.ArgSignature+")")
	}
	if len(after) != 2 {
		t.Fatalf("after dropping one overload, %d routines remain: %v", len(after), names)
	}
	for _, r := range after {
		if r.Name == "twin" && r.ArgSignature == "a text" {
			t.Errorf("the wrong overload survived: %v", names)
		}
	}
	if !strings.Contains(strings.Join(names, " "), "twin(a integer)") {
		t.Errorf("dropping twin(text) also removed twin(integer): %v", names)
	}

	// A zero-argument routine renders as name(), which must also work.
	for _, r := range after {
		if r.Name == "solo" {
			if r.ArgSignature != "" {
				t.Fatalf("solo should take no arguments, got %q", r.ArgSignature)
			}
			if err := conn.DropRoutine(ctx, scope, r); err != nil {
				t.Errorf("DropRoutine(solo()): %v", err)
			}
		}
	}
}

// TestLivePostgresDropTriggerNeedsItsTable — PostgreSQL names a trigger by its
// table, and two tables may carry the same trigger name.
func TestLivePostgresDropTriggerNeedsItsTable(t *testing.T) {
	env := liveEnvFor(t, "POSTGRES", "postgres", 5432, "postgres")
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
	conn, err := driver.Open(ctx, d, dbParams)
	if err != nil {
		t.Fatalf("connect to %s: %v", liveDB, err)
	}
	defer conn.Close()

	for _, s := range []string{
		`CREATE TABLE a (id int)`,
		`CREATE TABLE b (id int)`,
		`CREATE FUNCTION noop() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END $$`,
		// Same trigger NAME on two tables — legal here, and the reason tgname
		// alone can neither identify nor order a trigger. Created on b FIRST so
		// creation order and sorted order disagree; seeded a-then-b, the missing
		// ORDER BY key would be invisible.
		`CREATE TRIGGER stamp BEFORE INSERT ON b FOR EACH ROW EXECUTE FUNCTION noop()`,
		`CREATE TRIGGER stamp BEFORE INSERT ON a FOR EACH ROW EXECUTE FUNCTION noop()`,
	} {
		if _, err := conn.Exec(ctx, s); err != nil {
			t.Fatalf("seed %q: %v", s, err)
		}
	}
	scope := driver.Scope{Database: liveDB, Schema: "public"}

	triggers, err := conn.ListTriggers(ctx, scope)
	if err != nil {
		t.Fatalf("ListTriggers: %v", err)
	}
	if len(triggers) != 2 {
		t.Fatalf("ListTriggers returned %d, want 2", len(triggers))
	}
	// Sorted by table, not by creation: b's trigger was created first, so this
	// fails whenever tgname is the only ORDER BY key.
	if triggers[0].Table != "a" || triggers[1].Table != "b" {
		t.Fatalf("same-named triggers are ordered by creation, not by table (%+v); "+
			"row indexes into this list would not be stable", triggers)
	}

	// Drop the one on b; a's must survive.
	var onB int = -1
	for i, tr := range triggers {
		if tr.Table == "b" {
			onB = i
		}
	}
	if err := conn.DropTrigger(ctx, scope, triggers[onB]); err != nil {
		t.Fatalf("DropTrigger: %v", err)
	}
	left, err := conn.ListTriggers(ctx, scope)
	if err != nil {
		t.Fatalf("ListTriggers after drop: %v", err)
	}
	if len(left) != 1 || left[0].Table != "a" {
		t.Fatalf("wrong trigger dropped; remaining: %+v", left)
	}
}

func TestLiveMySQLDropPrograms(t *testing.T) {
	liveDropPrograms(t, liveEnvFor(t, "MYSQL", "mysql", 3306, "root"))
}

func TestLiveMariaDBDropPrograms(t *testing.T) {
	liveDropPrograms(t, liveEnvFor(t, "MARIADB", "mysql", 3306, "root"))
}

// liveDropPrograms covers the one engine that has all three program kinds.
func liveDropPrograms(t *testing.T, env liveEnv) {
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
	conn, err := driver.Open(ctx, d, dbParams)
	if err != nil {
		t.Fatalf("connect to %s: %v", liveDB, err)
	}
	defer conn.Close()

	for _, s := range []string{
		`CREATE TABLE t (id INT AUTO_INCREMENT PRIMARY KEY, note VARCHAR(32))`,
		`CREATE PROCEDURE bump(IN lo INT, OUT hi INT) SET hi = lo + 1`,
		`CREATE FUNCTION dbl(a INT) RETURNS INT DETERMINISTIC RETURN a * 2`,
		`CREATE TRIGGER trg BEFORE INSERT ON t FOR EACH ROW SET NEW.note = 'x'`,
		`CREATE EVENT ev ON SCHEDULE EVERY 1 DAY DO SET @x = 1`,
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
		t.Fatalf("want 2 routines, got %d", len(routines))
	}
	// Drop the PROCEDURE and confirm the FUNCTION survives: the two need
	// different statements, so a builder that always says one of them would
	// either error or take the wrong object.
	for _, r := range routines {
		if strings.EqualFold(r.Type, "PROCEDURE") {
			if err := conn.DropRoutine(ctx, scope, r); err != nil {
				t.Fatalf("DropRoutine(%s): %v", r.Name, err)
			}
		}
	}
	left, err := conn.ListRoutines(ctx, scope)
	if err != nil {
		t.Fatalf("ListRoutines after drop: %v", err)
	}
	if len(left) != 1 || !strings.EqualFold(left[0].Type, "FUNCTION") {
		t.Fatalf("after dropping the procedure, remaining = %+v", left)
	}
	if err := conn.DropRoutine(ctx, scope, left[0]); err != nil {
		t.Fatalf("DropRoutine(function): %v", err)
	}

	triggers, err := conn.ListTriggers(ctx, scope)
	if err != nil || len(triggers) != 1 {
		t.Fatalf("ListTriggers = %+v, %v", triggers, err)
	}
	if err := conn.DropTrigger(ctx, scope, triggers[0]); err != nil {
		t.Fatalf("DropTrigger: %v", err)
	}

	events, err := conn.ListEvents(ctx, scope)
	if err != nil || len(events) != 1 {
		t.Fatalf("ListEvents = %+v, %v", events, err)
	}
	if err := conn.DropEvent(ctx, scope, events[0]); err != nil {
		t.Fatalf("DropEvent: %v", err)
	}

	for _, check := range []struct {
		what string
		n    func() int
	}{
		{"routines", func() int { rs, _ := conn.ListRoutines(ctx, scope); return len(rs) }},
		{"triggers", func() int { ts, _ := conn.ListTriggers(ctx, scope); return len(ts) }},
		{"events", func() int { es, _ := conn.ListEvents(ctx, scope); return len(es) }},
	} {
		if got := check.n(); got != 0 {
			t.Errorf("%d %s left after dropping them all", got, check.what)
		}
	}
}
