package server_test

import (
	"bufio"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tablexdev/tablex/internal/audit"
	"github.com/tablexdev/tablex/internal/config"
)

// These tests cover E2 end to end. The action log's whole claim is that it is
// complete BY CONSTRUCTION — emitted from one middleware rather than from each
// mutating handler — so what is asserted is that ordinary use produces the
// records, and that nothing which could be replayed to gain access is among them.

// auditServer starts a TableX writing its audit trail to a JSON Lines file, and
// returns the path.
func auditServer(t *testing.T) (base string, client *http.Client, auditPath string) {
	t.Helper()
	auditPath = filepath.Join(t.TempDir(), "audit.jsonl")
	ts, client, _ := newTestServerWith(t, func(cfg *config.Config) {
		cfg.Audit = config.AuditConfig{File: auditPath}
	})
	return ts.URL, client, auditPath
}

// auditEvents reads the trail. It tolerates a missing file as "no events", so a
// test that expects none does not have to special-case it.
func auditEvents(t *testing.T, path string) []audit.Event {
	t.Helper()
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatalf("open the audit trail: %v", err)
	}
	defer f.Close()
	var out []audit.Event
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4<<20)
	for sc.Scan() {
		if strings.TrimSpace(sc.Text()) == "" {
			continue
		}
		var e audit.Event
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			t.Fatalf("audit line is not valid JSON (%v): %s", err, sc.Text())
		}
		out = append(out, e)
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("read the audit trail: %v", err)
	}
	return out
}

// TestUserTypedDCLPasswordNeverReachesTheTrail: the account FORMS redact their
// passwords via StatementEvent.Redact needles, but DCL the user TYPES — the
// SQL console, an imported script — carries none, because nothing upstream
// knows which literal inside the typed statement is the secret. The trail's
// contract (docs/security.md §7, audit.Event) is absolute: nothing recorded
// can be replayed to gain access. The grammar-shaped scrub in the statement
// observer must mask the literal while keeping the statement itself recorded —
// redaction, not omission. SQLite refuses CREATE USER, which is irrelevant
// here and also exactly the trap: the ERROR text echoes the statement, so both
// the statement and the detail must come out masked.
func TestUserTypedDCLPasswordNeverReachesTheTrail(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	ts, client, _ := newTestServerWith(t, func(cfg *config.Config) {
		cfg.Audit = config.AuditConfig{File: auditPath, Statements: true}
	})
	base := ts.URL
	login(t, client, base)
	csrf := csrfFrom(t, client, base+"/")

	// Both password-carrying CREATE USER grammars a user actually types: the
	// plain form and MySQL 8's plugin form, whose literal follows WITH … BY.
	// Each posts under its own account marker so the assertions below can find
	// each statement event unambiguously.
	forms := []struct{ name, marker, sql, secret string }{
		{"identified by", "app_plain",
			"CREATE USER app_plain IDENTIFIED BY 'hunter2-console-x9'", "hunter2-console-x9"},
		{"identified with by", "app_plugin",
			"CREATE USER app_plugin IDENTIFIED WITH caching_sha2_password BY 'hunter2-plugin-x7'", "hunter2-plugin-x7"},
	}
	for _, form := range forms {
		resp := postForm(t, client, base+"/db/main/sql", url.Values{
			"csrf_token": {csrf},
			"sql_query":  {form.sql},
		})
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: console POST = %d, want 200", form.name, resp.StatusCode)
		}
	}

	raw, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("read the trail: %v", err)
	}
	events := auditEvents(t, auditPath)
	for _, form := range forms {
		if strings.Contains(string(raw), form.secret) {
			t.Fatalf("%s: the typed DCL password reached the trail:\n%s", form.name, raw)
		}
		var stmt *audit.Event
		for _, e := range events {
			if e.Kind == audit.KindStatement && strings.Contains(e.Statement, form.marker) {
				ev := e
				stmt = &ev
			}
		}
		if stmt == nil {
			t.Fatalf("%s: the typed DCL left no statement event — redaction must not become omission", form.name)
		}
		if !strings.Contains(stmt.Statement, "'***'") {
			t.Errorf("%s: statement not masked: %q", form.name, stmt.Statement)
		}
		if !stmt.UserSQL {
			t.Errorf("%s: the console statement lost its UserSQL mark: %+v", form.name, stmt)
		}
		if stmt.Detail != "" && strings.Contains(stmt.Detail, form.secret) {
			t.Errorf("%s: the engine error echoed the password into the detail: %q", form.name, stmt.Detail)
		}
	}
}

// firstOf returns the first event matching kind and (when non-empty) path.
func firstOf(events []audit.Event, kind audit.Kind, path string) (audit.Event, bool) {
	for _, e := range events {
		if e.Kind == kind && (path == "" || e.Path == path) {
			return e, true
		}
	}
	return audit.Event{}, false
}

// TestAuditRecordsALoginAndAMutation is the walkthrough: log in, change
// something, log out, and read the trail back.
func TestAuditRecordsALoginAndAMutation(t *testing.T) {
	base, client, path := auditServer(t)

	login(t, client, base)
	csrf := csrfFrom(t, client, base+"/")

	// A mutation with a target: truncate the seeded table.
	//
	// Every POST in this file goes through postForm, which does not return until
	// the server has finished the request — the action records asserted below are
	// emitted by the outermost middleware after the response has begun.
	resp := postForm(t, client, base+"/db/main/table/widgets/operations",
		url.Values{"csrf_token": {csrf}, "action": {"truncate"}, "tx_confirm": {"1"}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("truncate = %d, want 303", resp.StatusCode)
	}

	postForm(t, client, base+"/logout", url.Values{"csrf_token": {csrf}})

	events := auditEvents(t, path)
	if len(events) == 0 {
		t.Fatal("the audit trail is empty after a login, a mutation and a logout")
	}

	// The login.
	in, ok := firstOf(events, audit.KindAuth, "/login")
	if !ok {
		t.Fatal("no auth event for the login")
	}
	if in.Outcome != audit.OutcomeOK {
		t.Errorf("login outcome = %q, want ok", in.Outcome)
	}
	if in.Server != testServerName {
		t.Errorf("login server = %q, want %q", in.Server, testServerName)
	}
	if in.Engine != "sqlite" {
		t.Errorf("login engine = %q, want sqlite", in.Engine)
	}
	if in.Remote == "" {
		t.Error("login event records no client address")
	}

	// The mutation, with the object named in engine-neutral dotted form so the
	// trail can be queried by object rather than by URL.
	act, ok := firstOf(events, audit.KindAction, "/db/main/table/widgets/operations")
	if !ok {
		t.Fatalf("no action event for the truncate; got %+v", events)
	}
	if act.Target != "main.widgets" {
		t.Errorf("action target = %q, want main.widgets", act.Target)
	}
	if act.Status != http.StatusSeeOther || act.Outcome != audit.OutcomeOK {
		t.Errorf("action status/outcome = %d/%q, want 303/ok", act.Status, act.Outcome)
	}
	if act.Method != "POST" {
		t.Errorf("action method = %q", act.Method)
	}
	if act.Request == "" {
		t.Error("action event carries no request id, so it cannot be tied to the access log")
	}
	// The identity on an ACTION event is the load-bearing part of the Pending
	// mechanism: it is learned by a middleware several layers below the one that
	// emits the event, and each layer passes on a request whose context the
	// emitter never sees. SQLite has no accounts, so the account field is
	// legitimately empty here — the server and engine are what prove the
	// identity crossed the chain, and a live engine asserts the account itself
	// (TestLiveAuditRecordsTheServerReportedAccount).
	if act.Server != testServerName {
		t.Errorf("action server = %q, want %q — the identity never reached the emitting middleware", act.Server, testServerName)
	}
	if act.Engine != "sqlite" {
		t.Errorf("action engine = %q, want sqlite", act.Engine)
	}

	// The logout.
	if out, ok := firstOf(events, audit.KindAuth, "/logout"); !ok {
		t.Error("no auth event for the logout")
	} else if out.Outcome != audit.OutcomeOK {
		t.Errorf("logout outcome = %q", out.Outcome)
	}
}

// TestAuditRecordsARejectedLogin is the event a status code describes worst: a
// rejected login re-renders the form, so the response is an ordinary page.
func TestAuditRecordsARejectedLogin(t *testing.T) {
	base, client, path := auditServer(t)
	csrf := csrfFrom(t, client, base+"/login")

	postForm(t, client, base+"/login",
		url.Values{"csrf_token": {csrf}, "server": {"no-such-server"}, "username": {"intruder"}})

	events := auditEvents(t, path)
	e, ok := firstOf(events, audit.KindAuth, "/login")
	if !ok {
		t.Fatalf("a rejected login was not recorded; got %+v", events)
	}
	if e.Outcome != audit.OutcomeDenied {
		t.Errorf("rejected login outcome = %q, want denied", e.Outcome)
	}
	if e.Account != "intruder" {
		t.Errorf("rejected login account = %q, want the username that was tried", e.Account)
	}
	if e.Detail == "" {
		t.Error("rejected login records no reason")
	}
}

// TestAuditSkipsReads keeps the trail readable: a GET changes nothing, and
// recording every page view would bury the events that matter under navigation.
func TestAuditSkipsReads(t *testing.T) {
	base, client, path := auditServer(t)
	login(t, client, base)
	for _, u := range []string{"/", "/db/main", "/db/main/table/widgets", "/server/status"} {
		if code, _ := getBody(t, client, base+u); code != http.StatusOK {
			t.Fatalf("GET %s = %d", u, code)
		}
	}
	for _, e := range auditEvents(t, path) {
		if e.Method == "GET" {
			t.Errorf("a GET was recorded in the audit trail: %+v", e)
		}
	}
}

// TestAuditOutcomeReflectsSemanticFailure (#13): the wire status can be
// misleading by design — renderError's htmx arm answers 200 so the panel
// swaps, and an error-flash redirect answers 303 — so a mutating POST that
// FAILED used to be filed outcome=ok. renderError and redirectTo now record
// the SEMANTIC outcome (IfUnset, so a policy layer's pre-set denial always
// wins), and an ordinary successful mutation still reads ok.
func TestAuditOutcomeReflectsSemanticFailure(t *testing.T) {
	base, client, path := auditServer(t)
	login(t, client, base)
	csrf := csrfFrom(t, client, base+"/")

	// (a) htmx mutation that fails: wire 200, semantic 400 → invalid.
	form := url.Values{"csrf_token": {csrf}, "action": {"bogus"}}
	req, _ := http.NewRequest(http.MethodPost, base+"/db/main/table/widgets/operations", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("HX-Request", "true")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("htmx POST: %v", err)
	}
	drainBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("htmx error = wire %d, want 200 (the panel swap) — this test needs the misleading wire status", resp.StatusCode)
	}

	// (b) error-flash redirect: a view's structure cannot be edited; the
	// refusal answers with a 303 + error flash. The view is created through
	// the console first (a normal, successful mutation → outcome ok).
	resp = postForm(t, client, base+"/db/main/sql", url.Values{"csrf_token": {csrf}, "sql_query": {"CREATE VIEW v1 AS SELECT * FROM widgets"}})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("console CREATE VIEW = %d, want 200", resp.StatusCode)
	}
	resp = postForm(t, client, base+"/db/main/table/v1/structure", url.Values{
		"csrf_token": {csrf}, "action": {"add_column"},
		"col_name": {"x"}, "col_type": {"TEXT"}, "col_nullable": {"1"}, "default_mode": {"none"},
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("view structure edit = %d, want 303 (error-flash redirect)", resp.StatusCode)
	}

	// (c) an ordinary successful mutation still reads ok.
	resp = postForm(t, client, base+"/db/main/table/widgets/operations",
		url.Values{"csrf_token": {csrf}, "action": {"truncate"}, "tx_confirm": {"1"}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("truncate = %d, want 303", resp.StatusCode)
	}

	byPath := map[string][]audit.Outcome{}
	for _, e := range auditEvents(t, path) {
		if e.Kind == audit.KindAction {
			byPath[e.Path] = append(byPath[e.Path], e.Outcome)
		}
	}
	if got := byPath["/db/main/table/widgets/operations"]; len(got) != 2 || got[0] != audit.OutcomeInvalid || got[1] != audit.OutcomeOK {
		t.Errorf("widgets/operations outcomes = %v, want [invalid ok] (htmx failure then truncate)", got)
	}
	if got := byPath["/db/main/table/v1/structure"]; len(got) != 1 || got[0] != audit.OutcomeInvalid {
		t.Errorf("view-structure outcomes = %v, want [invalid] (error-flash redirect)", got)
	}
	if got := byPath["/db/main/sql"]; len(got) != 1 || got[0] != audit.OutcomeOK {
		t.Errorf("console outcomes = %v, want [ok]", got)
	}
}

// TestAuditOutcomePolicyDenialWins: restricted mode pre-sets OutcomeDenied
// before the generic responder runs; the IfUnset write must not clobber it —
// on the htmx arm either, where the wire status is 200.
func TestAuditOutcomePolicyDenialWins(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	ts, client, _ := newTestServerWith(t, func(cfg *config.Config) {
		cfg.Audit = config.AuditConfig{File: auditPath}
		cfg.Restrict.ReadOnly = true
	})
	login(t, client, ts.URL)
	csrf := csrfFrom(t, client, ts.URL+"/")

	form := url.Values{"csrf_token": {csrf}, "action": {"truncate"}, "tx_confirm": {"1"}}
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/db/main/table/widgets/operations", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("HX-Request", "true")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("htmx POST: %v", err)
	}
	drainBody(t, resp)

	var outcomes []audit.Outcome
	for _, e := range auditEvents(t, auditPath) {
		if e.Kind == audit.KindAction {
			outcomes = append(outcomes, e.Outcome)
		}
	}
	if len(outcomes) != 1 || outcomes[0] != audit.OutcomeDenied {
		t.Errorf("read-only refusal outcomes = %v, want [denied] — the generic responder must not clobber the pre-set denial", outcomes)
	}
}

// drainBody reads resp to EOF and closes it — the barrier that orders the
// middleware's audit emit before the trail is read (see postForm).
func drainBody(t *testing.T, resp *http.Response) {
	t.Helper()
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		t.Fatalf("drain: %v", err)
	}
	resp.Body.Close()
}

// TestAuditRecordsCSRFRejectedLogin: auditAction skips /login (the login
// handler emits its own auth event) and the csrf middleware's 403 used to
// emit nothing — so a CSRF-rejected POST /login, the one shape a forged or
// replayed login form takes, produced NO audit event at all. The csrf layer
// now records an explicit denied auth event for exactly that path.
func TestAuditRecordsCSRFRejectedLogin(t *testing.T) {
	base, client, path := auditServer(t)
	resp := postForm(t, client, base+"/login", url.Values{
		"csrf_token": {"forged-token"}, "server": {testServerName},
	})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("forged-token login = %d, want 403 — the CSRF check did not fire, so this proves nothing", resp.StatusCode)
	}
	var found bool
	for _, e := range auditEvents(t, path) {
		if e.Kind == audit.KindAuth && e.Path == "/login" && e.Outcome == audit.OutcomeDenied {
			found = true
			if e.Detail == "" {
				t.Error("the CSRF denial event carries no detail")
			}
		}
	}
	if !found {
		t.Errorf("a CSRF-rejected POST /login left no denied auth event: %+v", auditEvents(t, path))
	}
}

// TestAuditNeverRecordsASecret is the security assertion, made against the whole
// file rather than field by field: nothing in the trail may be replayable.
func TestAuditNeverRecordsASecret(t *testing.T) {
	const password = "unmistakable-password-4Kx9"
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	ts, client, dbPath := newTestServerWith(t, func(cfg *config.Config) {
		cfg.Audit = config.AuditConfig{File: auditPath}
	})

	// An ad-hoc login attempt carrying a password, plus a predefined-server login
	// that succeeds, plus a mutation — so the trail has every kind of event in it.
	csrf := csrfFrom(t, client, ts.URL+"/login")
	postForm(t, client, ts.URL+"/login", url.Values{
		"csrf_token": {csrf}, "engine": {"sqlite"}, "file": {dbPath},
		"username": {"someone"}, "password": {password},
	})

	login(t, client, ts.URL)
	sessionCSRF := csrfFrom(t, client, ts.URL+"/")
	postForm(t, client, ts.URL+"/db/main/table/widgets/operations",
		url.Values{"csrf_token": {sessionCSRF}, "action": {"truncate"}, "tx_confirm": {"1"}})

	raw, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("read the audit trail: %v", err)
	}
	body := string(raw)
	if len(body) == 0 {
		t.Fatal("the audit trail is empty, so this test proves nothing")
	}
	for _, forbidden := range []struct{ what, value string }{
		{"the posted password", password},
		{"the session CSRF token", sessionCSRF},
		{"the pre-auth CSRF token", csrf},
	} {
		if strings.Contains(body, forbidden.value) {
			t.Errorf("the audit trail contains %s", forbidden.what)
		}
	}
	// The session cookie is the bearer credential; it must not be in there either.
	u, _ := url.Parse(ts.URL)
	for _, c := range client.Jar.Cookies(u) {
		if c.Value != "" && strings.Contains(body, c.Value) {
			t.Errorf("the audit trail contains the session cookie value (cookie %q)", c.Name)
		}
	}
}

// TestAuditOffByDefault: with no [audit] block nothing is written and nothing is
// asked of the filesystem.
func TestAuditOffByDefault(t *testing.T) {
	ts, client, _ := newTestServer(t)
	login(t, client, ts.URL)
	csrf := csrfFrom(t, client, ts.URL+"/")
	resp := postForm(t, client, ts.URL+"/db/main/table/widgets/operations",
		url.Values{"csrf_token": {csrf}, "action": {"truncate"}, "tx_confirm": {"1"}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Errorf("a mutation with auditing off = %d, want 303 — turning it off must not change behaviour", resp.StatusCode)
	}
}

// statementServer starts a TableX with statement auditing on.
func statementServer(t *testing.T) (base string, client *http.Client, auditPath string) {
	t.Helper()
	auditPath = filepath.Join(t.TempDir(), "audit.jsonl")
	ts, client, _ := newTestServerWith(t, func(cfg *config.Config) {
		cfg.Audit = config.AuditConfig{File: auditPath, Statements: true}
	})
	return ts.URL, client, auditPath
}

// statementsIn returns the statement records, in order.
func statementsIn(events []audit.Event) []audit.Event {
	var out []audit.Event
	for _, e := range events {
		if e.Kind == audit.KindStatement {
			out = append(out, e)
		}
	}
	return out
}

// TestAuditRecordsRowDML: with audit.statements on, the parameterized row
// paths record their statements — SQL text only, never the bound row values.
// They used to bypass the observer entirely via the bare pool, so the trail
// recorded DDL but no row-level data change at all. (The observed Tx,
// rollback-marker and prepared-aggregate contracts are pinned in
// internal/driver's TestObservedRowDML; this is the end-to-end wiring.)
func TestAuditRecordsRowDML(t *testing.T) {
	base, client, path := statementServer(t)
	login(t, client, base)
	csrf := csrfFrom(t, client, base+"/")
	const cell = "unmistakable-cell-7Qp"

	resp := postForm(t, client, base+"/db/main/table/widgets/insert", url.Values{
		"csrf_token": {csrf}, "v_name": {cell}, "v_qty": {"7"},
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("insert = %d, want 303 — nothing ran, so this proves nothing", resp.StatusCode)
	}

	var found bool
	for _, e := range statementsIn(auditEvents(t, path)) {
		if strings.Contains(e.Statement, "INSERT INTO") && strings.Contains(e.Statement, "widgets") {
			found = true
		}
		if strings.Contains(e.Statement, cell) || strings.Contains(e.Detail, cell) {
			t.Errorf("a bound row value leaked into the statement trail: %+v", e)
		}
	}
	if !found {
		t.Error("the row INSERT never reached the statement trail (the bare-pool bypass is back)")
	}
}

// TestAuditRecordsGeneratedSQL: the action log says a POST happened to a path;
// only the statement log says WHAT it did. This is the pair that makes the trail
// answer "who changed my database".
func TestAuditRecordsGeneratedSQL(t *testing.T) {
	base, client, path := statementServer(t)
	login(t, client, base)
	csrf := csrfFrom(t, client, base+"/")

	resp := postForm(t, client, base+"/db/main/table/widgets/structure",
		url.Values{
			"csrf_token": {csrf}, "action": {"add_column"},
			"col_name": {"note"}, "col_type": {"TEXT"}, "col_nullable": {"1"}, "default_mode": {"none"},
		})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("add_column = %d, want 303 — the fixture never changed anything, so this proves nothing", resp.StatusCode)
	}

	stmts := statementsIn(auditEvents(t, path))
	if len(stmts) == 0 {
		t.Fatalf("no statement was recorded for a structure change; got %+v", auditEvents(t, path))
	}
	var found bool
	for _, s := range stmts {
		if strings.Contains(strings.ToUpper(s.Statement), "ALTER TABLE") && strings.Contains(s.Statement, "note") {
			found = true
			if s.UserSQL {
				t.Error("SQL TableX generated is marked as user-authored")
			}
			if s.Outcome != audit.OutcomeOK {
				t.Errorf("statement outcome = %q, want ok", s.Outcome)
			}
			if s.Request == "" {
				t.Error("statement record carries no request id, so it cannot be tied to its action record")
			}
		}
	}
	if !found {
		t.Errorf("the ALTER TABLE that added the column was not recorded; got %+v", stmts)
	}
}

// TestAuditMarksUserAuthoredSQL: reading "DROP TABLE orders" in the trail, the
// first thing worth knowing is whether a person typed it or a button generated
// it.
func TestAuditMarksUserAuthoredSQL(t *testing.T) {
	base, client, path := statementServer(t)
	login(t, client, base)
	csrf := csrfFrom(t, client, base+"/")

	const typed = "SELECT name FROM widgets WHERE qty > 1"
	postForm(t, client, base+"/db/main/sql", url.Values{"csrf_token": {csrf}, "sql_query": {typed}})

	var got *audit.Event
	for _, s := range statementsIn(auditEvents(t, path)) {
		if strings.Contains(s.Statement, "SELECT name FROM widgets") {
			got = &s
		}
	}
	if got == nil {
		t.Fatalf("the console statement was not recorded; got %+v", statementsIn(auditEvents(t, path)))
	}
	if !got.UserSQL {
		t.Error("a statement typed into the console is not marked as user-authored")
	}
	// A read on a PINNED connection is recorded, unlike a generated browse read:
	// a pinned connection exists only to run the user's own script.
	if got.Rows < 0 {
		t.Errorf("the console read recorded rows = %d, want the number scanned", got.Rows)
	}
}

// TestAuditSkipsGeneratedReads is the other half of that rule, and the reason the
// trail stays readable: browsing a table runs SELECTs, counts and introspection
// that TableX generated for its own rendering, and none of them is a user action.
func TestAuditSkipsGeneratedReads(t *testing.T) {
	base, client, path := statementServer(t)
	login(t, client, base)
	for _, u := range []string{"/db/main", "/db/main/table/widgets", "/db/main/table/widgets/structure"} {
		if code, _ := getBody(t, client, base+u); code != http.StatusOK {
			t.Fatalf("GET %s = %d", u, code)
		}
	}
	for _, s := range statementsIn(auditEvents(t, path)) {
		if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(s.Statement)), "SELECT") {
			t.Errorf("a generated read was recorded: %q", s.Statement)
		}
	}
}

// TestAuditRecordsAFailedStatement: an ATTEMPTED change matters as much as one
// that worked, and its record must say so.
func TestAuditRecordsAFailedStatement(t *testing.T) {
	base, client, path := statementServer(t)
	login(t, client, base)
	csrf := csrfFrom(t, client, base+"/")

	postForm(t, client, base+"/db/main/sql",
		url.Values{"csrf_token": {csrf}, "sql_query": {"DROP TABLE no_such_table_here"}})

	var got *audit.Event
	for _, s := range statementsIn(auditEvents(t, path)) {
		if strings.Contains(s.Statement, "no_such_table_here") {
			got = &s
		}
	}
	if got == nil {
		t.Fatalf("a failed statement was not recorded; got %+v", statementsIn(auditEvents(t, path)))
	}
	if got.Outcome != audit.OutcomeError {
		t.Errorf("failed statement outcome = %q, want error", got.Outcome)
	}
	if got.Detail == "" {
		t.Error("failed statement records no reason")
	}
}

// TestStatementAuditingIsOptional: the rest of the trail is useful without the SQL
// text, which can carry row data — so the switch has to actually switch.
func TestStatementAuditingIsOptional(t *testing.T) {
	base, client, path := auditServer(t) // Statements not set
	login(t, client, base)
	csrf := csrfFrom(t, client, base+"/")
	postForm(t, client, base+"/db/main/table/widgets/operations",
		url.Values{"csrf_token": {csrf}, "action": {"truncate"}, "tx_confirm": {"1"}})

	events := auditEvents(t, path)
	if len(statementsIn(events)) != 0 {
		t.Errorf("statements were recorded with audit.statements off: %+v", statementsIn(events))
	}
	// The action record is still there — that is the point of the switch.
	if _, ok := firstOf(events, audit.KindAction, "/db/main/table/widgets/operations"); !ok {
		t.Error("turning statement auditing off also lost the action record")
	}
}
