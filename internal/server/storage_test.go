package server_test

import (
	"context"
	"database/sql"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tablexdev/tablex/internal/config"
	"github.com/tablexdev/tablex/internal/driver"
	"github.com/tablexdev/tablex/internal/server"
)

// These tests cover E4 end to end: with a metadata database configured, a
// session's IDENTITY becomes durable, which is what makes TableX usable behind a
// load balancer and across a restart. What must NOT become durable is the
// payload — the pools and the password — and that is asserted just as explicitly.

// storageServer starts a TableX whose sessions live in a metadata database at
// metaPath, alongside the usual seeded SQLite user database.
func storageServer(t *testing.T, metaPath string) (*httptest.Server, *http.Client) {
	t.Helper()
	ts, client, _ := newTestServerWith(t, func(cfg *config.Config) {
		cfg.Storage = config.StorageConfig{Engine: "sqlite", FilePath: metaPath}
	})
	return ts, client
}

// countMetaSessions reads the metadata database directly, so the assertions are
// about what was really stored rather than about what the store reports.
func countMetaSessions(t *testing.T, metaPath string) int {
	t.Helper()
	d, ok := driver.Get("sqlite")
	if !ok {
		t.Fatal("sqlite dialect is not registered")
	}
	conn, err := driver.Open(context.Background(), d, driver.ConnParams{FilePath: metaPath})
	if err != nil {
		t.Fatalf("open metadata database: %v", err)
	}
	defer conn.Close()
	var n int
	if err := conn.DB().QueryRow(`SELECT COUNT(*) FROM tablex_sessions`).Scan(&n); err != nil {
		if err == sql.ErrNoRows {
			return 0
		}
		t.Fatalf("count stored sessions: %v", err)
	}
	return n
}

// metaColumns returns the column names of the stored sessions table. The point of
// asserting on them is the negative: there must be nowhere for a credential to
// live.
func metaColumns(t *testing.T, metaPath string) []string {
	t.Helper()
	d, _ := driver.Get("sqlite")
	conn, err := driver.Open(context.Background(), d, driver.ConnParams{FilePath: metaPath})
	if err != nil {
		t.Fatalf("open metadata database: %v", err)
	}
	defer conn.Close()
	cols, err := d.Columns(context.Background(), conn.DB(), driver.TableRef{Table: "tablex_sessions"})
	if err != nil {
		t.Fatalf("introspect the sessions table: %v", err)
	}
	out := make([]string, 0, len(cols))
	for _, c := range cols {
		out = append(out, strings.ToLower(c.Name))
	}
	return out
}

// TestDurableSessionsServeRequests is the baseline: turning storage on must not
// change how TableX behaves, only where the session lives.
func TestDurableSessionsServeRequests(t *testing.T) {
	meta := filepath.Join(t.TempDir(), "meta.db")
	ts, client := storageServer(t, meta)

	// A pre-auth session is stored as soon as the login form is rendered — that
	// is the row a second replica needs in order to accept the CSRF token.
	csrfFrom(t, client, ts.URL+"/login")
	if n := countMetaSessions(t, meta); n != 1 {
		t.Fatalf("stored sessions after rendering the login form = %d, want 1", n)
	}

	login(t, client, ts.URL)
	if n := countMetaSessions(t, meta); n != 1 {
		t.Errorf("stored sessions after login = %d, want 1 (the pre-auth row is replaced, not added to)", n)
	}
	if code, body := getBody(t, client, ts.URL+"/db/main/table/widgets"); code != http.StatusOK {
		t.Fatalf("browse with a durable session = %d, want 200\n%.400s", code, body)
	}

	// Logout is authoritative: the row goes.
	csrf := csrfFrom(t, client, ts.URL+"/")
	resp, err := client.PostForm(ts.URL+"/logout", url.Values{"csrf_token": {csrf}})
	if err != nil {
		t.Fatalf("POST /logout: %v", err)
	}
	resp.Body.Close()
	if n := countMetaSessions(t, meta); n != 0 {
		t.Errorf("stored sessions after logout = %d, want 0", n)
	}
}

// TestStoredSessionHasNowhereToKeepACredential is the security assertion, made
// against the real schema rather than against a comment. If a future migration
// adds a password, a DSN or a host column, this fails.
func TestStoredSessionHasNowhereToKeepACredential(t *testing.T) {
	meta := filepath.Join(t.TempDir(), "meta.db")
	ts, client := storageServer(t, meta)
	login(t, client, ts.URL)

	got := metaColumns(t, meta)
	want := map[string]bool{"id": true, "csrf": true, "created": true, "last_seen": true}
	for _, c := range got {
		if !want[c] {
			t.Errorf("the stored session table has an unexpected column %q; the envelope is meant to be id/csrf/created/last_seen and nothing else", c)
		}
	}
	if len(got) != len(want) {
		t.Errorf("stored session columns = %v, want exactly %d of them", got, len(want))
	}

	// And nothing that looks like a credential is anywhere in the file.
	blob, err := os.ReadFile(meta)
	if err != nil {
		t.Fatalf("read the metadata database: %v", err)
	}
	for _, forbidden := range []string{"password", "sslmode", "secret"} {
		if strings.Contains(strings.ToLower(string(blob)), forbidden) {
			t.Errorf("the metadata database contains %q", forbidden)
		}
	}
}

// TestLoginSpansTwoProcesses is the case a durable store exists to fix, and the
// reason the PRE-AUTH session matters more than the authenticated one: the login
// form is rendered by one process and submitted to another.
//
// Without a shared store the second process has never issued that CSRF token, so
// behind a round-robin load balancer every login fails — a 403, not a retry.
func TestLoginSpansTwoProcesses(t *testing.T) {
	pair := newProcessPair(t)

	// Process one renders the form. No login here: a login would replace the
	// pre-auth session, which is exactly what anti-fixation requires.
	client := &http.Client{Jar: pair.jar, CheckRedirect: noRedirect}
	csrf := csrfFrom(t, client, pair.first.URL+"/login")
	cookie := sessionCookie(t, pair.jar, pair.first.URL)

	// Process two receives the submission.
	code, body := postLoginWithCookie(t, pair.second.URL, csrf, cookie)
	if code != http.StatusSeeOther {
		t.Fatalf("login submitted to the other process = %d, want 303 — the CSRF token minted by the first process was rejected\n%.400s", code, body)
	}
}

// TestARestartKeepsTheIdentityButNotThePayload pins both halves of the claim,
// which is where it would be easy to overstate what this feature does.
//
// Kept: the id and the CSRF token, so the cookie in the browser is still a
// session and a form already on screen still validates.
//
// Not kept: the payload. The pools and the password cannot be persisted, so the
// second process shows the login page rather than the browse page — and one
// login rebinds the same cookie to the new process.
func TestARestartKeepsTheIdentityButNotThePayload(t *testing.T) {
	pair := newProcessPair(t)

	client := &http.Client{Jar: pair.jar, CheckRedirect: noRedirect}
	csrfFrom(t, client, pair.first.URL+"/login")
	login(t, client, pair.first.URL)
	authedCSRF := csrfFrom(t, client, pair.first.URL+"/")
	authedCookie := sessionCookie(t, pair.jar, pair.first.URL)
	if code, _ := getBody(t, client, pair.first.URL+"/db/main/table/widgets"); code != http.StatusOK {
		t.Fatalf("fixture: browse on the first process = %d, want 200", code)
	}

	pair.stopFirst(t)
	// The row is still there: a shutdown releases this process's pools, it does
	// not end sessions for whoever serves the next request.
	if n := countMetaSessions(t, pair.meta); n != 1 {
		t.Fatalf("stored sessions after shutdown = %d, want 1", n)
	}

	// The payload is gone, so an authenticated page is refused. (The cookie is
	// carried by hand: the two servers listen on different ports, so a cookie jar
	// would not send it.)
	if code := statusWithCookie(t, pair.second.URL+"/db/main/table/widgets", authedCookie); code == http.StatusOK {
		t.Error("the second process served an authenticated page; the pools and the password must NOT have been persisted")
	}
	// But the identity is intact, so one login rebinds it.
	code, body := postLoginWithCookie(t, pair.second.URL, authedCSRF, authedCookie)
	if code != http.StatusSeeOther {
		t.Errorf("re-login after the restart = %d, want 303 — the surviving session's CSRF token was rejected\n%.400s", code, body)
	}
	if n := countMetaSessions(t, pair.meta); n != 1 {
		t.Errorf("stored sessions after the re-login = %d, want 1 (replaced, not added to)", n)
	}
}

// processPair is two TableX servers over one metadata database and one user
// database — a restart, or two replicas, depending on which the test needs.
type processPair struct {
	first, second *httptest.Server
	jar           http.CookieJar
	meta          string
	stopped       bool
	firstSrv      *server.Server
}

func newProcessPair(t *testing.T) *processPair {
	t.Helper()
	dir := t.TempDir()
	p := &processPair{meta: filepath.Join(dir, "meta.db"), jar: newJar(t)}
	userDB := filepath.Join(dir, "user.db")
	if err := os.WriteFile(userDB, nil, 0o600); err != nil {
		t.Fatalf("create the user database: %v", err)
	}
	seedWidgets(t, userDB)

	cfg := config.Default()
	cfg.Security.LoginRateMax = 1000
	cfg.Servers = []config.ServerConfig{{Name: testServerName, Engine: "sqlite", FilePath: userDB}}
	cfg.Storage = config.StorageConfig{Engine: "sqlite", FilePath: p.meta}
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))

	start := func(which string) (*server.Server, *httptest.Server) {
		srv, err := server.New(cfg, quiet, "test")
		if err != nil {
			t.Fatalf("server.New (%s): %v", which, err)
		}
		return srv, httptest.NewServer(srv.Handler())
	}
	firstSrv, ts1 := start("first")
	secondSrv, ts2 := start("second")
	p.firstSrv, p.first, p.second = firstSrv, ts1, ts2
	t.Cleanup(func() {
		p.stopFirst(t)
		ts2.Close()
		_ = secondSrv.Shutdown(context.Background())
	})
	return p
}

// stopFirst shuts the first process down; calling it twice is a no-op so a test
// can stop it explicitly and still leave the cleanup in place.
func (p *processPair) stopFirst(t *testing.T) {
	t.Helper()
	if p.stopped {
		return
	}
	p.stopped = true
	p.first.Close()
	if err := p.firstSrv.Shutdown(context.Background()); err != nil {
		t.Errorf("shutdown (first): %v", err)
	}
}

// postLoginWithCookie submits the login form with an explicit cookie, which is
// how a request is moved between two servers on different ports.
func postLoginWithCookie(t *testing.T, base, csrf, cookie string) (int, string) {
	t.Helper()
	form := url.Values{"csrf_token": {csrf}, "server": {testServerName}}
	req, err := http.NewRequest("POST", base+"/login", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("build the login request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Cookie", cookie)
	resp, err := (&http.Client{CheckRedirect: noRedirect}).Do(req)
	if err != nil {
		t.Fatalf("POST %s/login: %v", base, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

// --- helpers ------------------------------------------------------------------

// noRedirect makes a client return the 3xx rather than following it, matching
// what newTestServerWith hands back.
func noRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

func newJar(t *testing.T) http.CookieJar {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookie jar: %v", err)
	}
	return jar
}

// seedWidgets puts the same fixture table in a database file that
// newTestServerWith seeds, for the tests that build their own server pair.
func seedWidgets(t *testing.T, path string) {
	t.Helper()
	d, _ := driver.Get("sqlite")
	conn, err := driver.Open(context.Background(), d, driver.ConnParams{FilePath: path})
	if err != nil {
		t.Fatalf("seed open: %v", err)
	}
	defer conn.Close()
	for _, stmt := range []string{
		`CREATE TABLE widgets (id INTEGER PRIMARY KEY, name TEXT NOT NULL, qty INTEGER)`,
		`INSERT INTO widgets (name, qty) VALUES ('bolt', 5)`,
	} {
		if _, err := conn.Exec(context.Background(), stmt); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
}

// sessionCookie returns the session cookie the jar holds for base, formatted for
// a Cookie request header.
func sessionCookie(t *testing.T, jar http.CookieJar, base string) string {
	t.Helper()
	u, err := url.Parse(base)
	if err != nil {
		t.Fatalf("parse %s: %v", base, err)
	}
	for _, c := range jar.Cookies(u) {
		if c.Name == config.Default().Session.CookieName {
			return c.Name + "=" + c.Value
		}
	}
	t.Fatalf("no session cookie for %s", base)
	return ""
}

// statusWithCookie GETs u with an explicit Cookie header (the jar cannot be used
// across two httptest servers on different ports).
func statusWithCookie(t *testing.T, u, cookie string) int {
	t.Helper()
	req, _ := http.NewRequest("GET", u, nil)
	req.Header.Set("Cookie", cookie)
	resp, err := (&http.Client{CheckRedirect: noRedirect}).Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", u, err)
	}
	resp.Body.Close()
	return resp.StatusCode
}
