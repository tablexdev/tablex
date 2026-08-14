package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"html"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/tablexdev/tablex/internal/config"
	"github.com/tablexdev/tablex/internal/driver"
	_ "github.com/tablexdev/tablex/internal/driver/mysql"
	_ "github.com/tablexdev/tablex/internal/driver/postgres"
	_ "github.com/tablexdev/tablex/internal/driver/sqlite"
	"github.com/tablexdev/tablex/internal/server"
)

var csrfRE = regexp.MustCompile(`csrf-token" content="([^"]+)"`)

// testServerName is the predefined SQLite server the test suite logs in through
// (ad-hoc SQLite login is disabled; SQLite is reachable only via a configured
// server).
const testServerName = "testdb"

// newTestServer seeds a temp SQLite DB and returns a running httptest server
// plus a cookie-jar client and the DB path.
func newTestServer(t *testing.T) (*httptest.Server, *http.Client, string) {
	return newTestServerWith(t, nil)
}

// newTestServerWith is newTestServer with a hook to tweak the config before the
// server starts (e.g. to disable ad-hoc login for the login-form tests).
func newTestServerWith(t *testing.T, mutate func(*config.Config)) (*httptest.Server, *http.Client, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "web_test.db")
	// BuildDSN no longer auto-creates a missing file; start from an empty one
	// (a zero-byte file is a valid empty SQLite database).
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("create temp db file: %v", err)
	}
	d, _ := driver.Get("sqlite")
	conn, err := driver.Open(context.Background(), d, driver.ConnParams{FilePath: path})
	if err != nil {
		t.Fatalf("seed open: %v", err)
	}
	ctx := context.Background()
	for _, s := range []string{
		`CREATE TABLE widgets (id INTEGER PRIMARY KEY, name TEXT NOT NULL, qty INTEGER)`,
		`INSERT INTO widgets (name, qty) VALUES ('bolt', 5)`,
		`INSERT INTO widgets (name, qty) VALUES ('nut', 12)`,
	} {
		if _, err := conn.Exec(ctx, s); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	conn.Close()

	cfg := config.Default()
	cfg.Security.LoginRateMax = 1000
	// SQLite is reachable only via a predefined server; expose the seeded file.
	cfg.Servers = []config.ServerConfig{{Name: testServerName, Engine: "sqlite", FilePath: path}}
	if mutate != nil {
		mutate(&cfg)
	}
	srv, err := server.New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), "test")
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	// Close pools (and free the temp SQLite file) before TempDir cleanup runs.
	t.Cleanup(func() { ts.Close(); _ = srv.Shutdown(context.Background()) })
	jar, _ := cookiejar.New(nil)
	return ts, &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, path
}

// csrfFrom extracts the CSRF token from a page that renders the meta tag. Use
// /login before auth and / (home) after auth (the login page redirects once
// authenticated).
func csrfFrom(t *testing.T, client *http.Client, fullURL string) string {
	t.Helper()
	resp, err := client.Get(fullURL)
	if err != nil {
		t.Fatalf("GET %s: %v", fullURL, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	m := csrfRE.FindStringSubmatch(string(b))
	if len(m) < 2 || m[1] == "" {
		t.Fatalf("no CSRF token on %s", fullURL)
	}
	return m[1]
}

// postForm POSTs a form and returns the response with its body already read to
// EOF and closed.
//
// The drain is a BARRIER, not tidiness. A test that reads a side effect the
// server produces after the handler returns — chiefly the action record the
// logging middleware emits once it knows the final status — cannot rely on
// PostForm having returned: PostForm returns when the response HEADERS arrive,
// and any response larger than net/http's 2 KiB write buffer (every rendered
// page, once gzip has dropped Content-Length and made the response chunked) is
// on the wire while the handler is still running. Reading to EOF is what orders
// the two: the terminating chunk is written by finishRequest, which runs after
// every middleware — the audit emitter included — has returned.
//
// Not a hypothetical: the live audit tests failed on CI exactly here, finding
// only the login event because the console POST's action record had not been
// written yet when the trail was read.
func postForm(t *testing.T, client *http.Client, u string, form url.Values) *http.Response {
	t.Helper()
	resp, err := client.PostForm(u, form)
	if err != nil {
		t.Fatalf("POST %s: %v", u, err)
	}
	defer resp.Body.Close()
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		t.Fatalf("POST %s: reading the response body: %v", u, err)
	}
	return resp
}

func login(t *testing.T, client *http.Client, base string) {
	t.Helper()
	csrf := csrfFrom(t, client, base+"/login")
	form := url.Values{"csrf_token": {csrf}, "server": {testServerName}}
	resp := postForm(t, client, base+"/login", form)
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("login status = %d, want 303", resp.StatusCode)
	}
}

func getBody(t *testing.T, client *http.Client, u string) (int, string) {
	t.Helper()
	resp, err := client.Get(u)
	if err != nil {
		t.Fatalf("GET %s: %v", u, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// getResp GETs u for tests that inspect status/headers only. It fails the
// test on a transport error — the old `resp, _ := client.Get(...)` pattern
// nil-dereferenced resp on error — and closes the (unread) body.
func getResp(t *testing.T, client *http.Client, u string) *http.Response {
	t.Helper()
	resp, err := client.Get(u)
	if err != nil {
		t.Fatalf("GET %s: %v", u, err)
	}
	resp.Body.Close()
	return resp
}

func TestHealthz(t *testing.T) {
	ts, client, _ := newTestServer(t)
	code, body := getBody(t, client, ts.URL+"/healthz")
	if code != 200 || strings.TrimSpace(body) != "ok" {
		t.Errorf("healthz = %d %q", code, body)
	}
}

// TestNavTreeFragment covers the sidebar-refresh endpoint (Theme L): GET /nav
// returns the top-level database tree fragment so a structural change can
// re-sync the sidebar. Unauthenticated access is refused.
func TestNavTreeFragment(t *testing.T) {
	ts, client, _ := newTestServer(t)

	// Before auth, /nav is refused.
	resp0 := getResp(t, client, ts.URL+"/nav")
	if resp0.StatusCode == http.StatusOK {
		t.Error("GET /nav should require auth")
	}

	login(t, client, ts.URL)
	code, body := getBody(t, client, ts.URL+"/nav")
	if code != http.StatusOK {
		t.Fatalf("GET /nav = %d, want 200", code)
	}
	if !strings.Contains(body, "tx-tree-root") || !strings.Contains(body, "main") {
		t.Errorf("nav fragment missing the tree/database node:\n%s", body)
	}
}

// TestStaticAssetETag covers Theme K: an embedded static asset carries a content
// ETag and long cache lifetime, and a matching If-None-Match revalidates to 304
// (no re-download) instead of fully re-fetching after max-age.
func TestStaticAssetETag(t *testing.T) {
	ts, client, _ := newTestServer(t)
	const path = "/static/css/tablex.css"

	resp, err := client.Get(ts.URL + path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("GET %s = %d, want 200", path, resp.StatusCode)
	}
	etag := resp.Header.Get("ETag")
	if etag == "" {
		t.Fatal("static asset missing an ETag")
	}
	if cc := resp.Header.Get("Cache-Control"); !strings.Contains(cc, "max-age=") {
		t.Errorf("static Cache-Control = %q, want a max-age", cc)
	}

	req, _ := http.NewRequest("GET", ts.URL+path, nil)
	req.Header.Set("If-None-Match", etag)
	resp2, err := client.Do(req)
	if err != nil {
		t.Fatalf("conditional GET: %v", err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusNotModified {
		t.Errorf("conditional GET with matching ETag = %d, want 304", resp2.StatusCode)
	}
}

// TestStaticUnknownPaths404 covers 2.3: /static/ serves ONLY enumerated real
// files. Directory paths (which http.FileServerFS would answer with an
// unauthenticated rendered listing), unknown paths, and the vendor MANIFEST
// (exact vendored versions + upstream URLs — provenance for the repo/binary,
// not for the network) all 404, while real assets keep serving.
func TestStaticUnknownPaths404(t *testing.T) {
	ts, client, _ := newTestServer(t)
	for _, path := range []string{
		"/static/",
		"/static/vendor/",
		"/static/css/",
		"/static/vendor/MANIFEST",
		"/static/no-such-file.css",
	} {
		resp, err := client.Get(ts.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", path, resp.StatusCode)
		}
	}
	resp, err := client.Get(ts.URL + "/static/vendor/bootstrap/bootstrap.min.css")
	if err != nil {
		t.Fatalf("GET real asset: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("real vendored asset = %d, want 200", resp.StatusCode)
	}
}

func TestUnauthenticatedRedirects(t *testing.T) {
	ts, client, _ := newTestServer(t)
	resp := getResp(t, client, ts.URL+"/")
	if resp.StatusCode != http.StatusSeeOther {
		t.Errorf("anonymous / = %d, want redirect", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/login" {
		t.Errorf("redirect to %q, want /login", loc)
	}
}

func TestSecurityHeaders(t *testing.T) {
	ts, client, _ := newTestServer(t)
	resp := getResp(t, client, ts.URL+"/login")
	csp := resp.Header.Get("Content-Security-Policy")
	if !strings.Contains(csp, "script-src 'self'") || strings.Contains(csp, "unsafe-eval") {
		t.Errorf("CSP missing or unsafe: %q", csp)
	}
	if resp.Header.Get("X-Frame-Options") != "DENY" {
		t.Error("missing X-Frame-Options: DENY")
	}
	if resp.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Error("missing nosniff")
	}
}

func TestLoginAndBrowse(t *testing.T) {
	ts, client, _ := newTestServer(t)
	login(t, client, ts.URL)

	code, home := getBody(t, client, ts.URL+"/")
	if code != 200 || !strings.Contains(home, "SQLite") {
		t.Fatalf("home = %d, contains SQLite=%v", code, strings.Contains(home, "SQLite"))
	}

	code, browse := getBody(t, client, ts.URL+"/db/main/table/widgets")
	if code != 200 {
		t.Fatalf("browse status = %d", code)
	}
	if !strings.Contains(browse, "bolt") || !strings.Contains(browse, "nut") {
		t.Error("browse should list seeded rows")
	}
	if !strings.Contains(browse, "Showing") {
		t.Error("browse should show pagination bar")
	}
}

// TestInsertShowsInBrowse: an inserted row appears on the browse page.
// (Deletion is covered by TestBrowseRowDeleteRoundTrip.)
func TestInsertShowsInBrowse(t *testing.T) {
	ts, client, _ := newTestServer(t)
	login(t, client, ts.URL)
	csrf := csrfFrom(t, client, ts.URL+"/")

	// Insert a row.
	resp, err := client.PostForm(ts.URL+"/db/main/table/widgets/insert",
		url.Values{"csrf_token": {csrf}, "v_name": {"washer"}, "v_qty": {"99"}})
	if err != nil {
		t.Fatalf("insert: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("insert status = %d", resp.StatusCode)
	}

	_, browse := getBody(t, client, ts.URL+"/db/main/table/widgets")
	if !strings.Contains(browse, "washer") {
		t.Error("inserted row should appear in browse")
	}
}

// TestNoJSMutationFlash pins afterMutation's no-JS fallback: a full-page
// (non-htmx) row mutation must store its flash before the 303 so the
// confirmation survives the redirect to the browse page — htmx passes the
// flash inline, but the plain-form fallback used to drop it.
func TestNoJSMutationFlash(t *testing.T) {
	ts, client, _ := newTestServer(t)
	login(t, client, ts.URL)
	csrf := csrfFrom(t, client, ts.URL+"/")

	// client.PostForm sends no HX-Request header — this is the no-JS path.
	resp, err := client.PostForm(ts.URL+"/db/main/table/widgets/insert",
		url.Values{"csrf_token": {csrf}, "v_name": {"grommet"}, "v_qty": {"7"}})
	if err != nil {
		t.Fatalf("insert: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("insert status = %d, want 303", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if loc == "" {
		t.Fatal("insert redirect carries no Location")
	}

	code, browse := getBody(t, client, ts.URL+loc)
	if code != http.StatusOK {
		t.Fatalf("browse after redirect = %d, want 200", code)
	}
	if !strings.Contains(browse, "Row inserted.") || !strings.Contains(browse, "tx-alert-success") {
		t.Error("browse page after the no-JS redirect should show the success flash")
	}
	// The flash is one-shot: a reload must not repeat it.
	_, again := getBody(t, client, ts.URL+loc)
	if strings.Contains(again, "Row inserted.") {
		t.Error("flash should be consumed by the first page load")
	}
}

func TestCSRFRejected(t *testing.T) {
	ts, client, _ := newTestServer(t)
	login(t, client, ts.URL)
	// POST without a token must be rejected.
	resp, err := client.PostForm(ts.URL+"/db/main/table/widgets/insert",
		url.Values{"v_name": {"x"}})
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("missing CSRF token = %d, want 403", resp.StatusCode)
	}
}

// TestExpiredSessionPostRedirectsToLogin covers the CSRF/auth-gate interplay
// for expired sessions: the CSRF middleware runs BEFORE the auth gate, so a
// POST from a session with no app payload (the state a reaped session
// presents) used to dead-end in 403. It must route to login instead — 303 for
// full-page, 401 + HX-Redirect for htmx — while /login itself and
// authenticated token mismatches keep the plain 403.
func TestExpiredSessionPostRedirectsToLogin(t *testing.T) {
	ts, client, _ := newTestServer(t)
	// Prime the jar with a fresh, payload-less session.
	resp0, err := client.Get(ts.URL + "/login")
	if err != nil {
		t.Fatalf("prime session: %v", err)
	}
	resp0.Body.Close()

	resp, err := client.PostForm(ts.URL+"/db/main/table/widgets/insert", url.Values{"v_name": {"x"}})
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/login" {
		t.Errorf("full-page expired POST = %d loc=%q, want 303 to /login",
			resp.StatusCode, resp.Header.Get("Location"))
	}

	req, _ := http.NewRequest("POST", ts.URL+"/db/main/table/widgets/insert", strings.NewReader("v_name=x"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("HX-Request", "true")
	resp2, err := client.Do(req)
	if err != nil {
		t.Fatalf("htmx post: %v", err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusUnauthorized || resp2.Header.Get("HX-Redirect") != "/login" {
		t.Errorf("htmx expired POST = %d HX-Redirect=%q, want 401 with /login",
			resp2.StatusCode, resp2.Header.Get("HX-Redirect"))
	}

	// Login CSRF protection stays intact: a pre-auth session legitimately has
	// no payload, but forging a login must still be refused outright.
	resp3, err := client.PostForm(ts.URL+"/login", url.Values{"server": {testServerName}})
	if err != nil {
		t.Fatalf("login post: %v", err)
	}
	resp3.Body.Close()
	if resp3.StatusCode != http.StatusForbidden {
		t.Errorf("login POST without token = %d, want 403", resp3.StatusCode)
	}
}

// TestTableRenameWithSpace covers the new-identifier policy end to end: names
// with spaces are legal once quoted and were already browsable, so renaming to
// one must work; injection-shaped names stay refused.
func TestTableRenameWithSpace(t *testing.T) {
	ts, client, _ := newTestServer(t)
	login(t, client, ts.URL)
	csrf := csrfFrom(t, client, ts.URL+"/")

	resp, err := client.PostForm(ts.URL+"/db/main/table/widgets/operations",
		url.Values{"csrf_token": {csrf}, "action": {"rename"}, "new_name": {"my widgets"}})
	if err != nil {
		t.Fatalf("rename post: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("rename = %d, want 303", resp.StatusCode)
	}
	code, body := getBody(t, client, ts.URL+"/db/main/table/"+url.PathEscape("my widgets"))
	if code != 200 || !strings.Contains(body, "bolt") {
		t.Errorf("renamed table browse = %d; rows visible = %v", code, strings.Contains(body, "bolt"))
	}

	// Injection-shaped names are still refused before any SQL is built.
	resp2, err := client.PostForm(ts.URL+"/db/main/table/"+url.PathEscape("my widgets")+"/operations",
		url.Values{"csrf_token": {csrf}, "action": {"rename"}, "new_name": {`x";DROP TABLE "y`}})
	if err != nil {
		t.Fatalf("bad rename post: %v", err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusBadRequest {
		t.Errorf("injection-shaped rename = %d, want 400", resp2.StatusCode)
	}
}

// TestAdHocSQLiteRejected confirms SQLite cannot be opened via an ad-hoc login:
// it has no credentials, so that would be unauthenticated arbitrary file access.
// Ad-hoc login is enabled in the test config, so this exercises the
// SQLite-specific guard, not the ad-hoc-disabled path.
func TestAdHocSQLiteRejected(t *testing.T) {
	ts, client, dbPath := newTestServer(t)
	csrf := csrfFrom(t, client, ts.URL+"/login")
	resp, err := client.PostForm(ts.URL+"/login",
		url.Values{"csrf_token": {csrf}, "engine": {"sqlite"}, "file": {dbPath}})
	if err != nil {
		t.Fatalf("login post: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusSeeOther {
		t.Fatal("ad-hoc SQLite login should be rejected, got 303 (logged in)")
	}
	// It must not have established a session: home still redirects to /login.
	resp2 := getResp(t, client, ts.URL+"/")
	if resp2.StatusCode != http.StatusSeeOther || resp2.Header.Get("Location") != "/login" {
		t.Errorf("after rejected ad-hoc SQLite, / = %d loc=%q, want redirect to /login",
			resp2.StatusCode, resp2.Header.Get("Location"))
	}
}

// TestPredefinedSQLiteIgnoresPostedFile confirms a predefined SQLite server uses
// only the operator-configured path: a posted `file` (here a bogus path that
// would fail to open) is ignored, so login still succeeds against the seeded DB.
func TestPredefinedSQLiteIgnoresPostedFile(t *testing.T) {
	ts, client, _ := newTestServer(t)
	csrf := csrfFrom(t, client, ts.URL+"/login")
	resp, err := client.PostForm(ts.URL+"/login", url.Values{
		"csrf_token": {csrf}, "server": {testServerName},
		"file": {filepath.Join(t.TempDir(), "attacker-controlled.db")},
	})
	if err != nil {
		t.Fatalf("login post: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("predefined SQLite login status = %d, want 303 (posted file ignored)", resp.StatusCode)
	}
	// The session targets the seeded DB (widgets table), not the posted file.
	code, browse := getBody(t, client, ts.URL+"/db/main/table/widgets")
	if code != http.StatusOK || !strings.Contains(browse, "bolt") {
		t.Errorf("browse after predefined login = %d, seeded data present=%v", code, strings.Contains(browse, "bolt"))
	}
}

// TestHTMXErrorRendersAt200 confirms a failed action surfaces to the user:
// for an htmx request the error panel comes back as a 200 retargeted to
// #page_content (htmx won't swap a 4xx) with no out-of-band chrome that would
// blank the breadcrumb/tabs; for a full-page request the real 4xx is kept with
// an HTML content type.
func TestHTMXErrorRendersAt200(t *testing.T) {
	ts, client, _ := newTestServer(t)
	login(t, client, ts.URL)
	csrf := csrfFrom(t, client, ts.URL+"/")

	form := url.Values{"csrf_token": {csrf}, "action": {"frobnicate"}}
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/db/main/table/widgets/structure", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("HX-Request", "true")
	req.Header.Set("X-CSRF-Token", csrf)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("htmx post: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("htmx error status = %d, want 200 (so htmx swaps it)", resp.StatusCode)
	}
	if got := resp.Header.Get("HX-Retarget"); got != "#page_content" {
		t.Errorf("HX-Retarget = %q, want #page_content", got)
	}
	if !strings.Contains(string(body), "Unknown operation") {
		t.Errorf("htmx error body missing the message:\n%s", body)
	}
	if strings.Contains(string(body), "hx-swap-oob") {
		t.Error("htmx error must not emit OOB chrome (would blank breadcrumb/tabs)")
	}

	// The same error as a full-page request keeps the real 4xx with an HTML
	// content type (not octet-stream under the global nosniff header).
	resp2, err := client.PostForm(ts.URL+"/db/main/table/widgets/structure", form)
	if err != nil {
		t.Fatalf("full-page post: %v", err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusBadRequest {
		t.Errorf("full-page error status = %d, want 400", resp2.StatusCode)
	}
	if ct := resp2.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("full-page error Content-Type = %q, want text/html", ct)
	}
}

// TestBrowsePageSizeClamped confirms a hostile/zero page size is bounded rather
// than crashing or driving a huge query (and that rows=0 can't divide-by-zero).
func TestBrowsePageSizeClamped(t *testing.T) {
	ts, client, _ := newTestServer(t)
	login(t, client, ts.URL)
	// A page size beyond the largest allowed option (500) must clamp to 500 and
	// never echo the raw value into the selector — observable even on a 2-row
	// table via the rendered <option ... selected>.
	code, body := getBody(t, client, ts.URL+"/db/main/table/widgets?rows=99999999&pos=0")
	if code != http.StatusOK {
		t.Fatalf("browse with a huge page size = %d, want 200 (clamped)", code)
	}
	if !strings.Contains(body, `value="500" selected`) {
		t.Errorf("over-limit page size did not clamp to 500:\n%s", body)
	}
	if strings.Contains(body, "99999999") {
		t.Errorf("raw over-limit page size leaked into the page")
	}
	// A valid mid option is honored — proving the selector reflects the request,
	// so the clamp above is a real change and not a constant.
	if _, body := getBody(t, client, ts.URL+"/db/main/table/widgets?rows=100"); !strings.Contains(body, `value="100" selected`) {
		t.Errorf("rows=100 not reflected as the selected page size:\n%s", body)
	}
	if code, _ := getBody(t, client, ts.URL+"/db/main/table/widgets?rows=0"); code != http.StatusOK {
		t.Errorf("browse with rows=0 = %d, want 200 (no divide-by-zero)", code)
	}
}

// TestImportRejectsTooLargeBody confirms an upload past the import cap is refused
// with 413 (the MaxBytesReader DoS guard), not accepted or spilled to disk.
func TestImportRejectsTooLargeBody(t *testing.T) {
	ts, client, _ := newTestServer(t)
	login(t, client, ts.URL)
	csrf := csrfFrom(t, client, ts.URL+"/")

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	_ = mw.WriteField("csrf_token", csrf)
	_ = mw.WriteField("format", "csv")
	fw, _ := mw.CreateFormFile("file", "big.csv")
	fw.Write(bytes.Repeat([]byte("a"), 33<<20)) // 33 MiB > the 32 MiB import cap
	mw.Close()

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/db/main/table/widgets/import", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("X-CSRF-Token", csrf)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("oversized import post: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized import = %d, want 413", resp.StatusCode)
	}
}

// TestImportCapEnforcedNoCSRFHeader is the Regression: a no-JS import POST
// carries its CSRF token in the form field (not the X-CSRF-Token header), so the
// csrf middleware parses the whole multipart body to read the token. Before the
// fix that parse ran under the looser 64 MiB global cap, so a body between 32 and
// 64 MiB slipped past the 32 MiB import cap (the handler's own MaxBytesReader then
// no-opped because the form was already parsed). With limitBody made route-aware,
// the 32 MiB cap applies *before* csrf parses, so the body is rejected. Asserting
// a bare 413 would be wrong: on the no-JS path the cap is hit while csrf reads the
// token, yielding an empty token and a 403 — so accept 403 *or* 413.
func TestImportCapEnforcedNoCSRFHeader(t *testing.T) {
	ts, client, _ := newTestServer(t)
	login(t, client, ts.URL)
	csrf := csrfFrom(t, client, ts.URL+"/")

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	_ = mw.WriteField("csrf_token", csrf) // token in the form field, not a header
	_ = mw.WriteField("format", "csv")
	fw, _ := mw.CreateFormFile("file", "big.csv")
	fw.Write(bytes.Repeat([]byte("a"), 33<<20)) // 33 MiB: over the 32 MiB import cap, under the 64 MiB global cap
	mw.Close()

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/db/main/table/widgets/import", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	// Deliberately NO X-CSRF-Token header: this is the no-JS full-page-form path.
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("oversized no-header import post: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden && resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized no-header import = %d, want 403 or 413 (import cap enforced before/at handler)", resp.StatusCode)
	}
}

// --- WS-3: pre-auth body cap + two-stage login throttling -----------------------

// TestPreAuthLoginBodyCapped: an unauthenticated /login POST with an oversized
// body (> the 1 MiB pre-auth cap) is bounded before the 64 MiB authenticated cap
// ever applies. With a valid token in the X-CSRF-Token header the request passes
// CSRF and Login's own parse hits the cap → 413; with the token only inside the
// oversized body the csrf-side bounded parse hits the cap first, the token reads
// empty → 403.
func TestPreAuthLoginBodyCapped(t *testing.T) {
	ts, client, _ := newTestServer(t)
	csrf := csrfFrom(t, client, ts.URL+"/login") // primes the pre-auth session cookie
	big := strings.Repeat("a", 2<<20)            // 2 MiB > 1 MiB pre-auth cap

	// Token in header → passes CSRF, Login.ParseForm hits the cap → 413.
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/login", strings.NewReader("pad="+big))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-CSRF-Token", csrf)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("header-token login: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized pre-auth login (header token) = %d, want 413", resp.StatusCode)
	}

	// Token only in the oversized body → csrf-side bounded parse hits the cap,
	// the token reads empty → 403.
	req2, _ := http.NewRequest(http.MethodPost, ts.URL+"/login", strings.NewReader("csrf_token="+csrf+"&pad="+big))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp2, err := client.Do(req2)
	if err != nil {
		t.Fatalf("body-token login: %v", err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusForbidden {
		t.Errorf("oversized pre-auth login (body token) = %d, want 403", resp2.StatusCode)
	}
}

// TestAuthenticatedConsoleBodyAbovePreAuthCap guards against over-tightening: a
// logged-in SQL console POST larger than the 1 MiB pre-auth cap must NOT be
// rejected (the authenticated cap is 64 MiB), so large pasted scripts keep
// working.
func TestAuthenticatedConsoleBodyAbovePreAuthCap(t *testing.T) {
	ts, client, _ := newTestServer(t)
	login(t, client, ts.URL)
	csrf := csrfFrom(t, client, ts.URL+"/")

	// A valid single statement padded past 1 MiB via a trailing comment.
	body := url.Values{"sql_query": {"SELECT 1 -- " + strings.Repeat("a", 2<<20)}}.Encode()
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/db/main/sql", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-CSRF-Token", csrf)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("large console post: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusRequestEntityTooLarge {
		t.Errorf("2 MiB authenticated console POST = 413, want it accepted (authed cap is 64 MiB)")
	}
}

// TestUnauthProtectedLargeBodyRedirects: an unauthenticated POST to a protected
// route redirects to /login before the body is ever parsed — no 413, no parse —
// because the auth gate would redirect it anyway.
func TestUnauthProtectedLargeBodyRedirects(t *testing.T) {
	ts, client, _ := newTestServer(t)
	// Prime a payload-less session (unauthenticated).
	resp0, _ := client.Get(ts.URL + "/login")
	if resp0 != nil {
		resp0.Body.Close()
	}
	body := "v_name=" + strings.Repeat("a", 2<<20)
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/db/main/table/widgets/insert", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("unauth protected post: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/login" {
		t.Errorf("unauth protected large POST = %d loc=%q, want 303 to /login (no parse/413)",
			resp.StatusCode, resp.Header.Get("Location"))
	}
}

// TestConsoleMultipartCSRFInBody exercises the H3 multipart dispatch end-to-end:
// a well-formed multipart console POST whose CSRF token rides the form body (no
// header) passes the csrf-side bounded parse and reaches the handler, which reads
// sql_query from the parsed multipart form.
func TestConsoleMultipartCSRFInBody(t *testing.T) {
	ts, client, _ := newTestServer(t)
	login(t, client, ts.URL)
	csrf := csrfFrom(t, client, ts.URL+"/")

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	_ = mw.WriteField("csrf_token", csrf)
	_ = mw.WriteField("sql_query", "SELECT name FROM widgets ORDER BY name")
	mw.Close()

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/db/main/sql", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	// No X-CSRF-Token header: the token must be found via the multipart body parse.
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("multipart console post: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusForbidden {
		t.Fatalf("multipart body-token console POST rejected as forbidden (token not found in multipart body)")
	}
	if !strings.Contains(string(b), "bolt") {
		t.Errorf("console did not execute the multipart-carried query (no results): %d", resp.StatusCode)
	}
}

// --- structure editing ----------------------------------------------------------

// inspectConn opens a fresh pool on the same SQLite file for out-of-band
// introspection (asserting that a structure op did/didn't change the schema).
func inspectConn(t *testing.T, dbPath string) *driver.Connection {
	t.Helper()
	d, _ := driver.Get("sqlite")
	conn, err := driver.Open(context.Background(), d, driver.ConnParams{FilePath: dbPath})
	if err != nil {
		t.Fatalf("inspect open: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

func columnNames(t *testing.T, dbPath, table string) []string {
	t.Helper()
	cols, err := inspectConn(t, dbPath).Columns(context.Background(), driver.TableRef{Database: "main", Table: table})
	if err != nil {
		t.Fatalf("introspect columns of %s: %v", table, err)
	}
	var out []string
	for _, c := range cols {
		out = append(out, c.Name)
	}
	return out
}

func indexNames(t *testing.T, dbPath, table string) []string {
	t.Helper()
	idxs, err := inspectConn(t, dbPath).Indexes(context.Background(), driver.TableRef{Database: "main", Table: table})
	if err != nil {
		t.Fatalf("introspect indexes of %s: %v", table, err)
	}
	var out []string
	for _, i := range idxs {
		out = append(out, i.Name)
	}
	return out
}

// structPost posts a structure-edit form to a table and returns the status code.
func structPost(t *testing.T, client *http.Client, base, table string, form url.Values) int {
	t.Helper()
	resp, err := client.PostForm(base+"/db/main/table/"+table+"/structure", form)
	if err != nil {
		t.Fatalf("structure POST: %v", err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

// TestStructureSQLiteLiveOps drives the real handler stack for the operations
// SQLite supports (add/drop column, add/drop index) and verifies each via
// introspection.
func TestStructureSQLiteLiveOps(t *testing.T) {
	ts, client, dbPath := newTestServer(t)
	login(t, client, ts.URL)
	csrf := csrfFrom(t, client, ts.URL+"/")

	// Add a nullable column.
	if code := structPost(t, client, ts.URL, "widgets", url.Values{
		"csrf_token": {csrf}, "action": {"add_column"},
		"col_name": {"color"}, "col_type": {"TEXT"}, "col_nullable": {"1"}, "default_mode": {"none"},
	}); code != http.StatusSeeOther {
		t.Fatalf("add_column status = %d, want 303", code)
	}
	if !slices.Contains(columnNames(t, dbPath, "widgets"), "color") {
		t.Error("color column should exist after add_column")
	}

	// Add an index on it.
	if code := structPost(t, client, ts.URL, "widgets", url.Values{
		"csrf_token": {csrf}, "action": {"add_index"}, "index_name": {"idx_color"}, "index_columns": {"color"},
	}); code != http.StatusSeeOther {
		t.Fatalf("add_index status = %d, want 303", code)
	}
	if !slices.Contains(indexNames(t, dbPath, "widgets"), "idx_color") {
		t.Error("idx_color should exist after add_index")
	}

	// Drop the index.
	if code := structPost(t, client, ts.URL, "widgets", url.Values{
		"csrf_token": {csrf}, "action": {"drop_index"}, "index_name": {"idx_color"}, "tx_confirm": {"1"},
	}); code != http.StatusSeeOther {
		t.Fatalf("drop_index status = %d, want 303", code)
	}
	if slices.Contains(indexNames(t, dbPath, "widgets"), "idx_color") {
		t.Error("idx_color should be gone after drop_index")
	}

	// Drop the column (no index/PK/FK references it now).
	if code := structPost(t, client, ts.URL, "widgets", url.Values{
		"csrf_token": {csrf}, "action": {"drop_column"}, "column": {"color"}, "tx_confirm": {"1"},
	}); code != http.StatusSeeOther {
		t.Fatalf("drop_column status = %d, want 303", code)
	}
	if slices.Contains(columnNames(t, dbPath, "widgets"), "color") {
		t.Error("color column should be gone after drop_column")
	}
}

// TestCreateTableSQLite drives the create-table form through the real handler
// stack (SQLite implements SchemaEditor, so this runs on every go test): the
// GET renders the fixed batch of indexed rows, a POST with a blank middle row
// skips it (the no-JS fallback), and the created table is verified via
// introspection — including the PRIMARY KEY. Invalid submissions get clean
// 400s before any SQL runs.
func TestCreateTableSQLite(t *testing.T) {
	ts, client, dbPath := newTestServer(t)
	login(t, client, ts.URL)
	csrf := csrfFrom(t, client, ts.URL+"/")

	code, body := getBody(t, client, ts.URL+"/db/main/create-table")
	if code != http.StatusOK || !strings.Contains(body, "col_name_0") || !strings.Contains(body, "col_name_7") {
		t.Fatalf("create-table GET = %d, indexed rows rendered = %v",
			code, strings.Contains(body, "col_name_0"))
	}
	// The structure page links to the form.
	if _, structure := getBody(t, client, ts.URL+"/db/main"); !strings.Contains(structure, "/db/main/create-table") {
		t.Error("db structure page should link to the create-table form")
	}

	post := func(form url.Values) int {
		t.Helper()
		form.Set("csrf_token", csrf)
		resp, err := client.PostForm(ts.URL+"/db/main/create-table", form)
		if err != nil {
			t.Fatalf("POST create-table: %v", err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}

	// Row 1 is left blank on purpose — the fixed 8-row form always submits its
	// empty rows and they must be skipped, not rejected. The PK column also has
	// its nullable checkbox set, to prove a PK is forced NOT NULL regardless.
	if code := post(url.Values{
		"table_name": {"gadgets"},
		"col_name_0": {"id"}, "col_type_0": {"INTEGER"}, "col_pk_0": {"1"}, "col_nullable_0": {"1"},
		"col_name_2": {"label"}, "col_type_2": {"TEXT"}, "col_nullable_2": {"1"},
		"col_name_3": {"made"}, "col_type_3": {"DATETIME"}, "default_mode_3": {"current"},
	}); code != http.StatusSeeOther {
		t.Fatalf("create-table POST = %d, want 303", code)
	}
	cols, err := inspectConn(t, dbPath).Columns(context.Background(), driver.TableRef{Database: "main", Table: "gadgets"})
	if err != nil {
		t.Fatalf("introspect gadgets: %v", err)
	}
	names := make([]string, len(cols))
	pkOK := false
	for i, c := range cols {
		names[i] = c.Name
		if c.Name == "id" {
			if c.IsPrimaryKey {
				pkOK = true
			}
			if c.Nullable {
				t.Error("a PRIMARY KEY column must be NOT NULL even when the nullable box is checked")
			}
		}
	}
	if want := []string{"id", "label", "made"}; !slices.Equal(names, want) {
		t.Errorf("gadgets columns = %v, want %v (blank row skipped, order kept)", names, want)
	}
	if !pkOK {
		t.Error("id should be the primary key")
	}

	// Clean rejections: duplicate table, no columns, hostile column name, PK
	// checkbox on a blank (skipped) row only.
	for name, form := range map[string]url.Values{
		"existing table name": {"table_name": {"widgets"}, "col_name_0": {"id"}, "col_type_0": {"INTEGER"}},
		"no columns":          {"table_name": {"empty1"}},
		"invalid column name": {"table_name": {"bad1"}, "col_name_0": {"a;b"}, "col_type_0": {"INTEGER"}},
		"invalid table name":  {"table_name": {"x;y"}, "col_name_0": {"id"}, "col_type_0": {"INTEGER"}},
	} {
		if code := post(form); code != http.StatusBadRequest {
			t.Errorf("%s: POST = %d, want 400", name, code)
		}
	}
}

// TestStructurePageRendersEditUI verifies the Structure GET page renders the
// edit controls and gates them by capability: SQLite supports add/drop column
// and index, but not column modify or foreign-key DDL, so those are hidden.
func TestStructurePageRendersEditUI(t *testing.T) {
	ts, client, _ := newTestServer(t)
	login(t, client, ts.URL)
	code, body := getBody(t, client, ts.URL+"/db/main/table/widgets/structure")
	if code != http.StatusOK {
		t.Fatalf("structure GET = %d, want 200", code)
	}
	for _, want := range []string{"Add column", "Add index"} {
		if !strings.Contains(body, want) {
			t.Errorf("structure page missing %q control", want)
		}
	}
	if strings.Contains(body, "Modify column") {
		t.Error("SQLite structure page should not offer Modify column")
	}
	if strings.Contains(body, "Add foreign key") {
		t.Error("SQLite structure page should not offer Add foreign key")
	}
}

// TestStructureValidationRejections drives the handler with invalid inputs and
// asserts each is rejected (4xx or a flash redirect) with no schema change.
func TestStructureValidationRejections(t *testing.T) {
	ts, client, dbPath := newTestServer(t)
	login(t, client, ts.URL)
	csrf := csrfFrom(t, client, ts.URL+"/")

	base := url.Values{"csrf_token": {csrf}}
	with := func(extra url.Values) url.Values {
		v := url.Values{}
		for k, vs := range base {
			v[k] = vs
		}
		for k, vs := range extra {
			v[k] = vs
		}
		return v
	}

	cases := []struct {
		name string
		form url.Values
	}{
		{"unknown action", with(url.Values{"action": {"frobnicate"}})},
		{"bad base type", with(url.Values{"action": {"add_column"}, "col_name": {"x"}, "col_type": {"NOTATYPE"}})},
		{"malformed length", with(url.Values{"action": {"add_column"}, "col_name": {"x"}, "col_type": {"TEXT"}, "col_length": {"abc"}})},
		// Names with spaces are legal now (ValidNewIdentifier); the invalid
		// fixture must carry a genuinely rejected character (backtick).
		{"invalid new column name", with(url.Values{"action": {"add_column"}, "col_name": {"bad`name"}, "col_type": {"TEXT"}, "col_nullable": {"1"}})},
		{"drop unknown column", with(url.Values{"action": {"drop_column"}, "column": {"nope"}})},
		{"drop unknown index", with(url.Values{"action": {"drop_index"}, "index_name": {"nope"}})},
		{"drop primary index", with(url.Values{"action": {"drop_index"}, "index_name": {"PRIMARY"}})},
		{"modify unsupported on sqlite", with(url.Values{"action": {"modify_column"}, "column": {"name"}, "col_type": {"TEXT"}})},
		{"fk unsupported on sqlite", with(url.Values{"action": {"add_fk"}, "fk_name": {"f"}, "fk_columns": {"qty"}, "fk_ref_table": {"widgets"}, "fk_ref_columns": {"id"}})},
		{"sqlite current default guard", with(url.Values{"action": {"add_column"}, "col_name": {"ts"}, "col_type": {"DATETIME"}, "col_nullable": {"1"}, "default_mode": {"current"}})},
		{"sqlite not-null without default", with(url.Values{"action": {"add_column"}, "col_name": {"req"}, "col_type": {"TEXT"}})},
	}

	want := []string{"id", "name", "qty"}
	sameColumns := func(got []string) bool {
		if len(got) != len(want) {
			return false
		}
		for i := range want {
			if got[i] != want[i] {
				return false
			}
		}
		return true
	}
	for _, c := range cases {
		code := structPost(t, client, ts.URL, "widgets", c.form)
		// A 2xx success is never acceptable for these guarded inputs. A 303 is
		// only acceptable when it carried an error flash and left the schema
		// unchanged — the exact column-set check below is what verifies that (a
		// count check alone would miss a wrongful rename that keeps the count).
		if code >= 200 && code < 300 {
			t.Errorf("%s: status = %d, expected rejection", c.name, code)
		}
		if got := columnNames(t, dbPath, "widgets"); !sameColumns(got) {
			t.Errorf("%s: widgets columns changed to %v, want %v", c.name, got, want)
		}
	}
}

// TestStructureViewRejected confirms a mutation against a view is refused by the
// handler (the UI also hides the controls) and leaves the view untouched.
func TestStructureViewRejected(t *testing.T) {
	ts, client, dbPath := newTestServer(t)
	login(t, client, ts.URL)
	csrf := csrfFrom(t, client, ts.URL+"/")

	if _, err := inspectConn(t, dbPath).Exec(context.Background(), "CREATE VIEW v_widgets AS SELECT id, name FROM widgets"); err != nil {
		t.Fatalf("create view: %v", err)
	}

	code := structPost(t, client, ts.URL, "v_widgets", url.Values{
		"csrf_token": {csrf}, "action": {"add_column"}, "col_name": {"color"}, "col_type": {"TEXT"}, "col_nullable": {"1"},
	})
	if code >= 200 && code < 300 {
		t.Errorf("view mutation status = %d, expected rejection", code)
	}
	if slices.Contains(columnNames(t, dbPath, "v_widgets"), "color") {
		t.Error("view should be unchanged after a rejected structure op")
	}
}

// TestStructureAutoIndexDropRejected confirms a constraint-backed auto-index is
// left to the engine, which refuses the drop — surfaced with no schema change.
func TestStructureAutoIndexDropRejected(t *testing.T) {
	ts, client, dbPath := newTestServer(t)
	login(t, client, ts.URL)
	csrf := csrfFrom(t, client, ts.URL+"/")

	if _, err := inspectConn(t, dbPath).Exec(context.Background(), "CREATE TABLE uniq (id INTEGER PRIMARY KEY, code TEXT UNIQUE)"); err != nil {
		t.Fatalf("create table: %v", err)
	}
	// Find the auto-generated unique-constraint index name.
	var auto string
	for _, n := range indexNames(t, dbPath, "uniq") {
		if strings.HasPrefix(n, "sqlite_autoindex_") {
			auto = n
		}
	}
	if auto == "" {
		t.Fatal("expected a sqlite_autoindex_* index on the UNIQUE column")
	}

	code := structPost(t, client, ts.URL, "uniq", url.Values{
		"csrf_token": {csrf}, "action": {"drop_index"}, "index_name": {auto},
	})
	if code == http.StatusSeeOther {
		t.Errorf("auto-index drop status = %d, expected an engine-rejected error", code)
	}
	if !slices.Contains(indexNames(t, dbPath, "uniq"), auto) {
		t.Error("the constraint-backed index should still exist after a rejected drop")
	}
}

// TestStructureDropKeyedColumnBlocked confirms the SQLite preflight refuses to
// drop a primary-key column (clear message, no schema change).
func TestStructureDropKeyedColumnBlocked(t *testing.T) {
	ts, client, dbPath := newTestServer(t)
	login(t, client, ts.URL)
	csrf := csrfFrom(t, client, ts.URL+"/")

	code := structPost(t, client, ts.URL, "widgets", url.Values{
		"csrf_token": {csrf}, "action": {"drop_column"}, "column": {"id"},
	})
	if code >= 200 && code < 300 {
		t.Errorf("dropping the PK column status = %d, expected rejection", code)
	}
	if !slices.Contains(columnNames(t, dbPath, "widgets"), "id") {
		t.Error("the primary-key column should still exist after a blocked drop")
	}
}

// TestDBExportAllTables covers the database-level export fix: CSV must emit every
// in-scope table (not just the first), and JSON must be valid with a key per
// table.
func TestDBExportAllTables(t *testing.T) {
	ts, client, dbPath := newTestServer(t)
	login(t, client, ts.URL)
	csrf := csrfFrom(t, client, ts.URL+"/")

	// Add a second table so a DB export must include more than one. A STORED
	// generated column verifies JSON keeps it (export-only typing) while CSV
	// drops it (unimportable header).
	conn := inspectConn(t, dbPath)
	if _, err := conn.Exec(context.Background(), "CREATE TABLE gadgets (id INTEGER PRIMARY KEY, label TEXT, label_up TEXT GENERATED ALWAYS AS (upper(label)) STORED)"); err != nil {
		t.Fatalf("create gadgets: %v", err)
	}
	if _, err := conn.Exec(context.Background(), "INSERT INTO gadgets (label) VALUES ('zap')"); err != nil {
		t.Fatalf("seed gadgets: %v", err)
	}

	// CSV: both tables present, each with its own "# <table>" comment line.
	resp, err := client.PostForm(ts.URL+"/db/main/export", url.Values{"csrf_token": {csrf}, "format": {"csv"}})
	if err != nil {
		t.Fatalf("csv export: %v", err)
	}
	csv, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	body := string(csv)
	for _, want := range []string{"# widgets", "# gadgets", "bolt", "zap"} {
		if !strings.Contains(body, want) {
			t.Errorf("CSV export missing %q:\n%s", want, body)
		}
	}

	// JSON: valid object with a key per table, decoded with UseNumber so the
	// typing is visible (plain Unmarshal coerces every number to float64).
	resp, err = client.PostForm(ts.URL+"/db/main/export", url.Values{"csrf_token": {csrf}, "format": {"json"}})
	if err != nil {
		t.Fatalf("json export: %v", err)
	}
	jsonBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	dec := json.NewDecoder(bytes.NewReader(jsonBody))
	dec.UseNumber()
	var out map[string]any
	if err := dec.Decode(&out); err != nil {
		t.Fatalf("JSON export is not valid JSON: %v\n%s", err, jsonBody)
	}
	if _, ok := out["widgets"]; !ok {
		t.Error("JSON export missing widgets key")
	}
	gadgets, ok := out["gadgets"].([]any)
	if !ok || len(gadgets) == 0 {
		t.Fatalf("JSON export missing gadgets rows: %v", out["gadgets"])
	}
	row, ok := gadgets[0].(map[string]any)
	if !ok {
		t.Fatalf("gadgets row is not a JSON object: %T", gadgets[0])
	}
	// A numeric column decodes as a json.Number (typed), not a quoted string.
	if n, ok := row["id"].(json.Number); !ok || n.String() != "1" {
		t.Errorf("gadgets.id should decode as json.Number 1, got %T %v", row["id"], row["id"])
	}
	// The generated column stays present in JSON (kept by design, unlike CSV).
	if _, ok := row["label_up"]; !ok {
		t.Errorf("JSON export should keep the generated column label_up: %v", row)
	}
}

// TestSQLiteViewTriggerRoundTrip pins the #6 fix: an INSTEAD OF trigger hangs
// off its VIEW in sqlite_master (tbl_name is the view, never a dumped table),
// so the old dumped-tables-only filter silently dropped it — after restore the
// view existed but was no longer updatable. A db-scope structure dump must
// carry the trigger, and the re-imported view must accept an INSERT again.
func TestSQLiteViewTriggerRoundTrip(t *testing.T) {
	ts, client, dbPath := newTestServer(t)
	login(t, client, ts.URL)
	csrf := csrfFrom(t, client, ts.URL+"/")

	conn := inspectConn(t, dbPath)
	for _, stmt := range []string{
		"CREATE VIEW widget_names AS SELECT id, name FROM widgets",
		"CREATE TRIGGER widget_names_ins INSTEAD OF INSERT ON widget_names BEGIN INSERT INTO widgets (name, qty) VALUES (NEW.name, 0); END",
	} {
		if _, err := conn.Exec(context.Background(), stmt); err != nil {
			t.Fatalf("seed %q: %v", stmt, err)
		}
	}

	resp, err := client.PostForm(ts.URL+"/db/main/export", url.Values{
		"csrf_token": {csrf}, "format": {"sql"},
		"structure": {"1"}, "data": {"1"}, "drop": {"1"},
	})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	dumpBytes, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	dump := string(dumpBytes)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("export = %d:\n%.2000s", resp.StatusCode, dump)
	}
	if !strings.Contains(dump, "widget_names_ins") {
		t.Fatalf("dump dropped the INSTEAD OF trigger on the view:\n%s", dump)
	}

	// Re-import over the live database: the drop=1 dump recreates the tables
	// and the view (DROP VIEW also removes the view's triggers).
	resp, err = client.PostForm(ts.URL+"/db/main/import", url.Values{
		"csrf_token": {csrf}, "format": {"sql"}, "sql_script": {dump},
	})
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	importBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || strings.Contains(string(importBody), "tx-alert-error") {
		t.Fatalf("import failed (%d):\n%.4000s\n--- dump ---\n%.4000s", resp.StatusCode, importBody, dump)
	}

	// The restored view must be updatable again — the INSTEAD OF trigger fires.
	check := inspectConn(t, dbPath)
	if _, err := check.Exec(context.Background(), "INSERT INTO widget_names (id, name) VALUES (0, 'via-view')"); err != nil {
		t.Fatalf("INSERT through the restored view failed (trigger missing?): %v", err)
	}
	rows := queryRows(t, check, "SELECT name FROM widgets WHERE name = 'via-view'")
	if len(rows) != 1 {
		t.Errorf("row inserted through the view not found in the base table: %v", rows)
	}
}

// TestCopyRowBlanksAutoIncrement covers #9: the Copy-row prefill must leave
// the auto-increment PK blank — rendering the source row's id would make the
// INSERT collide with the copied row's key — while every other column carries
// the copied value, and submitting the form inserts a new row.
func TestCopyRowBlanksAutoIncrement(t *testing.T) {
	ts, client, dbPath := newTestServer(t)
	login(t, client, ts.URL)
	csrf := csrfFrom(t, client, ts.URL+"/")

	_, browse := getBody(t, client, ts.URL+"/db/main/table/widgets")
	m := regexp.MustCompile(`href="([^"]*copy=1[^"]*)"`).FindStringSubmatch(browse)
	if m == nil {
		t.Fatalf("no copy link on the browse page:\n%.2000s", browse)
	}
	copyURL := strings.ReplaceAll(m[1], "&amp;", "&")
	code, form := getBody(t, client, ts.URL+copyURL)
	if code != http.StatusOK {
		t.Fatalf("copy form = %d", code)
	}
	if !regexp.MustCompile(`name="v_id"[^>]*value=""`).MatchString(form) {
		t.Errorf("copy form should render a BLANK auto-increment id:\n%.3000s", form)
	}
	// TEXT columns render as textareas; the copied name must be prefilled.
	if !strings.Contains(form, ">bolt</textarea>") && !strings.Contains(form, ">nut</textarea>") {
		t.Errorf("copy form should prefill the non-AI columns:\n%.3000s", form)
	}

	// Submitting the copy (id blank) inserts a new row rather than colliding.
	resp, err := client.PostForm(ts.URL+"/db/main/table/widgets/insert", url.Values{
		"csrf_token": {csrf}, "v_id": {""}, "v_name": {"bolt"}, "v_qty": {"5"},
	})
	if err != nil {
		t.Fatalf("insert: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	// A successful non-htmx insert redirects back to browse.
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("copy insert = %d, want 303:\n%.2000s", resp.StatusCode, body)
	}
	conn := inspectConn(t, dbPath)
	rows := queryRows(t, conn, "SELECT COUNT(*) FROM widgets WHERE name = 'bolt'")
	if len(rows) != 1 || rows[0] != "2" {
		t.Errorf("expected two 'bolt' rows after copy-insert, got %v", rows)
	}
}

// TestCSVEmptyTableRoundTrip covers #8: a zero-row table's CSV export must
// still carry the header row, and re-importing that export must succeed (zero
// rows) instead of failing with a "reading header" EOF.
func TestCSVEmptyTableRoundTrip(t *testing.T) {
	ts, client, dbPath := newTestServer(t)
	login(t, client, ts.URL)
	csrf := csrfFrom(t, client, ts.URL+"/")

	conn := inspectConn(t, dbPath)
	if _, err := conn.Exec(context.Background(), "CREATE TABLE empties (id INTEGER PRIMARY KEY, name TEXT)"); err != nil {
		t.Fatalf("create empties: %v", err)
	}

	resp, err := client.PostForm(ts.URL+"/db/main/table/empties/export",
		url.Values{"csrf_token": {csrf}, "format": {"csv"}})
	if err != nil {
		t.Fatalf("csv export: %v", err)
	}
	csvBytes, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	exported := string(csvBytes)
	if resp.StatusCode != http.StatusOK || !strings.Contains(exported, "id,name") {
		t.Fatalf("empty-table export (%d) missing header:\n%q", resp.StatusCode, exported)
	}

	// Re-import the complete export (leading '#' comments are stripped by the
	// production importer). Zero rows is a success, not an error.
	resp, err = client.PostForm(ts.URL+"/db/main/table/empties/import",
		url.Values{"csrf_token": {csrf}, "format": {"csv"}, "sql_script": {exported}})
	if err != nil {
		t.Fatalf("csv import: %v", err)
	}
	importBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(importBody), "Imported 0 row") {
		t.Fatalf("empty CSV re-import failed (%d):\n%.2000s\n--- csv ---\n%q", resp.StatusCode, importBody, exported)
	}
}

// TestCSVRoundTripSQLite covers F-3 CSV fidelity end-to-end: NULL vs empty
// string, a literal value beginning with a backslash (must not collide with the
// \N NULL sentinel), BLOB bytes (hex on export, decoded on import), and a STORED
// generated column (absent from the CSV, recomputed on import). Export → drop
// rows → re-import → row-by-row equality.
func TestCSVRoundTripSQLite(t *testing.T) {
	ts, client, dbPath := newTestServer(t)
	login(t, client, ts.URL)
	csrf := csrfFrom(t, client, ts.URL+"/")

	conn := inspectConn(t, dbPath)
	ctx := context.Background()
	for _, stmt := range []string{
		`CREATE TABLE items (
			id INTEGER PRIMARY KEY,
			name TEXT,
			note TEXT,
			data BLOB,
			name_up TEXT GENERATED ALWAYS AS (upper(name)) STORED)`,
		`INSERT INTO items (id, name, note, data) VALUES (1, 'ann', NULL, X'00FF10')`,
		`INSERT INTO items (id, name, note, data) VALUES (2, '', '\N', NULL)`, // empty name; literal \N note; NULL blob
		`INSERT INTO items (id, name, note, data) VALUES (3, 'back\slash', '', X'4869')`,
	} {
		if _, err := conn.Exec(ctx, stmt); err != nil {
			t.Fatalf("seed %q: %v", stmt, err)
		}
	}

	const snapSQL = "SELECT id, name, note, data, name_up FROM items ORDER BY id"
	before := queryRows(t, conn, snapSQL)
	if len(before) != 3 {
		t.Fatalf("seed snapshot = %d rows, want 3: %v", len(before), before)
	}

	// Export the table as CSV.
	resp, err := client.PostForm(ts.URL+"/db/main/table/items/export",
		url.Values{"csrf_token": {csrf}, "format": {"csv"}})
	if err != nil {
		t.Fatalf("csv export: %v", err)
	}
	csvBytes, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	exported := string(csvBytes)
	if strings.Contains(exported, "name_up") {
		t.Errorf("CSV export must exclude the generated column:\n%s", exported)
	}

	// Drop the data, then re-import. The single-table export prepends a
	// "# items" comment line; importCSV reads the first line as the header, so
	// strip that cosmetic comment before re-importing the data section.
	if _, err := conn.Exec(ctx, "DELETE FROM items"); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	csvData := exported
	if i := strings.IndexByte(csvData, '\n'); i >= 0 && strings.HasPrefix(csvData, "# ") {
		csvData = csvData[i+1:]
	}
	resp, err = client.PostForm(ts.URL+"/db/main/table/items/import",
		url.Values{"csrf_token": {csrf}, "format": {"csv"}, "sql_script": {csvData}})
	if err != nil {
		t.Fatalf("csv import: %v", err)
	}
	importBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(importBody), "Imported 3 row") {
		t.Fatalf("csv import did not import 3 rows (%d):\n%s\n--- csv ---\n%s", resp.StatusCode, importBody, csvData)
	}

	after := queryRows(t, conn, snapSQL)
	if strings.Join(before, "\n") != strings.Join(after, "\n") {
		t.Errorf("CSV round-trip mismatch:\n--- before ---\n%s\n--- after ---\n%s\n--- csv ---\n%s",
			strings.Join(before, "\n"), strings.Join(after, "\n"), exported)
	}
}

// TestCSVRoundTripSQLiteBinaryAlignment covers the R1 symmetric-CSV fix through
// the full HTTP stack, with the two shapes TestCSVRoundTripSQLite cannot catch:
// a generated column ordered BEFORE the binary column (a binaryCols index built
// over all columns would misalign against the non-generated SELECT) and a TEXT
// value stored in the BLOB-declared column (SQLite dynamic typing — before the
// fix this exported as "" / failed import; now it hexes the string bytes).
// Snapshots compare hex(data) so the TEXT→BLOB storage-class change on
// re-import (hex round-trips bytes, not storage class) doesn't false-fail.
func TestCSVRoundTripSQLiteBinaryAlignment(t *testing.T) {
	ts, client, dbPath := newTestServer(t)
	login(t, client, ts.URL)
	csrf := csrfFrom(t, client, ts.URL+"/")

	conn := inspectConn(t, dbPath)
	ctx := context.Background()
	for _, stmt := range []string{
		`CREATE TABLE bins (
			id INTEGER PRIMARY KEY,
			name_up TEXT GENERATED ALWAYS AS (upper(name)) STORED,
			name TEXT,
			data BLOB)`,
		`INSERT INTO bins (id, name, data) VALUES (1, 'ann', X'00FF10')`,
		`INSERT INTO bins (id, name, data) VALUES (2, 'bob', 'hello')`, // TEXT stored in the BLOB column
		`INSERT INTO bins (id, name, data) VALUES (3, 'cid', NULL)`,
	} {
		if _, err := conn.Exec(ctx, stmt); err != nil {
			t.Fatalf("seed %q: %v", stmt, err)
		}
	}

	const snapSQL = "SELECT id, name, name_up, hex(data) FROM bins ORDER BY id"
	before := queryRows(t, conn, snapSQL)

	resp, err := client.PostForm(ts.URL+"/db/main/table/bins/export",
		url.Values{"csrf_token": {csrf}, "format": {"csv"}})
	if err != nil {
		t.Fatalf("csv export: %v", err)
	}
	csvBytes, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	exported := string(csvBytes)
	if strings.Contains(exported, "# export error") {
		t.Fatalf("csv export reported an error:\n%s", exported)
	}
	if !strings.Contains(exported, "68656c6c6f") {
		t.Fatalf("string-in-blob cell must hex its bytes:\n%s", exported)
	}

	if _, err := conn.Exec(ctx, "DELETE FROM bins"); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	csvData := exported
	if i := strings.IndexByte(csvData, '\n'); i >= 0 && strings.HasPrefix(csvData, "# ") {
		csvData = csvData[i+1:]
	}
	resp, err = client.PostForm(ts.URL+"/db/main/table/bins/import",
		url.Values{"csrf_token": {csrf}, "format": {"csv"}, "sql_script": {csvData}})
	if err != nil {
		t.Fatalf("csv import: %v", err)
	}
	importBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(importBody), "Imported 3 row") {
		t.Fatalf("csv import did not import 3 rows (%d):\n%s\n--- csv ---\n%s", resp.StatusCode, importBody, csvData)
	}

	after := queryRows(t, conn, snapSQL)
	if strings.Join(before, "\n") != strings.Join(after, "\n") {
		t.Errorf("CSV round-trip mismatch:\n--- before ---\n%s\n--- after ---\n%s\n--- csv ---\n%s",
			strings.Join(before, "\n"), strings.Join(after, "\n"), exported)
	}
}

// TestCSVExportTextColumnClassifiedBinary covers the two text-column arms of
// the R1 decision: a valid-UTF8 value holding a NUL (classified binary by
// isPrintableUTF8) round-trips as CSV text, while genuinely non-UTF8 bytes in
// a text column produce the explicit "# export error:" trailer instead of hex
// that would re-import as literal hex text (silent corruption).
func TestCSVExportTextColumnClassifiedBinary(t *testing.T) {
	ts, client, dbPath := newTestServer(t)
	login(t, client, ts.URL)
	csrf := csrfFrom(t, client, ts.URL+"/")

	conn := inspectConn(t, dbPath)
	ctx := context.Background()
	for _, stmt := range []string{
		"CREATE TABLE nultext (id INTEGER PRIMARY KEY, txt TEXT)",
		"INSERT INTO nultext VALUES (1, X'610062')", // "a\x00b": valid UTF-8, NUL control char
	} {
		if _, err := conn.Exec(ctx, stmt); err != nil {
			t.Fatalf("seed %q: %v", stmt, err)
		}
	}
	const snapSQL = "SELECT id, hex(txt) FROM nultext ORDER BY id"
	before := queryRows(t, conn, snapSQL)

	resp, err := client.PostForm(ts.URL+"/db/main/table/nultext/export",
		url.Values{"csrf_token": {csrf}, "format": {"csv"}})
	if err != nil {
		t.Fatalf("csv export: %v", err)
	}
	csvBytes, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	exported := string(csvBytes)
	if strings.Contains(exported, "# export error") {
		t.Fatalf("NUL-holding valid-UTF8 text must export as text, not error:\n%q", exported)
	}
	if !strings.Contains(exported, "a\x00b") {
		t.Fatalf("NUL-holding text cell should be written verbatim:\n%q", exported)
	}

	if _, err := conn.Exec(ctx, "DELETE FROM nultext"); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	csvData := exported
	if i := strings.IndexByte(csvData, '\n'); i >= 0 && strings.HasPrefix(csvData, "# ") {
		csvData = csvData[i+1:]
	}
	resp, err = client.PostForm(ts.URL+"/db/main/table/nultext/import",
		url.Values{"csrf_token": {csrf}, "format": {"csv"}, "sql_script": {csvData}})
	if err != nil {
		t.Fatalf("csv import: %v", err)
	}
	importBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(importBody), "Imported 1 row") {
		t.Fatalf("csv import failed (%d):\n%s\n--- csv ---\n%q", resp.StatusCode, importBody, csvData)
	}
	after := queryRows(t, conn, snapSQL)
	if strings.Join(before, "\n") != strings.Join(after, "\n") {
		t.Errorf("NUL text round-trip mismatch: before %v, after %v", before, after)
	}

	// Genuinely non-UTF8 bytes in a TEXT column: explicit failure, never hex.
	if _, err := conn.Exec(ctx, "CREATE TABLE badtext (txt TEXT)"); err != nil {
		t.Fatalf("create badtext: %v", err)
	}
	if _, err := conn.Exec(ctx, "INSERT INTO badtext VALUES (X'80FF')"); err != nil {
		t.Fatalf("seed badtext: %v", err)
	}
	resp, err = client.PostForm(ts.URL+"/db/main/table/badtext/export",
		url.Values{"csrf_token": {csrf}, "format": {"csv"}})
	if err != nil {
		t.Fatalf("csv export: %v", err)
	}
	csvBytes, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	exported = string(csvBytes)
	if !strings.Contains(exported, "# export error") || !strings.Contains(exported, "not valid UTF-8") {
		t.Errorf("non-UTF8 text column should produce the explicit export error:\n%q", exported)
	}
	if strings.Contains(exported, "80ff") {
		t.Errorf("non-UTF8 text column must not silently hex-encode:\n%q", exported)
	}
}

// TestDBImportConnectNotHonored pins the R2 scope gate end-to-end: a
// db-scoped import (and any non-PostgreSQL engine) must never honor a
// \connect line — before the gate, the rest of the script silently executed
// against the named other database. The line now stays in the single
// target-bound section and is rejected as an unsupported meta-command.
func TestDBImportConnectNotHonored(t *testing.T) {
	ts, client, dbPath := newTestServer(t)
	login(t, client, ts.URL)
	csrf := csrfFrom(t, client, ts.URL+"/")

	script := "CREATE TABLE gate_ok (id INTEGER);\n\\connect other\nCREATE TABLE gate_leak (id INTEGER);"
	resp, err := client.PostForm(ts.URL+"/db/main/import",
		url.Values{"csrf_token": {csrf}, "format": {"sql"}, "sql_script": {script}})
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), "psql meta-commands are not supported") {
		t.Errorf("db-scope \\connect should be rejected as a meta-command, got:\n%.2000s", body)
	}

	conn := inspectConn(t, dbPath)
	tables := queryRows(t, conn, "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
	joined := strings.Join(tables, "\n")
	if !strings.Contains(joined, "gate_ok") {
		t.Errorf("statements before the \\connect line should have run: %v", tables)
	}
	if strings.Contains(joined, "gate_leak") {
		t.Errorf("statements after the \\connect line must not run in this database: %v", tables)
	}
}

// TestGeneratedColumnOmitted confirms a generated column is rendered read-only
// (no editable input) and never written on insert, even if a value is posted —
// the engine computes it.
func TestGeneratedColumnOmitted(t *testing.T) {
	ts, client, dbPath := newTestServer(t)
	login(t, client, ts.URL)

	conn := inspectConn(t, dbPath)
	if _, err := conn.Exec(context.Background(),
		"CREATE TABLE gizmos (a INTEGER, b INTEGER GENERATED ALWAYS AS (a*2) VIRTUAL)"); err != nil {
		t.Fatalf("create generated-column table: %v", err)
	}

	code, body := getBody(t, client, ts.URL+"/db/main/table/gizmos/insert")
	if code != http.StatusOK {
		t.Fatalf("insert form = %d", code)
	}
	if !strings.Contains(body, "generated") {
		t.Error("insert form should label the generated column")
	}
	if strings.Contains(body, `name="v_b"`) {
		t.Error("insert form must not render an editable input for the generated column")
	}

	// Even a crafted POST that includes v_b must not write it; b is computed.
	csrf := csrfFrom(t, client, ts.URL+"/")
	resp, err := client.PostForm(ts.URL+"/db/main/table/gizmos/insert",
		url.Values{"csrf_token": {csrf}, "v_a": {"5"}, "v_b": {"999"}})
	if err != nil {
		t.Fatalf("insert: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("insert status = %d, want 303", resp.StatusCode)
	}
	rs, err := conn.Query(context.Background(), "SELECT b FROM gizmos", 10)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(rs.Rows) != 1 || rs.Rows[0][0].Str != "10" {
		t.Errorf("generated b = %v, want computed 10 (not the submitted 999)", rs.Rows)
	}
}

// TestCSVImportShortRowNull confirms a CSV row with fewer fields than the header
// inserts NULL for the missing trailing column rather than an empty string.
func TestCSVImportShortRowNull(t *testing.T) {
	ts, client, dbPath := newTestServer(t)
	login(t, client, ts.URL)
	conn := inspectConn(t, dbPath)
	if _, err := conn.Exec(context.Background(), "CREATE TABLE imp (a TEXT, b TEXT, c TEXT)"); err != nil {
		t.Fatalf("create: %v", err)
	}
	csrf := csrfFrom(t, client, ts.URL+"/")

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	_ = mw.WriteField("csrf_token", csrf)
	_ = mw.WriteField("format", "csv")
	fw, _ := mw.CreateFormFile("file", "data.csv")
	fw.Write([]byte("a,b,c\nx,y\n")) // the data row is missing column c
	mw.Close()

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/db/main/table/imp/import", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("X-CSRF-Token", csrf)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	resp.Body.Close()

	rs, err := conn.Query(context.Background(), "SELECT a, b, c FROM imp", 10)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(rs.Rows) != 1 {
		t.Fatalf("expected 1 imported row, got %d", len(rs.Rows))
	}
	row := rs.Rows[0]
	if row[0].Str != "x" || row[1].Str != "y" || !row[2].Null {
		t.Errorf("short-row import = %v, want a=x b=y c=NULL", row)
	}
}

// TestServerExportImport covers the server-scope export (SQL dump of every
// database) and the server-scope import (running a script on the server conn).
func TestServerExportImport(t *testing.T) {
	ts, client, _ := newTestServer(t)
	login(t, client, ts.URL)
	csrf := csrfFrom(t, client, ts.URL+"/")

	// Server export: a SQL dump including the seeded table.
	resp, err := client.PostForm(ts.URL+"/server/export", url.Values{"csrf_token": {csrf}})
	if err != nil {
		t.Fatalf("server export: %v", err)
	}
	dump, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(dump), "widgets") || !strings.Contains(string(dump), "-- Database: main") {
		t.Errorf("server export missing the database/table dump:\n%s", dump)
	}
	// SQLite server framing (3.1): the dump stays main-only — no \connect
	// markers, no CREATE DATABASE headers — with the ATTACH note up top.
	for _, absent := range []string{`\connect`, "CREATE DATABASE"} {
		if strings.Contains(string(dump), absent) {
			t.Errorf("SQLite server dump must not contain %q:\n%.2000s", absent, dump)
		}
	}
	if !strings.Contains(string(dump), "ATTACH-ed databases are session-scoped") {
		t.Errorf("SQLite server dump missing the ATTACH header note:\n%.1000s", dump)
	}

	// Server import: run a SQL script (creates a table) via the server conn.
	resp2, err := client.PostForm(ts.URL+"/server/import",
		url.Values{"csrf_token": {csrf}, "format": {"sql"}, "sql_script": {"CREATE TABLE srv_imported (id INTEGER PRIMARY KEY);"}})
	if err != nil {
		t.Fatalf("server import: %v", err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("server import status = %d", resp2.StatusCode)
	}
	// The imported table should now appear in the database listing.
	if code, body := getBody(t, client, ts.URL+"/db/main"); code != http.StatusOK || !strings.Contains(body, "srv_imported") {
		t.Errorf("imported table not visible after server import (code=%d)", code)
	}
}

// TestQBE covers the query-by-example builder: selecting a table shows its
// columns, and a posted criterion runs a parameterized, filtered SELECT.
func TestQBE(t *testing.T) {
	ts, client, _ := newTestServer(t)
	login(t, client, ts.URL)

	code, form := getBody(t, client, ts.URL+"/db/main/qbe?table=widgets")
	if code != http.StatusOK || !strings.Contains(form, "qty") {
		t.Fatalf("qbe form for widgets: code=%d, has columns=%v", code, strings.Contains(form, "qty"))
	}

	csrf := csrfFrom(t, client, ts.URL+"/")
	resp, err := client.PostForm(ts.URL+"/db/main/qbe", url.Values{
		"csrf_token": {csrf}, "table": {"widgets"},
		"show_name": {"1"}, "show_qty": {"1"},
		"op_name": {"="}, "val_name": {"bolt"},
	})
	if err != nil {
		t.Fatalf("qbe run: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), "bolt") {
		t.Errorf("qbe should return the matching row:\n%s", body)
	}
	// The criterion name = 'bolt' must actually filter: the other seeded row
	// ('nut') is a data value that appears nowhere but the result grid, so its
	// presence would mean the WHERE clause was ignored (the old test passed on
	// the echoed form value alone).
	if strings.Contains(string(body), "nut") {
		t.Errorf("qbe criterion ignored: non-matching row 'nut' rendered:\n%s", body)
	}
}

// TestDesigner covers the schema/relations map: it lists tables and surfaces
// foreign-key relationships.
func TestDesigner(t *testing.T) {
	ts, client, dbPath := newTestServer(t)
	login(t, client, ts.URL)
	if _, err := inspectConn(t, dbPath).Exec(context.Background(),
		"CREATE TABLE parts (id INTEGER PRIMARY KEY, widget_id INTEGER REFERENCES widgets(id))"); err != nil {
		t.Fatalf("create related table: %v", err)
	}
	code, body := getBody(t, client, ts.URL+"/db/main/designer")
	if code != http.StatusOK {
		t.Fatalf("designer = %d", code)
	}
	// The rendered FK EDGE (5.2), not just table names: the card headers are
	// unconditional and the "Relationships" heading is .HasFKs-gated, so an
	// FK-rendering regression would have stayed green on those alone.
	for _, want := range []string{"widgets", "parts", "Relationships",
		"parts(widget_id)", "widgets(id)"} {
		if !strings.Contains(body, want) {
			t.Errorf("designer page missing %q", want)
		}
	}
}

func TestSQLConsole(t *testing.T) {
	ts, client, _ := newTestServer(t)
	login(t, client, ts.URL)
	csrf := csrfFrom(t, client, ts.URL+"/")
	resp, err := client.PostForm(ts.URL+"/db/main/sql",
		url.Values{"csrf_token": {csrf}, "sql_query": {"SELECT name, qty FROM widgets ORDER BY qty DESC;"}})
	if err != nil {
		t.Fatalf("sql: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(b), "nut") {
		t.Error("SQL console should render query results")
	}
}

// TestSQLConsoleScriptSessionState proves console scripts run on one pinned
// physical connection: a TEMP table created by an earlier statement (strictly
// connection-scoped in SQLite) must be visible to later statements in the same
// script. On the old pooled path, statements could land on different
// connections and session-scoped state silently failed to apply.
func TestSQLConsoleScriptSessionState(t *testing.T) {
	ts, client, _ := newTestServer(t)
	login(t, client, ts.URL)
	csrf := csrfFrom(t, client, ts.URL+"/")
	script := "CREATE TEMP TABLE scratch (x INT); INSERT INTO scratch VALUES (41); UPDATE scratch SET x = 42; SELECT x AS answer FROM scratch;"
	resp, err := client.PostForm(ts.URL+"/db/main/sql",
		url.Values{"csrf_token": {csrf}, "sql_query": {script}})
	if err != nil {
		t.Fatalf("sql: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(b), "42") {
		t.Error("script statements did not share one connection: TEMP table state was lost mid-script")
	}
	if strings.Contains(string(b), "no such table") {
		t.Error("a later statement could not see the TEMP table created earlier in the script")
	}
}

// TestSQLConsoleExplain confirms the one-click EXPLAIN runs the query plan.
func TestSQLConsoleExplain(t *testing.T) {
	ts, client, _ := newTestServer(t)
	login(t, client, ts.URL)
	csrf := csrfFrom(t, client, ts.URL+"/")
	resp, err := client.PostForm(ts.URL+"/db/main/sql",
		url.Values{"csrf_token": {csrf}, "explain": {"1"}, "sql_query": {"SELECT * FROM widgets"}})
	if err != nil {
		t.Fatalf("explain: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	// Assert a real plan rendered, not just the echoed query: SQLite's EXPLAIN
	// QUERY PLAN emits a "SCAN ... widgets" row (version-robust: both "SCAN
	// widgets" and older "SCAN TABLE widgets" contain "scan"). A failed EXPLAIN
	// would echo the SQL but carry no scan row.
	lb := strings.ToLower(string(b))
	if !strings.Contains(lb, "scan") || !strings.Contains(lb, "widgets") {
		t.Errorf("EXPLAIN QUERY PLAN did not render a real scan plan for widgets:\n%s", b)
	}
}

// --- WS-6 UI/UX fidelity --------------------------------------------------------

// getWithCookie issues a GET with an extra cookie added on top of the jar's
// (session) cookies, returning the response body.
func getWithCookie(t *testing.T, client *http.Client, u string, c *http.Cookie) string {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, u, nil)
	req.AddCookie(c)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", u, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

// TestNavWidthCookieRendersInlineStyle confirms a persisted sidebar width is
// rendered inline on the first paint (killing the FOUC), and that an
// out-of-range/garbage cookie is ignored rather than reflected into the page.
func TestNavWidthCookieRendersInlineStyle(t *testing.T) {
	ts, client, _ := newTestServer(t)
	login(t, client, ts.URL)

	if body := getWithCookie(t, client, ts.URL+"/", &http.Cookie{Name: "tx-nav-width", Value: "320px"}); !strings.Contains(body, "style=\"--tx-nav-width:320px\"") {
		t.Errorf("valid nav-width cookie not rendered inline on <html>")
	}
	// Out-of-range, negative, or non-numeric values are rebuilt-or-rejected, so
	// nothing untrusted (e.g. a CSS-injection attempt) reaches the style attr.
	for _, bad := range []string{"9999px", "10px", "abc", "-200px", "200"} {
		body := getWithCookie(t, client, ts.URL+"/", &http.Cookie{Name: "tx-nav-width", Value: bad})
		if strings.Contains(body, "--tx-nav-width:") {
			t.Errorf("invalid nav-width cookie %q should not be reflected into the page", bad)
		}
	}
}

// TestLoginFormProgressiveEnhancement confirms the ad-hoc credential inputs are
// real HTML (usable without JavaScript — not hidden inside an x-if <template>),
// the PostgreSQL sslmode selector is present, and the ad-hoc option is offered
// when ad-hoc login is enabled (the default test config).
func TestLoginFormProgressiveEnhancement(t *testing.T) {
	ts, client, _ := newTestServer(t)
	_, body := getBody(t, client, ts.URL+"/login")
	for _, want := range []string{`name="username"`, `name="password"`, `name="sslmode"`, "— Ad-hoc connection —"} {
		if !strings.Contains(body, want) {
			t.Errorf("login form missing %q", want)
		}
	}
	// The credential block must not be gated behind an Alpine <template x-if>,
	// which renders nothing without JS.
	if strings.Contains(body, "x-if=") {
		t.Error("login credential inputs must not be inside an x-if template (breaks no-JS login)")
	}
}

// TestLoginFormHidesAdHocWhenDisabled confirms that with ad-hoc login disabled
// the engine selector and the ad-hoc option are not rendered, leaving only the
// predefined server choice.
func TestLoginFormHidesAdHocWhenDisabled(t *testing.T) {
	ts, client, _ := newTestServerWith(t, func(c *config.Config) {
		c.Security.AllowAdHoc = false
	})
	_, body := getBody(t, client, ts.URL+"/login")
	if strings.Contains(body, `name="engine"`) {
		t.Error("ad-hoc engine selector should be absent when ad-hoc login is disabled")
	}
	if strings.Contains(body, "— Ad-hoc connection —") {
		t.Error("ad-hoc option should be absent when ad-hoc login is disabled")
	}
	if !strings.Contains(body, testServerName) {
		t.Error("the predefined server option should still be offered")
	}
}

// TestLoginFormShowsCredentialsForPredefined covers: a predefined network
// server that leaves user/password empty must still render the credential inputs
// (they are collected at login) even with ad-hoc login disabled, and its option
// carries the per-field needs flags that drive the client-side visibility.
func TestLoginFormShowsCredentialsForPredefined(t *testing.T) {
	ts, client, _ := newTestServerWith(t, func(c *config.Config) {
		c.Security.AllowAdHoc = false
		c.Servers = append(c.Servers, config.ServerConfig{Name: "pg1", Engine: "postgres", Host: "127.0.0.1"})
	})
	_, body := getBody(t, client, ts.URL+"/login")
	if !strings.Contains(body, `name="username"`) {
		t.Error("username input must render for a credential-less predefined server")
	}
	if !strings.Contains(body, `name="password"`) {
		t.Error("password input must render for a credential-less predefined server")
	}
	if !strings.Contains(body, `data-needs-password="1"`) {
		t.Error("the credential-less predefined server option should carry data-needs-password")
	}
	// SQLite predefined server needs no credentials.
	if !strings.Contains(body, `data-needs-password=""`) {
		t.Error("the SQLite predefined server option should not need a password")
	}
}

// TestBrowseRowDeleteIsRealButton confirms the per-row delete is a real submit
// button (no-JS fallback via formaction) rather than a dead href="#".
func TestBrowseRowDeleteIsRealButton(t *testing.T) {
	ts, client, _ := newTestServer(t)
	login(t, client, ts.URL)
	_, body := getBody(t, client, ts.URL+"/db/main/table/widgets")
	if !strings.Contains(body, "formaction=") {
		t.Error("per-row delete should be a submit button with formaction (no-JS fallback)")
	}
	if strings.Contains(body, `href="#"`) {
		t.Error("browse grid should not contain dead href=\"#\" links")
	}
}

// TestBrowseRowFilterOnlyWhenComplete keeps the decision that deleted the
// original client-side row filter: a filter over ONE PAGE is misleading,
// because a value that exists in the table but not on this page reads as
// absent. The filter is back, but only where it cannot lie — when the grid
// holds every row of the result.
func TestBrowseRowFilterOnlyWhenComplete(t *testing.T) {
	ts, client, path := newTestServer(t)
	login(t, client, ts.URL)

	// Two rows, one page: the grid IS the result.
	_, body := getBody(t, client, ts.URL+"/db/main/table/widgets")
	if !strings.Contains(body, "Filter rows") {
		t.Error("a complete result should offer the row filter")
	}
	if !strings.Contains(body, `x-data="rowFilter"`) || !strings.Contains(body, "x-cloak") {
		t.Error("the filter must be an Alpine control hidden until it works (x-cloak)")
	}

	// More rows than a page: the filter must disappear rather than filter a
	// slice of the table while looking like it filters the table.
	seedManyRows(t, path, 60)
	_, body = getBody(t, client, ts.URL+"/db/main/table/widgets?rows=25")
	if strings.Contains(body, "Filter rows") {
		t.Error("a paginated grid must not offer a filter over one page")
	}

	// Show all brings the whole result back on screen, so the filter returns.
	_, body = getBody(t, client, ts.URL+"/db/main/table/widgets?rows=all")
	if !strings.Contains(body, "Filter rows") {
		t.Error("Show all puts every row on screen; the filter should be offered again")
	}
}

// TestThemeToggleIconRendered confirms the theme toggle uses the dedicated theme
// glyph (circle-half) rather than the generic settings gear — exercising the new
// icon alias and its vendored SVG end-to-end.
func TestThemeToggleIconRendered(t *testing.T) {
	ts, client, _ := newTestServer(t)
	login(t, client, ts.URL)
	_, home := getBody(t, client, ts.URL+"/")
	if !strings.Contains(home, "icon-theme") {
		t.Error("theme toggle should render the dedicated theme icon (icon-theme)")
	}
}

// TestBrowseRowDeleteRoundTrip exercises the no-JS per-row delete path: posting
// the row's key token to the delete endpoint (exactly what the new submit
// button's formaction does without JavaScript) removes precisely that row.
func TestBrowseRowDeleteRoundTrip(t *testing.T) {
	ts, client, dbPath := newTestServer(t)
	login(t, client, ts.URL)

	_, browse := getBody(t, client, ts.URL+"/db/main/table/widgets")
	m := regexp.MustCompile(`name="rows\[\]" value="([^"]+)"`).FindStringSubmatch(browse)
	if len(m) < 2 {
		t.Fatalf("no row key token found on browse page")
	}

	csrf := csrfFrom(t, client, ts.URL+"/")
	resp, err := client.PostForm(ts.URL+"/db/main/table/widgets/delete",
		url.Values{"csrf_token": {csrf}, "rows[]": {m[1]}, "tx_confirm": {"1"}})
	if err != nil {
		t.Fatalf("delete post: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("no-JS row delete status = %d, want 303", resp.StatusCode)
	}

	rs, err := inspectConn(t, dbPath).Query(context.Background(), "SELECT COUNT(*) FROM widgets", 1)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if got := rs.Rows[0][0].Str; got != "1" {
		t.Errorf("after single-row delete, widgets count = %s, want 1", got)
	}
}

// TestBrowseSingleRowDeleteHTMX exercises the htmx per-row delete request shape.
// The per-row button lives inside the bulk-delete form, so its POST carries the
// form's checked "rows[]" checkboxes alongside the button's own "row" token; the
// handler must delete only the "row" the user clicked. This also pins the
// regression where hx-params="none" stripped the hx-vals token entirely
// (htmx 2 applies the hx-params filter after merging hx-vals).
func TestBrowseSingleRowDeleteHTMX(t *testing.T) {
	ts, client, dbPath := newTestServer(t)
	login(t, client, ts.URL)

	_, browse := getBody(t, client, ts.URL+"/db/main/table/widgets")
	if strings.Contains(browse, "hx-params") {
		t.Error(`browse grid must not use hx-params: it filters out hx-vals values in htmx 2, leaving the delete POST without a row token`)
	}
	if !strings.Contains(browse, `hx-vals='{"row":`) {
		t.Error(`per-row delete button should carry its key token under the dedicated "row" parameter`)
	}
	tokens := regexp.MustCompile(`name="rows\[\]" value="([^"]+)"`).FindAllStringSubmatch(browse, -1)
	if len(tokens) != 2 {
		t.Fatalf("expected 2 row checkbox tokens on browse page, got %d", len(tokens))
	}
	bolt, nut := tokens[0][1], tokens[1][1]

	// Click per-row delete on "bolt" while "nut"'s bulk checkbox is checked.
	csrf := csrfFrom(t, client, ts.URL+"/")
	resp, err := client.PostForm(ts.URL+"/db/main/table/widgets/delete",
		url.Values{"csrf_token": {csrf}, "row": {bolt}, "rows[]": {nut}, "tx_confirm": {"1"}})
	if err != nil {
		t.Fatalf("delete post: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("single-row delete status = %d, want 303", resp.StatusCode)
	}

	rs, err := inspectConn(t, dbPath).Query(context.Background(), "SELECT name FROM widgets ORDER BY id", 10)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(rs.Rows) != 1 || rs.Rows[0][0].Str != "nut" {
		got := make([]string, 0, len(rs.Rows))
		for _, r := range rs.Rows {
			got = append(got, r[0].Str)
		}
		t.Errorf("after clicking delete on bolt, remaining rows = %v, want [nut] only", got)
	}
}

// TestLoginFormSSLNoteIsServerRendered: the sslmode selector is now shown for
// MySQL/MariaDB too, and the vocabulary it offers is PostgreSQL's while the
// behaviour behind it is not — `prefer` falls back to plaintext on both, and
// `require` authenticates the server on NEITHER.
//
// So unlike the database hint beside it, this note must NOT be an empty div
// without JavaScript. Its whole job is to stop `prefer` being read with libpq's
// meaning, on a form this repo deliberately keeps usable with no JavaScript, so
// the SELECTED engine's note is server-rendered as the div's initial content and
// Alpine's x-text only takes over on change.
func TestLoginFormSSLNoteIsServerRendered(t *testing.T) {
	ts, client, _ := newTestServerWith(t, func(c *config.Config) {
		c.Security.AllowAdHoc = true
	})
	_, body := getBody(t, client, ts.URL+"/login")

	// Every offered engine's note rides its <option> as a data attribute, so
	// Alpine can swap it on change without this script naming an engine.
	if !strings.Contains(body, "data-ssl-note=") {
		t.Fatal("the engine options carry no data-ssl-note for Alpine to read")
	}
	for _, engine := range []string{"postgres", "mysql"} {
		d, ok := driver.Get(engine)
		if !ok {
			t.Fatalf("dialect %s not registered", engine)
		}
		note := d.Capabilities().SSLModeNote
		if note == "" {
			t.Fatalf("%s carries no SSLModeNote", engine)
		}
		if !strings.Contains(body, html.EscapeString(note)) {
			t.Errorf("%s's note is not on its <option>, so switching to it would show nothing", engine)
		}
	}

	// And the note of whichever engine is PRE-SELECTED is present as real text
	// as well as in that attribute — which is all a no-JS visitor ever sees.
	m := regexp.MustCompile(`<option value="([^"]+)"[^>]* selected`).FindStringSubmatch(body)
	if m == nil {
		t.Fatal("no engine option is marked selected")
	}
	d, ok := driver.Get(m[1])
	if !ok {
		t.Fatalf("the selected engine %q is not registered", m[1])
	}
	sel := html.EscapeString(d.Capabilities().SSLModeNote)
	if strings.Count(body, sel) < 2 {
		t.Errorf("the selected engine (%s) has its sslmode note only in the data attribute; a no-JS visitor sees an empty div", m[1])
	}
}
