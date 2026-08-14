package server_test

// Handler and security-property coverage that the original suite lacked:
// table operations (truncate/drop), the full row-edit flow, search (table +
// database), the navigation tree endpoint, table-level export, server monitor
// pages, logout, login rate limiting, the absolute session timeout, the SSRF
// host guard, and Secure/__Host-/HSTS behavior behind a TLS-terminating proxy.

import (
	"context"
	"io"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"net/url"

	"github.com/tablexdev/tablex/internal/config"
	"github.com/tablexdev/tablex/internal/driver"
)

func TestTableTruncateAndDrop(t *testing.T) {
	ts, client, dbPath := newTestServer(t)
	login(t, client, ts.URL)
	csrf := csrfFrom(t, client, ts.URL+"/")

	// Truncate empties the table but keeps it.
	resp, err := client.PostForm(ts.URL+"/db/main/table/widgets/operations",
		url.Values{"csrf_token": {csrf}, "action": {"truncate"}, "tx_confirm": {"1"}})
	if err != nil {
		t.Fatalf("truncate: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("truncate = %d, want 303", resp.StatusCode)
	}
	conn := inspectConn(t, dbPath)
	if n, err := conn.CountRows(context.Background(), driver.TableRef{Database: "main", Table: "widgets"}); err != nil || n != 0 {
		t.Errorf("rows after truncate = %d (%v), want 0", n, err)
	}

	// Drop removes it; the handler validates existence first.
	resp, err = client.PostForm(ts.URL+"/db/main/table/widgets/operations",
		url.Values{"csrf_token": {csrf}, "action": {"drop"}, "tx_confirm": {"1"}})
	if err != nil {
		t.Fatalf("drop: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("drop = %d, want 303", resp.StatusCode)
	}
	tables, err := conn.ListTableNames(context.Background(), driver.Scope{Database: "main"})
	if err != nil {
		t.Fatalf("list tables: %v", err)
	}
	for _, tb := range tables {
		if tb.Name == "widgets" {
			t.Error("widgets still present after drop")
		}
	}

	// Operating on the dropped table is a clean 404, not generated SQL.
	resp, err = client.PostForm(ts.URL+"/db/main/table/widgets/operations",
		url.Values{"csrf_token": {csrf}, "action": {"truncate"}, "tx_confirm": {"1"}})
	if err != nil {
		t.Fatalf("post-drop truncate: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("operation on dropped table = %d, want 404", resp.StatusCode)
	}
}

// TestRowEditFlow drives browse → edit form → save through the real templates:
// the row token comes from the browse page, the orig_ dirty markers from the
// edit form, and only the changed column is written.
func TestRowEditFlow(t *testing.T) {
	ts, client, dbPath := newTestServer(t)
	login(t, client, ts.URL)
	csrf := csrfFrom(t, client, ts.URL+"/")

	_, browse := getBody(t, client, ts.URL+"/db/main/table/widgets")
	m := regexp.MustCompile(`where=([A-Za-z0-9_-]+)`).FindStringSubmatch(browse)
	if m == nil {
		t.Fatalf("no row token on the browse page:\n%.2000s", browse)
	}
	token := m[1]

	_, form := getBody(t, client, ts.URL+"/db/main/table/widgets/edit?where="+token)
	orig := func(col string) string {
		om := regexp.MustCompile(`name="orig_` + col + `" value="([^"]*)"`).FindStringSubmatch(form)
		if om == nil {
			t.Fatalf("edit form missing orig_%s marker:\n%.2000s", col, form)
		}
		return om[1]
	}
	id, name, qty := orig("id"), orig("name"), orig("qty")
	if qty == "99" {
		t.Fatal("fixture row already has qty=99; pick another value")
	}

	resp, err := client.PostForm(ts.URL+"/db/main/table/widgets/edit", url.Values{
		"csrf_token": {csrf}, "where_token": {token},
		"v_id": {id}, "orig_id": {id},
		"v_name": {name}, "orig_name": {name},
		"v_qty": {"99"}, "orig_qty": {qty},
	})
	if err != nil {
		t.Fatalf("edit post: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("edit = %d, want 303 to browse", resp.StatusCode)
	}
	rows := queryRows(t, inspectConn(t, dbPath), `SELECT name, qty FROM widgets WHERE name = '`+name+`'`)
	if len(rows) != 1 || rows[0] != name+"|99" {
		t.Errorf("row after edit = %v, want [%s|99]", rows, name)
	}
}

func TestTableAndDatabaseSearch(t *testing.T) {
	ts, client, _ := newTestServer(t)
	login(t, client, ts.URL)
	csrf := csrfFrom(t, client, ts.URL+"/")

	resp, err := client.PostForm(ts.URL+"/db/main/table/widgets/search", url.Values{
		"csrf_token": {csrf}, "val_name": {"bolt"}, "op_name": {"="},
	})
	if err != nil {
		t.Fatalf("table search: %v", err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(b), "bolt") || strings.Contains(string(b), "nut") {
		t.Errorf("table search = %d; bolt found=%v nut excluded=%v",
			resp.StatusCode, strings.Contains(string(b), "bolt"), !strings.Contains(string(b), "nut"))
	}

	resp, err = client.PostForm(ts.URL+"/db/main/search", url.Values{
		"csrf_token": {csrf}, "term": {"bolt"},
	})
	if err != nil {
		t.Fatalf("db search: %v", err)
	}
	b, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(b), "widgets") || !strings.Contains(string(b), "match(es)") {
		t.Errorf("db search = %d, body misses widgets hit:\n%.1500s", resp.StatusCode, b)
	}
}

func TestNavChildren(t *testing.T) {
	ts, client, _ := newTestServer(t)
	login(t, client, ts.URL)
	code, body := getBody(t, client, ts.URL+"/nav/children?db=main")
	if code != http.StatusOK || !strings.Contains(body, "widgets") {
		t.Errorf("nav children = %d, widgets listed = %v", code, strings.Contains(body, "widgets"))
	}
}

func TestTableExportCSV(t *testing.T) {
	ts, client, _ := newTestServer(t)
	login(t, client, ts.URL)
	csrf := csrfFrom(t, client, ts.URL+"/")
	resp, err := client.PostForm(ts.URL+"/db/main/table/widgets/export",
		url.Values{"csrf_token": {csrf}, "format": {"csv"}})
	if err != nil {
		t.Fatalf("table export: %v", err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	body := string(b)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "bolt") || !strings.Contains(body, "nut") {
		t.Errorf("csv export = %d:\n%s", resp.StatusCode, body)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "text/csv") {
		t.Errorf("csv export content-type = %q", ct)
	}
}

func TestServerMonitorPages(t *testing.T) {
	ts, client, _ := newTestServer(t)
	login(t, client, ts.URL)
	// Section-header assertions (5.3), not just 200s: a monitor page that
	// renders the wrong template (or an error shell) must fail. Header-level
	// on purpose — SQLite exposes little status/process content.
	wantHeader := map[string]string{
		"/server/status":                    "Server status",
		"/server/variables":                 "Server variables",
		"/server/processes":                 "Processes",
		"/server":                           "",
		"/db/main/triggers":                 "",
		"/server/users":                     "",
		"/db/main/privileges":               "",
		"/db/main/table/widgets/privileges": "",
	}
	for path, header := range wantHeader {
		code, body := getBody(t, client, ts.URL+path)
		if code != http.StatusOK {
			t.Errorf("GET %s = %d, want 200", path, code)
			continue
		}
		if header != "" && !strings.Contains(body, header) {
			t.Errorf("GET %s missing section header %q", path, header)
		}
	}
}

// TestAccessControlSQLite proves what the SQLite-backed stack can prove about
// the account/privilege management feature: the GET pages hide every manage
// control (the dialect misses the UserManager/PrivilegeManager assertions),
// the POST routes are CSRF-protected by the global middleware, and a forged
// POST is refused with a clean "not supported" error — never a panic.
func TestAccessControlSQLite(t *testing.T) {
	ts, client, _ := newTestServer(t)
	login(t, client, ts.URL)

	for path, control := range map[string]string{
		"/server/users":                     "Create account",
		"/db/main/privileges":               "Grant privileges",
		"/db/main/table/widgets/privileges": "Grant privileges",
	} {
		code, body := getBody(t, client, ts.URL+path)
		if code != http.StatusOK {
			t.Errorf("GET %s = %d, want 200", path, code)
		}
		if strings.Contains(body, control) {
			t.Errorf("GET %s: manage control %q must be hidden on SQLite", path, control)
		}
	}

	// Without a CSRF token the global middleware refuses the POST outright.
	resp, err := client.PostForm(ts.URL+"/server/users", url.Values{"action": {"create_user"}, "user_name": {"x"}})
	if err != nil {
		t.Fatalf("POST /server/users: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("POST without CSRF = %d, want 403", resp.StatusCode)
	}

	// With a valid token, SQLite still has no UserManager/PrivilegeManager: the
	// handler must answer with a clean 400, not a panic or a silent success.
	csrf := csrfFrom(t, client, ts.URL+"/")
	for path, form := range map[string]url.Values{
		"/server/users":                     {"action": {"create_user"}, "user_name": {"x"}, "password": {"p"}},
		"/db/main/privileges":               {"action": {"grant"}, "grantee": {"x"}, "privs": {"SELECT"}},
		"/db/main/table/widgets/privileges": {"action": {"revoke"}, "grantee": {"x"}, "priv": {"SELECT"}},
	} {
		form.Set("csrf_token", csrf)
		resp, err := client.PostForm(ts.URL+path, form)
		if err != nil {
			t.Fatalf("POST %s: %v", path, err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest || !strings.Contains(string(b), "does not support") {
			t.Errorf("POST %s = %d, want 400 with a clean not-supported message:\n%.400s", path, resp.StatusCode, b)
		}
	}
}

func TestLogout(t *testing.T) {
	ts, client, _ := newTestServer(t)
	login(t, client, ts.URL)
	csrf := csrfFrom(t, client, ts.URL+"/")
	resp, err := client.PostForm(ts.URL+"/logout", url.Values{"csrf_token": {csrf}})
	if err != nil {
		t.Fatalf("logout: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Errorf("logout = %d, want 303", resp.StatusCode)
	}
	resp2 := getResp(t, client, ts.URL+"/")
	if resp2.StatusCode != http.StatusSeeOther || resp2.Header.Get("Location") != "/login" {
		t.Errorf("after logout / = %d loc=%q, want redirect to /login",
			resp2.StatusCode, resp2.Header.Get("Location"))
	}
}

// TestLoginRateLimited runs against a real (low-cap) limiter — the rest of the
// suite raises the cap to stay out of the way, so this is the only place the
// throttle path actually executes.
func TestLoginRateLimited(t *testing.T) {
	ts, client, _ := newTestServerWith(t, func(c *config.Config) {
		c.Security.LoginRateMax = 2
		c.Security.LoginRateWindow = time.Minute
	})
	csrf := csrfFrom(t, client, ts.URL+"/login")
	attempt := func() string {
		resp, err := client.PostForm(ts.URL+"/login",
			url.Values{"csrf_token": {csrf}, "server": {"no-such-server"}})
		if err != nil {
			t.Fatalf("login attempt: %v", err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return string(b)
	}
	for i := range 2 {
		if body := attempt(); !strings.Contains(body, "Unknown predefined server") {
			t.Fatalf("attempt %d should fail with unknown server, got:\n%.800s", i+1, body)
		}
	}
	if body := attempt(); !strings.Contains(body, "Too many login attempts") {
		t.Errorf("3rd attempt should be rate-limited, got:\n%.800s", body)
	}
}

// The absolute-timeout expiry test lives in the session package
// (TestAbsoluteTimeoutDeterministic), driven by an injected clock — its
// HTTP-level predecessor here raced the wall clock with fixed sleep margins
// and had a history of CI flakiness. The HTTP behaviors it also touched stay
// covered: expired-session redirects by TestUnauthenticatedRedirects, idle
// expiry by the session package's TestIdleExpiry.

// TestSSRFGuardBlocksMetadataHost confirms an ad-hoc login can never target
// link-local/cloud-metadata addresses (always refused, no configuration).
func TestSSRFGuardBlocksMetadataHost(t *testing.T) {
	ts, client, _ := newTestServer(t)
	csrf := csrfFrom(t, client, ts.URL+"/login")
	resp, err := client.PostForm(ts.URL+"/login", url.Values{
		"csrf_token": {csrf}, "engine": {"mysql"},
		"host": {"169.254.169.254"}, "username": {"x"}, "password": {"y"},
	})
	if err != nil {
		t.Fatalf("ssrf login: %v", err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode == http.StatusSeeOther {
		t.Fatal("metadata-address login unexpectedly succeeded")
	}
	body := string(b)
	// The client gets a generic message; the detailed CheckHost reason (which
	// embeds the resolved IP — a DNS oracle) is logged server-side, never returned.
	if !strings.Contains(body, "not permitted") {
		t.Errorf("metadata-address login should report a generic block, got:\n%.800s", body)
	}
	if strings.Contains(body, "resolves to a blocked") {
		t.Errorf("login response leaked the detailed SSRF reason to the client:\n%.800s", body)
	}
}

// TestAdHocLoginRequiresHost: an empty ad-hoc host must be refused outright.
// It used to fall through to the driver's LOCAL default (MySQL 127.0.0.1:3306,
// PostgreSQL its Unix socket) — a target the host allowlist/denylist never saw
// because CheckHost had nothing to match. The refusal must not depend on any
// SSRF control being configured.
func TestAdHocLoginRequiresHost(t *testing.T) {
	ts, client, _ := newTestServer(t)
	csrf := csrfFrom(t, client, ts.URL+"/login")
	resp, err := client.PostForm(ts.URL+"/login", url.Values{
		"csrf_token": {csrf}, "engine": {"mysql"},
		"host": {""}, "username": {"x"}, "password": {"y"},
	})
	if err != nil {
		t.Fatalf("empty-host login: %v", err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode == http.StatusSeeOther {
		t.Fatal("empty-host ad-hoc login unexpectedly succeeded")
	}
	if !strings.Contains(string(b), "Host is required") {
		t.Errorf("empty-host login should say the host is required, got:\n%.800s", b)
	}
}

// TestSecureCookiesOverProxy covers the TLS-terminating-proxy posture: with
// secure_cookies on (plain HTTP to TableX), cookies must carry __Host- +
// Secure and responses must carry HSTS.
func TestSecureCookiesOverProxy(t *testing.T) {
	ts, client, _ := newTestServerWith(t, func(c *config.Config) {
		c.Security.SecureCookies = true
	})
	resp, err := client.Get(ts.URL + "/login")
	if err != nil {
		t.Fatalf("login page: %v", err)
	}
	resp.Body.Close()
	if hsts := resp.Header.Get("Strict-Transport-Security"); hsts == "" {
		t.Error("HSTS header missing with secure_cookies on")
	}
	var sessionCookie *http.Cookie
	for _, c := range resp.Cookies() {
		if strings.Contains(c.Name, "tablex_session") {
			sessionCookie = c
		}
	}
	if sessionCookie == nil {
		t.Fatalf("no session cookie set; cookies: %v", resp.Cookies())
	}
	if !strings.HasPrefix(sessionCookie.Name, "__Host-") {
		t.Errorf("cookie name %q should carry the __Host- prefix", sessionCookie.Name)
	}
	if !sessionCookie.Secure || !sessionCookie.HttpOnly {
		t.Errorf("cookie must be Secure+HttpOnly, got Secure=%v HttpOnly=%v",
			sessionCookie.Secure, sessionCookie.HttpOnly)
	}
}
