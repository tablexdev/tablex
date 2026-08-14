package server_test

// The session-creation throttle (§6h).
//
// The login limiter cannot serve this: it short-circuits on safe methods, while
// an anonymous GET to ANY route mints a session — and, with [storage]
// configured, a durable ROW. So the cap is admitted inside Manager.Start, which
// is the only place that can tell a creation from a load without calling Load
// twice (Load is not a pure query: it deletes an expired session and rewrites
// LastSeen).

import (
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tablexdev/tablex/internal/audit"
	"github.com/tablexdev/tablex/internal/config"
)

// throttleAuditServer starts a throttled TableX writing its audit trail to a
// JSON Lines file, and returns the base URL, a client and the trail's path.
//
// The client is deliberately JAR-LESS. The one newTestServerWith hands back
// keeps cookies, and a replayed session cookie makes Manager.Load succeed — so
// Start returns early, Admit is never consulted and the throttle never engages.
// Every throttle test in this file has its own jar-less client for that reason.
func throttleAuditServer(t *testing.T, max int) (base string, client *http.Client, auditPath string) {
	t.Helper()
	auditPath = filepath.Join(t.TempDir(), "audit.jsonl")
	ts, _, _ := newTestServerWith(t, func(c *config.Config) {
		c.Audit = config.AuditConfig{File: auditPath}
		c.Security.SessionCreateMax = max
	})
	return ts.URL, &http.Client{CheckRedirect: noRedirect}, auditPath
}

// TestSessionCreateThrottleRefusesWith429: the refusal is a real 429 with
// Retry-After. Not a 503 (that is capacity for work in flight) and not a login
// redirect (there is no session yet to redirect).
func TestSessionCreateThrottleRefusesWith429(t *testing.T) {
	ts, _, _ := newTestServerWith(t, func(c *config.Config) {
		c.Security.SessionCreateMax = 2
	})
	// A cookie-less client: every request is a fresh creation attempt.
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	var got429 bool
	for i := 0; i < 6; i++ {
		resp, err := client.Get(ts.URL + "/login")
		if err != nil {
			t.Fatalf("GET /login: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusTooManyRequests {
			got429 = true
			if resp.Header.Get("Retry-After") == "" {
				t.Error("the refusal carries no Retry-After")
			}
			break
		}
	}
	if !got429 {
		t.Fatal("six cookie-less requests against a cap of two produced no 429")
	}
}

// TestSessionCreateThrottleIsNotDefeatedByAGarbageCookie: admission is keyed on
// the CREATION EVENT, not on cookie absence. Load returns nil for a missing,
// invalid or EXPIRED cookie, so a check for "no cookie" is defeated by sending
// anything at all.
func TestSessionCreateThrottleIsNotDefeatedByAGarbageCookie(t *testing.T) {
	ts, _, _ := newTestServerWith(t, func(c *config.Config) {
		c.Security.SessionCreateMax = 2
	})
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	var got429 bool
	for i := 0; i < 6; i++ {
		req, _ := http.NewRequest(http.MethodGet, ts.URL+"/login", nil)
		req.AddCookie(&http.Cookie{Name: "tablex_session", Value: "not-a-real-session-id"})
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("GET /login: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusTooManyRequests {
			got429 = true
			break
		}
	}
	if !got429 {
		t.Error("a garbage cookie defeated the throttle; admission must key on the creation, not on cookie absence")
	}
}

// TestSessionCreateThrottleRefusesHTMXWithTheRealStatus: renderError's htmx arm
// answers a not-logged-in caller with HX-Redirect /login at HTTP 200. Here that
// would be a redirect to the very page being throttled — a loop — and there is
// no in-page panel to swap into either. A full-page-only test passes whichever
// way this went, so the htmx variant is asserted specifically.
func TestSessionCreateThrottleRefusesHTMXWithTheRealStatus(t *testing.T) {
	ts, _, _ := newTestServerWith(t, func(c *config.Config) {
		c.Security.SessionCreateMax = 1
	})
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	for i := 0; i < 5; i++ {
		req, _ := http.NewRequest(http.MethodGet, ts.URL+"/login", nil)
		req.Header.Set("HX-Request", "true")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("GET /login: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusTooManyRequests {
			if loc := resp.Header.Get("HX-Redirect"); loc != "" {
				t.Errorf("the htmx refusal carries HX-Redirect %q; a redirect to the throttled page is a loop", loc)
			}
			return
		}
		if resp.Header.Get("HX-Redirect") != "" {
			t.Fatalf("an htmx refusal answered %d with HX-Redirect instead of 429", resp.StatusCode)
		}
	}
	t.Error("five htmx requests against a cap of one produced no 429")
}

// TestSessionCreateThrottleCountsAThrottledLogin: recordLoginRejected splits
// throttled from denied precisely so a rising throttled count shows the limiter
// holding. A 429 raised in the middleware means the login handler never runs, so
// without an explicit count the one metric built to show that stays flat.
func TestSessionCreateThrottleCountsAThrottledLogin(t *testing.T) {
	base, client, _ := metricsServer(t, func(c *config.Config) {
		c.Security.SessionCreateMax = 1
	})
	post := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for i := 0; i < 6; i++ {
		resp, err := post.PostForm(base+"/login", url.Values{"username": {"u"}})
		if err != nil {
			t.Fatalf("POST /login: %v", err)
		}
		resp.Body.Close()
	}
	s := samples(t, mustScrape(t, client, base))
	if got := s[`tablex_logins_total{result="throttled"}`]; got == 0 {
		t.Error(`logins_total{result="throttled"} stayed 0 while the session throttle refused POST /login`)
	}
}

// TestSessionCreateThrottleLeavesUnconfiguredSSOAt404: the SSO routes answer 404
// when no provider is configured, deliberately, so an unconfigured deployment
// does not advertise a feature it does not have. sessionMW runs ahead of the
// router, so a throttled request would otherwise answer 429 and advertise it.
func TestSessionCreateThrottleLeavesUnconfiguredSSOAt404(t *testing.T) {
	ts, _, _ := newTestServerWith(t, func(c *config.Config) {
		c.Security.SessionCreateMax = 1
	})
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	// Exhaust the limiter on an ordinary route first.
	for i := 0; i < 4; i++ {
		resp, err := client.Get(ts.URL + "/login")
		if err != nil {
			t.Fatalf("GET /login: %v", err)
		}
		resp.Body.Close()
	}
	for _, path := range []string{"/auth/sso/start", "/auth/sso/callback"} {
		resp, err := client.Get(ts.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		body := readBody(t, resp)
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("GET %s with the limiter exhausted = %d, want 404:\n%.300s", path, resp.StatusCode, body)
		}
		if strings.Contains(body, "session_create_max") {
			t.Errorf("GET %s advertised the throttle on an unconfigured SSO route", path)
		}
	}
}

// TestSessionCreateThrottleEmitsAnAuthEventForALoginPost: a 429 raised in the
// middleware means the login handler never runs, and auditAction returns early
// for /login precisely because that handler normally emits its own event — so
// both routes to the trail are closed and the refusal has to emit one itself.
// Without this the refused login attempts are the only ones an auditor cannot
// see, which is the wrong way round.
//
// Asserted on the FILE, not on Pending.Outcome(): what a security claim in
// docs/security.md rests on is a record an auditor can read.
func TestSessionCreateThrottleEmitsAnAuthEventForALoginPost(t *testing.T) {
	base, client, path := throttleAuditServer(t, 1)

	// Spend the single admission on a page load. A rejected login further up
	// would write an auth event for /login of its own, and behind a 429 the
	// handler never runs — so this leaves the refusal as the only possible source.
	first, err := client.Get(base + "/login")
	if err != nil {
		t.Fatalf("GET /login: %v", err)
	}
	readBody(t, first)
	if first.StatusCode != http.StatusOK {
		t.Fatalf("the first request was not admitted: %d", first.StatusCode)
	}

	resp, err := client.PostForm(base+"/login", url.Values{"username": {"u"}})
	if err != nil {
		t.Fatalf("POST /login: %v", err)
	}
	readBody(t, resp)
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("POST /login against an exhausted limiter = %d, want 429", resp.StatusCode)
	}

	events := auditEvents(t, path)
	var (
		throttled audit.Event
		found     bool
	)
	for _, e := range events {
		if e.Kind == audit.KindAuth && strings.Contains(e.Detail, "session_create_max") {
			throttled, found = e, true
			break
		}
	}
	if !found {
		t.Fatalf("a throttled login POST emitted no auth event naming the cap; got %+v", events)
	}
	if throttled.Path != "/login" {
		t.Errorf("throttled auth event path = %q, want /login", throttled.Path)
	}
	if throttled.Method != http.MethodPost {
		t.Errorf("throttled auth event method = %q, want POST", throttled.Method)
	}
	if throttled.Outcome != audit.OutcomeDenied {
		t.Errorf("throttled auth event outcome = %q, want denied — OutcomeForStatus would file a 429 as invalid, which is a malformed request, not a refusal", throttled.Outcome)
	}
	if throttled.Remote == "" {
		t.Error("the throttled auth event records no client address, which is the only thing tying a flood to its source")
	}
	// No account, and there cannot be one: admission runs upstream of csrf and of
	// any credential parse, so Pending.Identity() is necessarily empty. Pinning it
	// pins the ORDER — filling this field in would mean moving admission
	// downstream of the parse, reintroducing exactly the work the cap sheds.
	if throttled.Account != "" {
		t.Errorf("the throttled auth event carries account %q; admission runs before any credential is read", throttled.Account)
	}
}

// TestSessionCreateThrottleEmitsNoAuthEventForAPageLoad is the other half of
// "endpoint-aware". An anonymous GET of the login page is a page load, not a
// login attempt, and filing one as a denied authentication would put a burst of
// ordinary navigation into the trail as an attack. A blanket emit passes the test
// above; only this one rejects it.
func TestSessionCreateThrottleEmitsNoAuthEventForAPageLoad(t *testing.T) {
	base, client, path := throttleAuditServer(t, 1)

	first, err := client.Get(base + "/login")
	if err != nil {
		t.Fatalf("GET /login: %v", err)
	}
	readBody(t, first)
	if first.StatusCode != http.StatusOK {
		t.Fatalf("the first request was not admitted: %d", first.StatusCode)
	}
	second, err := client.Get(base + "/login")
	if err != nil {
		t.Fatalf("GET /login: %v", err)
	}
	readBody(t, second)
	if second.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("the second GET /login = %d, want 429", second.StatusCode)
	}

	events := auditEvents(t, path)
	if e, ok := firstOf(events, audit.KindAuth, ""); ok {
		t.Errorf("a throttled page load was recorded as an authentication event: %+v", e)
	}
	// And nothing else either: auditAction skips safe methods AND /login, so for
	// this request the trail is legitimately empty rather than merely auth-free.
	if len(events) != 0 {
		t.Errorf("a throttled page load wrote %d audit events: %+v", len(events), events)
	}
}

// TestSessionCreateThrottleLeavesUnconfiguredSSOUntouched finishes what
// TestSessionCreateThrottleLeavesUnconfiguredSSOAt404 starts. The bypass returns
// from sessionMW BEFORE Start, which is a stronger claim than the status code
// shows, and it is asserted in the two states that separate it from the
// near-misses:
//
//   - with the limiter still open, no session is created at all — no cookie, no
//     durable row. A bypass placed one layer later, after Start, answers the same
//     404 while minting a session per probe of a route that does not exist.
//   - with the limiter exhausted, nothing reaches the audit trail. No bypass at
//     all would answer 429 AND file the refusal as a denied authentication,
//     because isSSOPath is one of refuseSessionCreate's two emitting arms.
func TestSessionCreateThrottleLeavesUnconfiguredSSOUntouched(t *testing.T) {
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.jsonl")
	meta := filepath.Join(dir, "meta.db")
	// Built here rather than through storageServer, which takes no mutate
	// callback and so cannot also turn auditing on.
	ts, _, _ := newTestServerWith(t, func(c *config.Config) {
		c.Audit = config.AuditConfig{File: auditPath}
		c.Storage = config.StorageConfig{Engine: "sqlite", FilePath: meta}
		c.Security.SessionCreateMax = 1
	})
	client := &http.Client{CheckRedirect: noRedirect}
	ssoPaths := []string{"/auth/sso/start", "/auth/sso/callback"}

	get404 := func(when, path string) {
		t.Helper()
		resp, err := client.Get(ts.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		body := readBody(t, resp)
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("GET %s %s = %d, want 404:\n%.300s", path, when, resp.StatusCode, body)
		}
		if strings.Contains(body, "session_create_max") {
			t.Errorf("GET %s %s advertised the throttle on an unconfigured SSO route", path, when)
		}
		for _, c := range resp.Cookies() {
			if c.Name == config.Default().Session.CookieName && c.Value != "" {
				t.Errorf("GET %s %s set a session cookie; the bypass returns before Start", path, when)
			}
		}
	}

	// The limiter is untouched here, so admission would have ALLOWED a session.
	// None may be created anyway.
	for _, path := range ssoPaths {
		get404("with the limiter open", path)
	}
	if n := countMetaSessions(t, meta); n != 0 {
		t.Errorf("two bypassed SSO requests stored %d sessions; the bypass returns before Start, so it creates none", n)
	}

	// Now exhaust the limiter on an ordinary route. The one admitted request
	// creates a durable session of its own, so the snapshot is taken afterwards.
	for i := 0; i < 4; i++ {
		resp, err := client.Get(ts.URL + "/login")
		if err != nil {
			t.Fatalf("GET /login: %v", err)
		}
		readBody(t, resp)
	}
	before := countMetaSessions(t, meta)
	if before == 0 {
		t.Fatal("fixture: no durable session was stored, so an unchanged count below would prove nothing")
	}
	for _, path := range ssoPaths {
		get404("with the limiter exhausted", path)
	}
	if got := countMetaSessions(t, meta); got != before {
		t.Errorf("stored sessions went from %d to %d across two bypassed SSO requests, which must create none", before, got)
	}
	for _, e := range auditEvents(t, auditPath) {
		if e.Kind == audit.KindAuth && (e.Path == "/auth/sso/start" || e.Path == "/auth/sso/callback") {
			t.Errorf("a bypassed SSO route emitted an auth event: %+v", e)
		}
	}
}

// TestSessionCreateThrottleOffByDefault: it is keyed on the client IP and, unlike
// the login limiter, gates GETs too — so behind a NAT an under-sized value
// refuses the login PAGE to a whole office. Shipping it off is the decision.
func TestSessionCreateThrottleOffByDefault(t *testing.T) {
	if got := config.Default().Security.SessionCreateMax; got > 0 {
		t.Errorf("session_create_max defaults to %d; it must ship disabled", got)
	}
	// The window still has a default, so enabling the throttle is ONE key.
	if got := config.Default().Security.SessionCreateWindow; got <= 0 {
		t.Errorf("session_create_window defaults to %v; enabling the throttle must be one key", got)
	}
}
