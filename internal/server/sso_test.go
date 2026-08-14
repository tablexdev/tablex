package server_test

// The SSO gate, exercised through the real server.
//
// The point of these tests is the PLACEMENT of the gate, which is the whole design
// decision: SSO is an extra factor in front of the credential login, so an
// unverified person must not reach the login form, and a verified one must still
// have to type credentials. A test that only checked "SSO works" would miss both
// halves.

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tablexdev/tablex/internal/config"
)

// fakeIDP is a provider good enough to complete one flow. It records the nonce it
// was asked for so the token it mints matches, which is what the callback checks.
type fakeIDP struct {
	srv      *httptest.Server
	clientID string
	email    string
	subject  string
	// emailVerified is emitted verbatim as the email_verified claim; nil
	// omits it. The default is true so the allowlist tests keep testing the
	// allowlist (a verified-but-not-admitted email), not the verification
	// gate in front of it.
	emailVerified any
	// tokenCalls counts token-endpoint hits — the concurrency test's whole
	// assertion is that racing callbacks reach the exchange at most once.
	tokenCalls atomic.Int64
}

func newFakeIDP(t *testing.T) *fakeIDP {
	t.Helper()
	p := &fakeIDP{clientID: "tablex", email: "dana@example.com", subject: "sub-42", emailVerified: true}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 p.srv.URL,
			"authorization_endpoint": p.srv.URL + "/authorize",
			"token_endpoint":         p.srv.URL + "/token",
		})
	})
	// The authorization endpoint echoes state and nonce back through the code, so
	// the token endpoint can mint a token that matches without shared state.
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		redirect, _ := url.Parse(q.Get("redirect_uri"))
		rq := redirect.Query()
		rq.Set("code", q.Get("nonce")) // the "code" carries the nonce
		rq.Set("state", q.Get("state"))
		redirect.RawQuery = rq.Encode()
		http.Redirect(w, r, redirect.String(), http.StatusFound)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		p.tokenCalls.Add(1)
		_ = r.ParseForm()
		nonce := r.PostFormValue("code")
		enc := func(v any) string {
			b, _ := json.Marshal(v)
			return base64.RawURLEncoding.EncodeToString(b)
		}
		claims := map[string]any{
			"iss": p.srv.URL, "sub": p.subject, "aud": p.clientID,
			"exp": time.Now().Add(5 * time.Minute).Unix(), "iat": time.Now().Unix(),
			"nonce": nonce, "email": p.email,
		}
		if p.emailVerified != nil {
			claims["email_verified"] = p.emailVerified
		}
		tok := enc(map[string]string{"alg": "RS256"}) + "." + enc(claims) + ".sig"
		_ = json.NewEncoder(w).Encode(map[string]any{"id_token": tok, "token_type": "Bearer"})
	})
	p.srv = httptest.NewServer(mux)
	t.Cleanup(p.srv.Close)
	return p
}

// gatedServer starts TableX with the gate pointed at a fake provider.
func gatedServer(t *testing.T, tune func(*config.SSOConfig)) (*httptest.Server, *http.Client, *fakeIDP) {
	t.Helper()
	idp := newFakeIDP(t)
	var ts *httptest.Server
	var client *http.Client
	ts, client, _ = newTestServerWith(t, func(c *config.Config) {
		c.SSO = config.SSOConfig{
			Issuer:       idp.srv.URL,
			ClientID:     idp.clientID,
			ClientSecret: "shh",
			// Filled in below once the test server's URL is known — the provider
			// only echoes it back, so any absolute URL on this host works.
			RedirectURL: "http://127.0.0.1/auth/sso/callback",
		}
		if tune != nil {
			tune(&c.SSO)
		}
	})
	return ts, client, idp
}

// TestSSOGateStandsInFrontOfTheLoginForm is the core of the design: the gate is
// in front of /login, not instead of it.
func TestSSOGateStandsInFrontOfTheLoginForm(t *testing.T) {
	ts, client, _ := gatedServer(t, nil)

	for _, path := range []string{"/", "/login", "/db/main", "/server"} {
		resp, err := client.Get(ts.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusSeeOther {
			t.Errorf("GET %s = %d, want 303 to the provider", path, resp.StatusCode)
			continue
		}
		if loc := resp.Header.Get("Location"); loc != "/auth/sso/start" {
			t.Errorf("GET %s redirected to %q, want /auth/sso/start", path, loc)
		}
	}
}

// TestSSOGateLetsMachineEndpointsThrough: a browser redirect in front of a probe
// or a scraper would break it while adding nothing — neither is a person, and
// /metrics has its own token/allowlist.
func TestSSOGateLetsMachineEndpointsThrough(t *testing.T) {
	ts, client, _ := gatedServer(t, nil)
	for _, tc := range []struct {
		path       string
		wantStatus int
	}{
		{"/healthz", http.StatusOK},
		{"/static/css/tablex.css", http.StatusOK},
		{"/auth/sso/start", http.StatusSeeOther}, // to the provider, not to itself
	} {
		resp, err := client.Get(ts.URL + tc.path)
		if err != nil {
			t.Fatalf("GET %s: %v", tc.path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != tc.wantStatus {
			t.Errorf("GET %s = %d, want %d", tc.path, resp.StatusCode, tc.wantStatus)
		}
		if tc.path == "/auth/sso/start" {
			if loc := resp.Header.Get("Location"); !strings.Contains(loc, "/authorize?") {
				t.Errorf("/auth/sso/start redirected to %q, want the provider's authorize endpoint", loc)
			}
		}
	}
}

// TestSSOFlowReachesTheLoginFormAndNoFurther walks the whole handshake and then
// checks the half that matters most: passing the provider does NOT log you in.
func TestSSOFlowReachesTheLoginFormAndNoFurther(t *testing.T) {
	ts, client, _ := gatedServer(t, nil)

	// 1. Start: the redirect carries state, nonce and an S256 challenge.
	resp, err := client.Get(ts.URL + "/auth/sso/start")
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	resp.Body.Close()
	authURL, err := resp.Location()
	if err != nil {
		t.Fatalf("start did not redirect: %v", err)
	}
	q := authURL.Query()
	if q.Get("state") == "" || q.Get("nonce") == "" || q.Get("code_challenge") == "" {
		t.Fatalf("authorize URL is missing handshake parameters: %s", authURL.RawQuery)
	}
	if got := q.Get("code_challenge_method"); got != "S256" {
		t.Errorf("code_challenge_method = %q, want S256", got)
	}

	// 2. Follow the provider by hand, then bring its answer back to TableX.
	callback := ts.URL + "/auth/sso/callback?code=" + url.QueryEscape(q.Get("nonce")) +
		"&state=" + url.QueryEscape(q.Get("state"))
	resp, err = client.Get(callback)
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("callback = %d, want 303", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/login" {
		t.Fatalf("callback redirected to %q, want /login — SSO must land on the credential form", loc)
	}

	// 3. The login form is now reachable...
	code, body := getBody(t, client, ts.URL+"/login")
	if code != http.StatusOK {
		t.Fatalf("GET /login after SSO = %d, want 200", code)
	}
	if !strings.Contains(body, `name="password"`) {
		t.Error("the login form has no password field; SSO must not replace the credential login")
	}

	// 4. ...but nothing behind it is, because no database credential was supplied.
	// This is the assertion that would catch someone "improving" the gate into a
	// single-sign-on that logs people straight in.
	resp, err = client.Get(ts.URL + "/db/main")
	if err != nil {
		t.Fatalf("GET /db/main: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/login" {
		t.Errorf("after SSO, /db/main = %d loc=%q; want 303 to /login — passing the gate is not logging in",
			resp.StatusCode, resp.Header.Get("Location"))
	}

	// 5. And the credential login still works through the gate.
	login(t, client, ts.URL)
	if code, _ := getBody(t, client, ts.URL+"/"); code != http.StatusOK {
		t.Errorf("GET / after SSO + login = %d, want 200", code)
	}
}

func TestSSOCallbackRefusals(t *testing.T) {
	t.Run("a callback with no handshake is refused", func(t *testing.T) {
		// Nobody started a flow on this browser, so there is nothing to complete.
		// Accepting it would make the state parameter decorative.
		ts, client, _ := gatedServer(t, nil)
		resp, err := client.Get(ts.URL + "/auth/sso/callback?code=x&state=y")
		if err != nil {
			t.Fatalf("callback: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusSeeOther && resp.Header.Get("Location") == "/login" {
			t.Fatal("a callback with no stored handshake reached the login form")
		}
	})

	t.Run("a forged state is refused", func(t *testing.T) {
		ts, client, _ := gatedServer(t, nil)
		resp, _ := client.Get(ts.URL + "/auth/sso/start") // establishes a handshake
		resp.Body.Close()
		loc, err := resp.Location()
		if err != nil {
			t.Fatalf("start did not redirect: %v", err)
		}
		bad := ts.URL + "/auth/sso/callback?code=" + url.QueryEscape(loc.Query().Get("nonce")) +
			"&state=not-the-state"
		resp, err = client.Get(bad)
		if err != nil {
			t.Fatalf("callback: %v", err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode == http.StatusSeeOther && resp.Header.Get("Location") == "/login" {
			t.Fatal("a forged state reached the login form")
		}
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("forged state = %d, want 403", resp.StatusCode)
		}
		// The error page renders a "detail" as the offending SQL — under a
		// "Statement:" heading, in a code block. This page is reached routinely
		// by people who typed no SQL at all, so the guidance belongs in the
		// message and the detail must be empty.
		if strings.Contains(string(body), "Statement:") {
			t.Errorf("the single sign-on failure page presents its guidance as a SQL statement:\n%.900s", body)
		}
		// The guidance itself must survive that move, or the page loses the one
		// link that fixes the common, innocent case.
		if !strings.Contains(string(body), "/auth/sso/start") {
			t.Errorf("the single sign-on failure page no longer points back to the start route:\n%.900s", body)
		}
	})

	t.Run("a failed callback spends the handshake", func(t *testing.T) {
		// A SUCCESSFUL callback overwrites the stored state with the verified
		// identity anyway, so replaying a success proves nothing; the property
		// that needs a test is that a FAILED attempt also leaves nothing
		// reusable. ConsumeSSOHandshake spends the handshake atomically on the
		// state match itself, and every denial past that check clears the whole
		// SSO state — otherwise a state value that leaked could be retried
		// until it worked.
		ts, client, _ := gatedServer(t, nil)
		resp, _ := client.Get(ts.URL + "/auth/sso/start")
		resp.Body.Close()
		loc, err := resp.Location()
		if err != nil {
			t.Fatalf("start did not redirect: %v", err)
		}
		nonce, state := loc.Query().Get("nonce"), loc.Query().Get("state")

		// Attempt 1: the right state but no code — fails after the state check.
		bad, err := client.Get(ts.URL + "/auth/sso/callback?state=" + url.QueryEscape(state))
		if err != nil {
			t.Fatalf("first callback: %v", err)
		}
		bad.Body.Close()
		if bad.StatusCode != http.StatusForbidden {
			t.Fatalf("a callback with no code = %d, want 403 (positive control)", bad.StatusCode)
		}

		// Attempt 2: the same state, now WITH a valid code. It must still be
		// refused, because attempt 1 spent the handshake.
		retry, err := client.Get(ts.URL + "/auth/sso/callback?code=" + url.QueryEscape(nonce) +
			"&state=" + url.QueryEscape(state))
		if err != nil {
			t.Fatalf("second callback: %v", err)
		}
		retry.Body.Close()
		if retry.StatusCode == http.StatusSeeOther && retry.Header.Get("Location") == "/login" {
			t.Error("a state reused after a failed callback was accepted; the handshake is not spent on failure")
		}
	})

	t.Run("the handshake is single-use", func(t *testing.T) {
		// Replaying a completed callback must not work: the stored state is spent
		// when the callback runs, so the second attempt has nothing to match.
		ts, client, _ := gatedServer(t, nil)
		resp, _ := client.Get(ts.URL + "/auth/sso/start")
		resp.Body.Close()
		loc, _ := resp.Location()
		cb := ts.URL + "/auth/sso/callback?code=" + url.QueryEscape(loc.Query().Get("nonce")) +
			"&state=" + url.QueryEscape(loc.Query().Get("state"))

		first, err := client.Get(cb)
		if err != nil {
			t.Fatalf("first callback: %v", err)
		}
		first.Body.Close()
		if first.StatusCode != http.StatusSeeOther {
			t.Fatalf("first callback = %d, want 303 (positive control)", first.StatusCode)
		}
		second, err := client.Get(cb)
		if err != nil {
			t.Fatalf("second callback: %v", err)
		}
		second.Body.Close()
		if second.StatusCode == http.StatusSeeOther && second.Header.Get("Location") == "/login" {
			t.Error("the same callback was accepted twice; the handshake is not single-use")
		}
	})

	t.Run("concurrent callbacks reach the exchange at most once", func(t *testing.T) {
		// SSO()+SetSSO were two lock acquisitions, so two racing callbacks on
		// one session cookie both read the same handshake, both passed the
		// state check against their own copies, and BOTH reached the token
		// exchange. ConsumeSSOHandshake is the single serialization point;
		// the sequential single-use tests above cannot observe this at all.
		ts, client, idp := gatedServer(t, nil)
		resp, _ := client.Get(ts.URL + "/auth/sso/start")
		resp.Body.Close()
		loc, err := resp.Location()
		if err != nil {
			t.Fatalf("start did not redirect: %v", err)
		}
		cb := ts.URL + "/auth/sso/callback?code=" + url.QueryEscape(loc.Query().Get("nonce")) +
			"&state=" + url.QueryEscape(loc.Query().Get("state"))

		const racers = 8
		var wg sync.WaitGroup
		var wins atomic.Int64
		for range racers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				resp, err := client.Get(cb)
				if err != nil {
					return
				}
				resp.Body.Close()
				if resp.StatusCode == http.StatusSeeOther && resp.Header.Get("Location") == "/login" {
					wins.Add(1)
				}
			}()
		}
		wg.Wait()
		if got := wins.Load(); got != 1 {
			t.Errorf("%d of %d racing callbacks succeeded, want exactly 1", got, racers)
		}
		if got := idp.tokenCalls.Load(); got > 1 {
			t.Errorf("the token endpoint was hit %d times; a racing loser must never reach Exchange", got)
		}
	})

	t.Run("an identity outside the allowlist is refused", func(t *testing.T) {
		ts, client, _ := gatedServer(t, func(s *config.SSOConfig) {
			s.AllowedDomains = []string{"allowed.example"}
		})
		resp, _ := client.Get(ts.URL + "/auth/sso/start")
		resp.Body.Close()
		loc, _ := resp.Location()
		resp, err := client.Get(ts.URL + "/auth/sso/callback?code=" +
			url.QueryEscape(loc.Query().Get("nonce")) + "&state=" + url.QueryEscape(loc.Query().Get("state")))
		if err != nil {
			t.Fatalf("callback: %v", err)
		}
		resp.Body.Close()
		// The provider vouched for dana@example.com, which is not in
		// allowed.example — verified, but not admitted.
		if resp.StatusCode == http.StatusSeeOther && resp.Header.Get("Location") == "/login" {
			t.Fatal("an identity outside sso.allowed_domains reached the login form")
		}
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("disallowed identity = %d, want 403", resp.StatusCode)
		}
	})

}

// gatedServerLowRate is gatedServer with the login rate limit lowered to max,
// so the SSO routes (which inherit login_rate_window/max) can be exhausted in
// a handful of requests instead of the test harness's default 1000.
func gatedServerLowRate(t *testing.T, max int) (*httptest.Server, *http.Client, *fakeIDP) {
	t.Helper()
	idp := newFakeIDP(t)
	ts, client, _ := newTestServerWith(t, func(c *config.Config) {
		c.Security.LoginRateMax = max
		c.Security.LoginRateWindow = time.Minute
		c.SSO = config.SSOConfig{
			Issuer:       idp.srv.URL,
			ClientID:     idp.clientID,
			ClientSecret: "shh",
			RedirectURL:  "http://127.0.0.1/auth/sso/callback",
		}
	})
	return ts, client, idp
}

// anonClient is a cookie-less client: every request it makes arrives with no
// session, which is the shape the sso:start budget bounds (a start that must
// MINT state). It follows no redirects, matching the harness's client.
func anonClient() *http.Client {
	return &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// TestSSORateLimiting: with [sso] on, both routes are throttled — an anonymous
// /auth/sso/start loop cannot mint handshake state without bound, and the
// callback cannot drive unbounded token-endpoint exchanges — keyed by IP under
// login_rate_window/max, with the refusal a real 429 (never an HX-Redirect
// loop). The keys are namespaced, so exhausting SSO leaves /login usable and
// vice versa. A rate-denied callback must leave the handshake intact, because
// Reserve is ahead of the consume.
func TestSSORateLimiting(t *testing.T) {
	t.Run("an anonymous start loop is throttled with a real 429", func(t *testing.T) {
		ts, _, _ := gatedServerLowRate(t, 3)
		// SESSIONLESS requests: each one would mint a new session, which is the
		// unbounded resource this budget exists to bound. A jar-carrying client
		// is the wrong instrument here — it would hold the session minted by
		// its first request and every later start would be the exempt O(1)
		// overwrite (asserted by the next subtest).
		var got429 bool
		for i := 0; i < 5; i++ {
			r, err := anonClient().Get(ts.URL + "/auth/sso/start")
			if err != nil {
				t.Fatalf("start %d: %v", i, err)
			}
			r.Body.Close()
			if r.StatusCode == http.StatusTooManyRequests {
				got429 = true
				if r.Header.Get("Retry-After") == "" {
					t.Error("a throttled start carries no Retry-After")
				}
				// Never an HX-Redirect (that would loop back to the start route).
				if r.Header.Get("HX-Redirect") != "" {
					t.Error("a throttled start emitted HX-Redirect — the redirect loop is back")
				}
				break
			}
		}
		if !got429 {
			t.Error("an unbounded anonymous start loop was never throttled")
		}
	})

	t.Run("an established session is never locked out of the start route", func(t *testing.T) {
		// The regression this exemption exists for. ssoGate redirects EVERY
		// unverified request for every human route to /auth/sso/start, so an
		// IP-keyed budget charged on each arrival is spent by ordinary page
		// loads — and behind one NAT egress address a handful of colleagues, or
		// one person with several restored tabs, would lock the whole office
		// out of the sign-in entry point. A session-bearing start overwrites
		// that session's own handshake slot in place: no new session, no
		// provider contact, so it is not throttled at all.
		ts, client, _ := gatedServerLowRate(t, 3)
		for i := 0; i < 12; i++ { // well past max=3
			r, err := client.Get(ts.URL + "/auth/sso/start")
			if err != nil {
				t.Fatalf("start %d: %v", i, err)
			}
			r.Body.Close()
			if r.StatusCode == http.StatusTooManyRequests {
				t.Fatalf("start %d for an ESTABLISHED session was throttled; ordinary page loads through ssoGate would lock a shared IP out", i)
			}
			if r.StatusCode != http.StatusSeeOther {
				t.Fatalf("start %d = %d, want 303 to the provider", i, r.StatusCode)
			}
		}
		// And the anonymous budget is still intact for that IP: the exempt
		// requests spent nothing.
		r, err := anonClient().Get(ts.URL + "/auth/sso/start")
		if err != nil {
			t.Fatalf("anonymous start: %v", err)
		}
		r.Body.Close()
		if r.StatusCode == http.StatusTooManyRequests {
			t.Error("the exempt session-bearing starts spent the anonymous IP budget after all")
		}
	})

	t.Run("a garbage session cookie does not buy an exemption", func(t *testing.T) {
		// The trap session.Manager.Start documents: Load returns nil for a
		// missing, invalid OR expired cookie, so an exemption keyed on cookie
		// PRESENCE would hand every attacker a free pass for the price of one
		// forged header — each request would still mint a whole new session.
		// Only a cookie that resolves to a live session is exempt.
		ts, _, _ := gatedServerLowRate(t, 3)
		var got429 bool
		for i := 0; i < 5; i++ {
			req, err := http.NewRequest(http.MethodGet, ts.URL+"/auth/sso/start", nil)
			if err != nil {
				t.Fatalf("build request: %v", err)
			}
			req.AddCookie(&http.Cookie{Name: "tablex_session", Value: "forged-not-a-real-session-id"})
			r, err := anonClient().Do(req)
			if err != nil {
				t.Fatalf("start %d: %v", i, err)
			}
			r.Body.Close()
			if r.StatusCode == http.StatusTooManyRequests {
				got429 = true
				break
			}
		}
		if !got429 {
			t.Error("a forged session cookie exempted the request from the start budget; cookie presence is not a session")
		}
	})

	t.Run("a rate-denied callback leaves the handshake intact", func(t *testing.T) {
		ts, client, idp := gatedServerLowRate(t, 4)
		resp, _ := client.Get(ts.URL + "/auth/sso/start")
		resp.Body.Close()
		loc, _ := resp.Location()
		realCB := ts.URL + "/auth/sso/callback?code=" + url.QueryEscape(loc.Query().Get("nonce")) +
			"&state=" + url.QueryEscape(loc.Query().Get("state"))
		// Exhaust the sso:cb budget with junk-state callbacks (they reserve
		// but never consume the handshake), then the real one must 429.
		for i := 0; i < 4; i++ {
			r, _ := client.Get(ts.URL + "/auth/sso/callback?state=wrong")
			r.Body.Close()
		}
		r, err := client.Get(realCB)
		if err != nil {
			t.Fatalf("throttled callback: %v", err)
		}
		r.Body.Close()
		if r.StatusCode != http.StatusTooManyRequests {
			t.Fatalf("callback past the budget = %d, want 429", r.StatusCode)
		}
		if idp.tokenCalls.Load() != 0 {
			t.Error("a rate-denied callback reached the token exchange")
		}
	})

	t.Run("start and callback budgets are separate keyspaces", func(t *testing.T) {
		// sso:start|ip and sso:cb|ip are namespaced (the limiter keyspace is
		// flat, and /login reserves the bare IP): exhausting the START budget
		// must not spend the CALLBACK budget, so a real callback still gets to
		// consume its handshake rather than being 429'd by the wrong bucket.
		ts, client, _ := gatedServerLowRate(t, 4)
		// One real start to mint this client's session and its handshake (it
		// reserves once, being the sessionless first arrival).
		resp, _ := client.Get(ts.URL + "/auth/sso/start")
		resp.Body.Close()
		if resp.StatusCode != http.StatusSeeOther {
			t.Fatalf("first start = %d, want 303", resp.StatusCode)
		}
		loc, _ := resp.Location()
		if loc == nil {
			t.Fatal("no successful start produced a handshake")
		}
		// Spend the rest of the START budget with sessionless requests — the
		// only shape that charges it.
		for i := 0; i < 4; i++ {
			r, _ := anonClient().Get(ts.URL + "/auth/sso/start")
			r.Body.Close()
		}
		// A further anonymous start is refused — the start budget really is spent.
		r, _ := anonClient().Get(ts.URL + "/auth/sso/start")
		r.Body.Close()
		if r.StatusCode != http.StatusTooManyRequests {
			t.Fatalf("anonymous start past the budget = %d, want 429 (this test needs the start budget exhausted)", r.StatusCode)
		}
		// The callback budget is untouched, so this completes (303 to /login),
		// not 429.
		r, err := client.Get(ts.URL + "/auth/sso/callback?code=" + url.QueryEscape(loc.Query().Get("nonce")) +
			"&state=" + url.QueryEscape(loc.Query().Get("state")))
		if err != nil {
			t.Fatalf("callback: %v", err)
		}
		r.Body.Close()
		if r.StatusCode == http.StatusTooManyRequests {
			t.Error("a callback was 429'd by the exhausted START budget — the keyspaces collided")
		}
		if r.StatusCode != http.StatusSeeOther || r.Header.Get("Location") != "/login" {
			t.Errorf("callback with the start budget exhausted = %d loc=%q, want 303 to /login", r.StatusCode, r.Header.Get("Location"))
		}
	})
}

// TestSSOUnverifiedEmailWithAllowlist pins the strict email_verified rule: the
// allowlists admit by EMAIL, and an email the provider has not verified is an
// attacker-choosable string on any self-service provider — register
// victim@allowed-domain.com and sso.allowed_domains falls (CVE-2024-27918 is
// this class). Absent counts as unverified; with no allowlist configured
// nothing is matched on the email and nothing changes.
func TestSSOUnverifiedEmailWithAllowlist(t *testing.T) {
	// completeFlow runs start → callback and returns the callback response.
	completeFlow := func(t *testing.T, ts *httptest.Server, client *http.Client) *http.Response {
		t.Helper()
		resp, err := client.Get(ts.URL + "/auth/sso/start")
		if err != nil {
			t.Fatalf("start: %v", err)
		}
		resp.Body.Close()
		loc, err := resp.Location()
		if err != nil {
			t.Fatalf("start did not redirect: %v", err)
		}
		resp, err = client.Get(ts.URL + "/auth/sso/callback?code=" +
			url.QueryEscape(loc.Query().Get("nonce")) + "&state=" + url.QueryEscape(loc.Query().Get("state")))
		if err != nil {
			t.Fatalf("callback: %v", err)
		}
		resp.Body.Close()
		return resp
	}
	allowDana := func(s *config.SSOConfig) { s.AllowedDomains = []string{"example.com"} }

	cases := []struct {
		name     string
		tune     func(*config.SSOConfig)
		verified any // the email_verified claim; nil = absent
		admit    bool
	}{
		{"allowlist + absent claim is refused", allowDana, nil, false},
		{"allowlist + boolean false is refused", allowDana, false, false},
		{"allowlist + string false is refused", allowDana, "false", false},
		{"allowlist + boolean true is admitted", allowDana, true, true},
		{"allowlist + string true is admitted", allowDana, "true", true},
		{"no allowlist + absent claim stays admitted", nil, nil, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ts, client, idp := gatedServer(t, tc.tune)
			idp.emailVerified = tc.verified
			resp := completeFlow(t, ts, client)
			admitted := resp.StatusCode == http.StatusSeeOther && resp.Header.Get("Location") == "/login"
			if tc.admit && !admitted {
				t.Fatalf("callback = %d loc=%q; a verified, admitted identity must reach the login form",
					resp.StatusCode, resp.Header.Get("Location"))
			}
			if !tc.admit {
				if admitted {
					t.Fatal("an unverified email passed an allowlist it must not be matched against")
				}
				if resp.StatusCode != http.StatusForbidden {
					t.Errorf("unverified email with an allowlist = %d, want 403", resp.StatusCode)
				}
			}
		})
	}
}

// TestNoSSOConfiguredChangesNothing is the negative control for the whole
// feature: without [sso] the gate must be absent, not merely permissive.
func TestNoSSOConfiguredChangesNothing(t *testing.T) {
	ts, client, _ := newTestServer(t)

	code, body := getBody(t, client, ts.URL+"/login")
	if code != http.StatusOK {
		t.Fatalf("GET /login without SSO = %d, want 200", code)
	}
	if !strings.Contains(body, `name="password"`) {
		t.Error("the login form did not render")
	}
	// The gate's own routes must not exist, so an unconfigured deployment does not
	// advertise a feature it does not have.
	for _, path := range []string{"/auth/sso/start", "/auth/sso/callback"} {
		resp, err := client.Get(ts.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("GET %s without SSO = %d, want 404", path, resp.StatusCode)
		}
	}
}

// ssoVerify drives one complete flow so the session ends up carrying a verified
// identity, and returns the state/nonce of that handshake.
func ssoVerify(t *testing.T, ts *httptest.Server, client *http.Client) {
	t.Helper()
	resp, err := client.Get(ts.URL + "/auth/sso/start")
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	resp.Body.Close()
	authURL, err := resp.Location()
	if err != nil {
		t.Fatalf("start did not redirect: %v", err)
	}
	q := authURL.Query()
	resp, err = client.Get(ts.URL + "/auth/sso/callback?code=" + url.QueryEscape(q.Get("nonce")) +
		"&state=" + url.QueryEscape(q.Get("state")))
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/login" {
		t.Fatalf("verifying flow = %d loc=%q, want 303 to /login", resp.StatusCode, resp.Header.Get("Location"))
	}
}

// ssoVerified reports whether the gate currently lets this client past — which
// is exactly SSO().Verified(), read the way the middleware reads it.
func ssoVerified(t *testing.T, ts *httptest.Server, client *http.Client) bool {
	t.Helper()
	resp, err := client.Get(ts.URL + "/login")
	if err != nil {
		t.Fatalf("GET /login: %v", err)
	}
	resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusOK:
		return true
	case resp.StatusCode == http.StatusSeeOther && resp.Header.Get("Location") == handlersSSOStart:
		return false
	}
	t.Fatalf("GET /login = %d loc=%q; neither verified nor gated", resp.StatusCode, resp.Header.Get("Location"))
	return false
}

const handlersSSOStart = "/auth/sso/start"

// TestSSOIdentitySurvivesRestartButNotDenial is the paired half of the gate's
// design, and the two halves only make sense together.
//
// SSOStart used to replace the whole session.SSO struct, so merely ARRIVING at
// /auth/sso/start — a stray click, an htmx HX-Redirect, a bookmark — discarded
// an identity the provider had already vouched for and forced the flow again.
//
// Preserving it there is only safe if every denial CLEARS it, because ssoGate
// re-checks Verified() and never re-checks the allowlist. Without that, removing
// somebody from allowed_emails would leave them with access until their session
// expired.
func TestSSOIdentitySurvivesRestartButNotDenial(t *testing.T) {
	t.Run("a verified session survives /auth/sso/start", func(t *testing.T) {
		ts, client, _ := gatedServer(t, nil)
		ssoVerify(t, ts, client)
		if !ssoVerified(t, ts, client) {
			t.Fatal("the flow did not leave the session verified")
		}
		// Start a second flow and abandon it: the identity must still be there.
		resp, err := client.Get(ts.URL + "/auth/sso/start")
		if err != nil {
			t.Fatalf("second start: %v", err)
		}
		resp.Body.Close()
		if !ssoVerified(t, ts, client) {
			t.Error("visiting /auth/sso/start signed out an already-verified session")
		}
	})

	t.Run("an allowlist denial clears the identity", func(t *testing.T) {
		// The allowlist admits the identity the fake IdP starts with, so the
		// first flow succeeds and the second — after the IdP switches address —
		// is turned away by TableX rather than by the provider.
		ts, client, idp := gatedServer(t, func(sc *config.SSOConfig) {
			sc.AllowedEmails = []string{"dana@example.com"}
		})
		ssoVerify(t, ts, client)
		if !ssoVerified(t, ts, client) {
			t.Fatal("the flow did not leave the session verified")
		}
		// The same person, now outside the set this deployment admits. The
		// provider still vouches for them, so only TableX can turn them away —
		// and it must not leave the earlier verification standing.
		idp.email = "removed@example.com"
		resp, err := client.Get(ts.URL + "/auth/sso/start")
		if err != nil {
			t.Fatalf("start: %v", err)
		}
		resp.Body.Close()
		authURL, _ := resp.Location()
		q := authURL.Query()
		resp, err = client.Get(ts.URL + "/auth/sso/callback?code=" + url.QueryEscape(q.Get("nonce")) +
			"&state=" + url.QueryEscape(q.Get("state")))
		if err != nil {
			t.Fatalf("callback: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("a denied callback = %d, want 403", resp.StatusCode)
		}
		if ssoVerified(t, ts, client) {
			t.Error("a denied identity kept its earlier verification — locked out must mean locked out")
		}
	})

	t.Run("a state-mismatched callback leaves a verified session alone", func(t *testing.T) {
		ts, client, _ := gatedServer(t, nil)
		ssoVerify(t, ts, client)
		// Unauthenticated: anyone can aim a victim's browser at this URL, so
		// clearing here would be a logout CSRF. It is the state check that makes
		// a denial attributable, which is why the clearing starts after it.
		resp, err := client.Get(ts.URL + "/auth/sso/callback?code=x&state=forged")
		if err != nil {
			t.Fatalf("callback: %v", err)
		}
		resp.Body.Close()
		if !ssoVerified(t, ts, client) {
			t.Error("a forged callback signed out a verified session: that is a logout CSRF")
		}
	})
}
