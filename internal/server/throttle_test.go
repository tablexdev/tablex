package server_test

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/tablexdev/tablex/internal/config"
)

// TestLoginThrottleReturns429 covers: a refused-by-the-throttle attempt used
// to answer 401 with no Retry-After — asserting the credentials were rejected
// when nothing had been checked at all, so no client could tell "wrong
// password" from "slow down", nor how long to wait.
func TestLoginThrottleReturns429(t *testing.T) {
	const window = 90
	ts, client, _ := newTestServerWith(t, func(c *config.Config) {
		c.Security.LoginRateMax = 2
		c.Security.LoginRateWindow = window * 1e9 // 90s as a time.Duration
	})

	csrf := csrfFrom(t, client, ts.URL+"/login")
	form := url.Values{
		"csrf_token": {csrf}, "engine": {"mysql"},
		"host": {"127.0.0.1"}, "port": {"1"},
		"username": {"nobody"}, "password": {"wrong"},
	}

	var last *http.Response
	for i := range 6 {
		resp, err := client.PostForm(ts.URL+"/login", form)
		if err != nil {
			t.Fatalf("attempt %d: %v", i, err)
		}
		resp.Body.Close()
		last = resp
		if resp.StatusCode == http.StatusTooManyRequests {
			break
		}
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("attempt %d = %d, want 401 (bad credential) or 429 (throttled)", i, resp.StatusCode)
		}
	}
	if last.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("never throttled: last status %d, want 429", last.StatusCode)
	}
	ra := last.Header.Get("Retry-After")
	if ra == "" {
		t.Fatal("429 carries no Retry-After")
	}
	n, err := strconv.Atoi(ra)
	if err != nil || n <= 0 || n > window {
		t.Errorf("Retry-After = %q, want a positive number of seconds no greater than the %ds window", ra, window)
	}
}

// TestAccountLockoutIsNotScopedToTheClientAddress covers the one brute-force gap
// E1 named that is independent of SSO. Every other login key starts with the
// client IP, so the throttle they give is per-SOURCE: an attacker with an IPv6
// /64 or a botnet gets login_rate_max attempts EACH against the same account.
//
// The test therefore has to attack from MANY addresses, or it cannot tell a
// per-account key from a per-IP one — a single-client version of this test passed
// while the key was silently prefixed with the address. Each attempt arrives with
// a different X-Forwarded-For, honoured because the loopback peer is configured
// as a trusted proxy, so every per-IP key sees exactly one attempt and only the
// account key can be what refuses.
func TestAccountLockoutIsNotScopedToTheClientAddress(t *testing.T) {
	ts, client, _ := newTestServerWith(t, func(c *config.Config) {
		c.Security.LoginRateMax = 5    // per-IP: never reached, one attempt each
		c.Security.LoginAccountMax = 3 // the account itself is what is bounded
		c.Security.LoginRateWindow = 90 * 1e9
		c.Security.TrustedProxy = true
		c.Security.TrustedProxyCIDRs = []string{"127.0.0.0/8", "::1/128"}
	})

	csrf := csrfFrom(t, client, ts.URL+"/login")
	// attempt posts a login as `user`, appearing to come from `from`.
	attempt := func(user, from string) int {
		req, err := http.NewRequest(http.MethodPost, ts.URL+"/login",
			strings.NewReader(url.Values{
				"csrf_token": {csrf}, "engine": {"mysql"},
				"host": {"127.0.0.1"}, "port": {"1"},
				"username": {user}, "password": {"wrong"},
			}.Encode()))
		if err != nil {
			t.Fatalf("build request: %v", err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("X-Forwarded-For", from)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("attempt as %q from %s: %v", user, from, err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}

	// Three attempts against one account, each from a DIFFERENT address. No
	// per-IP key is anywhere near its cap of 5.
	for i, from := range []string{"203.0.113.1", "203.0.113.2", "203.0.113.3"} {
		if got := attempt("victim", from); got == http.StatusTooManyRequests {
			t.Fatalf("attempt %d from %s was throttled too early (%d); the account cap is 3", i+1, from, got)
		}
	}
	// A fourth, from a fourth address, must be refused — and the ONLY key that
	// could refuse it is the one that does not contain an address.
	if got := attempt("victim", "203.0.113.4"); got != http.StatusTooManyRequests {
		t.Fatalf("the 4th attempt against one account, from a 4th address, = %d, want 429; "+
			"the account is not bounded independently of the client address", got)
	}

	// Positive control: the lockout is per ACCOUNT, not global. Another account,
	// even from an address already used, must still be allowed — otherwise this
	// would be a denial of service on the whole login form.
	if got := attempt("someone-else", "203.0.113.1"); got == http.StatusTooManyRequests {
		t.Errorf("a different account was locked out too (%d); the key is not per-account", got)
	}
}

// TestAccountLockoutCanBeDisabled: an operator who turns it off gets the old
// behaviour, and Warnings tells them what they gave up (asserted in config).
func TestAccountLockoutCanBeDisabled(t *testing.T) {
	ts, client, _ := newTestServerWith(t, func(c *config.Config) {
		c.Security.LoginRateMax = 10_000
		c.Security.LoginAccountMax = 0 // disabled
		c.Security.LoginRateWindow = 90 * 1e9
		c.Security.TrustedProxy = true
		c.Security.TrustedProxyCIDRs = []string{"127.0.0.0/8", "::1/128"}
	})
	csrf := csrfFrom(t, client, ts.URL+"/login")
	for i := range 6 {
		req, err := http.NewRequest(http.MethodPost, ts.URL+"/login",
			strings.NewReader(url.Values{
				"csrf_token": {csrf}, "engine": {"mysql"},
				"host": {"127.0.0.1"}, "port": {"1"},
				"username": {"victim"}, "password": {"wrong"},
			}.Encode()))
		if err != nil {
			t.Fatalf("build request: %v", err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("X-Forwarded-For", "203.0.113."+strconv.Itoa(10+i))
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("attempt %d: %v", i, err)
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusTooManyRequests {
			t.Fatalf("attempt %d was throttled with login_account_max = 0", i+1)
		}
	}
}
