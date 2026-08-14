package auth

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/tablexdev/tablex/internal/config"
)

func TestCheckCSRF(t *testing.T) {
	if !CheckCSRF("token123", "token123") {
		t.Error("matching tokens should pass")
	}
	if CheckCSRF("token123", "wrong") {
		t.Error("mismatched tokens should fail")
	}
	if CheckCSRF("", "") || CheckCSRF("t", "") || CheckCSRF("", "t") {
		t.Error("empty tokens should fail")
	}
}

func TestRateLimiterReserve(t *testing.T) {
	rl := NewRateLimiter(time.Minute, 2)
	ip, user := "1.2.3.4", "1.2.3.4|root"
	for i := range 2 {
		if !rl.Reserve(ip, user) {
			t.Fatalf("reserve %d should succeed", i+1)
		}
	}
	if rl.Reserve(ip, user) {
		t.Error("3rd reserve should be refused at the cap")
	}
	// A refused Reserve must record nothing: a different user key sharing the
	// exhausted IP key stays unrecorded, so it still has full budget.
	if !rl.Reserve("1.2.3.4|other") {
		t.Error("refused reserve leaked a recording onto another key")
	}
	rl.Reset(ip)
	rl.Reset(user)
	if !rl.Reserve(ip, user) {
		t.Error("reserve should succeed again after reset")
	}

	// All-or-nothing: when one key is exhausted, the other is not consumed.
	rl2 := NewRateLimiter(time.Minute, 1)
	if !rl2.Reserve("a") {
		t.Fatal("first reserve on a")
	}
	if rl2.Reserve("a", "b") {
		t.Error("reserve with an exhausted key should fail")
	}
	if !rl2.Reserve("b") {
		t.Error("key b was consumed by a failed multi-key reserve")
	}

	// Disabled / nil limiters never refuse.
	if !NewRateLimiter(time.Minute, 0).Reserve("x") {
		t.Error("disabled limiter should never refuse")
	}
	var nilRL *RateLimiter
	if !nilRL.Reserve("x") {
		t.Error("nil limiter should never refuse")
	}
}

func TestRateLimiterWindowExpiry(t *testing.T) {
	rl := NewRateLimiter(time.Minute, 2)
	now := time.Unix(1000, 0)
	rl.now = func() time.Time { return now }
	if !rl.Reserve("k") {
		t.Fatal("first reserve should succeed")
	}
	if !rl.Reserve("k") {
		t.Fatal("second reserve should succeed")
	}
	if rl.Reserve("k") {
		t.Error("should be blocked at the limit")
	}
	now = now.Add(2 * time.Minute) // advance past the window
	if !rl.Reserve("k") {
		t.Error("should be allowed after window expiry")
	}
}

// TestRateLimiterSweepReclaimsUntouchedKeys: a key is pruned only when someone
// Reserves it AGAIN, and an attacker never does — each failed login uses a fresh
// username, so each plants an entry that its own traffic will never reclaim.
// Sweep is the only thing that gets them back, which is why every limiter the
// server builds has to be on the sweeper.
func TestRateLimiterSweepReclaimsUntouchedKeys(t *testing.T) {
	rl := NewRateLimiter(time.Minute, 5)
	now := time.Unix(1000, 0)
	rl.now = func() time.Time { return now }

	for _, user := range []string{"a", "b", "c", "d", "e", "f", "g", "h"} {
		if !rl.Reserve("account:" + user) {
			t.Fatalf("reserve for %q should succeed", user)
		}
	}
	if got := len(rl.hits); got != 8 {
		t.Fatalf("after 8 distinct keys, len(hits) = %d, want 8", got)
	}

	// Still inside the window: a sweep must not forget a live lockout.
	rl.Sweep()
	if got := len(rl.hits); got != 8 {
		t.Errorf("a sweep inside the window dropped keys: len(hits) = %d, want 8", got)
	}

	now = now.Add(2 * time.Minute)
	rl.Sweep()
	if got := len(rl.hits); got != 0 {
		t.Errorf("after the window expired, sweep left %d keys, want 0", got)
	}
}

func TestClientIPProxyTrust(t *testing.T) {
	req := func(remote, xff string) *http.Request {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = remote
		if xff != "" {
			r.Header.Set("X-Forwarded-For", xff)
		}
		return r
	}
	trust, err := NewProxyTrust([]string{"10.0.0.0/8", "172.17.0.1"})
	if err != nil {
		t.Fatalf("NewProxyTrust: %v", err)
	}

	cases := []struct {
		name   string
		trust  *ProxyTrust
		remote string
		xff    string
		want   string
	}{
		// No trusted proxies configured: XFF is never consulted.
		{"no trust ignores xff", nil, "203.0.113.9:4444", "1.2.3.4", "203.0.113.9"},
		// Direct client spoofing XFF: RemoteAddr is not a trusted proxy.
		{"untrusted remote ignores xff", trust, "203.0.113.9:4444", "1.2.3.4", "203.0.113.9"},
		// Behind the proxy, no header: the proxy address itself.
		{"trusted remote no xff", trust, "10.1.2.3:5555", "", "10.1.2.3"},
		// Single hop: the client the proxy saw.
		{"single hop", trust, "10.1.2.3:5555", "198.51.100.7", "198.51.100.7"},
		// Client-spoofed prefix: rightmost untrusted entry wins, the attacker's
		// forged leftmost entry is ignored.
		{"spoofed prefix", trust, "10.1.2.3:5555", "6.6.6.6, 198.51.100.7", "198.51.100.7"},
		// Chain through a second trusted hop (bare-IP trust entry).
		{"two trusted hops", trust, "10.1.2.3:5555", "198.51.100.7, 172.17.0.1", "198.51.100.7"},
		// Every hop trusted: leftmost (closest to the client) is used.
		{"all trusted", trust, "10.1.2.3:5555", "10.9.9.9", "10.9.9.9"},
		// Malformed entry: the chain cannot be trusted past it.
		{"garbage xff", trust, "10.1.2.3:5555", "not-an-ip", "10.1.2.3"},
	}
	for _, c := range cases {
		if got := ClientIP(req(c.remote, c.xff), c.trust); got != c.want {
			t.Errorf("%s: ClientIP = %q, want %q", c.name, got, c.want)
		}
	}

	if _, err := NewProxyTrust([]string{"not-a-cidr"}); err == nil {
		t.Error("invalid CIDR should be rejected")
	}
	if pt, err := NewProxyTrust(nil); err != nil || pt.Trusted(net.ParseIP("10.0.0.1")) {
		t.Error("empty trust set must trust nothing")
	}
}

func TestCheckHostAllowlist(t *testing.T) {
	sec := config.SecurityConfig{HostAllowlist: []string{"db.internal"}}
	if err := CheckHost(context.Background(), "db.internal", sec); err != nil {
		t.Errorf("allowlisted host should pass: %v", err)
	}
	if err := CheckHost(context.Background(), "evil.example.com", sec); err == nil {
		t.Error("non-allowlisted host should be rejected")
	}
}

func TestCheckHostDenylist(t *testing.T) {
	sec := config.SecurityConfig{HostDenylist: []string{"blocked.host"}}
	if err := CheckHost(context.Background(), "blocked.host", sec); err == nil {
		t.Error("denylisted host should be rejected")
	}
}

// TestCheckHostRefusesEmptyHost: an empty ad-hoc host used to mean "the
// driver's local default" — a target no allowlist, denylist, or BlockPrivate
// check ever saw. CheckHost must fail closed on it under every configuration,
// including no configuration at all.
func TestCheckHostRefusesEmptyHost(t *testing.T) {
	cases := []struct {
		name string
		sec  config.SecurityConfig
	}{
		{"allowlist configured", config.SecurityConfig{HostAllowlist: []string{"db.internal"}}},
		{"block_private", config.SecurityConfig{BlockPrivate: true}},
		{"no controls", config.SecurityConfig{}},
	}
	for _, c := range cases {
		if err := CheckHost(context.Background(), "", c.sec); err == nil {
			t.Errorf("%s: empty host must be refused", c.name)
		}
	}
	// Whitespace canonicalizes to empty and must be refused the same way.
	if err := CheckHost(context.Background(), "   ", config.SecurityConfig{}); err == nil {
		t.Error("whitespace-only host must be refused")
	}
}

// TestCheckHostBracketCanonicalization: allow/deny matching must canonicalize
// BOTH sides — a posted "[::1]" must match a configured "::1" and vice versa,
// or the bracketed spelling of the same address slips past the policy.
func TestCheckHostBracketCanonicalization(t *testing.T) {
	// Denylist, both spelling directions.
	if err := CheckHost(context.Background(), "[2001:db8::7]", config.SecurityConfig{HostDenylist: []string{"2001:db8::7"}}); err == nil {
		t.Error("posted [2001:db8::7] should match denylisted 2001:db8::7")
	}
	if err := CheckHost(context.Background(), "2001:db8::7", config.SecurityConfig{HostDenylist: []string{"[2001:db8::7]"}}); err == nil {
		t.Error("posted 2001:db8::7 should match denylisted [2001:db8::7]")
	}
	// Allowlist, both spelling directions.
	if err := CheckHost(context.Background(), "[2001:db8::7]", config.SecurityConfig{HostAllowlist: []string{"2001:db8::7"}}); err != nil {
		t.Errorf("posted [2001:db8::7] should match allowlisted 2001:db8::7: %v", err)
	}
	if err := CheckHost(context.Background(), "2001:db8::7", config.SecurityConfig{HostAllowlist: []string{"[2001:db8::7]"}}); err != nil {
		t.Errorf("posted 2001:db8::7 should match allowlisted [2001:db8::7]: %v", err)
	}
	// The IP-level guards see the bare literal too: a bracketed loopback is
	// still recognized as loopback under BlockPrivate.
	if err := CheckHost(context.Background(), "[::1]", config.SecurityConfig{BlockPrivate: true}); err == nil {
		t.Error("BlockPrivate should reject bracketed loopback [::1]")
	}
}

func TestCheckHostBlocksPrivateLiteral(t *testing.T) {
	sec := config.SecurityConfig{BlockPrivate: true}
	for _, h := range []string{"127.0.0.1", "10.0.0.5", "192.168.1.1", "169.254.169.254", "172.16.0.1",
		// RFC 6598 CGNAT (100.64.0.0/10) counts as private.
		"100.64.0.1", "100.127.255.254"} {
		if err := CheckHost(context.Background(), h, sec); err == nil {
			t.Errorf("BlockPrivate should reject %s", h)
		}
	}
	// Public literals pass — including the 100.x addresses just outside the
	// 100.64.0.0/10 CGNAT range.
	for _, h := range []string{"8.8.8.8", "100.63.255.255", "100.128.0.1"} {
		if err := CheckHost(context.Background(), h, sec); err != nil {
			t.Errorf("public IP %s should pass: %v", h, err)
		}
	}
}

func TestCheckHostBlocksMetadataByDefault(t *testing.T) {
	// Link-local / cloud-metadata is refused even without BlockPrivate.
	// 100.100.100.200 is Alibaba Cloud's metadata endpoint (RFC 6598 space):
	// docs/security.md promises metadata addresses are refused regardless of
	// settings, so it sits in the always-on tier alongside 169.254.169.254.
	sec := config.SecurityConfig{BlockPrivate: false}
	for _, h := range []string{"169.254.169.254", "169.254.0.1", "fe80::1", "100.100.100.200"} {
		if err := CheckHost(context.Background(), h, sec); err == nil {
			t.Errorf("link-local/metadata %s should be blocked by default", h)
		}
	}
	// Loopback and private hosts (including non-metadata CGNAT space) stay
	// reachable for local admin when BlockPrivate is off, and public hosts
	// always pass.
	for _, h := range []string{"127.0.0.1", "192.168.1.10", "100.64.0.1", "8.8.8.8"} {
		if err := CheckHost(context.Background(), h, sec); err != nil {
			t.Errorf("%s should pass when BlockPrivate is off: %v", h, err)
		}
	}
}

func TestDialControlReChecksResolvedIP(t *testing.T) {
	// The dial-time hook mirrors CheckHost but on the resolved peer address,
	// closing the DNS-rebinding window. Without BlockPrivate, link-local/metadata
	// is refused while loopback/private/public pass.
	hook := DialControl(config.SecurityConfig{BlockPrivate: false})
	for _, addr := range []string{"169.254.169.254:3306", "[fe80::1]:5432", "100.100.100.200:3306"} {
		if err := hook("tcp", addr, nil); err == nil {
			t.Errorf("dial to %s should be blocked", addr)
		}
	}
	for _, addr := range []string{"127.0.0.1:3306", "10.0.0.5:5432", "8.8.8.8:3306"} {
		if err := hook("tcp", addr, nil); err != nil {
			t.Errorf("dial to %s should pass when BlockPrivate is off: %v", addr, err)
		}
	}
	// With BlockPrivate, loopback/private are refused too; public still passes.
	strict := DialControl(config.SecurityConfig{BlockPrivate: true})
	for _, addr := range []string{"127.0.0.1:3306", "10.0.0.5:5432", "192.168.1.1:3306"} {
		if err := strict("tcp", addr, nil); err == nil {
			t.Errorf("BlockPrivate dial to %s should be blocked", addr)
		}
	}
	if err := strict("tcp", "8.8.8.8:5432", nil); err != nil {
		t.Errorf("public dial should pass under BlockPrivate: %v", err)
	}
	// A non-IP target (unix socket) carries no SSRF risk and is ignored.
	if err := strict("unix", "/var/run/mysqld.sock", nil); err != nil {
		t.Errorf("unix socket dial should be ignored: %v", err)
	}
}

func TestSafeMethod(t *testing.T) {
	if !SafeMethod("GET") || !SafeMethod("HEAD") {
		t.Error("GET/HEAD are safe")
	}
	if SafeMethod("POST") || SafeMethod("DELETE") {
		t.Error("POST/DELETE are unsafe")
	}
}
