package main

import "testing"

// TestHealthcheckURL covers #13b: the container healthcheck probes the
// CONFIGURED bind host when it is concrete (a loopback probe would
// false-negative a server bound to one interface) and falls back to loopback
// only for wildcard/empty binds. IPv6 hosts stay bracketed; a scoped
// literal's zone is %-escaped per RFC 6874.
func TestHealthcheckURL(t *testing.T) {
	cases := []struct {
		name   string
		listen string
		tls    bool
		want   string
	}{
		{"empty listen", "", false, "http://127.0.0.1:8080/healthz"},
		{"port-only wildcard", ":9090", false, "http://127.0.0.1:9090/healthz"},
		{"ipv4 wildcard", "0.0.0.0:8080", false, "http://127.0.0.1:8080/healthz"},
		{"ipv6 wildcard", "[::]:8080", false, "http://127.0.0.1:8080/healthz"},
		{"concrete ipv4", "10.0.0.5:8080", false, "http://10.0.0.5:8080/healthz"},
		{"hostname", "localhost:8443", true, "https://localhost:8443/healthz"},
		{"concrete ipv6 stays bracketed", "[2001:db8::7]:9", false, "http://[2001:db8::7]:9/healthz"},
		{"scoped ipv6 zone escaped", "[fe80::1%eth0]:9", false, "http://[fe80::1%25eth0]:9/healthz"},
		{"missing port defaults", "10.0.0.5", false, "http://127.0.0.1:8080/healthz"},
	}
	for _, c := range cases {
		if got := healthcheckURL(c.listen, c.tls); got != c.want {
			t.Errorf("%s: healthcheckURL(%q, tls=%v) = %q, want %q", c.name, c.listen, c.tls, got, c.want)
		}
	}
}
