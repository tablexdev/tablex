package auth

import (
	"context"
	"testing"

	"github.com/tablexdev/tablex/internal/config"
)

// TestSSRFEmbeddedIPv4Forms exists because the old classifier branched on
// net.IP.To4(), which is non-nil only for IPv4 and IPv4-MAPPED IPv6 — so an
// IPv4-COMPATIBLE address (::169.254.169.254) matched neither the IPv4 rules
// nor the IPv6 ones and passed the pre-flight AND the dial-time check. A NAT64
// gateway makes 64:ff9b::169.254.169.254 reach the same metadata service.
func TestSSRFEmbeddedIPv4Forms(t *testing.T) {
	open := config.SecurityConfig{BlockPrivate: false}
	dial := DialControl(open)

	blocked := []struct{ host, addr string }{
		{"::169.254.169.254", "[::169.254.169.254]:3306"},               // IPv4-compatible
		{"::ffff:169.254.169.254", "[::ffff:169.254.169.254]:3306"},     // IPv4-mapped
		{"64:ff9b::169.254.169.254", "[64:ff9b::169.254.169.254]:5432"}, // NAT64 well-known
		{"::100.100.100.200", "[::100.100.100.200]:3306"},               // Alibaba metadata, v4-compatible
	}
	for _, c := range blocked {
		if err := CheckHost(context.Background(), c.host, open); err == nil {
			t.Errorf("CheckHost(%s) allowed a metadata address", c.host)
		}
		if err := dial(c.addr, c.addr, nil); err == nil {
			t.Errorf("DialControl(%s) allowed a metadata address", c.addr)
		}
	}

	// The embedded-IPv4 rules must not swallow a public target reached over
	// NAT64: blocking those would break a legitimate IPv6-only deployment.
	for _, h := range []string{"64:ff9b::8.8.8.8", "::8.8.8.8", "2606:4700:4700::1111"} {
		if err := CheckHost(context.Background(), h, open); err != nil {
			t.Errorf("CheckHost(%s) blocked a public target: %v", h, err)
		}
	}

	// ::1 lives inside ::/96 too. It must stay PRIVATE (reachable by default
	// for local admin), not get promoted to always-blocked by reading its low
	// 32 bits as the IPv4 address 0.0.0.1.
	if err := CheckHost(context.Background(), "::1", open); err != nil {
		t.Errorf("IPv6 loopback must stay reachable when block_private is off: %v", err)
	}
	if err := CheckHost(context.Background(), "::1", config.SecurityConfig{BlockPrivate: true}); err == nil {
		t.Error("IPv6 loopback must be refused under block_private")
	}
}

// TestSSRFUnlistedRanges covers the ranges the byte tests never named at all.
func TestSSRFUnlistedRanges(t *testing.T) {
	open := config.SecurityConfig{BlockPrivate: false}
	for _, h := range []string{
		"fec0::1",         // deprecated site-local
		"fed0::1",         // …fec0::/10 runs all the way to feff::
		"192.0.0.171",     // IETF protocol assignments (NAT64 discovery)
		"198.18.0.1",      // RFC 2544 benchmarking
		"198.19.255.254",  // …upper half of the same /15
		"0.0.0.0",         // unspecified
		"0.1.2.3",         // rest of "this network"
		"224.0.0.1",       // multicast
		"239.255.255.250", // administratively-scoped multicast (SSDP)
		"255.255.255.255", // limited broadcast
		"ff02::1",         // IPv6 link-local multicast
		"ff01::1",         // IPv6 interface-local multicast
		"::",              // IPv6 unspecified
		"fe80::1",         // IPv6 link-local (already covered; guards the rewrite)
		"169.254.169.254", // the classic
		"100.100.100.200", // Alibaba metadata inside CGNAT
	} {
		if err := CheckHost(context.Background(), h, open); err == nil {
			t.Errorf("CheckHost(%s) should be blocked regardless of block_private", h)
		}
	}

	// Addresses just outside each newly-named range must still pass.
	for _, h := range []string{
		"1.0.0.1",         // just past 0.0.0.0/8
		"192.0.1.1",       // just past 192.0.0.0/24
		"198.17.255.255",  // just before 198.18.0.0/15
		"198.20.0.1",      // just past it
		"223.255.255.255", // just before multicast
		"fe00::1",         // fe00::/10 — just BELOW fe80::/10; fec0::/10 runs to feff:: and abuts ff00::/8
		"2001:db8::1",     // documentation prefix, but routable as far as we care
	} {
		if err := CheckHost(context.Background(), h, open); err != nil {
			t.Errorf("CheckHost(%s) should pass: %v", h, err)
		}
	}
}

// TestSSRFZonedIPv6 covers the parsing half of the same defect: net.ParseIP
// rejects a zone outright, so DialControl saw nil and allowed the connection.
// netip.Prefix.Contains also refuses a zoned address, so the zone has to be
// stripped before the table is consulted rather than merely parsed.
func TestSSRFZonedIPv6(t *testing.T) {
	dial := DialControl(config.SecurityConfig{BlockPrivate: false})
	for _, addr := range []string{"[fe80::1%eth0]:5432", "[fe80::1%25eth0]:3306"} {
		if err := dial("tcp", addr, nil); err == nil {
			t.Errorf("DialControl(%s) allowed a zoned link-local address", addr)
		}
	}
	// A zoned address outside the blocked table still passes.
	if err := dial("tcp", "[2001:4860:4860::8888%eth0]:5432", nil); err != nil {
		t.Errorf("zoned public address should pass: %v", err)
	}
}

// TestSSRFPrivateTierUnchanged guards the tier split through the rewrite: these
// are refused ONLY under block_private, because local DB admin is the primary
// use case.
func TestSSRFPrivateTierUnchanged(t *testing.T) {
	open := config.SecurityConfig{BlockPrivate: false}
	strict := config.SecurityConfig{BlockPrivate: true}
	for _, h := range []string{
		"127.0.0.1", "10.0.0.5", "172.16.0.1", "172.31.255.254",
		"192.168.1.1", "100.64.0.1", "100.127.255.254", "::1", "fd00::1", "fc00::1",
		"::ffff:127.0.0.1", "::127.0.0.1",
	} {
		if err := CheckHost(context.Background(), h, open); err != nil {
			t.Errorf("%s must stay reachable when block_private is off: %v", h, err)
		}
		if err := CheckHost(context.Background(), h, strict); err == nil {
			t.Errorf("%s must be refused under block_private", h)
		}
	}
	// Just outside 172.16.0.0/12 and the CGNAT range.
	for _, h := range []string{"172.15.0.1", "172.32.0.1", "100.63.255.255", "100.128.0.1"} {
		if err := CheckHost(context.Background(), h, strict); err != nil {
			t.Errorf("%s is public and must pass even under block_private: %v", h, err)
		}
	}
}
