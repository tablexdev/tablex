package auth

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"syscall"

	"github.com/tablexdev/tablex/internal/config"
)

// CIDRSet is a parsed list of networks an address can be tested against. A nil
// set contains nothing, which is the safe reading for every caller here: an
// unconfigured list must never mean "everything".
type CIDRSet struct {
	nets []*net.IPNet
}

// NewCIDRSet parses a CIDR list (bare IPs are accepted as /32 or /128), or
// returns nil when the list is empty. Invalid entries are rejected so a typo
// cannot silently widen or narrow the set; setting names the config key in the
// error, since the two callers are different keys.
func NewCIDRSet(setting string, cidrs []string) (*CIDRSet, error) {
	if len(cidrs) == 0 {
		return nil, nil
	}
	s := &CIDRSet{}
	for _, c := range cidrs {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		if _, n, err := net.ParseCIDR(c); err == nil {
			s.nets = append(s.nets, n)
			continue
		}
		ip := net.ParseIP(c)
		if ip == nil {
			return nil, fmt.Errorf("%s: %q is not a CIDR or IP address", setting, c)
		}
		bits := 32
		if ip.To4() == nil {
			bits = 128
		}
		s.nets = append(s.nets, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
	}
	if len(s.nets) == 0 {
		return nil, nil
	}
	return s, nil
}

// Contains reports whether ip falls in one of the parsed networks.
func (s *CIDRSet) Contains(ip net.IP) bool {
	if s == nil || ip == nil {
		return false
	}
	for _, n := range s.nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// ContainsAddr is Contains for a textual address, which is the form both the
// access log and the metrics gate carry. An unparseable address is not in any
// set.
func (s *CIDRSet) ContainsAddr(addr string) bool {
	return s.Contains(net.ParseIP(strings.TrimSpace(addr)))
}

// ProxyTrust is the parsed trusted_proxy_cidrs set: the proxy addresses whose
// X-Forwarded-For entries may be skipped when resolving the real client IP.
// A nil/empty set trusts nothing — X-Forwarded-For is then never consulted.
//
// It is a distinct type from the CIDRSet it holds because trusting a proxy is a
// different claim from matching an address, and one that must never be passed
// where the other is meant. The set is a named field rather than embedded, so
// Trusted stays the only way to ask — a promoted Contains would be a second name
// for the same question.
type ProxyTrust struct {
	nets *CIDRSet
}

// NewProxyTrust parses the configured trusted_proxy_cidrs list.
func NewProxyTrust(cidrs []string) (*ProxyTrust, error) {
	set, err := NewCIDRSet("trusted_proxy_cidrs", cidrs)
	if err != nil || set == nil {
		return nil, err
	}
	return &ProxyTrust{nets: set}, nil
}

// Trusted reports whether ip belongs to a configured trusted-proxy range.
func (p *ProxyTrust) Trusted(ip net.IP) bool {
	if p == nil {
		return false
	}
	return p.nets.Contains(ip)
}

// ClientIP returns the client's IP. Shared by the access log and the login
// rate limiter so they key on the same value.
//
// X-Forwarded-For is consulted only when the request arrived FROM a trusted
// proxy, and is then parsed right to left, skipping trusted hops: each proxy
// appends the address it received the request from, so the rightmost entry
// not in the trusted set is the real client. Anything left of that is
// attacker-controllable (the client can send its own X-Forwarded-For header),
// which is why the previous leftmost-entry behavior was spoofable and why an
// untrusted RemoteAddr means the header is ignored entirely.
func ClientIP(r *http.Request, trust *ProxyTrust) string {
	remote := remoteHost(r)
	if !trust.Trusted(net.ParseIP(remote)) {
		return remote
	}
	// Proxies may append to one header or add separate ones; the wire order is
	// preserved by joining them.
	xff := strings.Join(r.Header.Values("X-Forwarded-For"), ",")
	if strings.TrimSpace(xff) == "" {
		return remote
	}
	parts := strings.Split(xff, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		entry := strings.TrimSpace(parts[i])
		ip := net.ParseIP(entry)
		if ip == nil {
			// A malformed hop means the chain can't be trusted past this point;
			// fall back to the directly-connected address.
			return remote
		}
		if !trust.Trusted(ip) {
			return entry
		}
	}
	// Every hop is a trusted proxy; the leftmost is the one closest to the
	// client (e.g. an internal health check originating on a proxy host).
	return strings.TrimSpace(parts[0])
}

// remoteHost strips the port from RemoteAddr (or returns it raw without one).
func remoteHost(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// CheckHost enforces the SSRF controls from docs/security.md for ad-hoc logins:
// an optional allowlist/denylist and, when BlockPrivate is set, refusal to
// connect to loopback/private/link-local (incl. cloud metadata) addresses.
// The caller must pass the network target's host; an empty host is refused.
// (File-backed engines never reach here — Login gates on IsNetworkEngine.)
func CheckHost(ctx context.Context, host string, sec config.SecurityConfig) error {
	// Canonicalize BOTH sides of every list match below: a posted "[::1]" and a
	// configured "::1" — or the reverse — must compare equal, or a bracketed
	// spelling would slip past a denylist entry. Load already canonicalizes the
	// config lists; re-applying here keeps hand-constructed configs safe too.
	host = config.CanonicalHost(host)
	if host == "" {
		// An empty host gives the name lists nothing to match, yet a network
		// driver would still dial its LOCAL default (MySQL 127.0.0.1:3306;
		// PostgreSQL falls back to its Unix socket, which DialControl — an
		// IP:port hook — never sees). Fail closed rather than let "no host"
		// mean "the host every control missed".
		return fmt.Errorf("an ad-hoc login must name its target host")
	}
	lower := strings.ToLower(host)

	// The denylist matches the literal posted host by name only — it does NOT
	// resolve and compare IPs, so denylisting "metadata.google.internal" does not
	// by itself block a request that posts 169.254.169.254 or another alias. That
	// is acceptable because the IP-level guards below (isLinkLocalOrMetadata /
	// isPrivateOrLoopback) and the authoritative DialControl re-check still block
	// metadata/private targets regardless of the name used. The denylist is a
	// name-level policy convenience, not the SSRF boundary.
	for _, d := range sec.HostDenylist {
		if strings.EqualFold(config.CanonicalHost(d), host) {
			return fmt.Errorf("host %q is denied by configuration", host)
		}
	}
	if len(sec.HostAllowlist) > 0 {
		ok := false
		for _, a := range sec.HostAllowlist {
			if strings.EqualFold(config.CanonicalHost(a), host) {
				ok = true
				break
			}
		}
		if !ok {
			return fmt.Errorf("host %q is not in the allowlist", host)
		}
	}

	// Resolve the target so link-local/cloud-metadata addresses can be refused
	// regardless of BlockPrivate (they are never legitimate ad-hoc DB targets),
	// and loopback/private addresses refused when BlockPrivate is set. When the
	// host can't be resolved we only fail under BlockPrivate; otherwise the
	// connection attempt surfaces the real error.
	//
	// This pre-flight resolve is a best-effort, fast-fail UX aid only: its result
	// is intentionally discarded (the driver re-resolves at dial time). The
	// authoritative SSRF guard is DialControl below, which re-checks the actual
	// resolved peer address and so is immune to DNS-rebinding between this lookup
	// and the dial. Keeping the lookup here lets an obviously-blocked host fail at
	// login with a clear message instead of after a dial attempt.
	var ips []netip.Addr
	if ip, err := netip.ParseAddr(lower); err == nil {
		ips = []netip.Addr{ip}
	} else {
		// LookupNetIP, not LookupIPAddr: it hands back netip.Addr directly, so a
		// resolved IPv6 keeps its zone through to the classifier instead of being
		// laundered through net.IP (which cannot carry one).
		addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if err != nil {
			if sec.BlockPrivate {
				return fmt.Errorf("cannot resolve host %q: %w", host, err)
			}
			return nil
		}
		ips = addrs
	}
	for _, ip := range ips {
		if isLinkLocalOrMetadata(ip) {
			return fmt.Errorf("host %q resolves to a blocked link-local/metadata address (%s)", host, ip)
		}
		if sec.BlockPrivate && isPrivateOrLoopback(ip) {
			return fmt.Errorf("host %q resolves to a blocked private address (%s)", host, ip)
		}
	}
	return nil
}

// DialControl returns a net.Dialer.Control hook that enforces the same IP
// policy as CheckHost, but on the *resolved peer address* of each connection
// rather than on a pre-flight DNS lookup. CheckHost resolves and validates once
// at login; the driver then re-resolves when it actually dials, so a
// DNS-rebinding answer could otherwise slip a blocked address past the guard.
// Installing this on the dialer closes that TOCTOU window: link-local/metadata
// addresses are always refused, and private/loopback addresses are refused when
// BlockPrivate is set. It is attached (via ConnParams.DialControl) to ad-hoc
// network logins only; predefined servers are operator-trusted.
func DialControl(sec config.SecurityConfig) func(network, address string, c syscall.RawConn) error {
	blockPrivate := sec.BlockPrivate
	return func(_, address string, _ syscall.RawConn) error {
		// ParseAddrPort handles the bracketed IPv6 forms including a zone
		// ("[fe80::1%eth0]:5432"), which net.ParseIP rejected outright — so a
		// zoned link-local peer used to slip past this hook entirely.
		ap, err := netip.ParseAddrPort(address)
		if err != nil {
			return nil // not an IP:port (e.g. a unix socket) — nothing to check
		}
		ip := ap.Addr()
		if isLinkLocalOrMetadata(ip) {
			return fmt.Errorf("connection to link-local/metadata address %s is blocked", ip)
		}
		if blockPrivate && isPrivateOrLoopback(ip) {
			return fmt.Errorf("connection to private address %s is blocked", ip)
		}
		return nil
	}
}

// --- address classification ----------------------------------------------------
//
// This is the SSRF boundary, so the rules are an explicit prefix table rather
// than a hand-rolled byte test. The previous byte tests branched on
// net.IP.To4(), which is non-nil ONLY for IPv4 and IPv4-MAPPED IPv6 — so an
// IPv4-COMPATIBLE address like ::169.254.169.254 matched neither the IPv4 rules
// nor the IPv6 ones and passed both the pre-flight and the dial-time check.

// alwaysBlockedPrefixes are refused for every ad-hoc login, whatever
// block_private says: none is ever a legitimate database target, and several
// are the classic SSRF destinations.
var alwaysBlockedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),          // "this network"; 0.0.0.0 also reaches localhost on Linux
	netip.MustParsePrefix("169.254.0.0/16"),     // link-local, incl. the 169.254.169.254 cloud-metadata endpoint
	netip.MustParsePrefix("100.100.100.200/32"), // Alibaba Cloud metadata: inside CGNAT, which is otherwise only private-blocked
	netip.MustParsePrefix("192.0.0.0/24"),       // IETF protocol assignments, incl. 192.0.0.170/171 NAT64 discovery
	netip.MustParsePrefix("198.18.0.0/15"),      // RFC 2544 benchmarking
	netip.MustParsePrefix("224.0.0.0/4"),        // multicast — never a TCP peer
	netip.MustParsePrefix("255.255.255.255/32"), // limited broadcast
	netip.MustParsePrefix("::/128"),             // unspecified
	netip.MustParsePrefix("fe80::/10"),          // link-local unicast
	netip.MustParsePrefix("fec0::/10"),          // deprecated site-local
	netip.MustParsePrefix("ff00::/8"),           // multicast, incl. link- and interface-local
}

// privatePrefixes are legitimate local-admin targets, so they are refused only
// when block_private is enabled.
var privatePrefixes = []netip.Prefix{
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("100.64.0.0/10"), // RFC 6598 carrier-grade NAT
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("fc00::/7"), // unique-local
}

// nat64WellKnown is RFC 6052's well-known prefix, whose /96 layout puts the
// embedded IPv4 in the low 32 bits. A NAT64 gateway forwards
// 64:ff9b::169.254.169.254 straight to the metadata service, so the embedded
// address has to be judged on the IPv4 rules. (RFC 8215's local-use
// 64:ff9b:1::/48 admits several layouts and is deliberately not decomposed —
// guessing wrong would block real hosts, and it is deployed knowingly.)
var nat64WellKnown = netip.MustParsePrefix("64:ff9b::/96")

// v4Compatible is the deprecated ::a.b.c.d form. Unlike ::ffff:a.b.c.d
// (IPv4-mapped, which Unmap already collapses), Go's net.IP.To4 never
// recognized it — which is exactly how ::169.254.169.254 slipped through.
var v4Compatible = netip.MustParsePrefix("::/96")

// thisNetwork guards the embedded-IPv4 extraction: every address in ::/104 is
// really a plain IPv6 special (:: and ::1 above all), not a v4-compatible
// address, and treating ::1 as "embeds 0.0.0.1" would wrongly promote IPv6
// loopback from private-blocked to always-blocked.
var thisNetwork = netip.MustParsePrefix("0.0.0.0/8")

// targetsFor returns every address a peer must be judged by: the address
// itself, canonicalized, plus any IPv4 it embeds.
//
// Canonicalization matters twice. Unmap collapses ::ffff:a.b.c.d so the IPv4
// rules apply to it; stripping the zone matters because netip.Prefix.Contains
// returns false outright for a zoned address — a link-local peer reached as
// fe80::1%eth0 would otherwise match nothing at all. (It also could not even be
// parsed before: net.ParseIP rejects zones, so DialControl silently allowed it.)
func targetsFor(a netip.Addr) []netip.Addr {
	a = a.Unmap().WithZone("")
	out := []netip.Addr{a}
	if v4, ok := embeddedIPv4(a); ok {
		out = append(out, v4)
	}
	return out
}

// embeddedIPv4 extracts the IPv4 address carried in the low 32 bits of an
// IPv4-compatible or well-known-NAT64 IPv6 address. ok is false when there is
// none, or when the result lands in 0.0.0.0/8 (see thisNetwork).
func embeddedIPv4(a netip.Addr) (netip.Addr, bool) {
	if !a.Is6() || !(v4Compatible.Contains(a) || nat64WellKnown.Contains(a)) {
		return netip.Addr{}, false
	}
	b := a.As16()
	v4 := netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]})
	if thisNetwork.Contains(v4) {
		return netip.Addr{}, false
	}
	return v4, true
}

// inAny reports whether any canonical form of a falls inside prefixes.
func inAny(a netip.Addr, prefixes []netip.Prefix) bool {
	for _, t := range targetsFor(a) {
		for _, p := range prefixes {
			if p.Contains(t) {
				return true
			}
		}
	}
	return false
}

// isLinkLocalOrMetadata reports addresses that are never valid ad-hoc DB
// targets and are refused regardless of BlockPrivate.
func isLinkLocalOrMetadata(a netip.Addr) bool { return inAny(a, alwaysBlockedPrefixes) }

// isPrivateOrLoopback reports loopback, RFC1918, RFC 6598 CGNAT and IPv6
// unique-local addresses, refused only when BlockPrivate is enabled.
func isPrivateOrLoopback(a netip.Addr) bool { return inAny(a, privatePrefixes) }
