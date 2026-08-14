// Package config resolves TableX's runtime configuration from (in increasing
// precedence) built-in defaults, an optional TOML file, environment variables
// (TABLEX_*), and command-line flags.
//
// The config defines the listen address, TLS, session policy, optional
// predefined servers, and the SSRF/ad-hoc-login controls described in
// docs/security.md. Credentials are never required here: the default mode is
// ad-hoc cookie login where nothing is persisted.
package config

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/tablexdev/tablex/internal/driver"
)

// Config is the fully-resolved application configuration.
type Config struct {
	Listen  string `toml:"listen"`
	TLSCert string `toml:"tls_cert"`
	TLSKey  string `toml:"tls_key"`

	// MaxExactCount is the row-count ceiling for Browse/Structure renders
	// (one knob covering both the estimate cutoff and the bounded-count role
	// for views). It bounds the work a row count may cost in two ways: when the engine's
	// statistics estimate a relation above it, the page shows the estimate;
	// when there is no usable estimate at all — a VIEW on every engine, a
	// never-analyzed relation, or an engine with no estimator (SQLite) — the
	// count runs but stops here and reports a lower bound. Either way the page
	// marks the total approximate and offers a "count exact" affordance, which
	// is the one path that may run an unbounded COUNT(*). <= 0 always counts
	// exactly.
	MaxExactCount int `toml:"max_exact_count"`

	// PoolCap is the process-wide budget of cached per-database connection
	// pools (each pool holds up to PoolMaxConns connections). When opening one
	// more pool would exceed it, the session's least-recently-used idle pool is
	// closed first; if nothing is evictable the request fails rather than growing
	// unboundedly. <= 0 removes the cap.
	PoolCap int `toml:"pool_cap"`

	// PoolMaxConns / PoolIdleConns size each database connection pool. The
	// product PoolCap × PoolMaxConns bounds TableX's outbound connections to
	// one server, which is what has to stay clear of the server's own
	// max_connections. <= 0 falls back to the driver defaults.
	PoolMaxConns  int `toml:"pool_max_conns"`
	PoolIdleConns int `toml:"pool_idle_conns"`

	// ReadStmtTimeout bounds a single GENERATED read statement (introspection,
	// browse, count, estimate) so a few slow reads cannot tie up a whole pool
	// until the client disconnects. It is deliberately NOT applied to the SQL
	// console, export streaming, any pinned script, or any generated mutation —
	// see driver.ReadStmtTimeout. <= 0 falls back to the driver default.
	ReadStmtTimeout time.Duration `toml:"read_stmt_timeout"`

	// MaxConcurrentDBOps caps how many requests may simultaneously hold a
	// PRIVATE database connection — a streaming export, a SQL console script or
	// a SQL import. Those deliberately sit outside PoolCap (they must not share
	// or evict a cached pool), so without this nothing bounded them: enough
	// parallel exports could exhaust the DATABASE's max_connections and take
	// down every other client of that server. Over the cap a request is refused
	// with 503 + Retry-After rather than queued indefinitely. <= 0 removes the
	// cap.
	MaxConcurrentDBOps int `toml:"max_concurrent_db_ops"`

	// MaxConcurrentImports caps how many import UPLOADS may be in flight at once.
	// Separate from MaxConcurrentDBOps, and deliberately lower: an import slot is
	// held across the whole upload — the multipart parse and its temp-file spill
	// happen in the CSRF middleware, before any handler runs — while a database
	// op slot is held only across database work. Holding a database connection
	// for the length of a slow upload would be its own denial of service.
	//
	// Over the cap a request is refused with 503 + Retry-After rather than
	// queued: a queued upload holds an HTTP worker while contributing nothing.
	// <= 0 removes the cap.
	MaxConcurrentImports int `toml:"max_concurrent_imports"`

	// MaxScriptStatements caps how many statements ONE script may lex into. The
	// splitter materializes every statement of a script before the first one
	// runs, so a 128 MiB upload of bare `a;` is ~67 million entries and well over
	// a gigabyte of slice — and a Go allocation failure is not something the
	// panic middleware can recover from. Distinct from SessionQueryBudget, which
	// bounds a session's statements over TIME: this bounds one script's size in
	// memory, before anything executes.
	//
	// An over-limit script is REFUSED WHOLE, never truncated: executing a prefix
	// of a restore commits half of it. <= 0 removes the cap.
	MaxScriptStatements int `toml:"max_script_statements"`

	// SessionQueryBudget caps how many statements ONE session may submit per
	// SessionQueryWindow. MaxConcurrentDBOps bounds how much work runs at once;
	// this bounds how much one session may ask for over time, which is the
	// dimension a single logged-in user can otherwise saturate on their own.
	//
	// It charges the SQL a user WROTE — the console, EXPLAIN, and a SQL import —
	// and deliberately not the queries TableX generates for them. Charging those
	// would make ordinary navigation run out of budget (one page render costs
	// several introspection reads), and they are already bounded per request by
	// read_stmt_timeout and the pool caps. <= 0 removes the budget.
	SessionQueryBudget int `toml:"session_query_budget"`

	// SessionQueryWindow is the period SessionQueryBudget is counted over. It is
	// a fixed window, not a sliding one: the count resets when the window rolls,
	// so the honest worst case is two budgets' worth across a window boundary.
	SessionQueryWindow time.Duration `toml:"session_query_window"`

	Session  SessionConfig  `toml:"session"`
	Security SecurityConfig `toml:"security"`
	SSO      SSOConfig      `toml:"sso"`
	Storage  StorageConfig  `toml:"storage"`
	Audit    AuditConfig    `toml:"audit"`
	Restrict RestrictConfig `toml:"restrict"`
	Metrics  MetricsConfig  `toml:"metrics"`
	Servers  []ServerConfig `toml:"servers"`
}

// MetricsConfig exposes /metrics in the Prometheus text exposition format.
//
// Off by default, and when on it is ACCESS-CONTROLLED rather than public. That is
// the whole reason this block has three keys instead of one: the numbers describe
// TableX's internals — how many sessions exist, how much work is in flight,
// whether the audit trail is failing — and none of it belongs to an anonymous
// caller. /healthz stays a bare "ok" for the same reason, so a container probe
// never has to be given a credential.
//
// Enabling it without either a token or an address allowlist refuses startup.
// There is no safe default to pick on the operator's behalf: guessing "loopback
// only" would silently break the common case (a Prometheus on another host), and
// guessing "anyone" would publish the internals of a database admin tool.
type MetricsConfig struct {
	Enabled bool `toml:"enabled"`

	// Token, when set, is required as `Authorization: Bearer <token>`. Compared
	// in constant time.
	Token string `toml:"token"`

	// AllowCIDRs, when non-empty, restricts scraping to these networks (CIDRs or
	// bare IPs). The address compared is the one TableX resolves for every other
	// purpose, so X-Forwarded-For is honoured only from a configured trusted
	// proxy — otherwise this would be a header away from meaningless.
	AllowCIDRs []string `toml:"allow_cidrs"`
}

// Authorizes reports what a scrape must satisfy. Both checks apply when both are
// configured: an allowlisted network still needs the token.
func (m MetricsConfig) Authorizes() (needToken, needNetwork bool) {
	return strings.TrimSpace(m.Token) != "", len(m.AllowCIDRs) > 0
}

// RestrictConfig narrows what a logged-in user may do, BELOW what their database
// grants already allow. It is defence in depth and nothing more: the database's
// own privileges remain the real boundary, and an operator who needs a user not
// to be able to drop a table should also not grant them DROP.
//
// What it buys is the case grants cannot express — an operator who must use a
// privileged account (a shared read-only console, a support login on a DBA
// credential) and wants TableX itself to refuse the dangerous half.
//
// Enforcement is in the middleware, keyed on the route. It is deliberately NOT
// in the templates: a hidden button is not a control, and every restriction here
// must hold against a request typed by hand.
type RestrictConfig struct {
	// ReadOnly refuses every state-changing request. That includes the SQL
	// console and SQL import, because TableX will not try to decide whether
	// somebody's SQL writes — a classifier is the wrong thing to stake a
	// read-only guarantee on. Exports, browsing and every other read are
	// unaffected.
	ReadOnly bool `toml:"read_only"`

	// AllowConsole permits the SQL console and SQL import: arbitrary SQL, under
	// the user's own credentials. Defaults to true. Turning it off leaves the
	// generated operations — browse, edit, structure — working, which is the
	// point: it removes the path whose reach TableX cannot describe.
	AllowConsole bool `toml:"allow_console"`

	// AllowDDL permits schema and access-control changes: create/drop database
	// and schema, the structure editor, table operations, stored programs,
	// accounts and grants. Defaults to true. Row edits (INSERT/UPDATE/DELETE)
	// are NOT DDL and stay available — the distinction is deliberate, because
	// "let them fix data but not reshape it" is the common ask.
	AllowDDL bool `toml:"allow_ddl"`

	// Databases, when non-empty, is the set of databases the UI may address.
	// Every route naming a database outside it is refused.
	//
	// Its limit has to be stated: it is a ROUTE restriction. While the console
	// is enabled, a user can name any database their credentials can reach in
	// SQL, and TableX does not parse their statements to stop them. Startup
	// warns about that combination. Paired with allow_console = false it is a
	// real confinement; on its own it is navigation scoping.
	Databases []string `toml:"database_allowlist"`
}

// Restricted reports whether any restriction is in force.
func (r RestrictConfig) Restricted() bool {
	return r.ReadOnly || !r.AllowConsole || !r.AllowDDL || len(r.Databases) > 0
}

// DatabaseAllowed reports whether a database may be addressed. An empty
// allowlist permits everything.
func (r RestrictConfig) DatabaseAllowed(name string) bool {
	if len(r.Databases) == 0 {
		return true
	}
	return slices.Contains(r.Databases, name)
}

// AuditConfig turns on the audit trail (internal/audit) — a durable record of
// who changed what, distinct from the access log that has always gone to stderr.
//
// It is on when it has at least one destination, and off otherwise: there is no
// separate `enabled` flag to contradict the destinations. A block that names none
// is refused rather than silently ignored.
type AuditConfig struct {
	// File is a JSON Lines path. Its DIRECTORY must exist; the file is created
	// 0600 because it records account names and client addresses.
	File string `toml:"file"`
	// MaxBytes rotates File once it would exceed this, keeping one ".1"
	// generation. It is a floor against filling a disk unattended, not a
	// retention policy — point File somewhere your own rotation handles, or ship
	// the lines, which is what the JSON Lines format is for. <= 0 uses the
	// built-in default.
	MaxBytes int64 `toml:"max_bytes"`
	// Log writes events through TableX's own logger, and therefore to stderr —
	// which is the container log stream, journald, or whatever the host already
	// collects. This is how the trail reaches syslog without TableX speaking it.
	Log bool `toml:"log"`
	// Statements records the SQL text of each statement TableX runs on a user's
	// behalf, not merely that a request happened. Statement text can carry row
	// data (an INSERT's values, a WHERE clause), which is the one reason an
	// operator might want the rest of the trail without it.
	Statements bool `toml:"statements"`
}

// Enabled reports whether the audit trail has anywhere to write.
func (a AuditConfig) Enabled() bool { return strings.TrimSpace(a.File) != "" || a.Log }

// SessionConfig controls cookie and timeout policy.
type SessionConfig struct {
	CookieName      string        `toml:"cookie_name"`
	IdleTimeout     time.Duration `toml:"idle_timeout"`
	AbsoluteTimeout time.Duration `toml:"absolute_timeout"`
}

// SSOConfig puts an OpenID Connect provider IN FRONT OF the login form.
//
// It is deliberately not "log in with SSO". TableX opens every database
// connection with the user's OWN credentials — that is what makes the audit
// trail's "account" field the truthful answer to whose privileges a statement ran
// under, and what lets the promise that TableX never stores a credential stand.
// Authenticating a PERSON does not produce database credentials, so SSO here is
// an EXTRA FACTOR: you must pass the provider to reach the login form, and then
// you still supply your own credentials.
//
// The two alternatives were considered and rejected on purpose. Mapping SSO users
// onto predefined servers would give one-click access but make every user share
// one database identity, which collapses the audit trail to "someone who passed
// SSO". Storing per-user credentials encrypted in the metadata database would
// give both, at the cost of reversing a documented guarantee and making the
// encryption key the most valuable secret in the deployment.
//
// Off unless Issuer is set. Half-configured refuses startup, for the same reason
// MetricsConfig does: a provider that silently does not engage is worse than one
// that fails loudly, because the gate it was supposed to be is simply absent.
type SSOConfig struct {
	// Issuer is the provider's base URL. Discovery reads
	// <issuer>/.well-known/openid-configuration.
	Issuer string `toml:"issuer"`

	ClientID     string `toml:"client_id"`
	ClientSecret string `toml:"client_secret"`

	// RedirectURL must be the absolute URL of TableX's callback route and must be
	// registered with the provider. It cannot be derived from the request: behind
	// a proxy the Host and scheme TableX sees need not be the ones the browser
	// used, and a redirect_uri the provider does not recognize fails the exchange.
	RedirectURL string `toml:"redirect_url"`

	// Scopes is the scope list to request; openid is always included (without
	// it the provider is not doing OIDC at all), so an empty list resolves to
	// just ["openid"]. No default is ever assigned to this field — the
	// disabled-block validation relies on a set Scopes meaning the OPERATOR
	// set it; see ResolvedScopes.
	Scopes []string `toml:"scopes"`

	// AllowedEmails / AllowedDomains narrow WHICH verified identities may reach
	// the login form. Empty means any identity the provider vouches for, which is
	// the right default only when the provider's own audience is already the set
	// of people who should be here.
	AllowedEmails  []string `toml:"allowed_emails"`
	AllowedDomains []string `toml:"allowed_domains"`
}

// Enabled reports whether the SSO gate is configured.
func (s SSOConfig) Enabled() bool { return strings.TrimSpace(s.Issuer) != "" }

// ResolvedScopes returns the scopes to request, always including openid.
func (s SSOConfig) ResolvedScopes() []string {
	out := make([]string, 0, len(s.Scopes)+1)
	seen := map[string]bool{}
	for _, sc := range append([]string{"openid"}, s.Scopes...) {
		sc = strings.TrimSpace(sc)
		if sc == "" || seen[sc] {
			continue
		}
		seen[sc] = true
		out = append(out, sc)
	}
	return out
}

// HasAllowlist reports whether the operator narrowed WHO may pass the gate by
// email. It is also the condition under which an unverified email must be
// refused: an allowlist matches on the email string, and on a self-service
// provider an unverified email is an attacker-choosable string — register
// victim@allowed-domain.com and the list falls. With no allowlist the email is
// never matched against anything, so verification is not required.
func (s SSOConfig) HasAllowlist() bool {
	return len(s.AllowedEmails) > 0 || len(s.AllowedDomains) > 0
}

// PermitsIdentity reports whether a verified identity may proceed to the login
// form. The subject is accepted on the strength of the provider alone; the
// allowlists, when set, narrow it further by email. Callers must have already
// refused an unverified email when HasAllowlist is true — this only matches
// the string.
func (s SSOConfig) PermitsIdentity(email string) bool {
	if !s.HasAllowlist() {
		return true
	}
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" {
		// An allowlist is configured but the provider told us no email, so there
		// is nothing to match. Refusing is the only safe reading: the operator
		// asked for a narrower set than "anyone the provider vouches for".
		return false
	}
	// Blank entries are skipped DEFENSIVELY in both loops: a blank domain
	// entry would match an email whose domain part is empty ("x@"), and a
	// blank email entry an empty address. validate() refuses blank entries at
	// startup, so a blank-only list can never exist and this skip can never
	// widen the gate — which is also why the blanks must NOT be filtered out
	// at parse time: emptying the slice would flip HasAllowlist to false and
	// turn an over-restrictive allowlist into no allowlist at all.
	for _, a := range s.AllowedEmails {
		if a = strings.TrimSpace(a); a != "" && strings.EqualFold(a, email) {
			return true
		}
	}
	_, domain, ok := strings.Cut(email, "@")
	if !ok {
		return false
	}
	for _, d := range s.AllowedDomains {
		if d = normalizeAllowedDomain(d); d != "" && strings.EqualFold(d, domain) {
			return true
		}
	}
	return false
}

// normalizeAllowedDomain is THE domain-entry normalization, shared by the
// validator and the matcher so the two can never disagree about what an entry
// means: trim, drop one leading "@", trim again. It exists because they once
// differed by exactly the inner TrimSpace — an entry like "@ example.com"
// passed validation as "example.com" while the matcher compared
// " example.com", a silently dead allowlist entry the validator claimed to
// have checked.
func normalizeAllowedDomain(d string) string {
	return strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(d), "@"))
}

// validate refuses a half-configured provider. Every field below is required for
// the authorization-code flow to complete at all, and a gate that cannot complete
// is a gate that is not there.
func (s SSOConfig) validate() error {
	set := func(v string) bool { return strings.TrimSpace(v) != "" }
	// Ordered slices, not maps: with several fields set the reported name
	// must be deterministic — the first in block order.
	ordered := []struct {
		name  string
		value string
	}{
		{"client_id", s.ClientID},
		{"client_secret", s.ClientSecret},
		{"redirect_url", s.RedirectURL},
	}
	if !s.Enabled() {
		for _, f := range ordered {
			if set(f.value) {
				return fmt.Errorf("sso.%s is set but sso.issuer is not, so no SSO gate would be applied; set sso.issuer or remove the block", f.name)
			}
		}
		if len(s.AllowedEmails) > 0 || len(s.AllowedDomains) > 0 {
			return fmt.Errorf("sso.allowed_emails/allowed_domains are set but sso.issuer is not, so nothing would be checked against them; set sso.issuer or remove the block")
		}
		if len(s.Scopes) > 0 {
			return fmt.Errorf("sso.scopes is set but sso.issuer is not, so no flow would ever request them; set sso.issuer or remove the block")
		}
		return nil
	}
	for _, f := range ordered {
		if !set(f.value) {
			return fmt.Errorf("sso.issuer is set but sso.%s is empty; the authorization-code flow cannot complete without it", f.name)
		}
	}
	// Blank allowlist entries refuse startup — the same fail-closed shape as
	// every other block validator. A blank domain entry would otherwise match
	// an email with an empty domain part ("x@"); it cannot simply be dropped
	// at parse time, because filtering ["" ] down to [] flips HasAllowlist to
	// false and PermitsIdentity would then admit EVERY provider-verified
	// identity. (The env path is untouched: listEnv already drops blanks, and
	// a separator-only value still clears the list, as documented.)
	for i, a := range s.AllowedEmails {
		if strings.TrimSpace(a) == "" {
			return fmt.Errorf("sso.allowed_emails entry %d is blank; remove it (a blank entry cannot name anyone, and dropping it silently would widen the allowlist)", i+1)
		}
	}
	for i, d := range s.AllowedDomains {
		// The SAME normalization the matcher applies (normalizeAllowedDomain),
		// so an entry accepted here is exactly what will be compared later.
		n := normalizeAllowedDomain(d)
		if n == "" {
			return fmt.Errorf("sso.allowed_domains entry %d is blank; remove it (a blank entry cannot name a domain, and dropping it silently would widen the allowlist)", i+1)
		}
		if strings.ContainsAny(n, " \t") {
			return fmt.Errorf("sso.allowed_domains entry %d (%q) contains whitespace; a domain cannot, so the entry could never match anyone and the allowlist would be silently narrower than configured", i+1, d)
		}
	}
	iss, err := url.Parse(strings.TrimSpace(s.Issuer))
	if err != nil || iss.Host == "" {
		return fmt.Errorf("sso.issuer: %q is not an absolute URL", s.Issuer)
	}
	if iss.Scheme != "https" && !isLoopbackHost(iss.Hostname()) {
		// The ID token's trustworthiness rests entirely on TLS to the token
		// endpoint (see internal/auth/oidc.go), so plaintext to a remote issuer
		// would remove the only thing holding the flow up. Loopback is allowed
		// because that is how it gets tested.
		return fmt.Errorf("sso.issuer must be https (got %q); the flow's security depends on TLS to the provider", s.Issuer)
	}
	rd, err := url.Parse(strings.TrimSpace(s.RedirectURL))
	if err != nil || rd.Host == "" || rd.Scheme == "" {
		return fmt.Errorf("sso.redirect_url: %q is not an absolute URL", s.RedirectURL)
	}
	return nil
}

// listenIsExposed reports whether a listen address accepts connections from
// beyond this machine. It borrows healthcheckURL's PARSING and inverts its
// CLASSIFICATION, which is the whole point of not sharing the function: that one
// picks a PROBE TARGET, so an empty or wildcard host maps to 127.0.0.1 because
// loopback reaches a wildcard listener from inside the container. For an
// EXPOSURE question those same hosts mean the opposite — and since Listen
// defaults to ":8080", transcribing it would classify the shipped default as
// loopback and suppress the one warning worth giving.
//
// So: exposed unless the host is a CONCRETE loopback. An address that will not
// parse is exposed too — the cost of a false positive is one advisory line,
// while a false negative is the warning silently not appearing.
func listenIsExposed(listen string) bool {
	host, port, err := net.SplitHostPort(listen)
	if err != nil || port == "" {
		host = ""
	}
	if host == "" {
		return true // ":8080" and "" — the default, and a wildcard bind
	}
	ip := net.ParseIP(host)
	if ip == nil {
		// A zone-scoped literal (fe80::1%eth0) does not ParseIP whole; strip the
		// zone so the loopback test can still see through it.
		if i := strings.IndexByte(host, '%'); i >= 0 {
			ip = net.ParseIP(host[:i])
		}
	}
	if ip != nil {
		if ip.IsUnspecified() {
			return true // 0.0.0.0, ::
		}
		return !ip.IsLoopback()
	}
	return !isLoopbackHost(host) // "localhost", and anything that will not parse
}

// isLoopbackHost reports whether a host is localhost or a loopback literal, the
// one place plaintext OIDC is acceptable (a test provider on this machine).
func isLoopbackHost(h string) bool {
	if strings.EqualFold(h, "localhost") {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// SecurityConfig captures login/SSRF hardening knobs.
type SecurityConfig struct {
	AllowAdHoc      bool          `toml:"allow_adhoc"`       // permit arbitrary host login
	BlockPrivate    bool          `toml:"block_private"`     // block loopback/private hosts for ad-hoc (link-local/metadata are always blocked)
	SecureCookies   bool          `toml:"secure_cookies"`    // force Secure/__Host- cookies + HSTS behind a TLS-terminating proxy
	HostAllowlist   []string      `toml:"host_allowlist"`    // if set, only these hosts may be targeted
	HostDenylist    []string      `toml:"host_denylist"`     // always-blocked hosts
	LoginRateWindow time.Duration `toml:"login_rate_window"` // throttle window; keys: IP, (IP,user), (IP,predefined-server)
	LoginRateMax    int           `toml:"login_rate_max"`    // max attempts per window

	// LoginAccountMax caps failed attempts against ONE ACCOUNT NAME per window,
	// across every source address. Every other login key above starts with the
	// client IP, so the throttle they provide is per-source: an IPv6 /64, a
	// botnet, or anything else with addresses to spend gets login_rate_max
	// attempts EACH against the same account. This is the key that is not keyed
	// on the attacker's choice of address.
	//
	// It is deliberately more permissive than login_rate_max, because it is
	// shared: several people behind different addresses may be typing the same
	// shared account name, and one of them fat-fingering must not lock the rest
	// out. <= 0 disables it (and Warnings says so).
	LoginAccountMax int `toml:"login_account_max"`

	// SessionCreateWindow / SessionCreateMax throttle how many SESSIONS one
	// client may cause to be created. The login limiter cannot serve: it
	// short-circuits on safe methods, while an anonymous GET to any route mints a
	// session — and, with [storage] configured, a durable ROW.
	//
	// Off by default (a max <= 0 disables limiting, matching NewRateLimiter), and
	// the window still has a default so turning it on is one key — the shape
	// SessionQueryWindow/SessionQueryBudget already use.
	//
	// It is off by default because it is keyed on the client IP and, unlike the
	// login limiter, gates GETs too: behind a NAT or a corporate egress an
	// under-sized value refuses the login PAGE to everyone sharing the address.
	SessionCreateWindow time.Duration `toml:"session_create_window"`
	SessionCreateMax    int           `toml:"session_create_max"`
	TrustedProxy        bool          `toml:"trusted_proxy"` // legacy intent flag; X-Forwarded-For is honored only with trusted_proxy_cidrs

	// TrustedProxyCIDRs lists the reverse proxies (CIDRs or bare IPs) whose
	// X-Forwarded-For entries may be skipped when resolving the client IP for
	// rate limiting and logs. XFF is parsed right-to-left, stopping at the
	// first address outside these ranges; when the list is empty XFF is never
	// consulted — a bare trusted_proxy=true would otherwise mean "trust any
	// client-supplied header", which is spoofable.
	TrustedProxyCIDRs []string `toml:"trusted_proxy_cidrs"`
}

// StorageConfig points TableX at a database of its OWN, for the state the
// application needs to outlive a process — today the session envelopes that make
// sessions survive a restart and work behind a load balancer (internal/storage).
//
// Engine empty (the default) means no metadata database and no behaviour change
// whatsoever: sessions live in process memory exactly as they always have.
//
// These credentials are operator-defined, like a predefined server's, which is
// the documented exception to "credentials are never persisted"
// (docs/security.md §2). The metadata database holds live session ids, so it is
// as sensitive as the cookies it stands in for — give TableX its own database
// and its own account.
type StorageConfig struct {
	// MaxSessions caps the DURABLE SESSIONS TABLE. Over it a new session is
	// refused a row and runs process-local, exactly as it does when storage is
	// unreachable; the reaper's repersist picks it up once there is room.
	//
	// PER REPLICA. Each enforces the cap against its own most recent count, so a
	// cluster may briefly hold roughly replicas × max_sessions rows. What
	// converges within a sweep (about a minute) is ADMISSION — every replica
	// reconciles from a fresh COUNT(*) and stops admitting. The excess ROWS do
	// not: nothing trims the table to fit, so they clear on the ordinary session
	// clock — a row becomes ELIGIBLE only after its session has been inactive for
	// session.idle_timeout plus the sweep's touch lag, or, for a session still in
	// use, no sooner than session.absolute_timeout — and is DELETED only by a
	// later successful sweep, so a storage outage extends it further.
	//
	// 20000 rather than an arbitrary number above the in-memory cap: the
	// in-memory store holds 10000 and EVICTS (pre-auth first) rather than
	// refusing, silently, while the row survives — so the table keeps growing
	// past 10000 and this is the only thing that bounds it. <= 0 removes the cap.
	MaxSessions int `toml:"max_sessions"`

	// maxSessionsSet records that max_sessions was EXPLICITLY configured (in
	// TOML, or through a non-empty, successfully parsed environment override —
	// applyEnv's own semantics, where TABLEX_STORAGE_MAX_SESSIONS="" is
	// absent). MaxSessions is the one [storage] key whose non-zero default
	// makes "set" undetectable from the value alone — 0 is a documented
	// explicit value meaning uncapped, so the default cannot be dropped and
	// re-seeded — and without this bit it was exempt from the block's
	// partly-configured rule: a [storage] block holding only max_sessions
	// started and silently did nothing. A Config built directly in code
	// leaves it false, which reads as "not set" — the correct default.
	maxSessionsSet bool

	Engine   string            `toml:"engine"`
	Host     string            `toml:"host"`
	Port     int               `toml:"port"`
	Socket   string            `toml:"socket"`
	Database string            `toml:"database"`
	FilePath string            `toml:"file"`
	User     string            `toml:"user"`
	Password string            `toml:"password"`
	SSLMode  string            `toml:"sslmode"`
	Params   map[string]string `toml:"params"`

	// TablePrefix is prepended to every metadata table name. It is concatenated
	// into DDL, so storage.Open validates its shape rather than escaping it —
	// quoting would let an absurd prefix through as a legal identifier.
	TablePrefix string `toml:"table_prefix"`
}

// Enabled reports whether a metadata database is configured.
func (s StorageConfig) Enabled() bool { return strings.TrimSpace(s.Engine) != "" }

// ServerConfig is a predefined server users can pick on the login page without
// typing host/port. Only User/Password are collectible at login (each collected
// only when left empty here); the connection topology — Host/Port/Database/
// SSLMode/FilePath — comes solely from this config, never from a posted value.
// A predefined PostgreSQL server on a managed host that blocks the default
// `postgres` database must therefore set Database here (an empty Database still
// defaults to "postgres" at connect time).
type ServerConfig struct {
	Name     string            `toml:"name"`
	Engine   string            `toml:"engine"`
	Host     string            `toml:"host"`
	Port     int               `toml:"port"`
	Socket   string            `toml:"socket"`
	Database string            `toml:"database"`
	FilePath string            `toml:"file"`
	User     string            `toml:"user"`
	Password string            `toml:"password"`
	SSLMode  string            `toml:"sslmode"`
	Params   map[string]string `toml:"params"`
}

// Default returns the built-in defaults (used when nothing overrides them).
func Default() Config {
	return Config{
		Listen:               ":8080",
		MaxExactCount:        50000, // large enough to count small tables exactly, small enough to bound a render
		PoolCap:              32,    // × PoolMaxConns = at most 256 outbound connections
		PoolMaxConns:         8,
		PoolIdleConns:        4,
		ReadStmtTimeout:      60 * time.Second,
		MaxConcurrentDBOps:   16,
		MaxConcurrentImports: 4,
		// Generous by design: this is a memory-exhaustion backstop, not a policy
		// on script size. A real restore of a large database can carry hundreds of
		// thousands of INSERTs, and refusing one of those would be the bug.
		MaxScriptStatements: 500000,
		// No query budget by default: a single-operator TableX has nobody to be
		// fair to, and a limit that surprises them is worse than none. The window
		// still has a default so turning the budget on is one key.
		SessionQueryWindow: time.Minute,
		Session: SessionConfig{
			CookieName:      "tablex_session",
			IdleTimeout:     30 * time.Minute,
			AbsoluteTimeout: 8 * time.Hour,
		},
		Security: SecurityConfig{
			AllowAdHoc:      true,
			BlockPrivate:    false,
			LoginRateWindow: time.Minute,
			LoginRateMax:    10,
			// 5x the per-IP cap: high enough that a shared account being typed
			// from several places is not locked by one typo, low enough that a
			// distributed guess against one account is bounded at all.
			LoginAccountMax: 50,
			// Off by default; the window still has a default, so enabling the
			// throttle is one key. See the field comment for why it ships off.
			SessionCreateWindow: time.Minute,
		},
		// Permissive by default, and set HERE rather than inferred: a Go bool is
		// false when a TOML key is absent, so an `allow_*` default of true has to
		// come from the defaults the file overrides — exactly as AllowAdHoc does.
		Restrict: RestrictConfig{
			AllowConsole: true,
			AllowDDL:     true,
		},
		// [storage] is off by default (Engine empty), so this binds only once an
		// operator has configured a metadata database. See the field comment for
		// why 20000 and not simply "more than the in-memory 10000".
		Storage: StorageConfig{MaxSessions: 20000},
	}
}

// Load resolves configuration from args (typically os.Args[1:]), the
// environment, and an optional TOML file. It returns the config and, when the
// user passes -help, flag.ErrHelp.
func Load(args []string) (Config, error) {
	cfg := Default()

	// First pass: discover the config-file path from flags/env without
	// committing other flags, so file values sit below env/flags in precedence.
	fs := flag.NewFlagSet("tablex", flag.ContinueOnError)
	var (
		configPath  = fs.String("config", os.Getenv("TABLEX_CONFIG"), "path to a TOML config file")
		listen      = fs.String("listen", "", "listen address, e.g. :8080 or 127.0.0.1:8080")
		tlsCert     = fs.String("tls-cert", "", "path to TLS certificate (enables HTTPS)")
		tlsKey      = fs.String("tls-key", "", "path to TLS private key")
		allowAdhoc  = fs.String("allow-adhoc", "", "allow ad-hoc host login: true|false")
		showVer     = fs.Bool("version", false, "print version and exit")
		healthcheck = fs.Bool("healthcheck", false, "probe GET /healthz on the configured listen address and exit 0/1 (for container HEALTHCHECK)")
	)
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "TableX — multi-database web admin (tablex.dev)\n\nUsage: tablex [flags]\n\nFlags:\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return cfg, err
	}
	if *showVer {
		return cfg, errVersion
	}
	// stdlib flag stops at the first non-flag argument and silently drops any
	// flags after it, so a stray positional arg (or a mistyped flag it swallowed)
	// must be a hard error rather than a silently-ignored one.
	if fs.NArg() > 0 {
		return cfg, fmt.Errorf("unexpected argument %q (TableX takes only flags)", fs.Arg(0))
	}

	if *configPath != "" {
		md, err := loadTOML(*configPath, &cfg)
		if err != nil {
			return cfg, fmt.Errorf("loading config %s: %w", *configPath, err)
		}
		// Presence, not value: max_sessions' non-zero default (and its
		// documented explicit 0) make "set" undetectable downstream, so the
		// partly-configured rule needs the decoder's own answer.
		if md.IsDefined("storage", "max_sessions") {
			cfg.Storage.maxSessionsSet = true
		}
	}

	// Environment overrides (only when set). A malformed scalar refuses startup.
	if errs := applyEnv(&cfg); len(errs) > 0 {
		return cfg, errors.Join(errs...)
	}
	// Past applyEnv without an error, a non-empty override was successfully
	// parsed and applied — exactly applyEnv's own "only when set" semantics,
	// so an empty TABLEX_STORAGE_MAX_SESSIONS stays "absent" here too.
	if os.Getenv("TABLEX_STORAGE_MAX_SESSIONS") != "" {
		cfg.Storage.maxSessionsSet = true
	}

	// Flag overrides (highest precedence) — only flags the user actually set.
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	if set["listen"] {
		cfg.Listen = *listen
	}
	if set["tls-cert"] {
		cfg.TLSCert = *tlsCert
	}
	if set["tls-key"] {
		cfg.TLSKey = *tlsKey
	}
	if set["allow-adhoc"] {
		b, err := parseBool(*allowAdhoc)
		if err != nil {
			return cfg, fmt.Errorf("-allow-adhoc: %w", err)
		}
		cfg.Security.AllowAdHoc = b
	}

	// -healthcheck only needs the resolved listen address / TLS (to probe
	// /healthz), so it returns before Validate — a container's HEALTHCHECK must
	// work regardless of the login/server policy.
	if *healthcheck {
		return cfg, errHealthcheck
	}

	// Canonicalize host spellings once at the boundary: a bracketed IPv6
	// literal in the allow/denylists or a predefined server's host is
	// normalized to bare form, so policy matching (which string-compares) and
	// DSN building (net.JoinHostPort would double-bracket) see one spelling.
	for i, a := range cfg.Security.HostAllowlist {
		cfg.Security.HostAllowlist[i] = CanonicalHost(a)
	}
	for i, d := range cfg.Security.HostDenylist {
		cfg.Security.HostDenylist[i] = CanonicalHost(d)
	}
	for i := range cfg.Servers {
		cfg.Servers[i].Host = CanonicalHost(cfg.Servers[i].Host)
	}

	if err := cfg.Validate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// errHealthcheck is returned by Load when -healthcheck is passed.
var errHealthcheck = fmt.Errorf("healthcheck requested")

// IsHealthcheckRequest reports whether err signals the -healthcheck flag.
func IsHealthcheckRequest(err error) bool { return err == errHealthcheck }

// errVersion is returned by Load when -version is passed.
var errVersion = fmt.Errorf("version requested")

// IsVersionRequest reports whether err signals the -version flag.
func IsVersionRequest(err error) bool { return err == errVersion }

// loadTOML decodes path into cfg and REFUSES a file carrying any key the
// config does not understand. TOML decoding silently ignores unknown keys, so
// a mistyped or misplaced hardening key ([restrict] readonly instead of
// read_only, database_allowlist at top level) would otherwise leave its
// permissive default in force with no error, no warning and no log line —
// the exact "a setting that does nothing" failure every block validator in
// this file already refuses (docs/architecture.md, "Configuration errors
// refuse startup").
//
// Known limitation, stated rather than hidden: the two free-form maps —
// [storage.params] and [[servers]].params — absorb their sub-keys as decoded,
// so a typo INSIDE them stays silent. The guard is strong, not total.
//
// The MetaData is returned so callers can presence-check individual keys
// (md.IsDefined) — a key whose non-zero default makes "set" undetectable from
// the value alone needs it.
func loadTOML(path string, cfg *Config) (toml.MetaData, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return toml.MetaData{}, err
	}
	md, err := toml.Decode(string(data), cfg)
	if err != nil {
		return md, err
	}
	if undecoded := md.Undecoded(); len(undecoded) > 0 {
		keys := make([]string, len(undecoded))
		for i, k := range undecoded {
			keys[i] = k.String()
		}
		return md, fmt.Errorf("unknown configuration key(s): %s (a mistyped or misplaced key would silently keep its permissive default; see tablex.example.toml for the accepted keys)",
			strings.Join(keys, ", "))
	}
	return md, nil
}

// applyEnv applies TABLEX_* overrides. A malformed scalar value is a hard error
// (collected, not fatal-on-first) so startup refuses rather than silently keeping
// the previous — often insecure — default. Every bad knob is reported at once.
//
// An UNKNOWN TABLEX_* variable is a hard error too — the environment-side
// mirror of loadTOML's unknown-key refusal: TABLEX_READONLY (for
// TABLEX_READ_ONLY) would otherwise leave the instance fully writable with no
// error, no warning and no log line. The known set is built by the very reads
// below (getenv registers every name it is asked for), so it cannot drift
// from the code that consumes it.
func applyEnv(cfg *Config) []error {
	var errs []error
	// TABLEX_CONFIG is loader metadata, read by Load before this runs.
	known := map[string]bool{"TABLEX_CONFIG": true}
	getenv := func(name string) string {
		known[name] = true
		return os.Getenv(name)
	}
	list := func(name string) ([]string, bool) {
		known[name] = true
		return listEnv(name)
	}
	boolEnv := func(name string, dst *bool) {
		if v := getenv(name); v != "" {
			if b, err := parseBool(v); err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", name, err))
			} else {
				*dst = b
			}
		}
	}
	intEnv := func(name string, dst *int) {
		if v := getenv(name); v != "" {
			if n, err := parseInt(v); err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", name, err))
			} else {
				*dst = n
			}
		}
	}
	durEnv := func(name string, dst *time.Duration) {
		if v := getenv(name); v != "" {
			if d, err := parseDuration(v); err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", name, err))
			} else {
				*dst = d
			}
		}
	}

	if v := getenv("TABLEX_LISTEN"); v != "" {
		cfg.Listen = v
	}
	if v := getenv("TABLEX_TLS_CERT"); v != "" {
		cfg.TLSCert = v
	}
	if v := getenv("TABLEX_TLS_KEY"); v != "" {
		cfg.TLSKey = v
	}
	if v := getenv("TABLEX_COOKIE_NAME"); v != "" {
		cfg.Session.CookieName = v
	}
	boolEnv("TABLEX_ALLOW_ADHOC", &cfg.Security.AllowAdHoc)
	boolEnv("TABLEX_SECURE_COOKIES", &cfg.Security.SecureCookies)
	boolEnv("TABLEX_BLOCK_PRIVATE", &cfg.Security.BlockPrivate)
	boolEnv("TABLEX_TRUSTED_PROXY", &cfg.Security.TrustedProxy)
	if v, ok := list("TABLEX_TRUSTED_PROXY_CIDRS"); ok {
		cfg.Security.TrustedProxyCIDRs = v
	}
	intEnv("TABLEX_MAX_EXACT_COUNT", &cfg.MaxExactCount)
	intEnv("TABLEX_POOL_CAP", &cfg.PoolCap)
	intEnv("TABLEX_POOL_MAX_CONNS", &cfg.PoolMaxConns)
	intEnv("TABLEX_POOL_IDLE_CONNS", &cfg.PoolIdleConns)
	intEnv("TABLEX_MAX_CONCURRENT_DB_OPS", &cfg.MaxConcurrentDBOps)
	intEnv("TABLEX_MAX_CONCURRENT_IMPORTS", &cfg.MaxConcurrentImports)
	intEnv("TABLEX_MAX_SCRIPT_STATEMENTS", &cfg.MaxScriptStatements)
	intEnv("TABLEX_SESSION_QUERY_BUDGET", &cfg.SessionQueryBudget)
	durEnv("TABLEX_SESSION_QUERY_WINDOW", &cfg.SessionQueryWindow)
	durEnv("TABLEX_READ_STMT_TIMEOUT", &cfg.ReadStmtTimeout)
	durEnv("TABLEX_IDLE_TIMEOUT", &cfg.Session.IdleTimeout)
	durEnv("TABLEX_ABSOLUTE_TIMEOUT", &cfg.Session.AbsoluteTimeout)

	// The metadata database. A password belongs in the environment rather than
	// a config file on most deployments, which is the main reason every field
	// here has an override — every field except Params, a map no environment
	// variable can express (tablex.example.toml records the same exception).
	strEnv := func(name string, dst *string) {
		if v := getenv(name); v != "" {
			*dst = v
		}
	}
	strEnv("TABLEX_STORAGE_ENGINE", &cfg.Storage.Engine)
	strEnv("TABLEX_STORAGE_HOST", &cfg.Storage.Host)
	intEnv("TABLEX_STORAGE_PORT", &cfg.Storage.Port)
	strEnv("TABLEX_STORAGE_SOCKET", &cfg.Storage.Socket)
	strEnv("TABLEX_STORAGE_DATABASE", &cfg.Storage.Database)
	strEnv("TABLEX_STORAGE_FILE", &cfg.Storage.FilePath)
	strEnv("TABLEX_STORAGE_USER", &cfg.Storage.User)
	strEnv("TABLEX_STORAGE_PASSWORD", &cfg.Storage.Password)
	strEnv("TABLEX_STORAGE_SSLMODE", &cfg.Storage.SSLMode)
	strEnv("TABLEX_STORAGE_TABLE_PREFIX", &cfg.Storage.TablePrefix)
	intEnv("TABLEX_STORAGE_MAX_SESSIONS", &cfg.Storage.MaxSessions)

	boolEnv("TABLEX_READ_ONLY", &cfg.Restrict.ReadOnly)
	boolEnv("TABLEX_ALLOW_CONSOLE", &cfg.Restrict.AllowConsole)
	boolEnv("TABLEX_ALLOW_DDL", &cfg.Restrict.AllowDDL)
	if v, ok := list("TABLEX_DATABASE_ALLOWLIST"); ok {
		cfg.Restrict.Databases = v
	}

	strEnv("TABLEX_AUDIT_FILE", &cfg.Audit.File)
	boolEnv("TABLEX_AUDIT_LOG", &cfg.Audit.Log)
	boolEnv("TABLEX_AUDIT_STATEMENTS", &cfg.Audit.Statements)
	if v := getenv("TABLEX_AUDIT_MAX_BYTES"); v != "" {
		// Its own 64-bit parse, not parseInt: Atoi is machine-sized, so on a
		// 32-bit build a value over 2 GiB refused startup from the environment
		// while the same value in TOML was accepted (BurntSushi decodes
		// straight into the int64 field). The two paths must agree on every
		// architecture.
		if n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64); err != nil {
			errs = append(errs, fmt.Errorf("TABLEX_AUDIT_MAX_BYTES: invalid integer %q", v))
		} else {
			cfg.Audit.MaxBytes = n
		}
	}

	boolEnv("TABLEX_METRICS_ENABLED", &cfg.Metrics.Enabled)
	strEnv("TABLEX_METRICS_TOKEN", &cfg.Metrics.Token)
	if v, ok := list("TABLEX_METRICS_ALLOW_CIDRS"); ok {
		cfg.Metrics.AllowCIDRs = v
	}

	// The SSO gate. The client secret belongs in the environment rather than a
	// file on disk — the example config has promised TABLEX_SSO_CLIENT_SECRET
	// since the block was added; these make good on it for every field. The
	// lists inherit listEnv's semantics unchanged: unset or empty never
	// clobbers the file, a separator-only value clears the configured list —
	// and a cleared allowlist means "anyone the provider vouches for", never a
	// blank entry that PermitsIdentity would have to treat as a wildcard.
	strEnv("TABLEX_SSO_ISSUER", &cfg.SSO.Issuer)
	strEnv("TABLEX_SSO_CLIENT_ID", &cfg.SSO.ClientID)
	strEnv("TABLEX_SSO_CLIENT_SECRET", &cfg.SSO.ClientSecret)
	strEnv("TABLEX_SSO_REDIRECT_URL", &cfg.SSO.RedirectURL)
	if v, ok := list("TABLEX_SSO_SCOPES"); ok {
		cfg.SSO.Scopes = v
	}
	if v, ok := list("TABLEX_SSO_ALLOWED_EMAILS"); ok {
		cfg.SSO.AllowedEmails = v
	}
	if v, ok := list("TABLEX_SSO_ALLOWED_DOMAINS"); ok {
		cfg.SSO.AllowedDomains = v
	}

	// The sweep (see the function comment). Carve-outs, deliberately named:
	// TABLEX_TEST_* carries the live-test credentials and rides the same
	// process environment as `go test`; installerEnvVars belong to the install
	// scripts, which export them and then run the very binary they installed.
	for _, kv := range os.Environ() {
		name, _, _ := strings.Cut(kv, "=")
		if !strings.HasPrefix(name, "TABLEX_") || known[name] {
			continue
		}
		if strings.HasPrefix(name, "TABLEX_TEST_") || installerEnvVars[name] {
			continue
		}
		errs = append(errs, fmt.Errorf("unknown environment variable %s (a mistyped or renamed override would silently keep its permissive default; unset it or fix the name — see tablex.example.toml for the accepted keys)", name))
	}
	return errs
}

// installerEnvVars is every variable the install scripts at the repository
// root (install.sh, install.ps1, install.cmd) document and export before
// running the very binary they installed: the version and location overrides,
// the download base, the PATH-modification opt-out and the .cmd shim's script
// URL. They legitimately share a process environment with TableX, so the
// unknown-TABLEX_* sweep above must not refuse startup over them — a user who
// exported TABLEX_NO_MODIFY_PATH=1 for the installer would otherwise find the
// freshly installed binary refusing to start. Keep this list in lockstep with
// the scripts. (TABLEX_DRIVERTEST_BROKEN is deliberately absent: it exists
// only inside a driver test's own subprocess and never shares an environment
// with a real binary.)
var installerEnvVars = map[string]bool{
	"TABLEX_VERSION":        true,
	"TABLEX_INSTALL_DIR":    true,
	"TABLEX_BASE_URL":       true,
	"TABLEX_NO_MODIFY_PATH": true,
	"TABLEX_PS1_URL":        true,
}

// listEnv reads a comma-separated environment variable into a slice, reporting
// whether it was set. An empty variable reads as unset, matching every other
// override here; a variable holding only separators or blanks yields an empty
// list that REPLACES the configured one, so an env-only deployment can still
// clear a list a config file provides.
func listEnv(name string) ([]string, bool) {
	v := os.Getenv(name)
	if v == "" {
		return nil, false
	}
	out := []string{}
	for item := range strings.SplitSeq(v, ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out, true
}

// parseBool accepts true/false, on/off, yes/no and 1/0 (case-insensitive). Any
// other token is an error — unlike strconv.ParseBool this refuses yes/no/on/off
// only by widening the accepted set, and refuses everything else outright so a
// typo can never silently keep the previous value.
func parseBool(s string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "t", "true", "on", "yes", "y":
		return true, nil
	case "0", "f", "false", "off", "no", "n":
		return false, nil
	}
	return false, fmt.Errorf("invalid boolean %q (want true/false, on/off, yes/no, or 1/0)", s)
}

func parseInt(s string) (int, error) {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0, fmt.Errorf("invalid integer %q", s)
	}
	return n, nil
}

func parseDuration(s string) (time.Duration, error) {
	d, err := time.ParseDuration(strings.TrimSpace(s))
	if err != nil {
		return 0, fmt.Errorf("invalid duration %q (e.g. 30m, 1h30m)", s)
	}
	return d, nil
}

// validateCookieName refuses a session cookie name net/http would silently
// drop: an RFC 6265 cookie-name is a token (ALPHA / DIGIT / one of
// !#$%&'*+-.^_`|~), and http.SetCookie writes NO Set-Cookie header at all for
// an invalid name — the server starts clean, login just never sticks, with
// zero diagnostics. The __Host-/__Secure- prefixes are refused for the same
// silent-breakage reason: the session layer prepends __Host- itself under TLS
// (a double prefix), and on plain HTTP a browser drops a literal __Host- or
// __Secure- cookie that does not carry the Secure attribute.
func validateCookieName(name string) error {
	for _, c := range []byte(name) {
		switch {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9':
		case strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0:
		default:
			return fmt.Errorf("session cookie_name %q contains %q, which is not an RFC 6265 token character (Go would silently set no cookie at all)", name, c)
		}
	}
	for _, p := range []string{"__Host-", "__Secure-"} {
		if strings.HasPrefix(name, p) {
			return fmt.Errorf("session cookie_name %q must not start with %q: the prefix is added automatically under TLS, and on plain HTTP a browser refuses the prefixed cookie", name, p)
		}
	}
	return nil
}

// Validate checks the resolved config for obvious inconsistencies.
func (c Config) Validate() error {
	if c.Listen == "" {
		return fmt.Errorf("listen address must not be empty")
	}
	if (c.TLSCert == "") != (c.TLSKey == "") {
		return fmt.Errorf("tls-cert and tls-key must be set together")
	}
	if c.Session.IdleTimeout <= 0 {
		return fmt.Errorf("session idle_timeout must be positive")
	}
	if c.Session.AbsoluteTimeout <= 0 {
		return fmt.Errorf("session absolute_timeout must be positive")
	}
	if strings.TrimSpace(c.Session.CookieName) == "" {
		return fmt.Errorf("session cookie_name must not be empty")
	}
	if err := validateCookieName(c.Session.CookieName); err != nil {
		return err
	}
	// A non-positive window with throttling enabled silently disables it: the
	// limiter's prune cutoff (now - window) collapses to now (or the future), so
	// every recorded attempt is dropped and Reserve always admits. Reject that
	// foot-gun. A non-positive max already disables limiting deliberately (with a
	// Warnings() advisory), so it stays valid for any window.
	if c.Security.LoginRateMax > 0 && c.Security.LoginRateWindow <= 0 {
		return fmt.Errorf("security.login_rate_window must be positive when login_rate_max > 0 (a non-positive window silently disables brute-force throttling)")
	}
	// Same foot-gun, same rule, for the session-creation throttle.
	if c.Security.SessionCreateMax > 0 && c.Security.SessionCreateWindow <= 0 {
		return fmt.Errorf("security.session_create_window must be positive when session_create_max > 0 (a non-positive window silently disables the throttle)")
	}
	// The engine allowlist IS the driver registry — there is no second copy to
	// keep in sync, so registering a new dialect makes it configurable with no
	// edit here. The registry is populated by each engine package's init() via
	// package main's blank imports; a config-only test that needs to validate
	// servers must blank-import the dialects too. (No import cycle:
	// internal/driver does not import config — the SSRF dial policy is injected
	// via ConnParams.DialControl.)
	known := driver.RegisteredNames()
	if len(c.Servers) > 0 && len(known) == 0 {
		return fmt.Errorf("predefined servers are configured but no database engines are registered (the binary was built without any driver)")
	}
	seen := map[string]bool{}
	for i, s := range c.Servers {
		if s.Name == "" {
			return fmt.Errorf("servers[%d]: name is required", i)
		}
		if seen[s.Name] {
			return fmt.Errorf("duplicate predefined server name %q", s.Name)
		}
		seen[s.Name] = true
		if s.Engine == "" {
			return fmt.Errorf("servers[%d] (%s): engine is required", i, s.Name)
		}
		d, ok := driver.Get(s.Engine)
		if !ok {
			return fmt.Errorf("servers[%d] (%s): unknown engine %q (want one of %s)", i, s.Name, s.Engine, strings.Join(known, ", "))
		}
		// Reject an operator-supplied driver parameter the engine would accept but
		// that breaks a TableX invariant (SQLite's text→time conversions), at
		// startup rather than at first login. BuildDSN re-checks as defense in
		// depth for runtime-supplied params.
		if v, ok := d.(driver.ParamsValidator); ok {
			if err := v.ValidateParams(s.Params); err != nil {
				return fmt.Errorf("servers[%d] (%s): %w", i, s.Name, err)
			}
		}
		// A predefined file-backed server's file is operator-fixed (visitors can
		// never supply it), so it must be configured here and must not be empty —
		// there is no host to fall back to. Anything beyond "non-empty" is the
		// engine's own rule, so it is asked.
		if !d.Capabilities().IsNetworkEngine {
			file := strings.TrimSpace(s.FilePath)
			if file == "" {
				return fmt.Errorf("servers[%d] (%s): a %s server requires a file path", i, s.Name, s.Engine)
			}
			if v, ok := d.(driver.FilePathValidator); ok {
				if err := v.ValidateFilePath(file); err != nil {
					return fmt.Errorf("servers[%d] (%s): %w", i, s.Name, err)
				}
			}
		}
	}
	if err := c.Storage.validate(); err != nil {
		return err
	}
	if err := c.Audit.validate(); err != nil {
		return err
	}
	if err := c.SSO.validate(); err != nil {
		return err
	}
	if err := c.Metrics.validate(); err != nil {
		return err
	}
	// A budget counted over a non-positive window would reset on every charge and
	// so never refuse anything — the same silent-no-op trap the login throttle
	// window has, refused for the same reason.
	if c.SessionQueryBudget > 0 && c.SessionQueryWindow <= 0 {
		return fmt.Errorf("session_query_window must be positive when session_query_budget > 0 (a non-positive window resets the count on every statement, so the budget would never apply)")
	}
	if !c.Security.AllowAdHoc && len(c.Servers) == 0 {
		return fmt.Errorf("ad-hoc login is disabled but no predefined servers are configured; nobody could log in")
	}
	for _, cidr := range c.Security.TrustedProxyCIDRs {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			continue
		}
		if _, _, err := net.ParseCIDR(cidr); err != nil && net.ParseIP(cidr) == nil {
			return fmt.Errorf("security.trusted_proxy_cidrs: %q is not a CIDR or IP address", cidr)
		}
	}
	return nil
}

// validate checks the [storage] block. An unconfigured block is valid and means
// "no metadata database"; a PARTLY configured one is not, because it would be
// silently ignored — an operator who filled in a host and a password expects
// something to happen, and a config block that does nothing is worse than a
// refusal to start.
func (s StorageConfig) validate() error {
	if !s.Enabled() {
		// An ordered slice, not a map: with several fields set the reported
		// name must be deterministic — the first in block order — so the
		// message is stable and a test can hold every field to it.
		for _, f := range []struct {
			name string
			set  bool
		}{
			// max_sessions leads because it is declared first in the block; it
			// is presence-TRACKED rather than value-tested (see maxSessionsSet).
			{"max_sessions", s.maxSessionsSet},
			{"host", s.Host != ""},
			{"port", s.Port != 0},
			{"socket", s.Socket != ""},
			{"database", s.Database != ""},
			{"file", s.FilePath != ""},
			{"user", s.User != ""},
			{"password", s.Password != ""},
			{"sslmode", s.SSLMode != ""},
			{"params", len(s.Params) > 0},
			{"table_prefix", s.TablePrefix != ""},
		} {
			if f.set {
				return fmt.Errorf("storage.%s is set but storage.engine is empty, so the metadata database would be ignored; set storage.engine or remove the block", f.name)
			}
		}
		return nil
	}
	engine := strings.TrimSpace(s.Engine)
	d, ok := driver.Get(engine)
	if !ok {
		known := driver.RegisteredNames()
		if len(known) == 0 {
			return fmt.Errorf("storage.engine is %q but no database engines are registered (the binary was built without any driver)", engine)
		}
		return fmt.Errorf("storage.engine %q is not a known engine (want one of %s)", engine, strings.Join(known, ", "))
	}
	// The capability, not the name, decides. An engine that cannot host the
	// metadata store says so here rather than after a connection attempt.
	if _, ok := d.(driver.StorageHost); !ok {
		return fmt.Errorf("storage.engine %q cannot host TableX's metadata database", engine)
	}
	// [storage.params] reaches the same DSN builder as a predefined server's
	// params (server.go passes them straight into driver.Open), so the same
	// fidelity foot-guns must be refused here too — for both file and network
	// storage engines, before the network split below returns early.
	if v, ok := d.(driver.ParamsValidator); ok {
		if err := v.ValidateParams(s.Params); err != nil {
			return fmt.Errorf("storage.params: %w", err)
		}
	}
	if !d.Capabilities().IsNetworkEngine {
		file := strings.TrimSpace(s.FilePath)
		if file == "" {
			return fmt.Errorf("storage.file is required for a %s metadata database", engine)
		}
		if v, ok := d.(driver.FilePathValidator); ok {
			if err := v.ValidateFilePath(file); err != nil {
				return fmt.Errorf("storage.file: %w", err)
			}
		}
		return nil
	}
	// A network engine needs to be told which database to put the tables in.
	// Letting it default would mean creating TableX's tables in whatever the
	// engine considers home — "postgres" on PostgreSQL — which is not somewhere
	// an operator would choose.
	if strings.TrimSpace(s.Database) == "" {
		return fmt.Errorf("storage.database is required for a %s metadata database (name the database TableX's own tables should live in)", engine)
	}
	return nil
}

// validate checks the [audit] block. An empty one is valid and means "no audit
// trail". A block that tunes the trail without giving it anywhere to write is
// not: those settings would do nothing, and an operator who wrote them believes
// auditing is on. Getting that wrong is exactly the kind of mistake an audit
// requirement exists to prevent, so it refuses to start rather than warn.
func (a AuditConfig) validate() error {
	if a.Enabled() {
		if dir := filepath.Dir(strings.TrimSpace(a.File)); a.File != "" {
			if info, err := os.Stat(dir); err != nil || !info.IsDir() {
				return fmt.Errorf("audit.file %q: the directory %s does not exist (TableX creates the file, not the directory)", a.File, dir)
			}
		}
		return nil
	}
	// Ordered like the storage validator, so the reported field is
	// deterministic when several are set.
	for _, f := range []struct {
		name string
		set  bool
	}{
		{"max_bytes", a.MaxBytes != 0},
		{"statements", a.Statements},
	} {
		if f.set {
			return fmt.Errorf("audit.%s is set but the audit trail has no destination, so nothing would be recorded; set audit.file or audit.log", f.name)
		}
	}
	return nil
}

// validate checks the [metrics] block. Enabling the endpoint without a way to
// authorize a scrape is refused rather than warned about: /metrics describes
// TableX's internals, the mistake is silent (a scrape succeeds either way, so
// nothing tells the operator it succeeded for everybody), and there is no
// defensible default to fill in — "loopback only" would break a remote
// Prometheus, "anyone" would publish the internals.
//
// Settings on a DISABLED block are refused for the same reason a tuned audit
// block with no destination is: they would do nothing, and the operator who
// wrote a token believes the endpoint is up.
func (m MetricsConfig) validate() error {
	needToken, needNetwork := m.Authorizes()
	if !m.Enabled {
		// Ordered like the storage validator, so the reported field is
		// deterministic when both are set.
		for _, f := range []struct {
			name string
			set  bool
		}{
			{"token", needToken},
			{"allow_cidrs", needNetwork},
		} {
			if f.set {
				return fmt.Errorf("metrics.%s is set but metrics.enabled is false, so /metrics would not be served; set metrics.enabled = true or remove the block", f.name)
			}
		}
		return nil
	}
	if !needToken && !needNetwork {
		return fmt.Errorf("metrics.enabled is true but neither metrics.token nor metrics.allow_cidrs is set; /metrics exposes TableX's internal state and will not be served without a way to authorize a scrape")
	}
	for _, cidr := range m.AllowCIDRs {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			continue
		}
		if _, _, err := net.ParseCIDR(cidr); err != nil && net.ParseIP(cidr) == nil {
			return fmt.Errorf("metrics.allow_cidrs: %q is not a CIDR or IP address", cidr)
		}
	}
	return nil
}

// Warnings returns non-fatal configuration advisories the server logs at
// startup (distinct from Validate's fatal errors).
func (c Config) Warnings() []string {
	var w []string
	if c.Security.LoginRateMax > 0 && c.Security.LoginAccountMax <= 0 {
		w = append(w, "the global per-account lockout is disabled (login_account_max <= 0); every remaining throttle key starts with the client IP, so an attacker with many addresses gets login_rate_max attempts per address against one account")
	}
	if c.Security.LoginRateMax <= 0 {
		w = append(w, "login rate limiting is disabled (login_rate_max <= 0); brute-force attempts are not throttled")
	}
	if c.Security.TrustedProxy && len(c.Security.TrustedProxyCIDRs) == 0 {
		w = append(w, "trusted_proxy is set but trusted_proxy_cidrs is empty: X-Forwarded-For stays UNTRUSTED (a bare boolean would trust any client-supplied header) — list your proxy addresses in trusted_proxy_cidrs")
	}
	if c.Security.AllowAdHoc && !c.Security.BlockPrivate {
		w = append(w, "ad-hoc logins may target loopback/private hosts (block_private = false); on a cloud or shared deployment set security.block_private = true to keep TableX from being used as an SSRF proxy into the internal network")
	}
	w = append(w, sslModeWarnings(c.Servers)...)
	// The one restricted-mode combination that promises more than it delivers.
	// database_allowlist refuses ROUTES; the console takes SQL, and TableX does
	// not parse it to find out which databases it names.
	if len(c.Restrict.Databases) > 0 && c.Restrict.AllowConsole && !c.Restrict.ReadOnly {
		w = append(w, "restrict.database_allowlist is set but the SQL console is enabled: the allowlist restricts the UI's ROUTES, and a user can still name any database their credentials reach in a console statement. Set restrict.allow_console = false to make the allowlist a real confinement.")
	}
	if listenIsExposed(c.Listen) && !c.CookiesSecure() {
		w = append(w, fmt.Sprintf("TableX is listening on %q, which is reachable from outside this machine, and no TLS is configured (no tls_cert/tls_key, and secure_cookies is off, so no TLS-terminating proxy is declared): the session cookie and every database credential typed into the login form cross the network in cleartext", c.Listen))
	}
	if needToken, _ := c.Metrics.Authorizes(); needToken && !c.CookiesSecure() {
		w = append(w, "metrics.token is set but TableX is not serving TLS (and secure_cookies is off, so no TLS-terminating proxy is declared): the scrape token crosses the network in cleartext on every scrape")
	}
	if c.Storage.Enabled() {
		// The metadata database holds live session ids, so an unauthenticated
		// TLS mode there is worth the same warning a user's server gets.
		if msg, flagged := sslModeWarning("the metadata database", c.Storage.SSLMode); flagged {
			w = append(w, msg)
		}
		if d, ok := driver.Get(strings.TrimSpace(c.Storage.Engine)); ok && !d.Capabilities().IsNetworkEngine {
			w = append(w, fmt.Sprintf("the metadata database is file-backed (storage.engine = %q), so sessions survive a RESTART but cannot be shared between replicas; point storage at a networked engine to run more than one TableX behind a load balancer", c.Storage.Engine))
		}
	}
	return w
}

// sslModeAdvice maps an sslmode that does NOT authenticate the server to the
// reason it doesn't. Both tiers are libpq-parity behaviour, which is why they
// are advisories rather than errors — but neither delivers what its name
// suggests, and only a startup warning tells the operator that.
//
// "require" is the trap here: it reads as the strict option and does
// force TLS, but libpq's own `require` validates a CA only when sslrootcert is
// configured, and TableX wires no CA pool. An operator writing
// sslmode = "require" reasonably expects MITM protection and gets encryption
// without authentication.
var sslModeAdvice = map[string]string{
	"require":     "the connection is encrypted but the server is NOT authenticated (no CA chain, no hostname check), so it gives no protection against a man-in-the-middle",
	"skip-verify": "the connection is encrypted but certificate and hostname verification are explicitly skipped",
	"skip_verify": "the connection is encrypted but certificate and hostname verification are explicitly skipped",
	"prefer":      "TLS is attempted but silently falls back to an UNENCRYPTED connection if the server declines, and is unverified either way",
	"allow":       "TLS is attempted but silently falls back to an UNENCRYPTED connection if the server declines, and is unverified either way",
	"preferred":   "TLS is attempted but silently falls back to an UNENCRYPTED connection if the server declines, and is unverified either way",
}

// sslModeWarnings flags predefined servers whose TLS mode does not authenticate
// the server. An empty sslmode is not flagged: plaintext to a local database is
// the zero-config case, and warning on it would bury the modes that *look*
// secure and aren't.
func sslModeWarnings(servers []ServerConfig) []string {
	var w []string
	for _, s := range servers {
		if msg, flagged := sslModeWarning(fmt.Sprintf("server %q", s.Name), s.SSLMode); flagged {
			w = append(w, msg)
		}
	}
	return w
}

// sslModeWarning renders the advisory for one connection's TLS mode, if it has
// one. subject names the connection ("server \"prod\"", "the metadata
// database"), so the same wording serves a user's server and TableX's own.
func sslModeWarning(subject, sslMode string) (string, bool) {
	mode := strings.ToLower(strings.TrimSpace(sslMode))
	advice, flagged := sslModeAdvice[mode]
	if !flagged {
		return "", false
	}
	return fmt.Sprintf("%s uses sslmode = %q: %s. Use sslmode = \"verify-full\" for a real guarantee.",
		subject, mode, advice), true
}

// TLSEnabled reports whether direct TLS serving is configured.
func (c Config) TLSEnabled() bool { return c.TLSCert != "" && c.TLSKey != "" }

// CookiesSecure reports whether cookies must carry the Secure attribute (and the
// __Host- prefix) and HSTS be emitted. True when TableX serves TLS directly, or
// when the operator opts in for a TLS-terminating reverse proxy. See
// docs/security.md §7.
func (c Config) CookiesSecure() bool { return c.TLSEnabled() || c.Security.SecureCookies }

// CanonicalHost returns host trimmed of surrounding whitespace, with a
// bracketed IP literal ("[::1]", "[fe80::1%eth0]") normalized to bare form
// ("::1"). URL-style brackets are a spelling, not a distinct host: left
// intact they would defeat the string-compared allow/denylist matching (a
// configured "::1" must match a posted "[::1]" and vice versa) and lead
// net.JoinHostPort to double-bracket the DSN authority ("[[::1]]:5432").
// Anything that is not a valid bracketed IP literal is returned unchanged.
// Load applies this to the allow/denylists and predefined server hosts; the
// login handler applies it to the posted ad-hoc host; auth.CheckHost applies
// it to both sides of every match as a backstop.
func CanonicalHost(host string) string {
	host = strings.TrimSpace(host)
	if len(host) >= 2 && host[0] == '[' && host[len(host)-1] == ']' {
		if _, err := netip.ParseAddr(host[1 : len(host)-1]); err == nil {
			return host[1 : len(host)-1]
		}
	}
	return host
}

// ServerByName returns the predefined server with the given name.
func (c Config) ServerByName(name string) (ServerConfig, bool) {
	for _, s := range c.Servers {
		if s.Name == name {
			return s, true
		}
	}
	return ServerConfig{}, false
}
