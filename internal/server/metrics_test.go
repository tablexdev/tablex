package server_test

import (
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/tablexdev/tablex/internal/config"
)

const metricsToken = "scrape-me-please"

// metricsServer starts a server with /metrics on and a bearer token, plus any
// further config the caller needs.
func metricsServer(t *testing.T, mutate func(*config.Config)) (base string, client *http.Client, dbPath string) {
	t.Helper()
	ts, client, dbPath := newTestServerWith(t, func(c *config.Config) {
		c.Metrics = config.MetricsConfig{Enabled: true, Token: metricsToken}
		if mutate != nil {
			mutate(c)
		}
	})
	return ts.URL, client, dbPath
}

// scrape performs a scrape with the given bearer token ("" sends no header) and
// returns the status and body.
func scrape(t *testing.T, client *http.Client, base, token string) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, base+"/metrics", nil)
	if err != nil {
		t.Fatalf("build scrape request: %v", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read /metrics body: %v", err)
	}
	return resp, string(b)
}

// mustScrape scrapes with the valid token and fails unless it succeeded.
func mustScrape(t *testing.T, client *http.Client, base string) string {
	t.Helper()
	resp, body := scrape(t, client, base, metricsToken)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("scrape status = %d, want 200; body:\n%.400s", resp.StatusCode, body)
	}
	return body
}

// samples parses an exposition into series -> value, keyed by the whole sample
// name including its labels ("tablex_logins_total{result=\"ok\"}").
func samples(t *testing.T, body string) map[string]float64 {
	t.Helper()
	out := map[string]float64{}
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, value, found := strings.Cut(line, " ")
		if !found {
			t.Errorf("exposition line is not `name value`: %q", line)
			continue
		}
		v, err := strconv.ParseFloat(value, 64)
		if err != nil {
			t.Errorf("exposition line %q has an unparseable value: %v", line, err)
			continue
		}
		if _, dup := out[name]; dup {
			t.Errorf("series %s appears more than once", name)
		}
		out[name] = v
	}
	return out
}

// TestMetricsDisabledIs404: off by default, and the route answers as though it
// does not exist — so the enabled flag is honoured in exactly one place.
func TestMetricsDisabledIs404(t *testing.T) {
	ts, client, _ := newTestServer(t)
	if got := config.Default().Metrics.Enabled; got {
		t.Error("metrics is enabled by default; it exposes internal state and must be opt-in")
	}
	resp, body := scrape(t, client, ts.URL, metricsToken)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("disabled /metrics = %d, want 404; body:\n%.300s", resp.StatusCode, body)
	}
	if strings.Contains(body, "tablex_") {
		t.Error("a disabled /metrics served an exposition anyway")
	}
}

// TestMetricsRequiresTheToken: the whole point of the block is that scraping is
// authorized. A missing or wrong token gets nothing.
func TestMetricsRequiresTheToken(t *testing.T) {
	base, client, _ := metricsServer(t, nil)

	for _, c := range []struct{ name, token string }{
		{"no header", ""},
		{"the wrong token", "not-the-token"},
		{"a prefix of the token", metricsToken[:5]},
		{"the token plus padding", metricsToken + "x"},
	} {
		resp, body := scrape(t, client, base, c.token)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s: status = %d, want 401", c.name, resp.StatusCode)
		}
		if strings.Contains(body, "tablex_build_info") {
			t.Errorf("%s: served the exposition anyway", c.name)
		}
		if got := resp.Header.Get("WWW-Authenticate"); !strings.Contains(got, "Bearer") {
			t.Errorf("%s: WWW-Authenticate = %q, want a Bearer challenge", c.name, got)
		}
	}

	// A token in the query string is NOT accepted: it would be written into the
	// access log on every scrape, turning a credential into a logged one.
	for _, param := range []string{"token", "access_token", "authorization"} {
		u := base + "/metrics?" + param + "=" + url.QueryEscape(metricsToken)
		resp, err := client.Get(u)
		if err != nil {
			t.Fatalf("GET %s: %v", u, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("a token in ?%s= was accepted (status %d)", param, resp.StatusCode)
		}
	}

	body := mustScrape(t, client, base)
	if !strings.Contains(body, "tablex_build_info") {
		t.Errorf("an authorized scrape is missing build_info:\n%.400s", body)
	}
}

// TestMetricsBearerSchemeIsTolerantButStrict: the scheme is matched
// case-insensitively as RFC 7235 requires, and nothing else is accepted as one.
func TestMetricsBearerSchemeIsTolerantButStrict(t *testing.T) {
	base, client, _ := metricsServer(t, nil)
	for header, want := range map[string]int{
		"Bearer " + metricsToken: http.StatusOK,
		"bearer " + metricsToken: http.StatusOK,
		"BEARER " + metricsToken: http.StatusOK,
		"Basic " + metricsToken:  http.StatusUnauthorized,
		metricsToken:             http.StatusUnauthorized, // no scheme at all
		"Bearer":                 http.StatusUnauthorized,
		"Bearer ":                http.StatusUnauthorized,
	} {
		req, _ := http.NewRequest(http.MethodGet, base+"/metrics", nil)
		req.Header.Set("Authorization", header)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("GET /metrics: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != want {
			t.Errorf("Authorization %q -> %d, want %d", header, resp.StatusCode, want)
		}
	}
}

// TestMetricsAddressAllowlist: an address allowlist is the other control, and
// when both are configured BOTH must pass — an allowlisted network still presents
// the token.
func TestMetricsAddressAllowlist(t *testing.T) {
	// A network the test client is definitely not on.
	elsewhere, client, _ := newTestServerWith(t, func(c *config.Config) {
		c.Metrics = config.MetricsConfig{Enabled: true, AllowCIDRs: []string{"10.99.0.0/16"}}
	})
	resp, body := scrape(t, client, elsewhere.URL, "")
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("scrape from outside the allowlist = %d, want 403", resp.StatusCode)
	}
	if strings.Contains(body, "tablex_build_info") {
		t.Error("an off-allowlist scrape served the exposition")
	}

	// httptest listens on loopback, so the loopback ranges admit it. Both
	// families are listed because a machine may resolve either.
	near, nearClient, _ := newTestServerWith(t, func(c *config.Config) {
		c.Metrics = config.MetricsConfig{Enabled: true, AllowCIDRs: []string{"127.0.0.0/8", "::1"}}
	})
	if resp, body := scrape(t, nearClient, near.URL, ""); resp.StatusCode != http.StatusOK {
		t.Errorf("scrape from the allowlist = %d, want 200; body:\n%.300s", resp.StatusCode, body)
	}

	// Both controls: the right network is not enough without the token.
	both, bothClient, _ := newTestServerWith(t, func(c *config.Config) {
		c.Metrics = config.MetricsConfig{Enabled: true, Token: metricsToken, AllowCIDRs: []string{"127.0.0.0/8", "::1"}}
	})
	if resp, _ := scrape(t, bothClient, both.URL, ""); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("allowlisted scrape with no token = %d, want 401", resp.StatusCode)
	}
	if resp, _ := scrape(t, bothClient, both.URL, metricsToken); resp.StatusCode != http.StatusOK {
		t.Errorf("allowlisted scrape with the token = %d, want 200", resp.StatusCode)
	}
}

// TestMetricsSetsNoCookie: a scraper never carries a session, so issuing one per
// scrape would grow the session store by an entry every interval, forever.
func TestMetricsSetsNoCookie(t *testing.T) {
	base, _, _ := metricsServer(t, nil)
	jar, _ := cookiejar.New(nil)
	fresh := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	req, _ := http.NewRequest(http.MethodGet, base+"/metrics", nil)
	req.Header.Set("Authorization", "Bearer "+metricsToken)
	resp, err := fresh.Do(req)
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	resp.Body.Close()
	if got := resp.Header["Set-Cookie"]; len(got) > 0 {
		t.Errorf("/metrics issued a cookie: %v", got)
	}
	u, _ := url.Parse(base)
	if got := jar.Cookies(u); len(got) > 0 {
		t.Errorf("the scrape left %d cookie(s) in the jar", len(got))
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "text/plain") || !strings.Contains(ct, "version=0.0.4") {
		t.Errorf("Content-Type = %q, want the 0.0.4 text format named explicitly", ct)
	}
}

// TestMetricsCountsRequestsButNotItsOwnScrape: the HTTP counters have to measure
// TableX rather than the act of measuring it — a scrape every interval would
// otherwise dominate the request rate and the latency histogram of an idle
// instance.
func TestMetricsCountsRequestsButNotItsOwnScrape(t *testing.T) {
	base, client, _ := metricsServer(t, nil)

	const gets = 3
	for range gets {
		if code, _ := getBody(t, client, base+"/healthz"); code != http.StatusOK {
			t.Fatalf("/healthz = %d", code)
		}
	}
	first := samples(t, mustScrape(t, client, base))
	const series = `tablex_http_requests_total{method="GET",status="2xx"}`
	if got := first[series]; got < gets {
		t.Fatalf("%s = %v after %d requests, want at least %d", series, got, gets, gets)
	}

	// Two further scrapes, and nothing else. The GET counter must not move.
	mustScrape(t, client, base)
	second := samples(t, mustScrape(t, client, base))
	if first[series] != second[series] {
		t.Errorf("%s moved from %v to %v across two scrapes; /metrics is counting itself",
			series, first[series], second[series])
	}
	if got := second["tablex_http_request_duration_seconds_count"]; got != first["tablex_http_request_duration_seconds_count"] {
		t.Errorf("the latency histogram observed the scrapes: %v then %v",
			first["tablex_http_request_duration_seconds_count"], got)
	}
	// In-flight is a gauge, and during its own scrape nothing else is running.
	if got := second["tablex_http_requests_in_flight"]; got != 0 {
		t.Errorf("in-flight during an unmeasured scrape = %v, want 0", got)
	}
}

// TestMetricsHistogramIsWellFormed: cumulative buckets, +Inf equal to the count,
// and a sum in seconds. A malformed histogram is silently discarded by a scraper.
func TestMetricsHistogramIsWellFormed(t *testing.T) {
	base, client, _ := metricsServer(t, nil)
	login(t, client, base)
	for _, u := range []string{"/", "/db/main", "/db/main/table/widgets", "/server/status"} {
		if code, _ := getBody(t, client, base+u); code != http.StatusOK {
			t.Fatalf("GET %s = %d", u, code)
		}
	}

	body := mustScrape(t, client, base)
	s := samples(t, body)

	// Buckets must be non-decreasing in le order, which is what "cumulative"
	// means and the one property a hand-written histogram gets wrong.
	var last float64
	var seen int
	for _, line := range strings.Split(body, "\n") {
		if !strings.HasPrefix(line, "tablex_http_request_duration_seconds_bucket") {
			continue
		}
		_, value, _ := strings.Cut(line, " ")
		v, err := strconv.ParseFloat(value, 64)
		if err != nil {
			t.Fatalf("bucket line %q: %v", line, err)
		}
		if v < last {
			t.Errorf("buckets are not cumulative: %v after %v (line %q)", v, last, line)
		}
		last, seen = v, seen+1
	}
	if seen < 2 {
		t.Fatalf("found %d bucket samples, want the whole ladder", seen)
	}

	count := s["tablex_http_request_duration_seconds_count"]
	if count < 4 {
		t.Errorf("histogram count = %v, want at least the 4 page requests", count)
	}
	if inf := s[`tablex_http_request_duration_seconds_bucket{le="+Inf"}`]; inf != count {
		t.Errorf("+Inf bucket = %v but count = %v; every observation must land in +Inf", inf, count)
	}
	if !strings.Contains(body, "tablex_http_request_duration_seconds_sum ") {
		t.Error("no _sum sample")
	}
	if sum := s["tablex_http_request_duration_seconds_sum"]; sum <= 0 || sum > 600 {
		t.Errorf("_sum = %v, which is not a plausible number of SECONDS for a handful of requests", sum)
	}

	// Every family carries HELP and TYPE, without which a scraper keeps the
	// series but a dashboard has nothing to explain it.
	for _, family := range []string{
		"tablex_build_info", "tablex_http_requests_total", "tablex_http_requests_in_flight",
		"tablex_http_request_duration_seconds", "tablex_sessions_active", "tablex_logins_total",
		"tablex_db_ops_in_flight", "tablex_db_ops_limit", "tablex_db_ops_refused_total",
		"tablex_db_pools_open", "tablex_db_pools_limit", "tablex_query_budget_refused_total",
	} {
		if !strings.Contains(body, "# HELP "+family+" ") {
			t.Errorf("%s has no HELP line", family)
		}
		if !strings.Contains(body, "# TYPE "+family+" ") {
			t.Errorf("%s has no TYPE line", family)
		}
	}
}

// TestMetricsReportsSessionsAndLogins: the numbers an operator actually watches —
// how many sessions this process holds, and whether logins are being rejected.
func TestMetricsReportsSessionsAndLogins(t *testing.T) {
	base, client, _ := metricsServer(t, nil)

	// A rejected login: an unknown predefined server.
	csrf := csrfFrom(t, client, base+"/login")
	resp, err := client.PostForm(base+"/login", url.Values{"csrf_token": {csrf}, "server": {"no-such-server"}})
	if err != nil {
		t.Fatalf("POST /login: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("rejected login status = %d, want 401", resp.StatusCode)
	}

	s := samples(t, mustScrape(t, client, base))
	if got := s[`tablex_logins_total{result="denied"}`]; got != 1 {
		t.Errorf(`logins_total{result="denied"} = %v, want 1`, got)
	}
	if got := s[`tablex_logins_total{result="ok"}`]; got != 0 {
		t.Errorf(`logins_total{result="ok"} = %v before any successful login`, got)
	}

	login(t, client, base)
	s = samples(t, mustScrape(t, client, base))
	if got := s[`tablex_logins_total{result="ok"}`]; got != 1 {
		t.Errorf(`logins_total{result="ok"} = %v after logging in, want 1`, got)
	}
	if got := s[`tablex_logins_total{result="denied"}`]; got != 1 {
		t.Errorf("a successful login changed the denied count to %v", got)
	}
	if got := s["tablex_sessions_active"]; got < 1 {
		t.Errorf("sessions_active = %v with a session logged in", got)
	}
	// Throttling is reported separately from a rejected credential: they are
	// different events, and an operator alarms on them differently.
	if got := s[`tablex_logins_total{result="throttled"}`]; got != 0 {
		t.Errorf(`logins_total{result="throttled"} = %v with a generous rate limit`, got)
	}
}

// TestMetricsReportsCapacity: the limits come from the config, so a dashboard can
// draw "in flight against the ceiling" without the ceiling being hard-coded there.
func TestMetricsReportsCapacity(t *testing.T) {
	base, client, _ := metricsServer(t, func(c *config.Config) {
		c.MaxConcurrentDBOps = 7
		c.PoolCap = 11
	})
	s := samples(t, mustScrape(t, client, base))
	if got := s["tablex_db_ops_limit"]; got != 7 {
		t.Errorf("db_ops_limit = %v, want the configured 7", got)
	}
	if got := s["tablex_db_pools_limit"]; got != 11 {
		t.Errorf("db_pools_limit = %v, want the configured 11", got)
	}
	if got := s["tablex_db_ops_refused_total"]; got != 0 {
		t.Errorf("db_ops_refused_total = %v on a quiet server", got)
	}

	// An unlimited configuration reports 0, which is how the exposition says
	// "no ceiling" without inventing one.
	openBase, openClient, _ := metricsServer(t, func(c *config.Config) {
		c.MaxConcurrentDBOps = 0
		c.PoolCap = 0
	})
	open := samples(t, mustScrape(t, openClient, openBase))
	if got := open["tablex_db_ops_limit"]; got != 0 {
		t.Errorf("unlimited db_ops_limit = %v, want 0", got)
	}
	if got := open["tablex_db_pools_limit"]; got != 0 {
		t.Errorf("unlimited db_pools_limit = %v, want 0", got)
	}
}

// TestMetricsOmitsUnconfiguredSubsystems: a series for a feature that is off would
// read as a flat zero on a dashboard, which is how an operator comes to believe a
// trail is being written when none is.
func TestMetricsOmitsUnconfiguredSubsystems(t *testing.T) {
	base, client, _ := metricsServer(t, nil)
	body := mustScrape(t, client, base)
	for _, absent := range []string{
		"tablex_audit_events_total", "tablex_audit_write_failures_total",
		"tablex_storage_up", "tablex_storage_degraded_total",
		"tablex_restricted_refused_total",
	} {
		if strings.Contains(body, absent) {
			t.Errorf("%s is exposed although the subsystem is not configured", absent)
		}
	}

	// With each subsystem on, its series appear.
	auditFile := filepath.Join(t.TempDir(), "audit.jsonl")
	metaFile := filepath.Join(t.TempDir(), "tablex_meta.db")
	onBase, onClient, _ := metricsServer(t, func(c *config.Config) {
		c.Audit = config.AuditConfig{File: auditFile}
		c.Storage = config.StorageConfig{Engine: "sqlite", FilePath: metaFile}
		c.Restrict.AllowDDL = false
	})
	login(t, onClient, onBase)
	s := samples(t, mustScrape(t, onClient, onBase))
	if got, ok := s["tablex_audit_events_total"]; !ok || got < 1 {
		t.Errorf("audit_events_total = %v (present %v), want at least the login event", got, ok)
	}
	if _, ok := s["tablex_audit_write_failures_total"]; !ok {
		t.Error("audit_write_failures_total is missing; an operator must be able to alarm on a trail losing records")
	}
	if got, ok := s["tablex_storage_up"]; !ok || got != 1 {
		t.Errorf("storage_up = %v (present %v), want 1 for a reachable metadata database", got, ok)
	}
	if got, ok := s["tablex_storage_degraded_total"]; !ok || got != 0 {
		t.Errorf("storage_degraded_total = %v (present %v), want 0 on a healthy store", got, ok)
	}
	if _, ok := s["tablex_restricted_refused_total"]; !ok {
		t.Error("restricted_refused_total is missing although a restriction is configured")
	}
}

// TestMetricsCountsRestrictedRefusals: restricted mode's refusals are only
// otherwise visible in the log, and a rising count is how an operator learns their
// policy is narrower than the work people are trying to do.
func TestMetricsCountsRestrictedRefusals(t *testing.T) {
	base, client, _ := metricsServer(t, func(c *config.Config) { c.Restrict.AllowDDL = false })
	login(t, client, base)
	csrf := csrfFrom(t, client, base+"/")

	if before := samples(t, mustScrape(t, client, base))["tablex_restricted_refused_total"]; before != 0 {
		t.Fatalf("restricted_refused_total = %v before any refusal", before)
	}
	code, _ := postTo(t, client, base+"/db/main/table/widgets/structure",
		url.Values{"csrf_token": {csrf}, "action": {"drop_column"}, "column": {"qty"}})
	if code != http.StatusForbidden {
		t.Fatalf("a DDL POST under allow_ddl=false = %d, want 403", code)
	}
	if got := samples(t, mustScrape(t, client, base))["tablex_restricted_refused_total"]; got != 1 {
		t.Errorf("restricted_refused_total = %v after one refusal, want 1", got)
	}
}

// TestMetricsBuildInfoCarriesTheVersion: the label is the only one whose value
// TableX does not choose itself, so it is also the only one that has to survive
// escaping.
func TestMetricsBuildInfoCarriesTheVersion(t *testing.T) {
	base, client, _ := metricsServer(t, nil)
	body := mustScrape(t, client, base)
	// newTestServerWith builds the server with version "test".
	if !strings.Contains(body, `tablex_build_info{version="test"} 1`) {
		t.Errorf("build_info does not carry the version:\n%.400s", body)
	}
}

// TestMetricsReportsImportCapacity: without these the new cap is invisible, and
// an in-flight gauge sitting at its ceiling looks identical whether work is
// being refused or the server is merely busy — the argument the limiter's own
// comment makes. They sit beside the shared limiter's three rather than inside
// the storage block, because the import limiter exists whether or not [storage]
// is configured.
func TestMetricsReportsImportCapacity(t *testing.T) {
	base, client, _ := metricsServer(t, func(c *config.Config) {
		c.MaxConcurrentImports = 3
	})
	s := samples(t, mustScrape(t, client, base))
	if got := s["tablex_import_ops_limit"]; got != 3 {
		t.Errorf("import_ops_limit = %v, want the configured 3", got)
	}
	// PRESENCE first, value second: samples is a map, so a missing series
	// reads back as 0 and a value-only assertion would stay green with the
	// metric deleted outright.
	if _, ok := s["tablex_import_ops_in_flight"]; !ok {
		t.Error("tablex_import_ops_in_flight is not exposed at all")
	}
	if got := s["tablex_import_ops_in_flight"]; got != 0 {
		t.Errorf("import_ops_in_flight = %v on a quiet server", got)
	}
	if _, ok := s["tablex_import_ops_refused_total"]; !ok {
		t.Error("tablex_import_ops_refused_total is not exposed at all")
	}
	if got := s["tablex_import_ops_refused_total"]; got != 0 {
		t.Errorf("import_ops_refused_total = %v on a quiet server", got)
	}

	// 0 means "no ceiling", the same convention as tablex_db_ops_limit — not an
	// omitted series, which is the convention for a subsystem that is OFF.
	openBase, openClient, _ := metricsServer(t, func(c *config.Config) {
		c.MaxConcurrentImports = 0
	})
	open := samples(t, mustScrape(t, openClient, openBase))
	if _, ok := open["tablex_import_ops_limit"]; !ok {
		t.Error("tablex_import_ops_limit is omitted when unlimited; it must report 0")
	}
	if got := open["tablex_import_ops_limit"]; got != 0 {
		t.Errorf("unlimited import_ops_limit = %v, want 0", got)
	}
}

// TestMetricsReportsSessionCapRefusals: the two session-store capacity counters
// are SIBLINGS of tablex_storage_degraded_total, never inputs to it. That metric
// is published as "sessions are not durable"; a configured cap doing its job
// must not make the one alarm meaning "durability is broken" rise steadily.
func TestMetricsReportsSessionCapRefusals(t *testing.T) {
	base, client, _ := metricsServer(t, func(c *config.Config) {
		c.Storage = config.StorageConfig{
			Engine:      "sqlite",
			FilePath:    filepath.Join(t.TempDir(), "meta.db"),
			MaxSessions: 20000,
		}
	})
	s := samples(t, mustScrape(t, client, base))
	for _, name := range []string{
		"tablex_storage_session_cap_refusals_total",
		"tablex_storage_session_marker_refusals_total",
	} {
		if _, ok := s[name]; !ok {
			t.Errorf("%s is not exposed with [storage] configured", name)
		}
		if got := s[name]; got != 0 {
			t.Errorf("%s = %v on a quiet server", name, got)
		}
	}
	// And the degradation counter is still its own number.
	if got := s["tablex_storage_degraded_total"]; got != 0 {
		t.Errorf("tablex_storage_degraded_total = %v on a quiet server", got)
	}
}
