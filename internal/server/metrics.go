package server

import (
	"bytes"
	"context"
	"crypto/subtle"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/tablexdev/tablex/internal/auth"
	"github.com/tablexdev/tablex/internal/server/handlers"
)

// metricsPath is the endpoint, fixed rather than configurable: a movable path is
// security by obscurity, and the token and the address allowlist are the controls
// that actually hold.
const metricsPath = "/metrics"

// /metrics — the Prometheus text exposition format, written by hand.
//
// No client library. The format is a few lines of text per series, TableX has one
// histogram, and a metrics dependency would be the largest in the module and the
// only one that is not a database driver or a config parser. What a library buys —
// a registry, collectors, concurrent-safe gathering — is here a handful of atomics
// read once per scrape.
//
// The numbers come from the subsystems that own them rather than from a central
// registry every package has to import: the limiter knows its refusals, the audit
// logger knows what it dropped, the session store knows when it degraded. This
// file asks them at scrape time. Only what nothing else could see — the HTTP
// counters, and the restricted-mode refusals — is counted here.

// durationBuckets are the request-latency buckets, in seconds. Chosen for what
// TableX actually does: the fast end resolves a template render and a cached
// browse (single-digit milliseconds), the slow end has to reach an unindexed
// COUNT(*) or a large export without everything piling into +Inf.
var durationBuckets = [...]float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}

// Bounded label sets. Both dimensions are closed on purpose: a metric labelled by
// request path or by status code would grow a series per database and per table a
// user visits, and unbounded cardinality is how a monitored process ends up
// killing its own monitoring.
var (
	methodLabels = [...]string{"GET", "POST", "HEAD", "OPTIONS", "other"}
	statusLabels = [...]string{"1xx", "2xx", "3xx", "4xx", "5xx"}
)

// metrics is the set of numbers only the HTTP layer sees. It is allocated only
// when [metrics] is enabled, and every method tolerates a nil receiver, so a
// default deployment does not pay an atomic add per request for numbers nobody
// can read.
type metrics struct {
	inFlight atomic.Int64
	requests [len(methodLabels)][len(statusLabels)]atomic.Int64

	// The histogram, as three parts: per-bucket counts (cumulative only at render
	// time), the total, and the sum. The sum is kept in MICROSECONDS as an
	// integer and divided on the way out — a float64 accumulator would need a
	// compare-and-swap loop to stay atomic, to hold a value nothing needs at
	// sub-microsecond precision.
	durations [len(durationBuckets) + 1]atomic.Int64 // last is +Inf
	durCount  atomic.Int64
	durMicros atomic.Int64

	restrictedRefused atomic.Int64
}

// metricsPingTimeout bounds the metadata-database probe a scrape performs. Short:
// a scrape that hangs is worse than a scrape reporting the store as down, and
// "down" is what a store that cannot answer in two seconds means to a request.
const metricsPingTimeout = 2 * time.Second

// observe records one completed request.
func (m *metrics) observe(method string, status int, d time.Duration) {
	if m == nil {
		return
	}
	m.requests[methodIndex(method)][statusIndex(status)].Add(1)
	m.durCount.Add(1)
	m.durMicros.Add(d.Microseconds())
	m.durations[bucketIndex(d)].Add(1)
}

// enter and leave maintain the in-flight gauge.
func (m *metrics) enter() {
	if m != nil {
		m.inFlight.Add(1)
	}
}

func (m *metrics) leave() {
	if m != nil {
		m.inFlight.Add(-1)
	}
}

// refusedByPolicy counts one request turned away by restricted mode.
func (m *metrics) refusedByPolicy() {
	if m != nil {
		m.restrictedRefused.Add(1)
	}
}

func methodIndex(method string) int {
	for i, m := range methodLabels {
		if m == method {
			return i
		}
	}
	return len(methodLabels) - 1 // "other"
}

// statusIndex maps a status onto its class. Anything outside 100–599 — which a
// handler should never write — is filed as 5xx rather than dropped: a number that
// cannot happen is exactly the one worth being able to see.
func statusIndex(status int) int {
	switch i := status/100 - 1; {
	case i < 0:
		return len(statusLabels) - 1
	case i >= len(statusLabels):
		return len(statusLabels) - 1
	default:
		return i
	}
}

// bucketIndex returns the index of the first bucket d fits in, or the +Inf slot.
func bucketIndex(d time.Duration) int {
	secs := d.Seconds()
	for i, b := range durationBuckets {
		if secs <= b {
			return i
		}
	}
	return len(durationBuckets)
}

// --- exposition ----------------------------------------------------------------

// exposition builds the response body. It buffers rather than streaming so the
// whole scrape is written in one Write: a scraper that reads a half-finished
// exposition treats the missing series as absent, which on a counter looks like a
// process restart.
type exposition struct {
	b bytes.Buffer
}

// declare writes the HELP and TYPE lines for one metric family.
func (e *exposition) declare(name, typ, help string) {
	fmt.Fprintf(&e.b, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, typ)
}

// value writes one sample. labels is the pre-rendered label set without braces,
// or "" for none.
func (e *exposition) value(name, labels string, v int64) {
	if labels == "" {
		fmt.Fprintf(&e.b, "%s %d\n", name, v)
		return
	}
	fmt.Fprintf(&e.b, "%s{%s} %d\n", name, labels, v)
}

// gauge and counter are the single-sample shorthand.
func (e *exposition) gauge(name, help string, v int64) {
	e.declare(name, "gauge", help)
	e.value(name, "", v)
}

func (e *exposition) counter(name, help string, v int64) {
	e.declare(name, "counter", help)
	e.value(name, "", v)
}

// label renders one key="value" pair with the value escaped as the exposition
// format requires. Only build_info carries a value TableX did not choose itself
// (the version string comes from the build), but escaping every label is cheaper
// than remembering which one needs it.
func label(k, v string) string {
	var r strings.Builder
	r.WriteString(k)
	r.WriteString(`="`)
	for _, c := range v {
		switch c {
		case '\\':
			r.WriteString(`\\`)
		case '"':
			r.WriteString(`\"`)
		case '\n':
			r.WriteString(`\n`)
		default:
			r.WriteRune(c)
		}
	}
	r.WriteString(`"`)
	return r.String()
}

// writeHTTP renders the request counters and the latency histogram — the part of
// the exposition that depends on nothing but this struct, which is what makes the
// histogram's arithmetic testable without a running server.
//
// A nil receiver would panic here, deliberately: metrics is allocated exactly when
// the endpoint is enabled, and the handler 404s when it is not, so reaching this
// with nothing to report is a wiring bug worth failing loudly rather than a state
// to paper over.
func (m *metrics) writeHTTP(e *exposition) {
	e.declare("tablex_http_requests_total", "counter", "HTTP requests by method and status class.")
	for mi, method := range methodLabels {
		for si, status := range statusLabels {
			n := m.requests[mi][si].Load()
			if n == 0 {
				continue // an unused combination is not a data point
			}
			e.value("tablex_http_requests_total", label("method", method)+","+label("status", status), n)
		}
	}
	e.gauge("tablex_http_requests_in_flight", "HTTP requests currently being served.", m.inFlight.Load())

	e.declare("tablex_http_request_duration_seconds", "histogram", "HTTP request latency.")
	var cumulative int64
	for i, b := range durationBuckets {
		cumulative += m.durations[i].Load()
		e.value("tablex_http_request_duration_seconds_bucket",
			label("le", strconv.FormatFloat(b, 'g', -1, 64)), cumulative)
	}
	// The overflow slot completes the cumulative total. Anything slower than the
	// last bucket is counted ONLY here, so leaving it out would make +Inf disagree
	// with _count — and a scraper answers "how many requests" from +Inf.
	cumulative += m.durations[len(durationBuckets)].Load()
	e.value("tablex_http_request_duration_seconds_bucket", label("le", "+Inf"), cumulative)
	// The sum is the one non-integer sample, so it is formatted directly rather
	// than through value().
	fmt.Fprintf(&e.b, "tablex_http_request_duration_seconds_sum %s\n",
		strconv.FormatFloat(float64(m.durMicros.Load())/1e6, 'f', 6, 64))
	e.value("tablex_http_request_duration_seconds_count", "", m.durCount.Load())
}

// writeMetrics renders the whole exposition.
//
// Series for a subsystem that is not configured are OMITTED rather than reported
// as zero: an absent audit trail has not "written 0 events", and a dashboard
// showing a flat zero for a feature that is off is how an operator comes to
// believe it is on.
func (s *Server) writeMetrics(ctx context.Context, e *exposition) {
	e.declare("tablex_build_info", "gauge", "Build information; always 1.")
	e.value("tablex_build_info", label("version", s.handlers.Version), 1)

	s.metrics.writeHTTP(e)

	// Sessions. THIS PROCESS's sessions, even with a shared metadata database:
	// the store's Len is deliberately process-local, and summing this across
	// replicas is the intended way to get a cluster total.
	e.gauge("tablex_sessions_active", "Sessions held by this process.", int64(s.sessions.ActiveSessions()))

	c := s.handlers.Counters.Snapshot()
	e.declare("tablex_logins_total", "counter", "Login attempts by result.")
	e.value("tablex_logins_total", label("result", "ok"), c.LoginsOK)
	e.value("tablex_logins_total", label("result", "denied"), c.LoginsDenied)
	e.value("tablex_logins_total", label("result", "throttled"), c.LoginsThrottled)

	// Capacity. The refusal counters are the ones to alarm on: an in-flight gauge
	// sitting at its limit is a busy server, and only a rising refusal count says
	// work is being turned away.
	e.gauge("tablex_db_ops_in_flight", "Private database connections held right now (exports, console scripts, imports).", int64(s.handlers.DBOps.InFlight()))
	e.gauge("tablex_db_ops_limit", "Ceiling on concurrent private database connections (max_concurrent_db_ops); 0 means unlimited.", int64(s.handlers.DBOps.Limit()))
	e.counter("tablex_db_ops_refused_total", "Operations refused because that ceiling was reached.", s.handlers.DBOps.Refused())
	// Beside the shared limiter's three, not inside the storage block below: the
	// import limiter exists whether or not [storage] is configured. Without these
	// the new cap is invisible, and an in-flight gauge at its ceiling looks the
	// same whether work is being refused or the server is merely busy.
	e.gauge("tablex_import_ops_in_flight", "Import uploads in flight right now.", int64(s.importLimit.InFlight()))
	e.gauge("tablex_import_ops_limit", "Ceiling on concurrent import uploads (max_concurrent_imports); 0 means unlimited.", int64(s.importLimit.Limit()))
	e.counter("tablex_import_ops_refused_total", "Import uploads refused because that ceiling was reached.", s.importLimit.Refused())
	e.gauge("tablex_db_pools_open", "Cached per-database connection pools charged to the process budget.", int64(s.handlers.Pools.InUse()))
	e.gauge("tablex_db_pools_limit", "Ceiling on cached pools (pool_cap); 0 means unlimited.", int64(s.handlers.Pools.Limit()))
	e.counter("tablex_query_budget_refused_total", "Statements refused because a session had spent its query budget (session_query_budget).", c.QueryBudgetRefused)

	if s.cfg.Restrict.Restricted() {
		// One series, two counters: the middleware's own refusals plus the ones a
		// handler makes for itself (saveProgram, whose route cannot see which
		// action the form carries). Whoever watches this number should not have to
		// know which layer said no.
		e.counter("tablex_restricted_refused_total", "Requests refused by restricted mode (the [restrict] policy).",
			s.metrics.restrictedRefused.Load()+c.RestrictedRefused)
	}

	if s.audit.Enabled() {
		emitted, dropped := s.audit.Stats()
		e.counter("tablex_audit_events_total", "Audit events emitted.", emitted)
		e.counter("tablex_audit_write_failures_total", "Audit sink writes that FAILED; a non-zero rate means the trail is losing records.", dropped)
	}

	if s.storage != nil {
		up := int64(1)
		pingCtx, cancel := context.WithTimeout(ctx, metricsPingTimeout)
		if err := s.storage.Ping(pingCtx); err != nil {
			up = 0
		}
		cancel()
		e.gauge("tablex_storage_up", "Whether TableX's own metadata database answered a probe.", up)
		e.counter("tablex_storage_degraded_total",
			"Session-store operations that fell back to this process's own view; while this rises, sessions are not durable.",
			s.metaSessions.Degradations())
		// SIBLINGS of the counter above, never inputs to it. Both of these are a
		// configured POLICY turning work away; feeding them into degraded_total
		// would make the one alarm meaning "durability is broken" rise steadily
		// under a cap doing exactly its job.
		e.counter("tablex_storage_session_cap_refusals_total",
			"Sessions denied a durable row because storage.max_sessions was reached; they run process-local.",
			s.metaSessions.CapRefusals())
		e.counter("tablex_storage_session_marker_refusals_total",
			"Sessions denied a durable row because the session-generation map was full; they run process-local.",
			s.metaSessions.MarkerRefusals())
	}
}

// --- the endpoint ---------------------------------------------------------------

// metricsHandler serves /metrics.
//
// The route is registered unconditionally and answers 404 when the feature is
// off, so "disabled" and "this build has no such endpoint" are the same response
// and there is no second place where the enabled flag has to be honoured.
func (s *Server) metricsHandler(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.Metrics.Enabled {
		http.NotFound(w, r)
		return
	}
	if status, ok := s.metricsAuthorized(r); !ok {
		s.log.Warn("metrics scrape refused",
			"remote", auth.ClientIP(r, s.proxy), "status", status, "reqid", handlers.RequestID(r.Context()))
		if status == http.StatusUnauthorized {
			w.Header().Set("WWW-Authenticate", `Bearer realm="tablex metrics"`)
		}
		http.Error(w, "Not authorized to scrape metrics.", status)
		return
	}
	var e exposition
	s.writeMetrics(r.Context(), &e)
	// The 0.0.4 text format, named explicitly: Prometheus accepts a bare
	// text/plain, but other scrapers use the version to pick a parser.
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	_, _ = w.Write(e.b.Bytes())
}

// metricsAuthorized reports whether a scrape may proceed, and the status to
// answer with when it may not.
//
// Both configured checks must pass — an allowlisted network still presents the
// token. The statuses are distinguished (403 for the wrong network, 401 for a bad
// token) because the person on the other end is nearly always an operator
// debugging their own scrape config, and one opaque code for both failures makes
// that needlessly hard. Neither answer reveals anything a caller who can reach
// the port does not already know.
func (s *Server) metricsAuthorized(r *http.Request) (int, bool) {
	mc := s.cfg.Metrics
	needToken, needNetwork := mc.Authorizes()
	if needNetwork && !s.metricsNets.ContainsAddr(auth.ClientIP(r, s.proxy)) {
		return http.StatusForbidden, false
	}
	if needToken && !bearerMatches(r.Header.Get("Authorization"), mc.Token) {
		return http.StatusUnauthorized, false
	}
	return http.StatusOK, true
}

// bearerMatches reports whether an Authorization header carries the expected
// bearer token, compared in constant time.
//
// The header is the only accepted carrier. A token in the query string would be
// written verbatim into TableX's own access log — and usually the proxy's — on
// every scrape, which turns a credential into a logged one.
func bearerMatches(header, want string) bool {
	// Trimmed on BOTH sides, and for the same reason MetricsConfig.Authorizes
	// trims when deciding whether a token is required: a configured token with a
	// stray trailing space would otherwise be treated as set but be impossible to
	// present, since the header's token is trimmed on the way in.
	want = strings.TrimSpace(want)
	if want == "" {
		return false
	}
	scheme, token, found := strings.Cut(strings.TrimSpace(header), " ")
	if !found || !strings.EqualFold(scheme, "Bearer") {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(strings.TrimSpace(token)), []byte(want)) == 1
}
