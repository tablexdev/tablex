package server

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"runtime/debug"
	"strings"
	"sync/atomic"
	"time"

	"github.com/tablexdev/tablex/internal/audit"
	"github.com/tablexdev/tablex/internal/auth"
	"github.com/tablexdev/tablex/internal/server/handlers"
	"github.com/tablexdev/tablex/internal/session"
	"github.com/tablexdev/tablex/internal/view"
)

// statusRecorder captures the response status for the access log.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

// Write records an implicit 200 on the first body write (a handler that streams
// without calling WriteHeader), so headerWritten() is correct afterward and the
// recover guard does not emit a superfluous WriteHeader onto an already-committed
// (e.g. mid-stream export) response.
func (s *statusRecorder) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	return s.ResponseWriter.Write(b)
}

// Unwrap exposes the wrapped ResponseWriter so http.ResponseController can reach
// the underlying connection (e.g. to set per-request write deadlines on
// streaming exports).
func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }

// Flush forwards a flush to the writer beneath. Without it this recorder is a
// dead end for flushing: it sits between the gzip writer and the real
// ResponseWriter, and gzipResponseWriter.Flush type-asserts http.Flusher on
// what it wraps — an assertion that fails against a recorder with no Flush, so
// the compressed bytes would reach the recorder and stop there. Records an
// implicit 200 for the same reason Write does: a flush commits the response.
func (s *statusRecorder) Flush() {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// maxRequestBody bounds any AUTHENTICATED request body so a single request
// cannot exhaust memory or (via multipart temp files) disk. The largest
// legitimate body is an import, which fits within this; handlers may impose a
// tighter cap.
const maxRequestBody = 64 << 20 // 64 MiB

// maxPreAuthBody is the far tighter cap for UNAUTHENTICATED unsafe-method
// requests (chiefly /login): the csrf middleware parses the body for the token
// before the auth gate runs, so without this cap an unauthenticated POST could
// buffer up to maxRequestBody (RAM, plus disk for multipart) before rate
// limiting engages. No legitimate pre-auth POST approaches 1 MiB.
const maxPreAuthBody = 1 << 20 // 1 MiB

// chain composes the middleware in the order described in docs/architecture.md:
// recover → logging → gzip → security headers → session → limit body →
// import admission → CSRF → SSO gate → auth gate → restrict → router.
//
// gzip sits inside logging so the access line still records the real status, and
// outside everything that writes a body so every response — pages, fragments,
// static assets and streamed dumps alike — passes through one encoder.
func (s *Server) chain(router http.Handler) http.Handler {
	h := router
	// Restricted mode runs INSIDE the auth gate: an unauthenticated request is
	// still sent to the login page rather than told which routes exist.
	h = s.restrict(h)
	h = s.authGate(h)
	// Outside authGate, so it is consulted FIRST: an unverified person is sent to
	// the provider rather than to a login form they are not yet entitled to see.
	h = s.ssoGate(h)
	h = s.csrf(h)
	// Wrapping csrf, wrapped BY limitBody: the chain is built by successive
	// reassignment, so this runs after sessionMW and limitBody (it needs the
	// session in context) and BEFORE csrf parses the upload.
	h = s.importAdmission(h)
	h = s.limitBody(h)
	h = s.sessionMW(h)
	h = s.securityHeaders(h)
	h = s.gzip(h)
	h = s.logging(h)
	h = s.recover(h)
	return h
}

// limitBody caps the request body for unsafe methods so no request can submit an
// unbounded body. Reads past the cap fail with *http.MaxBytesError, which the
// body-parsing handlers surface as 413. It runs before csrf (which reads the
// form for the token) and before the handlers.
//
// The cap is route-aware: import routes get the tighter import cap applied here,
// before csrf parses the multipart body for the token. Without that, a no-JS
// import POST (token in the form field, not a header) would have its whole body
// parsed by csrf under the looser global cap, letting the handler's own
// MaxBytesReader no-op and defeating the import cap.
func (s *Server) limitBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Delete the multipart temp files this request spilled. net/http's own
		// cleanup is keyed on the exact *Request it handed the OUTERMOST
		// handler — a pointer the chain's WithContext copies (recover, logging,
		// sessionMW) disconnected before anything could parse — so without
		// this, every successful upload with a file part over the in-memory
		// threshold leaves the full upload on disk permanently. This is the
		// right seam: sessionMW just above makes the LAST request copy, and
		// everything below (importAdmission, csrf, the gates, Go 1.22 ServeMux,
		// the handlers) mutates THIS pointer in place —
		// TestNoRequestCopiesBelowLimitBody holds that invariant, because a
		// WithContext added below would silently re-open the leak.
		// Unconditional, not inside the !SafeMethod guard: it must also cover
		// the skipSession paths and any parse a handler performs.
		defer func() {
			if r.MultipartForm != nil {
				_ = r.MultipartForm.RemoveAll()
			}
		}()
		if !auth.SafeMethod(r.Method) && r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, bodyLimitFor(r.URL.Path, requestAuthed(r)))
		}
		next.ServeHTTP(w, r)
	})
}

// bodyLimitFor returns the request-body cap for a path. An UNAUTHENTICATED
// unsafe-method request gets the tight pre-auth cap (the csrf middleware parses
// its body before the auth gate runs). Authenticated requests get the import cap
// for import routes (mirroring handlers.MaxImportBytes so the two never drift)
// and the global cap otherwise. A non-import POST that happens to end in
// "/import" (e.g. a database literally named "import") merely gets the tighter
// cap, which is harmless.
func bodyLimitFor(path string, authed bool) int64 {
	if !authed {
		return maxPreAuthBody
	}
	if strings.HasSuffix(path, "/import") {
		return handlers.MaxImportBytes
	}
	return maxRequestBody
}

// importPostPatterns are the three POST routes that carry an upload. The GET
// forms take nothing, so they are not admitted against.
var importPostPatterns = map[string]bool{
	"POST /server/import":                true,
	"POST /db/{db}/import":               true,
	"POST /db/{db}/table/{table}/import": true,
}

// isImportPost reports whether this request will be routed to one of the import
// uploads, resolved through the POLICY mux rather than by inspecting the path.
//
// That is not fastidiousness: this middleware runs before routing, which is the
// exact position where r.URL.Path and net/http's routing disagree. A SEGMENT
// test over the decoded path is a straight bypass — POST /db/app%2Fbackup/import
// routes to POST /db/{db}/import with db == "app/backup", so a three-segment
// test sees four, misses, and the import proceeds unadmitted. A SUFFIX test
// survives that but is broader than the three routes: bodyLimitFor uses one and
// documents why it is harmless THERE (a stray /import POST merely gets the
// tighter cap), and that reasoning does not transfer to a semaphore — an
// authenticated slow POST to any unrouted …/import path would hold a slot and,
// at exhaustion, answer 503 where the router would have answered 404.
//
// Asking the policy mux is needFor's existing discipline, exact rather than
// heuristic, and it inherits net/http's own %2F behaviour instead of working
// around it.
func (s *Server) isImportPost(r *http.Request) bool {
	_, pat := s.policy.Handler(r)
	return importPostPatterns[pat]
}

// importAdmission bounds how many imports may be in flight at once.
//
// It must be a MIDDLEWARE, not a hoisted acquireDBOp. csrf sits ahead of the
// router and calls BoundedParseForm for any request without a header token, so
// for every no-JS import the multipart parse and its temp-file spill are already
// done before the handler is reached — hoisting the acquire inside the handler
// limits nothing that matters.
//
// Its own semaphore, never MaxConcurrentDBOps: holding a DATABASE slot across a
// slow upload is its own denial of service, on a resource the upload does not
// need yet. acquireDBOp still guards the execution phase.
//
// Gated on requestAuthed, and that is enforcement rather than description.
// Sitting outside csrf, this would otherwise answer an UNAUTHENTICATED import
// POST with 503 before csrf could issue its login redirect — changing
// protected-route behaviour and advertising that the route exists and is busy.
// The scope of the finding is one logged-in user firing concurrent uploads.
//
// Non-blocking: a blocking semaphore in middleware would queue exactly the slow
// uploads this exists to shed.
func (s *Server) importAdmission(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !requestAuthed(r) || !s.isImportPost(r) {
			next.ServeHTTP(w, r)
			return
		}
		release, ok := s.importLimit.TryAcquire()
		if !ok {
			// The warning belongs here, not in the renderer: acquireDBOp's version
			// hard-codes h.DBOps.InFlight(), which is a different instance.
			s.log.Warn("import concurrency cap reached",
				"path", r.URL.Path, "inflight", s.importLimit.InFlight(),
				"reqid", handlers.RequestID(r.Context()))
			s.handlers.RenderCapacityRefusal(w, r, http.StatusServiceUnavailable,
				"The server is running the maximum number of concurrent imports (max_concurrent_imports). Please retry in a moment.", 5)
			return
		}
		// Released on EVERY exit path, csrf's 403 included: csrf is downstream.
		defer release()
		next.ServeHTTP(w, r)
	})
}

// requestAuthed reports whether the request carries an authenticated session
// (an app payload is attached) — the same predicate authGate and csrf use to
// distinguish a live login from a pre-auth/expired one. skipSession paths carry
// no session and read as unauthenticated (a tight cap on their unsafe methods
// is harmless).
func requestAuthed(r *http.Request) bool {
	sess, ok := session.FromContext(r.Context())
	return ok && sess.App() != nil
}

// recover turns panics into 500s so a single bad handler never crashes the
// process. The stack is logged server-side, never sent to the client.
func (s *Server) recover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Generate the request id here (the outermost middleware) and thread it
		// down via the context, so a panic — even one before the logging
		// middleware runs — is logged with the same id the access line carries,
		// instead of an empty one.
		id := newRequestID()
		r = r.WithContext(handlers.WithRequestID(r.Context(), id))
		// Wrap once here and pass the recorder down so the inner logging middleware
		// reuses it and headerWritten() stays live.
		rec := asRecorder(w)
		defer func() {
			if p := recover(); p != nil {
				s.log.Error("panic recovered",
					"err", p, "path", r.URL.Path,
					"reqid", id,
					"stack", string(debug.Stack()))
				if !headerWritten(rec) {
					http.Error(rec, "Internal Server Error", http.StatusInternalServerError)
				}
			}
		}()
		next.ServeHTTP(rec, r)
	})
}

// asRecorder returns w as a *statusRecorder, wrapping it only if it is not one
// already, so the recover and logging middlewares share a single recorder.
func asRecorder(w http.ResponseWriter) *statusRecorder {
	if sr, ok := w.(*statusRecorder); ok {
		return sr
	}
	return &statusRecorder{ResponseWriter: w}
}

// headerWritten is best-effort; statusRecorder tracks it.
func headerWritten(w http.ResponseWriter) bool {
	if sr, ok := w.(*statusRecorder); ok {
		return sr.status != 0
	}
	return false
}

// logging emits a structured access line with a request id. Credentials and
// full DSNs are never logged.
func (s *Server) logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The request id is set by the outermost recover middleware; reuse it so the
		// access line and any panic log share one id. Fall back to a fresh id if
		// logging is ever used without recover ahead of it (e.g. a test).
		id := handlers.RequestID(r.Context())
		if id == "" {
			id = newRequestID()
			r = r.WithContext(handlers.WithRequestID(r.Context(), id))
		}
		r = r.WithContext(handlers.WithListingMemo(r.Context()))
		// The audit slot is installed HERE, in the outermost middleware that sees
		// the whole request, because this is the only layer that learns the final
		// status and the total duration — while the identity is not known until
		// the session has been loaded several layers deeper, and each layer hands
		// on a derived request whose context this one never sees. A pointer is
		// what both ends can share.
		remote := auth.ClientIP(r, s.proxy)
		var pending *audit.Pending
		if s.audit.Enabled() {
			pending = &audit.Pending{}
			// The address is resolved on the way IN so a statement observer deep
			// in the driver can name the client without every layer between having
			// to pass it down.
			pending.SetRemote(remote)
			r = r.WithContext(audit.NewContext(r.Context(), pending))
		}
		w.Header().Set("X-Request-Id", id)
		rec := asRecorder(w)
		// A scrape is excluded from the numbers it reports: counting it would put a
		// request every scrape interval into the rate and the latency histogram of
		// an instance that may otherwise be idle, so /metrics measures TableX and
		// not the act of measuring it. The access line below still records it.
		//
		// Only the scrape. /healthz is automated too, but it is not the measuring
		// instrument — it is traffic this server actually served, and excluding
		// everything machine-generated would leave requests_total meaning something
		// narrower than its name.
		measured := r.URL.Path != metricsPath
		if measured {
			s.metrics.enter()
			defer s.metrics.leave()
		}
		start := time.Now()
		// The post-processing runs DEFERRED with an explicit completed flag, so
		// a panicking handler still leaves an access line, a metrics sample and
		// an audit record — unwinding used to skip all three for exactly the
		// case the recover middleware exists for (a mutating POST that panicked
		// after issuing its ALTER left no trace, and the 5xx counter never
		// moved). The block must NEVER write rec.status: recover sits OUTSIDE
		// logging, so this defer unwinds first, and recover's own guard reads
		// rec.status (headerWritten) to decide whether it may still send
		// http.Error — a mutation here (including the old completed-and-wrote-
		// nothing 200 default, were it moved into the defer) would suppress
		// that 500 and hang the client behind a fabricated access line. A
		// local observedStatus substitutes instead: 500 for a RECOVERED
		// INCOMPLETE request, 200 for a completed handler that wrote nothing —
		// never a blanket re-stamp, so a panic AFTER a partial 200 write keeps
		// the 200 the client actually saw.
		completed := false
		defer func() {
			observedStatus := rec.status
			if observedStatus == 0 {
				if completed {
					observedStatus = http.StatusOK
				} else {
					observedStatus = http.StatusInternalServerError
				}
			}
			// One duration for all three consumers: the access line, the audit
			// event and the histogram previously disagreed by however long the
			// log call took.
			dur := time.Since(start)
			if measured {
				s.metrics.observe(r.Method, observedStatus, dur)
			}
			s.log.Info("request",
				"id", id,
				"method", r.Method,
				"path", r.URL.Path,
				"status", observedStatus,
				"dur", dur.String(),
				"remote", remote)
			s.auditAction(pending, r, id, remote, observedStatus, dur, completed)
		}()
		next.ServeHTTP(rec, r)
		completed = true
	})
}

// auditAction records a state-changing request.
//
// This is the whole action log, in one place, on purpose. Auditing each mutating
// handler would mean ~35 call sites that a new route silently fails to join; here
// every unsafe method is covered by construction, and a route added tomorrow is
// audited the day it is added.
//
// Safe methods are skipped: a GET changes nothing, and recording every page view
// would drown the events that matter in navigation. An authentication event is
// normally skipped too — the login handler emits its own, because it knows which
// account it authenticated and whether the attempt failed, neither of which a
// status code reveals. Normally: a login handler that PANICKED emitted nothing,
// so that one case is recorded here (as the auth event it is) rather than
// leaving the credential submission with no trace at all.
//
// Note what this deliberately does NOT carry: the posted form's `action` field,
// which is how TableX discriminates a drop from an add. It is not readable here —
// the body is parsed on a derived request, several copies down — and a field
// populated for the no-JS path only would be worse than none. The statement log
// answers "what exactly" with the SQL itself.
func (s *Server) auditAction(p *audit.Pending, r *http.Request, id, remote string, status int, dur time.Duration, completed bool) {
	if !s.audit.Enabled() || auth.SafeMethod(r.Method) {
		return
	}
	kind := audit.KindAction
	if r.URL.Path == "/login" {
		// The login handler emits its own richer auth event on every path it
		// COMPLETES — but a handler that panicked emitted nothing, and the
		// credential submission is the one request class the trail most needs
		// complete. completed is false only on a recovered panic (the logging
		// defer sets it immediately after ServeHTTP returns), so exactly that
		// case lands here, as the auth event it is.
		if completed {
			return
		}
		kind = audit.KindAuth
	}
	account, server, engine := p.Identity()
	outcome, detail := p.Outcome()
	if outcome == "" {
		outcome = audit.OutcomeForStatus(status)
	}
	s.audit.Emit(audit.Event{
		Kind:    kind,
		Outcome: outcome,
		Detail:  detail,
		Request: id,
		Account: account,
		Server:  server,
		Engine:  engine,
		Remote:  remote,
		Method:  r.Method,
		Path:    r.URL.Path,
		Target:  audit.Target(r),
		Status:  status,
		Millis:  dur.Milliseconds(),
	})
}

// securityHeaders applies the header policy from docs/security.md to every
// response. script-src is 'self' only (no unsafe-inline/eval) — achievable
// because we use CSP-safe front-end builds.
func (s *Server) securityHeaders(next http.Handler) http.Handler {
	csp := strings.Join([]string{
		"default-src 'self'",
		"script-src 'self'",
		"style-src 'self' 'unsafe-inline'",
		"img-src 'self' data:",
		"font-src 'self'",
		"connect-src 'self'",
		"object-src 'none'",
		"base-uri 'self'",
		"form-action 'self'",
		"frame-ancestors 'none'",
	}, "; ")
	tls := s.cfg.CookiesSecure()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		head := w.Header()
		head.Set("Content-Security-Policy", csp)
		head.Set("X-Content-Type-Options", "nosniff")
		head.Set("Referrer-Policy", "no-referrer")
		head.Set("Cross-Origin-Opener-Policy", "same-origin")
		head.Set("Cross-Origin-Resource-Policy", "same-origin")
		head.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), interest-cohort=()")
		head.Set("X-Frame-Options", "DENY")
		if tls {
			head.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		}
		if !isStaticPath(r.URL.Path) {
			head.Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

// sessionMW loads or creates the session for HTML requests and stashes it in the
// context. Static assets and the health check skip session handling so they
// don't set cookies.
func (s *Server) sessionMW(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if skipSession(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		// The SSO gate's own two routes answer 404 when no provider is
		// configured, and the gate runs downstream of this. Throttling here would
		// turn that into a 429 and advertise a feature the deployment does not
		// have, so admission (and session creation) is bypassed entirely — the
		// same two predicates ssoGate itself uses.
		if s.handlers.SSO == nil && isSSOPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		sess := s.sessions.Start(w, r)
		if sess == nil {
			// Under the session-creation throttle. The guard is HERE, immediately
			// after Start, because both statements below dereference sess — Start
			// never returned nil before this existed, which is why no guard did.
			s.refuseSessionCreate(w, r)
			return
		}
		// Fill the audit identity as soon as it is knowable. A pre-auth session
		// leaves it empty, which is the truthful record for an unauthenticated
		// request; the login handler overwrites it once it knows better.
		if s.audit.Enabled() {
			if uc, ok := sess.App().(*handlers.UserContext); ok && uc != nil {
				audit.FromContext(r.Context()).SetIdentity(auditAccount(uc), uc.ServerName, uc.Engine)
			}
		}
		next.ServeHTTP(w, r.WithContext(session.NewContext(r.Context(), sess)))
	})
}

// refuseSessionCreate answers a request the session-creation throttle declined.
//
// The audit contract has to be filled in by hand. OutcomeForStatus maps 401 and
// 403 to denied and sends everything else in the 4xx range — 429 included — to
// OutcomeInvalid, which would file a capacity refusal as a malformed request.
//
// It cannot render this itself: renderError is unexported and this is package
// server, so it goes through RenderCapacityRefusal. And this refusal happens
// BEFORE a session exists, which changes what that renderer must do — renderError
// opens with currentUser(r), and its htmx arm takes the not-logged-in branch,
// emitting HX-Redirect /login at HTTP 200. A redirect to the very page being
// throttled is a loop, and there is no in-page panel to swap into, so BOTH
// full-page and htmx callers get the real 429 with Retry-After.
func (s *Server) refuseSessionCreate(w http.ResponseWriter, r *http.Request) {
	// Ceil-with-floor-1, shared with every throttled responder: rounding told
	// a client behind a 1.4s window to retry at 1s, where prune (which frees
	// a slot only after the FULL window) refused it again.
	retry := auth.RetryAfterSeconds(s.cfg.Security.SessionCreateWindow)
	s.log.Warn("session creation throttled",
		"path", r.URL.Path, "remote", auth.ClientIP(r, s.proxy),
		"reqid", handlers.RequestID(r.Context()))

	// Endpoint-aware, or it mislabels page loads as login attempts.
	if r.URL.Path == "/login" {
		if r.Method == http.MethodPost {
			// auditAction returns early for /login because the login handler emits
			// its own event — but a 429 here means that handler never runs, so both
			// routes are closed and the event has to be emitted at the refusal
			// site. KindAuth is the kind audit.go describes as the only one
			// recorded for an unauthenticated request.
			s.emitThrottledAuth(r)
			// recordLoginRejected splits throttled from denied precisely so a
			// rising throttled count shows the limiter holding. Skipping it leaves
			// the one metric built to show that flat while it holds.
			s.handlers.Counters.RecordLoginThrottled()
		}
		// A GET of the login page is a page load, not a login attempt: 429, no
		// auth event.
	} else if isSSOPath(r.URL.Path) {
		// A configured provider: this really is a step of an authentication.
		s.emitThrottledAuth(r)
	}

	// No account is carried, and cannot be: admission runs upstream of csrf and
	// of any credential parsing, so Pending.Identity() is necessarily empty. Do
	// not "fix" that by moving admission downstream of the parse — that would
	// reintroduce exactly the work this sheds.
	s.handlers.RenderCapacityRefusal(w, r, http.StatusTooManyRequests,
		"Too many new sessions from your address (security.session_create_max). Please retry in a moment.", retry)
}

// emitThrottledAuth records a throttled authentication step. It emits DIRECTLY
// rather than through a handler because package server already owns the audit
// logger; only the login COUNTER needed a new exported accessor.
func (s *Server) emitThrottledAuth(r *http.Request) {
	if !s.audit.Enabled() {
		return
	}
	s.audit.Emit(audit.Event{
		Kind:    audit.KindAuth,
		Outcome: audit.OutcomeDenied,
		Request: handlers.RequestID(r.Context()),
		Remote:  auth.ClientIP(r, s.proxy),
		Method:  r.Method,
		Path:    r.URL.Path,
		Detail:  "refused: security.session_create_max reached",
	})
}

// auditAccount is the identity to record: the account the SERVER reports for the
// connection, not what was typed at the login form. On MySQL that is
// "user@host" as the server resolved it, which is the form a grant is written
// against — the truthful answer to "whose privileges did this run under". SQLite
// has no accounts and reports nothing, which is also truthful.
func auditAccount(uc *handlers.UserContext) string {
	if c := uc.ServerConn(); c != nil {
		return c.Info().User
	}
	return ""
}

// csrf rejects unsafe-method requests without a valid per-session token.
//
// Expired sessions need distinguishing from forgery: this middleware runs
// BEFORE the auth gate, so a POST from a tab whose session was reaped carries
// a token for a session that no longer exists — the request gets a fresh,
// payload-less session whose new token cannot match. Without the check below
// every expired-session POST would dead-end in a 403 instead of reaching the
// auth gate's redirect to login.
func (s *Server) csrf(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if auth.SafeMethod(r.Method) || skipSession(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		authed := requestAuthed(r)
		// Defense-in-depth beyond the pre-auth body cap: engage rate limiting and
		// the auth redirect BEFORE any body parse (auth.TokenFromRequest ->
		// PostFormValue), so an unauthenticated attacker cannot make us parse a
		// body at all. The coarse bare-IP reservation for /login is taken with the
		// SAME auth.ClientIP the Login handler uses (which then reserves only the
		// identity keys, so the IP is charged exactly once per attempt). On
		// rejection the generic throttle response is returned without parsing.
		if r.URL.Path == "/login" && !authed {
			if !s.rate.Reserve(auth.ClientIP(r, s.proxy)) {
				s.log.Warn("login throttled (coarse IP, pre-parse)", "reqid", handlers.RequestID(r.Context()))
				s.handlers.RenderLoginThrottled(w, r)
				return
			}
		}
		// Unauthenticated request to a protected route: the auth gate would
		// redirect it anyway, so redirect here before extracting a token (only a
		// no-JS form-token request actually saves a body parse by this). This
		// subsumes the former expired-session redirect — a payload-less session is
		// exactly the unauthenticated state. /login stays public and falls through
		// to the CSRF check below, so a CSRF-invalid or forged /login still 403s
		// (and still consumed the coarse IP budget above).
		if !authed && !isPublicPath(r.URL.Path) {
			s.log.Warn("csrf: unauthenticated protected route", "path", r.URL.Path, "reqid", handlers.RequestID(r.Context()))
			s.redirectToLogin(w, r)
			return
		}
		// No header token means the token (if any) rides the form body. Bound that
		// FIRST parse here (BoundedParseForm caches it with the small multipart
		// threshold) so a later PostFormValue does not parse under Go's 32 MiB
		// default; an oversized body then fails closed at the CSRF check (403). A
		// header-token request never parses the body.
		if r.Header.Get(auth.CSRFHeader) == "" {
			_ = handlers.BoundedParseForm(r)
		}
		sess, ok := session.FromContext(r.Context())
		if ok && auth.CheckCSRF(sess.Token(), auth.TokenFromRequest(r)) {
			next.ServeHTTP(w, r)
			return
		}
		s.log.Warn("csrf rejected", "path", r.URL.Path, "reqid", handlers.RequestID(r.Context()))
		// auditAction deliberately skips /login (the login handler emits its
		// own auth event, knowing the account and the reason) — but a
		// CSRF-rejected login never REACHES the handler, so without an
		// explicit event here a forged or replayed login form left no trace
		// at all. Only /login needs it: every other path's 403 flows through
		// auditAction as denied.
		if r.URL.Path == "/login" && s.audit.Enabled() {
			s.audit.Emit(audit.Event{
				Kind:    audit.KindAuth,
				Outcome: audit.OutcomeDenied,
				Detail:  "CSRF token missing or invalid",
				Request: handlers.RequestID(r.Context()),
				Remote:  auth.ClientIP(r, s.proxy),
				Method:  r.Method,
				Path:    r.URL.Path,
			})
		}
		http.Error(w, "Invalid or missing CSRF token.", http.StatusForbidden)
	})
}

// redirectToLogin sends an unauthenticated request to /login, matching the
// htmx/full-page split the auth gate uses: htmx gets HX-Redirect + 401, a
// full-page request gets a 303.
func (s *Server) redirectToLogin(w http.ResponseWriter, r *http.Request) {
	if view.IsHTMX(r) {
		w.Header().Set("HX-Redirect", "/login")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// ssoGate stands in front of EVERYTHING a person uses, including the login form.
// That placement is the whole feature: SSO here is an extra factor rather than a
// replacement for the credential login, so its job is to decide who may reach the
// form — not who may use a database.
//
// Deliberately exempt: the gate's own routes (or it could never be passed),
// /healthz, /favicon.ico and /static/ (a container probe, and the page's own
// assets, are not people), and /metrics (a machine endpoint with its own
// token/allowlist —
// putting a browser redirect in front of a scraper would break it while adding
// nothing). /logout is exempt too: someone with a session must always be able to
// end it, even if the provider has since stopped answering.
func (s *Server) ssoGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.handlers.SSO == nil {
			next.ServeHTTP(w, r) // no provider configured: nothing to gate
			return
		}
		if isSSOPath(r.URL.Path) || isStaticPath(r.URL.Path) ||
			r.URL.Path == "/healthz" || r.URL.Path == "/favicon.ico" ||
			r.URL.Path == metricsPath || r.URL.Path == "/logout" {
			next.ServeHTTP(w, r)
			return
		}
		sess, ok := session.FromContext(r.Context())
		if ok && sess.SSO().Verified() {
			next.ServeHTTP(w, r)
			return
		}
		// Not verified. An htmx request must be told to navigate rather than be
		// handed a redirect it would swap into the page.
		if view.IsHTMX(r) {
			w.Header().Set("HX-Redirect", handlers.SSOStartPath)
			w.WriteHeader(http.StatusOK)
			return
		}
		http.Redirect(w, r, handlers.SSOStartPath, http.StatusSeeOther)
	})
}

// authGate redirects unauthenticated users to the login page for protected
// routes. htmx requests get an HX-Redirect so the client navigates fully.
func (s *Server) authGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isPublicPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		sess, ok := session.FromContext(r.Context())
		if !ok || sess.App() == nil {
			s.redirectToLogin(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// --- path predicates -----------------------------------------------------------

func isStaticPath(p string) bool { return strings.HasPrefix(p, "/static/") }

// skipSession lists the paths that get no session and therefore no cookie. A
// scrape is a machine that will never carry one, and issuing a session per scrape
// would grow the store by one entry every interval forever.
func skipSession(p string) bool {
	return isStaticPath(p) || p == "/healthz" || p == "/favicon.ico" || p == metricsPath
}

// isPublicPath lists the paths that bypass the auth gate. /metrics is public in
// that sense only: it does not use a TableX login, and is instead gated by
// metricsAuthorized (token and/or address allowlist) in its own handler.
func isPublicPath(p string) bool {
	switch p {
	case "/login", "/logout", "/healthz", "/favicon.ico", metricsPath:
		return true
	}
	return isSSOPath(p) || isStaticPath(p)
}

// isSSOPath is the gate's own two routes. They have to be reachable BEFORE the
// gate is satisfied, or passing it would be impossible.
func isSSOPath(p string) bool {
	return p == handlers.SSOStartPath || p == handlers.SSOCallbackPath
}

var reqIDFallback atomic.Uint64

func newRequestID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand should never fail; if it does, use a monotonic counter so
		// concurrent requests still get distinct, correlatable ids in the log.
		return fmt.Sprintf("seq-%015x", reqIDFallback.Add(1))
	}
	return hex.EncodeToString(b)
}
