// Package handlers implements TableX's HTTP handlers — one file per feature
// area (auth, home, server, database, table, sql, navigation). Handlers resolve
// the active Connection from the session's UserContext, call the engine-neutral
// driver API, build a view model and render via internal/view. They never import
// a concrete database driver or concatenate user input into SQL.
package handlers

import (
	"context"
	"errors"
	"html/template"
	"log/slog"
	"mime"
	"net/http"
	"strconv"
	"strings"

	"github.com/tablexdev/tablex/internal/audit"
	"github.com/tablexdev/tablex/internal/auth"
	"github.com/tablexdev/tablex/internal/config"
	"github.com/tablexdev/tablex/internal/driver"
	"github.com/tablexdev/tablex/internal/session"
	"github.com/tablexdev/tablex/internal/view"
)

// Handlers carries the shared dependencies for every handler.
type Handlers struct {
	View     *view.Renderer
	Sessions *session.Manager
	Cfg      config.Config
	Rate     RateLimiter
	Log      *slog.Logger
	Version  string
	Pools    *PoolBudget      // process-wide per-database pool budget (nil = unlimited)
	DBOps    *DBOpLimiter     // in-flight cap on private-connection ops (nil = unlimited)
	Proxy    *auth.ProxyTrust // trusted-proxy set for client-IP resolution (nil = XFF untrusted)
	Audit    *audit.Logger    // audit trail (nil = not configured; every method is nil-safe)
	Counters *Counters        // /metrics counters the handlers own (nil = not counted; nil-safe)

	// SSO is the discovered OIDC provider, or nil when no gate is configured.
	// Nil is the ONLY signal the handlers use: the gate routes 404 and the
	// middleware lets everything through, so a deployment without [sso] behaves
	// exactly as it did before the feature existed.
	SSO *auth.OIDCProvider

	// AccountRate throttles failed logins per ACCOUNT NAME, across all source
	// addresses. Separate from Rate because it needs its own, higher threshold:
	// its key is shared by everyone typing that name, so reusing the per-IP cap
	// would let one person's typo lock out a whole team. Nil = disabled.
	AccountRate *auth.RateLimiter
}

// tuning translates the operator's pool/timeout config into the driver's
// per-connection Tuning. Stamped onto the session's base params at login, so
// every derived dial inherits it.
func (h *Handlers) tuning() driver.Tuning {
	return driver.Tuning{
		MaxOpenConns:    h.Cfg.PoolMaxConns,
		MaxIdleConns:    h.Cfg.PoolIdleConns,
		ReadStmtTimeout: h.Cfg.ReadStmtTimeout,
	}
}

// acquireDBOp reserves an in-flight slot for an operation that opens a PRIVATE
// database connection (export, console script, import). When it reports false a
// 503 was already written and the caller must return. The returned release func
// is idempotent; `defer release()` is the intended use.
func (h *Handlers) acquireDBOp(w http.ResponseWriter, r *http.Request) (release func(), ok bool) {
	release, ok = h.DBOps.TryAcquire()
	if ok {
		return release, true
	}
	h.Log.Warn("database-operation concurrency cap reached",
		"path", r.URL.Path, "inflight", h.DBOps.InFlight(), "reqid", RequestID(r.Context()))
	// A capacity refusal is the server declining to do the work, not the work
	// failing. Left to the status code the audit trail would file this 503 as an
	// error, which sends whoever reads it looking for a fault that isn't there;
	// "denied" is the class the throttle and the policy refusals already use.
	audit.FromContext(r.Context()).SetOutcome(audit.OutcomeDenied,
		"refused: max_concurrent_db_ops reached")
	// Retry-After is advisory; a few seconds matches how long a typical export
	// or script holds its connection. Set before renderError, which writes the
	// status (and, for an htmx caller, reports it in-panel at wire 200).
	w.Header().Set("Retry-After", "5")
	h.renderError(w, r, http.StatusServiceUnavailable,
		"The server is running the maximum number of concurrent exports, imports and SQL scripts (max_concurrent_db_ops). Please retry in a moment.", "")
	return nil, false
}

// allowance translates the [restrict] policy into the shape the templates read.
//
// It is derived here, in one place, from the same config the middleware enforces,
// so the two cannot disagree about what is permitted — a second hand-maintained
// copy of the policy in the view layer is exactly how a UI comes to offer a
// button that 403s, or to hide one that would have worked.
//
// read_only clears all three: it refuses every state-changing request, the SQL
// console and import included (TableX will not classify somebody's SQL to decide
// whether it writes), and schema changes are state changes too.
func (h *Handlers) allowance() view.Allowance {
	rc := h.Cfg.Restrict
	if rc.ReadOnly {
		return view.Allowance{}
	}
	return view.Allowance{Write: true, Console: rc.AllowConsole, DDL: rc.AllowDDL}
}

// RateLimiter is the subset of auth.RateLimiter the handlers use (kept as an
// interface-like alias so tests can substitute a no-op).
type RateLimiter interface {
	// Reserve atomically checks and consumes one attempt against every key —
	// a single critical section, so a concurrent burst cannot pass a separate
	// Allowed check before any Record lands.
	Reserve(keys ...string) bool
	Reset(key string)
}

// --- session / user helpers ----------------------------------------------------

func (h *Handlers) currentSession(r *http.Request) *session.Session {
	s, _ := session.FromContext(r.Context())
	return s
}

func (h *Handlers) currentUser(r *http.Request) (*UserContext, *session.Session, bool) {
	s := h.currentSession(r)
	uc, ok := userFromSession(s)
	return uc, s, ok
}

// requireUser returns the logged-in UserContext. If there is no session it
// redirects to the login page and returns ok=false — the caller must return.
func (h *Handlers) requireUser(w http.ResponseWriter, r *http.Request) (*UserContext, bool) {
	uc, _, ok := h.currentUser(r)
	if !ok {
		http.Redirect(w, r, urlLogin(), http.StatusSeeOther)
		return nil, false
	}
	return uc, true
}

// requireConn is the shared db/table handler preamble: the logged-in user, the
// request scope (schema-defaulted) and the connection for its database. When
// ok is false a response (login redirect or error page) was already written
// and the caller must return.
func (h *Handlers) requireConn(w http.ResponseWriter, r *http.Request) (uc *UserContext, sc reqScope, conn *driver.Connection, ok bool) {
	uc, ok = h.requireUser(w, r)
	if !ok {
		return nil, reqScope{}, nil, false
	}
	sc = h.resolveScope(r).withSchemaDefault(uc.Capabilities())
	conn, err := uc.ConnFor(r.Context(), sc.DB)
	if err != nil {
		h.connError(w, r, uc, err)
		return nil, reqScope{}, nil, false
	}
	return uc, sc, conn, true
}

// --- scope resolution ----------------------------------------------------------

// reqScope captures the database/schema/table the request addresses.
type reqScope struct {
	DB     string
	Schema string
	Table  string
}

func (sc reqScope) tableRef() driver.TableRef {
	return driver.TableRef{Database: sc.DB, Schema: sc.Schema, Table: sc.Table}
}

func (sc reqScope) scope() driver.Scope {
	return driver.Scope{Database: sc.DB, Schema: sc.Schema}
}

// resolveScope reads db (path), table (path) and schema (query), unescaping the
// schema query value. It does not invent a default schema — callers that need a
// concrete schema use withSchemaDefault so the database page can still show
// PostgreSQL's schema list when none is selected.
func (h *Handlers) resolveScope(r *http.Request) reqScope {
	return reqScope{
		DB:     r.PathValue("db"),
		Table:  r.PathValue("table"),
		Schema: r.URL.Query().Get("schema"),
	}
}

// withSchemaDefault returns a copy of sc with the schema defaulted to "public"
// for schema-having engines when none was supplied (used by table-level ops).
func (sc reqScope) withSchemaDefault(caps driver.Capabilities) reqScope {
	if caps.HasSchemas && sc.Schema == "" {
		sc.Schema = "public"
	}
	return sc
}

// --- rendering -----------------------------------------------------------------

// newLoggedPage seeds a Page with the logged-in chrome: server identity,
// capabilities, CSRF token, theme and (for full-page loads) the navigation tree.
func (h *Handlers) newLoggedPage(r *http.Request, uc *UserContext, title string) *view.Page {
	p := view.NewPage(title)
	if t := themeFromRequest(r); t != "" {
		p.Theme = t
	}
	p.NavWidthStyle = navWidthStyle(r)
	p.LoggedIn = true
	p.ServerName = uc.ServerName
	p.Info = uc.ServerConn().Info()
	p.Caps = uc.Capabilities()
	p.Allow = h.allowance()
	if s := h.currentSession(r); s != nil {
		p.CSRF = s.Token()
	}
	if !view.IsHTMX(r) {
		p.Nav = h.buildNav(r, uc)
	}
	p.Flashes = append(p.Flashes, uc.takeFlashes()...)
	return p
}

func (h *Handlers) render(w http.ResponseWriter, r *http.Request, page string, data *view.Page) {
	if err := h.View.Render(w, r, page, data); err != nil {
		h.renderFailed(w, r, err, "page "+page)
	}
}

// renderFailed is THE response-safe handling for a failed Render/RenderNamed,
// shared by every caller. A template failure gets the 500 — Render buffers,
// so nothing reached the client. A CLIENT-side write failure (view.WriteError:
// an aborted large download) gets a log line and nothing else: the response
// is already partly on the wire, so an http.Error would re-stamp a completed
// request as 500 in the access line, the 5xx metric and the audit record, and
// net/http would log a superfluous WriteHeader.
func (h *Handlers) renderFailed(w http.ResponseWriter, r *http.Request, err error, what string) {
	if view.IsWriteError(err) {
		h.Log.Info("client aborted the response write", "what", what, "err", err, "reqid", RequestID(r.Context()))
		return
	}
	h.Log.Error("render failed", "what", what, "err", err, "reqid", RequestID(r.Context()))
	http.Error(w, "internal error", http.StatusInternalServerError)
}

// errorBody backs the error page panel.
type errorBody struct {
	Status  int
	Message string
	Detail  string
}

// renderError shows the classic error panel. Server-side detail is logged
// with the request id; the client never sees stack traces or credentials.
//
// htmx does not swap non-2xx responses by default, so a 4xx/5xx returned to a
// fragment request would leave the user with no feedback. For logged-in htmx
// requests we therefore render the error panel into #page_content at HTTP 200
// (mirroring the SQL console, which surfaces failures inline) — panel only, no
// out-of-band chrome, so the breadcrumb/tabs are preserved rather than blanked.
// Full-page (non-htmx) requests keep the real 4xx/5xx status, with Content-Type
// set before WriteHeader so the global nosniff header doesn't mislabel the body.
func (h *Handlers) renderError(w http.ResponseWriter, r *http.Request, status int, message, detail string) {
	uc, _, loggedIn := h.currentUser(r)

	// Record the SEMANTIC status for the audit trail: the wire status is
	// misleading by design on the htmx arm (200 so the panel swaps), and the
	// trail must not file a rejected mutation as outcome=ok. IfUnset, so a
	// policy/capacity layer's pre-set OutcomeDenied is never clobbered.
	audit.FromContext(r.Context()).SetOutcomeIfUnset(audit.OutcomeForStatus(status), message)

	if view.IsHTMX(r) {
		if !loggedIn {
			// An unauthenticated error has no chrome; a normal fragment would
			// OOB-blank the (empty) breadcrumb/tabs. Reload the login page.
			w.Header().Set("HX-Redirect", urlLogin())
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("HX-Retarget", "#page_content")
		w.Header().Set("HX-Reswap", "innerHTML")
		ep := view.NewPage("Error")
		ep.Body = errorBody{Status: status, Message: message, Detail: detail}
		// The plain-text fallback is for a failed RENDER only; a client-side
		// write failure means the panel is already partly on the wire.
		if err := h.View.RenderNamed(w, "error", "content", ep); err != nil && !view.IsWriteError(err) {
			http.Error(w, message, status)
		}
		return
	}

	var p *view.Page
	if loggedIn {
		p = h.newLoggedPage(r, uc, "Error")
	} else {
		p = view.NewPage("Error")
	}
	p.Body = errorBody{Status: status, Message: message, Detail: detail}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := h.View.Render(w, r, "error", p); err != nil && !view.IsWriteError(err) {
		http.Error(w, message, status)
	}
}

// dbError logs the underlying error and shows a sanitized message + the offending
// SQL (when provided) in the error panel. The log line is routed through
// redactConnError so a driver that echoes a DSN in a post-connect error can't
// leak it to the server log (the same rule the login path enforces); the
// user-facing panel keeps the full driver message — the user runs under their
// own credentials and is entitled to see their own query's error. That is a
// DECIDED trade-off, re-examined and kept in the 2026-08 production-readiness
// review (docs/architecture.md §8, "the three error tiers"): do not re-flag
// the full message as a leak.
func (h *Handlers) dbError(w http.ResponseWriter, r *http.Request, err error, sql string) {
	h.Log.Warn("database error", "err", redactConnError(err), "reqid", RequestID(r.Context()))
	h.renderError(w, r, http.StatusBadRequest, err.Error(), sql)
}

// stagedError records WHICH step of a multi-step operation failed and — the
// part the caller cannot otherwise recover — whether the statement ever reached
// the server.
//
// dropDatabase is the case: it can fail before the DROP (no maintenance
// connection could be opened) and after it (the server-connection rebind), and
// both come back as a plain error. The caller attached the SQL to either,
// telling a user their DROP had failed when it had never been issued — and, for
// the pre-DROP case, showing a raw DIAL error, which is the one kind of message
// that can echo the DSN.
type stagedError struct {
	// Stage names the step, for the log line only; it is not shown to the user.
	Stage string
	// Executed reports whether the statement reached the server. False means the
	// operation failed BEFORE issuing it, so it must not be displayed as though
	// it had been tried.
	Executed bool
	Err      error
}

func (e *stagedError) Error() string { return e.Err.Error() }
func (e *stagedError) Unwrap() error { return e.Err }

// dbErrorStaged is dbError for an operation whose failure may PREDATE its
// statement, and may therefore be a failed dial rather than a rejected query.
//
// It takes the *UserContext because that is the only credential-aware sanitizer
// available: redactErr builds its needles from the session password and the DSN
// that embeds it. Plain dbError has no access to either and shows err.Error()
// verbatim — right for a statement error, which happens after a successful
// connect and cannot echo a credential, and wrong for a dial. connError takes uc
// for exactly this reason; this mirrors it rather than inventing a second
// redaction rule.
//
// Redaction is applied ONLY on the not-executed path, deliberately. Trimming a
// statement error to its first line would take back the full driver message the
// user is entitled to see for their own query — a trade-off decided in the
// 2026-08 review and kept. A failure that never issued a statement has no such
// message to lose, and is precisely the one that can carry a DSN.
func (h *Handlers) dbErrorStaged(w http.ResponseWriter, r *http.Request, uc *UserContext, err error, sql string) {
	stage, executed := "unspecified", true
	var se *stagedError
	if errors.As(err, &se) {
		stage, executed = se.Stage, se.Executed
	}
	msg := err.Error()
	if !executed {
		msg = uc.redactErr(err)
		sql = "" // never show a statement that was not issued
	}
	h.Log.Warn("database operation failed", "stage", stage, "executed", executed,
		"err", uc.redactErr(err), "reqid", RequestID(r.Context()))
	h.renderError(w, r, http.StatusBadRequest, msg, sql)
}

// multipartMemoryThreshold bounds how much of a multipart body is buffered in
// memory before spilling to a temp file. It only picks RAM-vs-tempfile; the
// overall size cap stays with the MaxBytesReader the limitBody middleware
// installs, so this is far below Go's 32 MiB ParseMultipartForm default.
const multipartMemoryThreshold = 1 << 20 // 1 MiB

// BoundedParseForm parses the request form, dispatching on media type:
// multipart/form-data goes through ParseMultipartForm (with the small in-memory
// threshold above), everything else through ParseForm. This closes two gaps:
// ParseForm never reads a multipart body (so a later PostFormValue would trigger
// ParseMultipartForm under Go's 32 MiB default), and a prior successful ParseForm
// leaves r.PostForm non-nil so a multipart body's fields would silently read
// empty. It is idempotent (a cached form is reused). Exported so the csrf
// middleware can bound the FIRST parse of a no-JS (form-token) request before it
// extracts the token.
func BoundedParseForm(r *http.Request) error {
	if ct := r.Header.Get("Content-Type"); ct != "" {
		if mt, _, err := mime.ParseMediaType(ct); err == nil && mt == "multipart/form-data" {
			return r.ParseMultipartForm(multipartMemoryThreshold)
		}
	}
	return r.ParseForm()
}

// parseFormOr400 parses the request form, rendering the shared "Invalid form."
// on a malformed body and "Request too large." on an over-cap body. When it
// reports false a response was already written and the caller must return. Both
// statuses ride renderError's semantic-vs-wire split (a logged-in htmx caller
// sees the status in the #page_content panel at wire 200; a full-page caller
// gets the real WriteHeader), so a 413 is never forced onto an htmx swap. (The
// login handler keeps its own variant — it runs before a UserContext exists.)
func (h *Handlers) parseFormOr400(w http.ResponseWriter, r *http.Request) bool {
	if err := BoundedParseForm(r); err != nil {
		if bodyTooLarge(err) {
			h.renderError(w, r, http.StatusRequestEntityTooLarge, "Request too large.", "")
		} else {
			h.renderError(w, r, http.StatusBadRequest, "Invalid form.", "")
		}
		return false
	}
	return true
}

// RenderRestricted answers a request refused by restricted mode
// (config [restrict]) with a 403 and an explanation naming the setting
// responsible. Exported because the enforcement is a middleware in the server
// package, which owns the policy but not the renderer.
func (h *Handlers) RenderRestricted(w http.ResponseWriter, r *http.Request, msg string) {
	h.renderError(w, r, http.StatusForbidden, msg, "")
}

// RefuseByPolicy is RenderRestricted plus the two things the middleware's own
// refusal does: file it in the audit trail as a refusal rather than as whatever
// the status implies, and count it. A handler that enforces part of the policy
// itself — saveProgram, whose route cannot see the `action` field — must be
// indistinguishable from the middleware to anyone reading the trail or the
// metrics.
func (h *Handlers) RefuseByPolicy(w http.ResponseWriter, r *http.Request, msg string) {
	h.Log.Warn("refused by restricted mode",
		"path", r.URL.Path, "method", r.Method, "reqid", RequestID(r.Context()))
	h.Counters.restrictedRefusal()
	audit.FromContext(r.Context()).SetOutcome(audit.OutcomeDenied, msg)
	h.RenderRestricted(w, r, msg)
}

// RenderCapacityRefusal answers a request the server is declining for capacity,
// in the shape acquireDBOp defines: Retry-After, an audit outcome of DENIED
// rather than whatever the status implies, and the ordinary error render. A
// capacity refusal is the server choosing not to do the work, not the work
// failing, and filing it as an error sends whoever reads the trail looking for a
// fault that is not there.
//
// Exported because the caps that use it are enforced by middleware in the server
// package, which owns the policy but reaches neither acquireDBOp nor renderError
// — both unexported. Same reason as RenderRestricted, RefuseByPolicy and
// RenderLoginThrottled.
//
// status is a parameter because the callers genuinely differ: import admission
// refuses with 503, session-creation admission with 429.
//
// It does NO accounting, deliberately. TryAcquire has already counted the
// refusal on whichever limiter was asked, and acquireDBOp's warning hard-codes
// h.DBOps.InFlight() — the wrong instance for any other limiter. So the CALLER
// logs, naming its own limiter's in-flight count, and nothing here re-counts.
func (h *Handlers) RenderCapacityRefusal(w http.ResponseWriter, r *http.Request, status int, msg string, retryAfter int) {
	audit.FromContext(r.Context()).SetOutcome(audit.OutcomeDenied, msg)
	// Before the render, which writes the status.
	w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
	// An htmx caller with NO session is the one case renderError gets wrong here:
	// its unauthenticated arm answers HX-Redirect /login at HTTP 200, and for a
	// refusal raised before any session exists that is a redirect to the very
	// page being throttled — a loop — with no in-page panel to swap into either.
	// Answer the real status instead. An AUTHENTICATED htmx caller (the import
	// cap) keeps renderError's ordinary fragment contract.
	if _, _, loggedIn := h.currentUser(r); !loggedIn && view.IsHTMX(r) {
		http.Error(w, msg, status)
		return
	}
	h.renderError(w, r, status, msg, "")
}

// RenderLoginThrottled renders the generic "too many login attempts" response
// from the csrf middleware's coarse bare-IP throttle, which fires BEFORE the
// body is parsed — so no posted sticky values (username/host/server) can be
// echoed back. It reuses loginThrottled, matching Login's own throttle
// rejection: a full-page caller gets the login form + HTTP 429 + Retry-After;
// an htmx caller gets HTTP 200 + HX-Redirect /login.
func (h *Handlers) RenderLoginThrottled(w http.ResponseWriter, r *http.Request) {
	h.loginThrottled(w, r, h.loginViewModel())
}

// connError is dbError's sibling for connection-open failures (ConnFor /
// PinnedFor / ExportConnFor): a backend being unreachable or the pool cap
// being hit is a service condition, not a bad request, so the error page is
// 503, not 400. Unlike a statement error, a failed dial's message may echo
// the DSN (which embeds the password), so both the log line and the
// user-facing panel carry the redacted form (see UserContext.redactErr).
// Note: htmx requests still surface the panel at HTTP 200 (renderError's
// fragment contract); the 503 is observable on full-page loads.
func (h *Handlers) connError(w http.ResponseWriter, r *http.Request, uc *UserContext, err error) {
	msg := uc.redactErr(err)
	h.Log.Warn("connection open failed", "err", msg, "reqid", RequestID(r.Context()))
	h.renderError(w, r, http.StatusServiceUnavailable, "Connection failed: "+msg, "")
}

// --- small request helpers -----------------------------------------------------

// themeFromRequest returns the persisted color theme ("dark"/"light") from the
// tx-theme cookie, or "" when unset. The client-side toggle mirrors its choice
// into this cookie so the server renders the correct theme on the first paint.
func themeFromRequest(r *http.Request) string {
	if c, err := r.Cookie("tx-theme"); err == nil && (c.Value == "dark" || c.Value == "light") {
		return c.Value
	}
	return ""
}

// navWidthStyle returns a trusted `--tx-nav-width:<n>px` declaration from the
// tx-nav-width cookie (mirrored by the client when the sidebar is resized), or
// "" when unset/invalid. The value is rebuilt from a clamped integer so only
// digits and the literal "px" are ever emitted — safe to mark template.CSS and
// render inline so the persisted width applies on the first paint (no FOUC).
func navWidthStyle(r *http.Request) template.CSS {
	c, err := r.Cookie("tx-nav-width")
	if err != nil {
		return ""
	}
	v := strings.TrimSpace(c.Value)
	if !strings.HasSuffix(v, "px") {
		return ""
	}
	n, err := strconv.Atoi(strings.TrimSuffix(v, "px"))
	if err != nil || n < 160 || n > 480 {
		return ""
	}
	return template.CSS("--tx-nav-width:" + strconv.Itoa(n) + "px")
}

// bodyTooLarge reports whether err is the request body exceeding the
// MaxBytesReader cap, which handlers map to 413 Request Entity Too Large.
func bodyTooLarge(err error) bool {
	var maxErr *http.MaxBytesError
	return errors.As(err, &maxErr)
}

func intParam(r *http.Request, name string, def int) int {
	v := r.URL.Query().Get(name)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

// int64Param is intParam's 64-bit twin for values that must not truncate
// through a platform int (browse positions on 32-bit builds).
func int64Param(r *http.Request, name string, def int64) int64 {
	v := r.URL.Query().Get(name)
	if v == "" {
		return def
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return def
	}
	return n
}

// --- request id context (set by middleware) ------------------------------------

type reqIDKey struct{}

// WithRequestID stashes a request id in ctx (called by the logging middleware).
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, reqIDKey{}, id)
}

// RequestID returns the request id, or "" if unset.
func RequestID(ctx context.Context) string {
	id, _ := ctx.Value(reqIDKey{}).(string)
	return id
}
