package handlers

import (
	"context"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/tablexdev/tablex/internal/audit"
	"github.com/tablexdev/tablex/internal/auth"
	"github.com/tablexdev/tablex/internal/config"
	"github.com/tablexdev/tablex/internal/driver"
	"github.com/tablexdev/tablex/internal/view"
)

// engineOption / serverOption back the login form selectors.
type engineOption struct {
	Name        string
	DisplayName string
	DefaultPort int
	// Per-engine ad-hoc form presentation, rendered as data-attributes on the
	// engine <option> (alongside data-port) so app.js reads the dataset
	// instead of naming engines — sourced from the dialect's Capabilities and
	// LoginDatabaseHint.
	ShowSSLMode   bool
	SSLNote       string
	DBLabel       string
	DBPlaceholder string
	DBDefault     string
	DBNote        string
}

type serverOption struct {
	Name   string
	Engine string
	Host   string
	// NeedsUser/NeedsPassword drive the per-field credential inputs: a predefined
	// server collects a credential at login only when its config leaves that field
	// empty (and it is a network engine — SQLite has no credentials). Connection
	// topology (host/port/database/sslmode/file) always comes from config.
	NeedsUser     bool
	NeedsPassword bool
}

// loginBody is the login page view model (with sticky field values on error).
type loginBody struct {
	Engines    []engineOption
	Servers    []serverOption
	AllowAdHoc bool
	Error      string
	Engine     string
	Host       string
	Port       string
	User       string
	Database   string
	File       string
	Server     string
	SSLMode    string
}

func (h *Handlers) loginViewModel() loginBody {
	var engines []engineOption
	for _, d := range driver.All() {
		// A file-backed engine has no credentials, so an ad-hoc login for it
		// would be an unauthenticated, arbitrary file open/create. Such engines
		// are reachable only through an operator-configured predefined server
		// (see Servers below).
		if !d.Capabilities().IsNetworkEngine {
			continue
		}
		opt := engineOption{
			Name:          d.Name(),
			DisplayName:   d.DisplayName(),
			DefaultPort:   d.DefaultPort(),
			ShowSSLMode:   d.Capabilities().ShowsSSLModeUI,
			SSLNote:       d.Capabilities().SSLModeNote,
			DBLabel:       "Database",
			DBPlaceholder: "optional",
		}
		if lh, ok := d.(driver.LoginFormHinter); ok {
			hint := lh.LoginDatabaseHint()
			if hint.Label != "" {
				opt.DBLabel = hint.Label
			}
			if hint.Placeholder != "" {
				opt.DBPlaceholder = hint.Placeholder
			}
			opt.DBDefault = hint.Default
			opt.DBNote = hint.Note
		}
		engines = append(engines, opt)
	}
	var servers []serverOption
	for _, s := range h.Cfg.Servers {
		network := isNetworkEngine(s.Engine)
		servers = append(servers, serverOption{
			Name:          s.Name,
			Engine:        s.Engine,
			Host:          s.Host,
			NeedsUser:     network && s.User == "",
			NeedsPassword: network && s.Password == "",
		})
	}
	body := loginBody{
		Engines:    engines,
		Servers:    servers,
		AllowAdHoc: h.Cfg.Security.AllowAdHoc,
	}
	// The pre-selected engine is simply the first one offered — driver.All()
	// sorts by name, so the choice is stable without naming an engine here.
	if len(engines) > 0 {
		body.Engine = engines[0].Name
		if p := engines[0].DefaultPort; p > 0 {
			body.Port = strconv.Itoa(p)
		}
	}
	return body
}

// isNetworkEngine reports whether the named engine connects to a network
// address with credentials rather than opening a local file. An unregistered
// name — which config validation already rejects — answers false, hiding the
// credential inputs for a predefined server whose login would fail anyway.
func isNetworkEngine(name string) bool {
	d, ok := driver.Get(name)
	return ok && d.Capabilities().IsNetworkEngine
}

// LoginForm renders the login page (GET /login). Already-authenticated users are
// redirected home.
func (h *Handlers) LoginForm(w http.ResponseWriter, r *http.Request) {
	if _, _, ok := h.currentUser(r); ok {
		http.Redirect(w, r, urlHome(), http.StatusSeeOther)
		return
	}
	p := view.NewPage("Log in")
	if t := themeFromRequest(r); t != "" {
		p.Theme = t
	}
	p.CSRF = h.sessionCSRF(r)
	p.Body = h.loginViewModel()
	h.render(w, r, "login", p)
}

// Login authenticates (POST /login) by opening a real database connection with
// the supplied (or predefined-server) parameters. On success it builds the
// session's UserContext, mints the authenticated session in one atomic step
// (fresh ID + CSRF — anti-fixation) and redirects home. Failures are
// rate-limited and reported generically.
func (h *Handlers) Login(w http.ResponseWriter, r *http.Request) {
	// Already-authenticated users are redirected home (mirrors LoginForm),
	// before the rate-limit reservation and the DB dial: re-posting /login over
	// a live session would displace it via store.Replace — the one removal path
	// whose close is Authenticate's responsibility — and there is no legitimate
	// re-login flow. Log out first to switch servers.
	if _, _, ok := h.currentUser(r); ok {
		http.Redirect(w, r, urlHome(), http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		if bodyTooLarge(err) {
			h.renderError(w, r, http.StatusRequestEntityTooLarge, "Request too large.", "")
			return
		}
		h.renderError(w, r, http.StatusBadRequest, "Invalid form submission.", "")
		return
	}
	ip := auth.ClientIP(r, h.Proxy)
	vm := h.loginViewModel()
	serverName := strings.TrimSpace(r.PostFormValue("server"))
	engine := strings.TrimSpace(r.PostFormValue("engine"))
	user := r.PostFormValue("username")
	password := r.PostFormValue("password")
	// CanonicalHost also strips URL-style brackets from an IPv6 literal, so the
	// SSRF checks and the DSN both see the bare spelling ("[::1]" → "::1").
	host := config.CanonicalHost(r.PostFormValue("host"))
	database := strings.TrimSpace(r.PostFormValue("database"))
	file := strings.TrimSpace(r.PostFormValue("file"))
	sslmode := strings.TrimSpace(r.PostFormValue("sslmode"))
	port, _ := strconv.Atoi(strings.TrimSpace(r.PostFormValue("port")))

	// Restore sticky values for re-render on error.
	vm.Engine, vm.Host, vm.User, vm.Database, vm.File, vm.Server = engine, host, user, database, file, serverName
	vm.SSLMode = sslmode
	if port > 0 {
		vm.Port = strconv.Itoa(port)
	}

	// Throttle by client IP, by (IP, username), and — for a predefined server —
	// by (IP, predefined-server) so neither a single source IP, a single targeted
	// account, nor a single predefined server can be brute-forced. The reservation
	// is TWO-STAGE: the coarse bare-IP key is reserved in the csrf middleware
	// BEFORE the body is parsed (so a flood cannot even make us parse), and the
	// identity keys are reserved atomically here. Every failure path below —
	// unknown server, refused engine, SSRF check, dial — consumes exactly one
	// attempt against each. A successful login releases the identity-scoped
	// reservations via Reset, but NOT the bare-IP one (so a valid credential can't
	// reset the IP-wide counter). See docs/security.md §8.
	//
	// The predefined key closes a bypass: a predefined server resolves its
	// username from config (firstNonEmpty(sc.User, user)), so an attacker could
	// blank or rotate the posted username to skip the per-(IP, username) counter.
	// The posted serverName equals sc.Name once validated, so keying on it here
	// (before resolution) is correct; it is IP-scoped, so it cannot lock out other
	// source IPs.
	rateKeys := loginRateKeys(ip, user, serverName)
	// Two-stage reservation: the bare-IP key (rateKeys[0]) was already reserved
	// atomically in the csrf middleware BEFORE the body was parsed, so reserve
	// only the identity keys here — (IP, user) and (IP, predefined-server) — to
	// avoid double-charging the IP. Every failure path below still consumes one
	// attempt against each, and a concurrent burst cannot slip a key past its
	// window (Reserve is atomic per key-group). A successful login releases the
	// identity keys via Reset, but NOT the bare-IP hit. See docs/security.md §8.
	if len(rateKeys) > 1 && !h.Rate.Reserve(rateKeys[1:]...) {
		h.loginThrottled(w, r, vm)
		return
	}
	// The one key that is NOT scoped to the client's address. Every key above
	// starts with the IP, so the throttle they give is per-source: an IPv6 /64 or
	// a botnet gets login_rate_max attempts EACH against the same account. This
	// bounds the account itself. Reserved on its own limiter because its cap is
	// higher — the key is shared by everyone typing that name.
	accountKey := loginAccountKey(user, serverName)
	if accountKey != "" && !h.AccountRate.Reserve(accountKey) {
		h.loginThrottled(w, r, vm)
		return
	}

	var (
		params   driver.ConnParams
		dialect  driver.Dialect
		serverID = "adhoc"
		display  string
		predef   bool
	)

	if serverName != "" {
		sc, ok := h.Cfg.ServerByName(serverName)
		if !ok {
			h.loginError(w, r, "Unknown predefined server.", vm)
			return
		}
		predef = true
		serverID = "predef:" + sc.Name
		display = sc.Name
		engine = sc.Engine
		d, ok := driver.Get(sc.Engine)
		if !ok {
			h.loginError(w, r, "Predefined server has an unknown engine.", vm)
			return
		}
		dialect = d
		params = paramsFromConfig(d, sc, user, password)
	} else {
		if !h.Cfg.Security.AllowAdHoc {
			h.loginError(w, r, "Ad-hoc login is disabled; please choose a predefined server.", vm)
			return
		}
		d, ok := driver.Get(engine)
		if !ok {
			h.loginError(w, r, "Please choose a database engine.", vm)
			return
		}
		// A file-backed engine has no credentials: an ad-hoc login for it is
		// unauthenticated and would let any visitor open (and, historically,
		// create) arbitrary files on the host. Such engines are reachable only
		// via a predefined server. The form does not offer them either
		// (loginViewModel), so this is the server-side authority for a posted
		// engine name that bypassed the form.
		if !d.Capabilities().IsNetworkEngine {
			h.loginError(w, r, d.DisplayName()+" is only available via a configured server.", vm)
			return
		}
		// A network engine must name its target. An empty host historically
		// meant "the driver's local default" (MySQL 127.0.0.1:3306, PostgreSQL
		// its Unix socket) — a target the operator's host allowlist/denylist
		// never saw, because CheckHost had nothing to match. CheckHost below
		// also refuses an empty host; rejecting here as well gives the user an
		// actionable message instead of the generic host-policy one.
		if host == "" {
			h.loginError(w, r, "Host is required for an ad-hoc login.", vm)
			return
		}
		dialect = d
		if port == 0 {
			port = d.DefaultPort()
		}
		params = driver.ConnParams{
			Host: host, Port: port, User: user, Password: password,
			Database: database, FilePath: file, SSLMode: sslModeFor(d, sslmode),
			// Re-check the resolved peer IP at dial time so DNS rebinding cannot
			// bypass the CheckHost pre-flight. Ad-hoc network logins only; the
			// hook is carried into every per-database pool via ConnFor.
			DialControl: auth.DialControl(h.Cfg.Security),
		}
		display = adhocDisplay(d, host, file)
	}

	// Engine-specific login defaults live with the dialect (PostgreSQL binds
	// one database per connection and defaults an empty connect database to
	// "postgres"). Applied to the params — never inside BuildDSN — so
	// params.Database stays observably set for the session's base params and
	// the ConnFor server-connection reuse test.
	if n, ok := dialect.(driver.ParamsNormalizer); ok {
		params = n.NormalizeParams(params)
	}

	// Stamp the operator's pool/timeout settings once, here. params becomes the
	// session's base params, so every derived dial — per-database pool, pinned
	// script, export connection, maintenance connection — inherits them without
	// a package-level variable or another config reference.
	params.Tuning = h.tuning()

	// SSRF guard for network engines on ad-hoc logins. The failure consumes the
	// reservation made above — no extra recording needed.
	if !predef && dialect.Capabilities().IsNetworkEngine {
		if err := auth.CheckHost(r.Context(), params.Host, h.Cfg.Security); err != nil {
			// CheckHost's message embeds the resolved IP (internal/auth/host.go),
			// so returning it verbatim to the unauthenticated client is a
			// DNS-resolution oracle (notably against split-horizon/internal DNS).
			// Log the detail server-side and give the client a generic message,
			// mirroring the Open() failure path below.
			h.Log.Warn("login blocked by host policy",
				"server", serverID,
				"engine", engine,
				"host", redact(effectiveHost(params)),
				"reqid", RequestID(r.Context()),
				"err", err)
			h.loginError(w, r, "Cannot log in. The requested host is not permitted.", vm)
			return
		}
	}

	conn, err := driver.Open(r.Context(), dialect, params)
	if err != nil {
		// Server-side diagnostics must survive without leaking credentials to the
		// unauthenticated client. Log the redacted *effective* connection target
		// (params.Host/Socket/FilePath — the posted `host` is empty for predefined
		// servers) plus a redacted error (password + DSN stripped); the client gets
		// a fixed generic message. See docs/security.md (credentials never logged).
		dsn, _ := dialect.BuildDSN(params)
		h.Log.Warn("login failed",
			"server", serverID,
			"engine", engine,
			"host", redact(effectiveHost(params)),
			"reqid", RequestID(r.Context()),
			"err", redactConnError(err, password, params.Password, dsn))
		h.loginError(w, r, "Cannot log in. Check the host, credentials, and that the server is reachable.", vm)
		return
	}

	// Success: release the reserved attempt on the identity-scoped keys only —
	// (IP, user) and (IP, predefined-server). The bare-IP key (always rateKeys[0])
	// is deliberately NOT reset: otherwise an attacker holding one valid credential
	// on a shared source IP could log in to wipe the IP-wide brute-force counter at
	// will, defeating the per-IP throttle for every other account. A successful
	// login therefore still consumes one slot of the (generous) per-IP window.
	for _, k := range rateKeys[1:] {
		h.Rate.Reset(k)
	}
	// A correct credential for this account clears its global counter too:
	// whatever the earlier failures were, they were not this account being
	// guessed successfully, and leaving the count standing would let a burst of
	// wrong guesses lock out the person who knows the password.
	if accountKey != "" {
		h.AccountRate.Reset(accountKey)
	}
	// conn.Dialect() — NOT the registry `dialect` — is the copy driver.Open
	// specialized from the detected flavor/version/sql_mode. Handing the raw
	// registry singleton to the session would leave uc.Dialect() (and every gate
	// reading it, e.g. driver.ProfileOf in the console splitter) looking at the
	// zero value forever.
	// Statement auditing is stamped onto the session's base params, so every dial
	// derived from them — each per-database pool, each pinned script connection,
	// each export connection — inherits it without another wiring point. The login
	// pool is already open by now and could not have carried it (it is the
	// connection that reveals the identity), so it is installed directly, before
	// the UserContext publishes it.
	if obs := h.statementObserver(); obs != nil {
		params.OnStatement = obs
		conn.SetStatementObserver(obs)
	}
	// Attribute anything else this request does to the account just authenticated:
	// until now the session was pre-auth and the audit identity was empty.
	audit.FromContext(r.Context()).SetIdentity(audit.Name(conn.Info().User), display, engine)

	uc := NewUserContext(serverID, display, conn.Dialect(), params, conn, h.Pools)

	// Authenticate mints a NEW session (fresh ID + CSRF, payload attached
	// before the object is shared) and atomically replaces the pre-auth one —
	// the pre-auth ID can never become authenticated, and a pre-auth session
	// that was evicted/reaped/destroyed mid-login fails cleanly instead of
	// being resurrected. On failure the caller-owned pools are closed here:
	// honest backpressure at the session cap, not an evictable retry.
	s := h.currentSession(r)
	if s == nil {
		s = h.Sessions.Start(w, r)
	}
	if _, ok := h.Sessions.Authenticate(w, s, uc, uc.Close); !ok {
		uc.Close()
		h.loginError(w, r, "Cannot log in: the session ended during login (server at session capacity, or the session expired). Please try again.", vm)
		return
	}

	// The account recorded is the one the SERVER reports, not the one that was
	// typed: a predefined server may supply the username from config, and MySQL
	// resolves the host part itself. What an auditor needs is whose privileges
	// this session runs under.
	h.auditAuth(r, audit.OutcomeOK, conn.Info().User, display, engine, "")
	h.Counters.recordLoginSuccess()

	// A server older than the documented engine floor is reported once, here —
	// TableX used to say nothing, so an unsupported release surfaced later as an
	// empty listing or a confusing error at the point of use, with nothing
	// pointing at the cause. It is a warning, not a refusal: most of the tool
	// still works, and locking an operator out over a feature floor would be the
	// worse trade. Logged as well as flashed, so it survives the one page view.
	if warn := conn.FloorWarning(); warn != "" {
		h.Log.Warn("connected server is below the documented engine floor",
			"engine", engine, "flavor", conn.Info().Flavor, "version", conn.Info().Version)
		uc.AddFlash(view.Flash{Kind: "warning", Message: warn})
	}
	http.Redirect(w, r, urlHome(), http.StatusSeeOther)
}

// Logout destroys the session and closes its pools (POST /logout).
func (h *Handlers) Logout(w http.ResponseWriter, r *http.Request) {
	s := h.currentSession(r)
	// Read the identity BEFORE Destroy: it closes the payload and drops the
	// reference, so afterwards there is nothing left to name.
	var account, server, engine string
	if s != nil {
		if uc, ok := s.App().(*UserContext); ok && uc != nil {
			if c := uc.ServerConn(); c != nil {
				account = c.Info().User
			}
			server, engine = uc.ServerName, uc.Engine
		}
	}
	h.Sessions.Destroy(w, s)
	h.auditAuth(r, audit.OutcomeOK, account, server, engine, "")
	http.Redirect(w, r, urlLogin(), http.StatusSeeOther)
}

// statementObserver returns the hook that records each statement TableX runs on
// the user's behalf, or nil when statement auditing is off — in which case the
// driver does not so much as read a clock.
//
// The identity is read from the REQUEST rather than captured here, because the
// session outlives this request: a closure that baked in the account would
// attribute every later statement to whatever was true at login and would name no
// client at all. audit.Pending, already in the context for the action log, is
// exactly the per-request carrier this needs.
func (h *Handlers) statementObserver() driver.StatementObserver {
	if !h.Audit.Enabled() || !h.Cfg.Audit.Statements {
		return nil
	}
	return func(ctx context.Context, ev driver.StatementEvent) {
		p := audit.FromContext(ctx)
		account, server, engine := p.Identity()
		sqlText := ev.SQL
		outcome, detail := audit.OutcomeOK, ""
		if ev.Err != nil {
			// The message may echo the statement, which is being recorded on this
			// very line, so — once both are redacted below — it discloses nothing
			// the trail does not already hold. A DIAL error could carry a DSN,
			// but a dial never reaches here.
			outcome, detail = audit.OutcomeError, ev.Err.Error()
		}
		// Strip the event's secrets (a DCL statement embeds the account's
		// password) from BOTH the statement and the error, and do it BEFORE
		// audit.Statement normalizes and truncates — a needle straddling the
		// truncation point would otherwise survive in fragments.
		for _, needle := range ev.Redact {
			if needle == "" {
				continue // ReplaceAll of "" would blank-redact the whole statement
			}
			sqlText = strings.ReplaceAll(sqlText, needle, "***")
			detail = strings.ReplaceAll(detail, needle, "***")
		}
		// The needles cover only TableX-generated DCL, where the password is in
		// hand. SQL the USER wrote — CREATE USER ... IDENTIFIED BY 's3cret' in
		// the console, an ALTER ROLE in an imported script — carries none, yet
		// the trail's contract is that nothing recorded can be replayed to gain
		// access. The grammar-shaped scrub masks the literal in every
		// password-bearing position, in both texts; applied unconditionally
		// because it is also defence in depth for the needle path.
		sqlText = audit.RedactCredentialLiterals(sqlText)
		detail = audit.RedactCredentialLiterals(detail)
		h.Audit.Emit(audit.Event{
			Kind:      audit.KindStatement,
			Outcome:   outcome,
			Detail:    detail,
			Request:   RequestID(ctx),
			Account:   account,
			Server:    server,
			Engine:    engine,
			Remote:    p.Remote(),
			Statement: audit.Statement(sqlText),
			Rows:      ev.Rows,
			UserSQL:   ev.UserSQL,
			Millis:    ev.Duration.Milliseconds(),
		})
	}
}

// auditAuth records a login or a logout.
//
// Authentication is the event an auditor cares about most and the one an HTTP
// status describes worst: a rejected login re-renders the form, so the response
// is an ordinary page — and on the htmx path a 200 with a redirect header. Only
// the handler knows which account was involved and whether the attempt was
// refused, so only the handler can record it.
func (h *Handlers) auditAuth(r *http.Request, outcome audit.Outcome, account, server, engine, detail string) {
	if !h.Audit.Enabled() {
		return
	}
	// The person, when a gate is configured, beside the account. Both matter: the
	// account is whose privileges ran, the subject is who was at the keyboard.
	var subject, email string
	if s := h.currentSession(r); s != nil {
		if v := s.SSO(); v.Verified() {
			subject, email = v.Subject, v.Email
		}
	}
	h.Audit.Emit(audit.Event{
		Kind:    audit.KindAuth,
		Outcome: outcome,
		Request: RequestID(r.Context()),
		Account: audit.Name(account),
		Subject: audit.Name(subject),
		Email:   audit.Name(email),
		Server:  audit.Name(server),
		Engine:  audit.Name(engine),
		Remote:  auth.ClientIP(r, h.Proxy),
		Method:  r.Method,
		Path:    r.URL.Path,
		Detail:  detail,
	})
}

// loginError re-renders the login form with msg and a 401 — the answer for a
// rejected credential.
func (h *Handlers) loginError(w http.ResponseWriter, r *http.Request, msg string, vm loginBody) {
	h.loginErrorStatus(w, r, http.StatusUnauthorized, msg, vm)
}

// loginThrottled is the answer when the rate limiter refused the attempt: 429
// with Retry-After, NOT the 401 a wrong password gets. 401 asserted the
// credentials were rejected when nothing had been checked at all, so no client —
// human or automated — could tell "wrong password" from "slow down", nor how
// long to wait. Retry-After is the configured window: an upper bound on the
// wait, since the oldest attempt in the window may expire sooner.
func (h *Handlers) loginThrottled(w http.ResponseWriter, r *http.Request, vm loginBody) {
	// Ceil-with-floor-1, shared with every throttled responder: truncation
	// dropped the header entirely for a sub-second window.
	w.Header().Set("Retry-After", strconv.Itoa(auth.RetryAfterSeconds(h.Cfg.Security.LoginRateWindow)))
	h.loginErrorStatus(w, r, http.StatusTooManyRequests,
		"Too many login attempts. Please wait and try again.", vm)
}

func (h *Handlers) loginErrorStatus(w http.ResponseWriter, r *http.Request, status int, msg string, vm loginBody) {
	// Every login rejection funnels through here — a wrong credential, a refused
	// host, a blocked engine, an unknown predefined server, and the throttle — so
	// this is the one place a failed attempt has to be recorded. It goes FIRST,
	// before the htmx short-circuit below, so the record does not depend on how
	// the client asked.
	h.auditAuth(r, audit.OutcomeDenied, vm.User, vm.Server, vm.Engine, msg)
	h.Counters.recordLoginRejected(status)
	// The login form is a normal full-page POST; re-render it with the message
	// and the status. Content-Type is set before WriteHeader so the global
	// nosniff header doesn't mislabel the body. A future htmx caller is sent back
	// to the login page rather than receiving an unswappable error status.
	if view.IsHTMX(r) {
		w.Header().Set("HX-Redirect", urlLogin())
		w.WriteHeader(http.StatusOK)
		return
	}
	vm.Error = msg
	p := view.NewPage("Log in")
	if t := themeFromRequest(r); t != "" {
		p.Theme = t
	}
	p.CSRF = h.sessionCSRF(r)
	p.Body = vm
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	h.render(w, r, "login", p)
}

// sessionCSRF returns the current session's CSRF token (empty if none).
func (h *Handlers) sessionCSRF(r *http.Request) string {
	if s := h.currentSession(r); s != nil {
		return s.Token()
	}
	return ""
}

// loginRateKeys builds the per-attempt throttle keys: always per-IP, plus
// per-(IP, username) when a username is posted, plus per-(IP, predefined-server)
// when a predefined server is selected. The predefined key closes a bypass — a
// predefined server resolves its username from config, so an attacker could
// blank or rotate the posted username to dodge the per-(IP, username) counter;
// keying on the selected server name (which equals the validated sc.Name)
// re-throttles those attempts. Every key is IP-scoped, so none can lock out
// other source IPs.
func loginRateKeys(ip, user, serverName string) []string {
	keys := []string{ip}
	if u := boundRateKeyPart(strings.ToLower(strings.TrimSpace(user))); u != "" {
		keys = append(keys, ip+"|"+u)
	}
	if serverName != "" {
		// serverName is the POSTED value: both key builders run before it is
		// validated against the config list, so treat it as attacker-chosen and
		// bound it like every other part.
		keys = append(keys, ip+"|predef:"+boundRateKeyPart(serverName))
	}
	return keys
}

// loginAccountKey is the address-independent key: the account name alone. For a
// predefined server the credentials may come from config rather than the form,
// so the server name is used instead — otherwise blanking the username would
// skip this counter exactly as it would have skipped the (IP, user) one. The
// server name reaching here is still the posted one (validation happens later),
// so this branch is attacker-chosen too.
//
// Bounded like every other key part: the posted username is only limited by the
// pre-auth body cap, and an unbounded key is a memory-growth primitive.
func loginAccountKey(user, serverName string) string {
	if serverName != "" {
		return "account:predef:" + boundRateKeyPart(serverName)
	}
	if u := boundRateKeyPart(strings.ToLower(strings.TrimSpace(user))); u != "" {
		return "account:" + u
	}
	return ""
}

// maxRateKeyPart bounds the attacker-controlled portion of a limiter key. The
// posted username is only bounded by the 1 MiB pre-auth body cap, and it was
// embedded verbatim: each attempt could plant a key kilobytes wide, and a
// limiter key is reclaimed only by the periodic sweep or by a successful login
// on that exact key — never by an attacker's own traffic. 64 bytes is MySQL's
// identifier maximum (PostgreSQL's is 63), so no real account name is affected.
const maxRateKeyPart = 64

// boundRateKeyPart truncates a key component on a UTF-8 rune boundary. Merging
// two absurdly long names onto one key STRENGTHENS the throttle (their attempts
// share a budget); it can never weaken it, since the bare-IP key is reserved
// first and independently.
func boundRateKeyPart(s string) string {
	if len(s) <= maxRateKeyPart {
		return s
	}
	cut := maxRateKeyPart
	for cut > 0 && cut > maxRateKeyPart-utf8.UTFMax && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

// sslModeFor returns the posted SSL mode only for engines whose ad-hoc login
// form exposes the selector (Capabilities().ShowsSSLModeUI). The selector is
// server-rendered in the HTML for every ad-hoc form and only *shown* per engine
// via Alpine x-show, so it stays in the DOM and the browser posts it for EVERY
// engine — including one that cannot honour it. Both network engines accept it
// today (MySQL's dialect maps the PostgreSQL vocabulary onto go-sql-driver's TLS
// names); an engine that does not must get "" rather than a value it would
// reject, and a file-backed engine has no transport to configure at all.
func sslModeFor(d driver.Dialect, sslmode string) string {
	if d.Capabilities().ShowsSSLModeUI {
		return sslmode
	}
	return ""
}

// paramsFromConfig resolves a predefined server's connection params. Only the
// user and password are collectible at login (and only when config leaves them
// empty); the connection topology — host/port/database/sslmode/file — comes
// solely from config, matching the SQLite branch — an operator-defined server's
// topology is the operator's, not the visitor's.
// A predefined PostgreSQL server on a managed host that blocks the
// `postgres` database must therefore set `database` in its config (an empty
// Database still defaults to "postgres" at the call site).
func paramsFromConfig(d driver.Dialect, sc config.ServerConfig, user, password string) driver.ConnParams {
	// A predefined file-backed server's file is fixed by the operator; the
	// posted values are never honored, so a logged-in user cannot redirect the
	// connection at an arbitrary path on the host. There is no network
	// topology and no credential to collect, so nothing else carries over.
	if !d.Capabilities().IsNetworkEngine {
		return driver.ConnParams{FilePath: sc.FilePath, Params: sc.Params}
	}
	return driver.ConnParams{
		Host:     sc.Host,
		Socket:   sc.Socket,
		Port:     sc.Port,
		User:     firstNonEmpty(sc.User, user),
		Password: firstNonEmpty(sc.Password, password),
		Database: sc.Database,
		FilePath: sc.FilePath,
		SSLMode:  sc.SSLMode,
		Params:   sc.Params,
	}
}

// adhocDisplay names an ad-hoc connection for the UI. The file-backed branch
// is unreachable from Login today (ad-hoc login is refused for those engines
// above) and is kept so the helper stays correct for any caller.
func adhocDisplay(d driver.Dialect, host, file string) string {
	if !d.Capabilities().IsNetworkEngine {
		if file != "" {
			return filepath.Base(file)
		}
		return d.DisplayName()
	}
	if host != "" {
		return host
	}
	return d.Name()
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// redact masks a host for logging (keeps shape, drops exact value beyond first
// label) — credentials and full DSNs are never logged.
func redact(host string) string {
	if host == "" {
		return ""
	}
	if i := strings.IndexByte(host, '.'); i > 0 {
		return host[:i] + ".***"
	}
	return "***"
}

// effectiveHost returns the connection target actually used (Host, then Unix
// socket, then SQLite file path), so a failed-login log records the real
// destination — the posted `host` is empty for predefined servers, whose target
// comes from config via paramsFromConfig.
func effectiveHost(p driver.ConnParams) string {
	switch {
	case p.Host != "":
		return p.Host
	case p.Socket != "":
		return p.Socket
	case p.FilePath != "":
		return p.FilePath
	default:
		return ""
	}
}

// redactConnError renders a driver/connection error safe to log: it strips the
// supplied secrets (the posted and effective passwords, and the full DSN, which
// embeds the password) so the "credentials are never logged" rule holds even
// when a driver echoes them, then keeps the first clause and bounds the length.
// Unlike a plain err.Error(), this is the only form safe to write to the log.
func redactConnError(err error, secrets ...string) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	for _, s := range secrets {
		if s != "" {
			msg = strings.ReplaceAll(msg, s, "***")
		}
	}
	// Keep the first clause; later lines are most likely to echo a DSN.
	if i := strings.IndexByte(msg, '\n'); i > 0 {
		msg = msg[:i]
	}
	if utf8.RuneCountInString(msg) > 200 {
		// Trim on a rune boundary so a multi-byte character is never split.
		msg = string([]rune(msg)[:200]) + "…"
	}
	return msg
}
