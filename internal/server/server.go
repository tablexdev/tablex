// Package server wires TableX's HTTP layer together: it builds the renderer,
// session manager, rate limiter and handlers, assembles the middleware chain and
// route table, serves embedded static assets, and manages graceful startup and
// shutdown (closing every session pool on the way out).
package server

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/tablexdev/tablex/internal/audit"
	"github.com/tablexdev/tablex/internal/auth"
	"github.com/tablexdev/tablex/internal/config"
	"github.com/tablexdev/tablex/internal/server/handlers"
	"github.com/tablexdev/tablex/internal/session"
	"github.com/tablexdev/tablex/internal/storage"
	"github.com/tablexdev/tablex/internal/view"
	"github.com/tablexdev/tablex/web"
)

// Server is the running TableX HTTP application.
type Server struct {
	cfg          config.Config
	log          *slog.Logger
	sessions     *session.Manager
	storage      *storage.Store        // nil unless a metadata database is configured
	metaSessions *storage.SessionStore // the durable session store, when that is what sessions uses
	audit        *audit.Logger         // nil unless the audit trail is configured
	metrics      *metrics              // nil unless [metrics] is enabled
	metricsNets  *auth.CIDRSet         // parsed metrics.allow_cidrs (nil = no network restriction)
	rate         *auth.RateLimiter
	accountRate  *auth.RateLimiter // the address-independent per-account limiter
	// sessionRate throttles session CREATION per client. Swept beside the other
	// two; the sweep interval is derived from LoginRateWindow alone and stays
	// correct, because prune is per-limiter and window-aware — a differently
	// sized SessionCreateWindow changes reclamation latency, never correctness.
	sessionRate *auth.RateLimiter
	proxy       *auth.ProxyTrust
	view        *view.Renderer
	handlers    *handlers.Handlers
	httpSrv     *http.Server
	// policy mirrors the router's patterns, holding each route's restricted-mode
	// need instead of its handler. Built by router(); read only by needFor.
	policy *http.ServeMux
	// importLimit bounds concurrent import UPLOADS. A second DBOpLimiter
	// instance, never the shared DBOps one: an upload holds this slot across the
	// whole request body, and a database connection must not be held for that.
	importLimit   *handlers.DBOpLimiter
	staticH       http.Handler
	stopCh        chan struct{}
	shutdownOnce  sync.Once
	baseCtx       context.Context    // parent of every request context
	baseCtxCancel context.CancelFunc // cancels in-flight requests on a drain timeout
}

// New constructs a Server from resolved config. It parses templates and loads
// icons up front so any template error surfaces at startup, not mid-request.
func New(cfg config.Config, log *slog.Logger, version string) (*Server, error) {
	renderer, err := view.New(web.FS)
	if err != nil {
		return nil, err
	}
	for _, msg := range cfg.Warnings() {
		log.Warn("config", "warning", msg)
	}

	// Pure validation runs first — before the SSO discovery round trip below
	// and before any resource is acquired. A malformed CIDR list must refuse
	// startup while there is nothing to release and before TableX has talked
	// to anything.
	pt, err := auth.NewProxyTrust(cfg.Security.TrustedProxyCIDRs)
	if err != nil {
		return nil, err
	}
	// The metrics allowlist is parsed here rather than per scrape, and a bad entry
	// refuses startup: an unparseable CIDR that silently dropped out of the list
	// would widen access, not narrow it.
	metricsNets, err := auth.NewCIDRSet("metrics.allow_cidrs", cfg.Metrics.AllowCIDRs)
	if err != nil {
		return nil, err
	}
	staticSub, err := fs.Sub(web.FS, "static")
	if err != nil {
		return nil, err
	}

	// The SSO gate, when configured. Discovery runs ONCE, here, and a failure is
	// fatal: a provider that could not be reached at startup would otherwise leave
	// the gate absent, which is the one outcome an operator who configured it must
	// never get silently.
	var ssoProvider *auth.OIDCProvider
	if cfg.SSO.Enabled() {
		// Its own bounded context rather than the server's baseCtx, which does not
		// exist yet at this point in construction. The provider's HTTP client has
		// its own timeout too; this bounds the whole discovery step so an
		// unreachable issuer fails startup promptly instead of hanging it.
		discoverCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		p, err := auth.NewOIDCProvider(discoverCtx, cfg.SSO.Issuer, cfg.SSO.ClientID,
			cfg.SSO.ClientSecret, cfg.SSO.RedirectURL, cfg.SSO.ResolvedScopes())
		cancel()
		if err != nil {
			return nil, err
		}
		ssoProvider = p
		log.Info("single sign-on gate enabled", "issuer", cfg.SSO.Issuer,
			"scopes", strings.Join(cfg.SSO.ResolvedScopes(), " "))
	}

	rl := auth.NewRateLimiter(cfg.Security.LoginRateWindow, cfg.Security.LoginRateMax)
	// A second limiter for the address-independent account key. Its own instance
	// because its cap is deliberately higher: that key is shared by everyone
	// typing the same account name.
	accountRL := auth.NewRateLimiter(cfg.Security.LoginRateWindow, cfg.Security.LoginAccountMax)
	// A per-client cap on session CREATION, off by default. The login limiter
	// cannot serve: it short-circuits on safe methods, while an anonymous GET to
	// any route mints a session — and, with [storage] on, a durable ROW.
	// Infallible by construction, so New's "nothing fallible after NewManager"
	// discipline is untouched.
	sessionRL := auth.NewRateLimiter(cfg.Security.SessionCreateWindow, cfg.Security.SessionCreateMax)

	// The audit trail comes before the metadata database so that a failure to
	// open it cannot leak the pool, and so its own startup line is the first
	// thing an operator sees.
	auditLog, err := openAuditLog(cfg, log)
	if err != nil {
		return nil, err
	}

	// Opened last of the fallible steps: nothing that can fail follows it, so
	// the release arm below is the only cleanup New needs. The audit sink
	// above is the only earlier acquisition, and a source-level test
	// (server_new_test.go) holds both halves — the arm releases the sink, and
	// no fallible call is ever added after session.NewManager, which would
	// silently re-open this class.
	//
	// Sessions live in process memory unless the operator has given TableX a
	// metadata database of its own, in which case their identity becomes durable
	// and shared. A metadata database that cannot be opened or migrated refuses
	// startup — continuing without it would silently fall back to non-durable
	// sessions, which the operator would discover only after a restart lost them.
	store, meta, err := openSessionStore(cfg, log)
	if err != nil {
		// Release the audit sink or its descriptor leaks — and joining rather
		// than discarding Close's error keeps a failure to flush the trail
		// from being silent.
		if auditLog != nil {
			err = errors.Join(err, auditLog.Close())
		}
		return nil, err
	}
	sm := session.NewManager(store, session.Config{
		CookieName:      cfg.Session.CookieName,
		IdleTimeout:     cfg.Session.IdleTimeout,
		AbsoluteTimeout: cfg.Session.AbsoluteTimeout,
		Secure:          cfg.CookiesSecure(),
		// Closes over the LOCALS, not over s: `s := &Server{...}` is declared
		// below this call, so referring to s.sessionRate/s.proxy here would not
		// compile. Keying with auth.ClientIP keeps internal/session free of
		// internal/auth while still honouring this deployment's proxy trust — a
		// raw RemoteAddr would carry an ephemeral port and ignore it.
		Admit: func(r *http.Request) bool { return sessionRL.Reserve(auth.ClientIP(r, pt)) },
	})

	// Allocated only when the endpoint is on, so nothing is counted that nothing
	// can read; every method on it is nil-safe.
	var met *metrics
	if cfg.Metrics.Enabled {
		met = &metrics{}
		log.Info("metrics enabled", "path", metricsPath,
			"token", cfg.Metrics.Token != "", "allow_cidrs", len(cfg.Metrics.AllowCIDRs))
	}

	baseCtx, baseCtxCancel := context.WithCancel(context.Background())
	s := &Server{
		cfg:      cfg,
		log:      log,
		sessions: sm,
		storage:  meta,
		// The durable store, when that is what was built. Metrics reads its
		// degradation counter; the manager only ever sees the interface.
		metaSessions: durableSessions(store),
		audit:        auditLog,
		metrics:      met,
		metricsNets:  metricsNets,
		rate:         rl,
		accountRate:  accountRL,
		sessionRate:  sessionRL,
		// Infallible by construction (a nil channel when <= 0), which is what
		// keeps New's "exactly one return after NewManager" discipline intact.
		importLimit: handlers.NewDBOpLimiter(cfg.MaxConcurrentImports),
		proxy:       pt,
		view:        renderer,
		handlers: &handlers.Handlers{
			View:        renderer,
			Sessions:    sm,
			Cfg:         cfg,
			Rate:        rl,
			Log:         log,
			Version:     version,
			Pools:       handlers.NewPoolBudget(cfg.PoolCap),
			DBOps:       handlers.NewDBOpLimiter(cfg.MaxConcurrentDBOps),
			Proxy:       pt,
			Audit:       auditLog,
			Counters:    &handlers.Counters{},
			AccountRate: accountRL,
			SSO:         ssoProvider,
		},
		staticH:       staticCache(renderer.AssetVersion(), buildStaticETags(staticSub), http.StripPrefix("/static/", http.FileServerFS(staticSub))),
		stopCh:        make(chan struct{}),
		baseCtx:       baseCtx,
		baseCtxCancel: baseCtxCancel,
	}

	s.httpSrv = &http.Server{
		Addr:              cfg.Listen,
		Handler:           s.chain(s.router()),
		ReadHeaderTimeout: 15 * time.Second,
		// ReadTimeout caps the whole request read (headers + body), bounding
		// slow-body uploads. No global WriteTimeout: exports stream and set their
		// own rolling per-write deadlines, and buffered page renders bound their
		// single write the same way — both clear the deadline afterwards so it
		// cannot linger on the keep-alive connection (see view.WriteTimeout).
		ReadTimeout: 2 * time.Minute,
		IdleTimeout: 90 * time.Second,
		ErrorLog:    slog.NewLogLogger(log.Handler(), slog.LevelError),
		// Parent every request context off baseCtx so a drain-timeout shutdown can
		// cancel in-flight requests (unsticking handlers blocked on a slow query
		// before the pools are force-closed).
		BaseContext: func(net.Listener) context.Context { return s.baseCtx },
	}
	if cfg.TLSEnabled() {
		s.httpSrv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	go s.sweepRateLimiter()
	return s, nil
}

// openAuditLog builds the audit trail the configuration calls for, or nil when
// none is configured. A destination that cannot be opened refuses startup: an
// audit requirement is not satisfied by a best effort, and an operator who asked
// for a trail must not be given a running server without one.
func openAuditLog(cfg config.Config, log *slog.Logger) (*audit.Logger, error) {
	if !cfg.Audit.Enabled() {
		return nil, nil
	}
	var sinks []audit.Sink
	if path := strings.TrimSpace(cfg.Audit.File); path != "" {
		f, err := audit.OpenFile(path, cfg.Audit.MaxBytes)
		if err != nil {
			return nil, err
		}
		// Out of band: a rotation whose rename failed but whose event still
		// landed is a warning, not a dropped record — Write's error return
		// (which the Logger counts as a drop) must not carry it.
		f.SetFailureReporter(func(err error) {
			log.Warn("audit rotation failed; the trail continues on the un-rotated file", "err", err)
		})
		sinks = append(sinks, f)
	}
	if cfg.Audit.Log {
		sinks = append(sinks, audit.NewLogSink(log))
	}
	log.Info("audit trail enabled", "file", cfg.Audit.File, "log", cfg.Audit.Log, "statements", cfg.Audit.Statements)
	return audit.New(log, sinks...), nil
}

// openSessionStore builds the session store the configuration calls for: the
// in-memory one by default, or a durable one over TableX's own metadata database
// when [storage] names an engine. The returned *storage.Store is nil in the
// first case and is the handle the server closes on shutdown in the second.
func openSessionStore(cfg config.Config, log *slog.Logger) (session.Store, *storage.Store, error) {
	if !cfg.Storage.Enabled() {
		return session.NewMemStore(), nil, nil
	}
	sc := cfg.Storage
	meta, err := storage.Open(context.Background(), storage.Config{
		Engine:      sc.Engine,
		Host:        sc.Host,
		Port:        sc.Port,
		Socket:      sc.Socket,
		User:        sc.User,
		Password:    sc.Password,
		Database:    sc.Database,
		FilePath:    sc.FilePath,
		SSLMode:     sc.SSLMode,
		Params:      sc.Params,
		TablePrefix: sc.TablePrefix,
	})
	if err != nil {
		return nil, nil, err
	}
	log.Info("session storage ready", "metadata", meta.Describe())
	return storage.NewSessionStore(meta, storage.SessionStoreConfig{
		IdleTimeout: cfg.Session.IdleTimeout,
		MaxSessions: sc.MaxSessions,
		Log:         log,
	}), meta, nil
}

// durableSessions returns the durable session store behind a session.Store, or
// nil for the in-memory one. Only /metrics needs to tell them apart — everything
// else deliberately talks to the interface — and a nil *storage.SessionStore
// answers its counter as zero, so the caller needs no second check.
func durableSessions(store session.Store) *storage.SessionStore {
	s, _ := store.(*storage.SessionStore)
	return s
}

// sweepRateLimiter periodically reclaims expired entries from BOTH login
// limiters (keys are otherwise only pruned when the same key is Reserved
// again). It stops on Shutdown.
//
// Both, because every key in both maps is attacker-chosen and neither is
// reclaimed by traffic alone: prune only runs for a key someone reserves a
// second time, and Reset only fires on a SUCCESSFUL login. The account map is
// the worse of the two — a distinct username per attempt plants a permanent
// entry each time, and loginAccountKey runs before the server name is
// validated, so the predefined-server branch is attacker-chosen too and the
// growth is not gated on allow_adhoc.
//
// Sweeping cannot erase a live lockout: prune drops only timestamps older than
// the window, and deletes a key only when none remain.
func (s *Server) sweepRateLimiter() {
	// Floor at 1 minute so a tiny window doesn't spin the sweeper; cap at 5
	// minutes so a large LoginRateWindow can't defer memory reclamation
	// indefinitely (expired keys are otherwise only pruned when next accessed).
	interval := min(max(s.cfg.Security.LoginRateWindow, time.Minute), 5*time.Minute)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-s.stopCh:
			return
		case <-t.C:
			s.rate.Sweep()
			s.accountRate.Sweep()
			s.sessionRate.Sweep()
		}
	}
}

// Handler returns the fully-wrapped HTTP handler (middleware chain + router),
// used by httptest in integration tests.
func (s *Server) Handler() http.Handler { return s.httpSrv.Handler }

// TLS reports whether the server serves HTTPS directly.
func (s *Server) TLS() bool { return s.cfg.TLSEnabled() }

// Listen binds the configured address and returns the listener, so the caller
// can log the ACTUAL bound address (which differs from cfg.Listen for a ":0"
// ephemeral port) only after the bind has succeeded — a bind failure surfaces
// here instead of after an already-emitted "listening" line. Pair with Serve.
func (s *Server) Listen() (net.Listener, error) {
	return net.Listen("tcp", s.cfg.Listen)
}

// Serve serves HTTP(S) on ln and blocks until the server stops. TLS is used when
// configured. http.ErrServerClosed (from a clean Shutdown) is success.
func (s *Server) Serve(ln net.Listener) error {
	if s.cfg.TLSEnabled() {
		return s.httpSrv.ServeTLS(ln, s.cfg.TLSCert, s.cfg.TLSKey)
	}
	return s.httpSrv.Serve(ln)
}

// Shutdown drains in-flight requests, then closes every session's DB pools so
// credentials don't linger. It is safe to call more than once.
//
// If the drain times out (a handler stuck past the ctx budget), it cancels every
// in-flight request context and force-closes the HTTP server so those handlers
// unwind, THEN still closes all session pools. Skipping the pool close on a
// timeout would leak OS-level DB connections and keep every session's credentials
// reachable in server-side memory — sessions.Shutdown() is the only server-exit
// path that closes all pools and drops the session-store references that hold
// them.
func (s *Server) Shutdown(ctx context.Context) error {
	// Always release the base context (it's harmless once requests have drained,
	// and it unsticks any still-running handler on the timeout path).
	defer s.baseCtxCancel()
	s.shutdownOnce.Do(func() { close(s.stopCh) })
	err := s.httpSrv.Shutdown(ctx)
	if err != nil {
		// Drain timed out: unstick in-flight requests, then force-close listeners
		// and connections so stuck handlers stop before we close their pools.
		s.baseCtxCancel()
		_ = s.httpSrv.Close()
	}
	// sessions.Shutdown() is itself idempotent (sync.Once), so the force-close
	// path above and an accidental second Shutdown both close every pool exactly
	// once.
	s.sessions.Shutdown()
	// The metadata pool closes AFTER the sessions, because releasing a session
	// may still write to it. Its rows deliberately survive: a session's identity
	// is durable, so a restart (or one replica of several going away) leaves
	// them for whoever serves the next request. Closing twice is harmless —
	// database/sql's Close is idempotent — which keeps this safe on the
	// force-close path above.
	if s.storage != nil {
		if cerr := s.storage.Close(); cerr != nil {
			s.log.Warn("closing the metadata database", "err", cerr)
		}
	}
	// The audit trail closes last, so anything the shutdown above audits is still
	// written. A close error is worth reporting: it can mean a buffered final
	// event never reached the disk.
	if cerr := s.audit.Close(); cerr != nil {
		s.log.Error("closing the audit trail", "err", cerr)
	}
	return err
}

// buildStaticETags precomputes a strong content ETag per embedded static asset,
// keyed by its request path (/static/<name>). Embedded files carry a zero
// ModTime, so http.FileServerFS emits no Last-Modified/ETag validator and a
// client re-downloads the whole ~700 KB of vendor JS/CSS once max-age expires; a
// content ETag lets it revalidate to a cheap 304 instead.
func buildStaticETags(staticSub fs.FS) map[string]string {
	etags := map[string]string{}
	_ = fs.WalkDir(staticSub, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		data, rerr := fs.ReadFile(staticSub, p)
		if rerr != nil {
			return nil
		}
		sum := sha256.Sum256(data)
		etags["/static/"+p] = `"` + hex.EncodeToString(sum[:8]) + `"`
		return nil
	})
	return etags
}

// staticCache serves embedded assets with a long cache lifetime plus a content
// ETag, and answers a matching If-None-Match with 304 so the asset is not
// re-downloaded after max-age (they are versioned by the binary, so the ETag is
// stable for a given build).
//
// It is also the /static/ allowlist: the ETag map enumerates every real
// embedded file, so any other path — notably directory paths, which
// http.FileServerFS would answer with an unauthenticated rendered listing —
// 404s before reaching the FileServer. The vendor MANIFEST (exact vendored
// versions + upstream source URLs) is denied by name: it is a real embedded
// file that stays in the repo and the binary for provenance (the vendored
// assets carry their own license banners), but it has no business being
// publicly served.
// A request whose ?v= matches the build's asset fingerprint is cached for a year
// and marked immutable: the templates stamp that fingerprint on every asset URL,
// so a new build asks for a different URL rather than waiting for a max-age to
// lapse. Anything else — a bookmarked bare path, an old v from a previous build —
// keeps the short lifetime, because freezing a URL whose content may change is
// how a client ends up pinned to a stale asset it will never re-request.
func staticCache(assetVer string, etags map[string]string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		etag, ok := etags[r.URL.Path]
		if !ok || r.URL.Path == "/static/vendor/MANIFEST" {
			http.NotFound(w, r)
			return
		}
		if assetVer != "" && r.URL.Query().Get("v") == assetVer {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			w.Header().Set("Cache-Control", "public, max-age=3600")
		}
		w.Header().Set("ETag", etag)
		if etagMatches(r.Header.Get("If-None-Match"), etag) {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// etagMatches reports whether an If-None-Match header (a comma-separated list of
// entity tags, or "*") matches etag.
func etagMatches(ifNoneMatch, etag string) bool {
	if ifNoneMatch == "" {
		return false
	}
	if strings.TrimSpace(ifNoneMatch) == "*" {
		return true
	}
	for _, t := range strings.Split(ifNoneMatch, ",") {
		t = strings.TrimSpace(t)
		if t == etag || strings.TrimPrefix(t, "W/") == etag {
			return true
		}
	}
	return false
}
