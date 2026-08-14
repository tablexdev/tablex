// Package session provides TableX's server-side session management: opaque
// 256-bit IDs (crypto/rand), a pluggable store, idle/absolute timeouts, CSRF
// token issuance, and login-time re-keying to prevent fixation — Authenticate
// mints a NEW session (fresh ID + CSRF, payload attached before the object is
// shared) and atomically replaces the pre-auth one, so the pre-auth ID can
// never become authenticated. Database credentials and live pools live only
// inside the session payload (server-side memory) — never in the cookie. See
// docs/security.md.
package session

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"sync"
	"time"
)

// Session is one authenticated (or pending) session. App holds the
// application-specific payload (the user's connection manager); closeFn is run
// exactly once when the session is destroyed or reaped, to release pools.
type Session struct {
	ID       string
	CSRF     string
	Created  time.Time
	LastSeen time.Time

	mu      sync.Mutex
	app     any
	closeFn func()
	closed  bool
	sso     SSO
}

// SSO is the state of an external identity handshake, and then its result.
//
// It lives on the session because the session cookie is the only thing that
// spans the redirect out to the provider and back — there is nowhere else to keep
// a per-browser nonce. The handshake fields are opaque to this package; what it
// guarantees is that they are stored per session and that Authenticate keeps only
// the VERIFIED half when it mints the post-login session.
type SSO struct {
	// Pending handshake, meaningful only between the redirect out and the
	// callback. Spent as soon as the callback runs.
	State    string
	Nonce    string
	Verifier string

	// Verified identity. Subject is non-empty once the provider has vouched for
	// this browser; it is the answer to "which PERSON", and deliberately not to
	// "which database account" — the connection still uses the user's own
	// credentials, so the audit trail keeps reporting the account.
	Subject string
	Email   string
	Name    string
}

// Verified reports whether an external identity has been established.
func (x SSO) Verified() bool { return x.Subject != "" }

// SSO returns a copy of this session's SSO state.
func (s *Session) SSO() SSO {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sso
}

// SetSSO replaces this session's SSO state.
func (s *Session) SetSSO(x SSO) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sso = x
}

// ConsumeSSOHandshake atomically compares the stored pending handshake
// against match and, on a match, returns the handshake fields and clears
// them — keeping the verified identity — all in ONE lock scope. On a
// mismatch (or with no pending handshake) everything is left intact.
//
// It exists because SSO() + SetSSO() are two separate lock acquisitions: two
// concurrent callbacks on one session cookie could both read the same
// handshake, both pass the state check against their own copies, and both
// reach the token exchange — the documented single-use guarantee held only
// for sequential callbacks. This is the single serialization point; exactly
// one caller can win. The comparison is a callback so this package stays
// free of the auth import (the caller supplies the constant-time compare).
func (s *Session) ConsumeSSOHandshake(match func(storedState string) bool) (state, nonce, verifier string, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sso.State == "" || !match(s.sso.State) {
		return "", "", "", false
	}
	state, nonce, verifier = s.sso.State, s.sso.Nonce, s.sso.Verifier
	s.sso.State, s.sso.Nonce, s.sso.Verifier = "", "", ""
	return state, nonce, verifier, true
}

// App returns the application payload (may be nil before login).
func (s *Session) App() any {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.app
}

// Token returns the session CSRF token. ID and CSRF are fixed at construction
// (Authenticate mints a NEW session rather than re-keying in place), so the
// locked read is uniformity with the mutable time fields, not a correctness
// requirement.
func (s *Session) Token() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.CSRF
}

// snapshotID returns the session ID (see Token for the locking rationale).
// The lock is released before the caller's store call so the store→session
// lock order is preserved.
func (s *Session) snapshotID() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ID
}

// close runs the close function once. It also drops the references to the
// payload and close hook under the lock: the payload (UserContext) holds the
// login params — including the password string — so releasing it here makes the
// credentials GC-eligible promptly once the pools are closed, rather than
// lingering until the session struct itself is collected. App() also takes
// s.mu, so a request racing close() sees a clean nil payload, not a closed one.
func (s *Session) close() {
	s.mu.Lock()
	fn := s.closeFn
	if s.closed || fn == nil {
		s.mu.Unlock()
		return
	}
	s.closed = true
	s.app = nil
	s.closeFn = nil
	s.mu.Unlock()
	fn()
}

// Config tunes the manager.
type Config struct {
	CookieName      string
	IdleTimeout     time.Duration
	AbsoluteTimeout time.Duration
	Secure          bool // set Secure + __Host- prefix (TLS deployments)
	// Now, when non-nil, replaces time.Now as the manager's clock — the
	// test-only injection point that lets expiry tests advance time
	// deterministically instead of racing the wall clock. It MUST be set at
	// construction (NewManager launches the reaper goroutine, which reads it);
	// assigning it afterwards would be a data race. Implementations must be
	// safe for concurrent use.
	Now func() time.Time
	// Admit, when non-nil, is consulted before a NEW session is created — never
	// before an existing one is loaded. Returning false makes Start return nil,
	// which the callers already treat as "the server is at session capacity".
	//
	// It lives here, and is invoked INSIDE Start, because the middleware cannot
	// tell a creation from a load without calling Load itself — and Load is not a
	// pure query: it deletes an expired session and rewrites LastSeen, so calling
	// it twice would double those side effects and still race. It takes the whole
	// request because a client key has to be resolved with the deployment's own
	// proxy-trust rules; a RemoteAddr string cannot reproduce them and carries an
	// ephemeral source port besides. Must be safe for concurrent use.
	Admit func(r *http.Request) bool
}

// Manager creates, loads, rotates and destroys sessions, and runs a background
// reaper that closes expired sessions' pools.
type Manager struct {
	store    Store
	cfg      Config
	stopCh   chan struct{}
	stopOnce sync.Once
}

// NewManager builds a Manager over the given store and starts the reaper.
func NewManager(store Store, cfg Config) *Manager {
	if cfg.CookieName == "" {
		cfg.CookieName = "tablex_session"
	}
	if cfg.IdleTimeout == 0 {
		cfg.IdleTimeout = 30 * time.Minute
	}
	if cfg.AbsoluteTimeout == 0 {
		cfg.AbsoluteTimeout = 8 * time.Hour
	}
	m := &Manager{store: store, cfg: cfg, stopCh: make(chan struct{})}
	go m.reaper()
	return m
}

// now is the manager's clock: cfg.Now when injected (tests), time.Now
// otherwise. EVERY expiry-governing time read goes through it — a partial
// injection would still race the wall clock.
func (m *Manager) now() time.Time {
	if m.cfg.Now != nil {
		return m.cfg.Now()
	}
	return time.Now()
}

// cookieName returns the cookie name, applying the __Host- prefix under TLS so
// the browser enforces host-only, Secure, Path=/ scoping.
func (m *Manager) cookieName() string {
	if m.cfg.Secure {
		return "__Host-" + m.cfg.CookieName
	}
	return m.cfg.CookieName
}

// newID returns a 256-bit URL-safe random identifier.
func newID() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("session: crypto/rand failed: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func (m *Manager) newSession() *Session {
	now := m.now()
	return &Session{ID: newID(), CSRF: newID(), Created: now, LastSeen: now}
}

// Envelope is a session's durable identity: everything a Store may keep outside
// this process, and nothing it may not. There is no field for a credential, and
// none for the payload — see Adopt.
type Envelope struct {
	ID       string
	CSRF     string
	Created  time.Time
	LastSeen time.Time
}

// Envelope snapshots the session's durable identity.
//
// A durable Store must read the timestamps through this rather than straight off
// the struct: Load writes LastSeen on every request, so a direct read of a
// session that has been published races it.
func (s *Session) Envelope() Envelope {
	s.mu.Lock()
	defer s.mu.Unlock()
	return Envelope{ID: s.ID, CSRF: s.CSRF, Created: s.Created, LastSeen: s.LastSeen}
}

// Adopt rebuilds a Session from an envelope a durable Store has kept outside
// this process. It exists for those Store implementations and has no other
// caller.
//
// The result deliberately carries NO payload. A payload holds live database
// pools and the password the user typed, neither of which can be persisted
// (internal/storage explains why), so a session adopted by a process that did
// not log it in is a valid session which is not logged in — precisely how the
// rest of the application already reads a nil App(). What it does carry is the
// identity: the same id and the same CSRF token, which is what lets a login
// posted to one replica be accepted by another.
func Adopt(e Envelope) *Session {
	return &Session{ID: e.ID, CSRF: e.CSRF, Created: e.Created, LastSeen: e.LastSeen}
}

func (m *Manager) expired(s *Session, now time.Time) bool {
	// Snapshot the time fields under the per-session lock: the reaper calls this
	// while Load may be writing LastSeen (data race otherwise; CI runs -race).
	s.mu.Lock()
	lastSeen, created := s.LastSeen, s.Created
	s.mu.Unlock()
	return now.Sub(lastSeen) > m.cfg.IdleTimeout || now.Sub(created) > m.cfg.AbsoluteTimeout
}

// Load returns the live session referenced by the request cookie, or nil if
// none/expired. It refreshes LastSeen on a hit.
func (m *Manager) Load(r *http.Request) *Session {
	c, err := r.Cookie(m.cookieName())
	if err != nil {
		return nil
	}
	s, ok := m.store.Get(c.Value)
	if !ok {
		return nil
	}
	now := m.now()
	if m.expired(s, now) {
		m.store.Delete(s.snapshotID())
		s.close()
		return nil
	}
	s.mu.Lock()
	s.LastSeen = now
	s.mu.Unlock()
	return s
}

// Start returns the existing session, or creates a fresh one and sets the
// cookie — or returns NIL when Config.Admit declines the creation, which is how
// a per-client cap on session CREATION is expressed without changing this
// signature (15 call sites) or adding per-request bookkeeping.
//
// Admission is keyed on the creation event and NOT on cookie absence: Load
// returns nil for a missing, invalid OR expired cookie, so a check for "no
// cookie" is defeated by sending garbage.
func (m *Manager) Start(w http.ResponseWriter, r *http.Request) *Session {
	if s := m.Load(r); s != nil {
		return s
	}
	// After the single Load, before anything is created: charged once per
	// genuine creation attempt. Both fallback callers are guarded by
	// currentSession, so a request whose session the middleware already created
	// never reaches here twice.
	if m.cfg.Admit != nil && !m.cfg.Admit(r) {
		return nil
	}
	s := m.newSession()
	m.store.Save(s)
	m.setCookie(w, s.ID)
	return s
}

// Authenticate atomically turns a pre-auth session into an authenticated one
// on successful login. It constructs a NEW session — fresh ID and CSRF token
// (anti-fixation: a pre-login ID or token must never survive into the
// authenticated session), with the payload attached before the object is ever
// shared — then atomically replaces preAuth in the store (Store.Replace
// membership-checks the exact pointer, so a pre-auth session that was evicted,
// reaped or destroyed since it was loaded fails cleanly) and sets the cookie.
//
// This is the ONLY attach path: the pre-auth object and ID never carry a
// payload, so there is no window in which a fixation-prone ID authenticates
// requests, no attach→re-key gap a terminal removal could interleave with,
// and capacity eviction's "pre-auth sessions hold no pools" invariant holds
// by construction. On ok=false nothing was attached or saved — the caller
// still owns the payload and must close it (honest backpressure at the
// session cap instead of an evictable fresh-session retry).
func (m *Manager) Authenticate(w http.ResponseWriter, preAuth *Session, app any, closeFn func()) (*Session, bool) {
	if preAuth == nil {
		return nil, false
	}
	s := m.newSession()
	// Construction-time attachment — the session is not shared yet, so the
	// fields are set directly; after Replace publishes it, App() reads them
	// under the session lock as usual.
	s.app = app
	s.closeFn = closeFn
	// Carry the VERIFIED identity across, and only that: the handshake fields are
	// spent, and copying them would leave a usable nonce on a live session. This
	// has to happen here because Authenticate deliberately replaces the session
	// object rather than re-keying it, so anything on the pre-auth session is
	// otherwise dropped — including the one thing that says which person passed
	// the gate.
	if v := preAuth.SSO(); v.Verified() {
		s.sso = SSO{Subject: v.Subject, Email: v.Email, Name: v.Name}
	}
	if !m.store.Replace(preAuth, s) {
		return nil, false
	}
	// Replace succeeds only when the stored session was the exact preAuth
	// pointer, so the displaced session is preAuth itself. Close it here —
	// Replace is the one removal path the store does not close for us — so a
	// payload-bearing session displaced by a re-login releases its pools and
	// budget slots instead of leaking them. For a normal login the pre-auth
	// session carries no payload and close() is a no-op. Runs outside the
	// store lock (store→session lock order preserved).
	preAuth.close()
	m.setCookie(w, s.ID)
	return s, true
}

// Destroy removes the session, closes its pools and clears the cookie.
//
// The cookie is cleared FIRST and unconditionally. A session that expired or was
// reaped between the request arriving and logout running leaves s == nil, and
// returning early there left the browser holding a dead session cookie it would
// re-send on every subsequent request — logout appeared to do nothing.
func (m *Manager) Destroy(w http.ResponseWriter, s *Session) {
	http.SetCookie(w, &http.Cookie{
		Name:     m.cookieName(),
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   m.cfg.Secure,
		SameSite: http.SameSiteLaxMode,
	})
	if s == nil {
		return
	}
	m.store.Delete(s.snapshotID())
	s.close()
}

func (m *Manager) setCookie(w http.ResponseWriter, id string) {
	http.SetCookie(w, &http.Cookie{
		Name:     m.cookieName(),
		Value:    id,
		Path:     "/",
		HttpOnly: true,
		Secure:   m.cfg.Secure,
		SameSite: http.SameSiteLaxMode,
	})
}

// reaper periodically removes expired sessions and closes their pools.
func (m *Manager) reaper() {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-m.stopCh:
			return
		case <-t.C:
			now := m.now()
			for _, s := range m.store.Reap(func(s *Session) bool { return m.expired(s, now) }) {
				s.close()
			}
		}
	}
}

// ActiveSessions reports how many sessions the store currently holds. After
// Shutdown (or a full reap) this is 0, since every reaped session is closed —
// making it a deterministic proxy for "all pools closed" in tests.
func (m *Manager) ActiveSessions() int { return m.store.Len() }

// Shutdown stops the reaper and closes all live sessions (graceful shutdown).
// It is idempotent: the server's shutdown path may call it more than once (e.g.
// after a drain timeout forces a second pass), and closing m.stopCh twice would
// otherwise panic.
func (m *Manager) Shutdown() {
	m.stopOnce.Do(func() {
		close(m.stopCh)
		for _, s := range m.detachAll() {
			s.close()
		}
	})
}

// detachAll removes every session THIS PROCESS holds and returns them so their
// pools can be closed.
//
// For the in-memory store that is the same thing as reaping everything. For a
// store whose membership is shared with other processes it is emphatically not:
// reaping everything there would end every session on every replica, so such a
// store implements Detacher to separate "release what I am holding" from "this
// session is over".
func (m *Manager) detachAll() []*Session {
	if d, ok := m.store.(Detacher); ok {
		return d.Detach()
	}
	return m.store.Reap(func(*Session) bool { return true })
}

// ---- request context plumbing ----

type ctxKey struct{}

// NewContext stashes a session in ctx.
func NewContext(ctx context.Context, s *Session) context.Context {
	return context.WithValue(ctx, ctxKey{}, s)
}

// FromContext retrieves the session stashed by the middleware.
func FromContext(ctx context.Context) (*Session, bool) {
	s, ok := ctx.Value(ctxKey{}).(*Session)
	return s, ok
}
