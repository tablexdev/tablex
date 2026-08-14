package session

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func newTestManager() *Manager {
	return NewManager(NewMemStore(), Config{
		CookieName:      "test_session",
		IdleTimeout:     time.Hour,
		AbsoluteTimeout: 24 * time.Hour,
	})
}

func TestStartCreatesSessionAndCookie(t *testing.T) {
	m := newTestManager()
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	s := m.Start(w, r)
	if s.ID == "" || s.CSRF == "" {
		t.Fatal("session should have an ID and CSRF token")
	}
	if len(s.ID) < 40 {
		t.Errorf("session ID too short (%d chars) for 256-bit", len(s.ID))
	}
	cookies := w.Result().Cookies()
	if len(cookies) == 0 || cookies[0].Value != s.ID {
		t.Fatal("Start should set the session cookie")
	}
	if !cookies[0].HttpOnly {
		t.Error("cookie must be HttpOnly")
	}
}

func TestLoadReturnsSession(t *testing.T) {
	m := newTestManager()
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	s := m.Start(w, r)

	r2 := httptest.NewRequest("GET", "/", nil)
	r2.AddCookie(&http.Cookie{Name: "test_session", Value: s.ID})
	got := m.Load(r2)
	if got == nil || got.ID != s.ID {
		t.Fatal("Load should return the same session")
	}
}

// TestAuthenticateReKeys covers the login re-key contract: Authenticate mints
// a NEW session with a fresh ID and CSRF token, the payload lands only on the
// new session (the pre-auth object never observes App() != nil — the fixation
// window is zero by construction), the old ID stops loading, and the cookie
// carries the new ID.
func TestAuthenticateReKeys(t *testing.T) {
	m := newTestManager()
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	pre := m.Start(w, r)
	oldID, oldCSRF := pre.ID, pre.CSRF

	w2 := httptest.NewRecorder()
	s, ok := m.Authenticate(w2, pre, "payload", nil)
	if !ok || s == nil {
		t.Fatal("Authenticate on a live pre-auth session must succeed")
	}
	if s.ID == oldID {
		t.Error("Authenticate must issue a new ID (anti-fixation)")
	}
	if s.CSRF == oldCSRF || s.CSRF == "" {
		t.Error("Authenticate must issue a fresh CSRF token (a pre-login token must not survive into the authenticated session)")
	}
	if s.App() != "payload" {
		t.Error("payload missing from the authenticated session")
	}
	// A request that pre-loaded the pre-auth pointer must NEVER see it
	// authenticated: the payload only ever exists on the new session.
	if pre.App() != nil {
		t.Error("the pre-auth session observed a payload")
	}
	// Old ID no longer resolves; the new one does.
	r2 := httptest.NewRequest("GET", "/", nil)
	r2.AddCookie(&http.Cookie{Name: "test_session", Value: oldID})
	if m.Load(r2) != nil {
		t.Error("old session ID should be invalid after login")
	}
	r3 := httptest.NewRequest("GET", "/", nil)
	r3.AddCookie(&http.Cookie{Name: "test_session", Value: s.ID})
	if got := m.Load(r3); got != s {
		t.Error("new session ID should load the authenticated session")
	}
	cookies := w2.Result().Cookies()
	if len(cookies) == 0 || cookies[0].Value != s.ID {
		t.Error("Authenticate should set the cookie to the new ID")
	}
}

// TestAuthenticateAfterRemoval: a pre-auth session that was destroyed, reaped
// or capacity-evicted between Start and login must fail Authenticate cleanly —
// nothing attached, nothing saved, the caller closes its own payload exactly
// once. These logical races are lock-clean (the membership check under the
// store lock decides), so they are pinned deterministically, not via -race.
func TestAuthenticateAfterRemoval(t *testing.T) {
	remove := map[string]func(m *Manager, pre *Session){
		"destroy": func(m *Manager, pre *Session) { m.Destroy(httptest.NewRecorder(), pre) },
		"reap":    func(m *Manager, pre *Session) { m.store.Reap(func(*Session) bool { return true }) },
		"evict": func(m *Manager, pre *Session) {
			for i := range maxSessions + 1 { // flood past the cap: pre-auth sessions evict FIFO
				m.store.Save(&Session{ID: "flood-" + strconv.Itoa(i)})
			}
		},
	}
	for name, kill := range remove {
		m := newTestManager()
		pre := m.Start(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))
		kill(m, pre)

		closes := 0
		s, ok := m.Authenticate(httptest.NewRecorder(), pre, "payload", func() { closes++ })
		if ok || s != nil {
			t.Errorf("%s: Authenticate on a removed session must fail", name)
		}
		// The caller owns the payload on failure and closes it exactly once.
		if closes != 0 {
			t.Errorf("%s: Authenticate closed the caller-owned payload itself", name)
		}
	}
}

// TestAuthenticateSingleWinner: concurrent Authenticate calls on ONE pre-auth
// session (a double-submitted login form) — exactly one Replace succeeds; each
// loser keeps ownership of its payload and closes it exactly once.
func TestAuthenticateSingleWinner(t *testing.T) {
	m := newTestManager()
	pre := m.Start(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))

	const workers = 16
	var wg sync.WaitGroup
	wins := make([]bool, workers)
	closes := make([]int, workers)
	for i := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			closeFn := func() { closes[i]++ }
			if _, ok := m.Authenticate(httptest.NewRecorder(), pre, i, closeFn); ok {
				wins[i] = true
			} else {
				closeFn() // the caller owns the losing payload
			}
		}()
	}
	wg.Wait()

	won := 0
	for i := range workers {
		if wins[i] {
			won++
			if closes[i] != 0 {
				t.Errorf("winner %d had its payload closed", i)
			}
		} else if closes[i] != 1 {
			t.Errorf("loser %d closed its payload %d times, want exactly 1", i, closes[i])
		}
	}
	if won != 1 {
		t.Errorf("%d Authenticate calls won, want exactly 1", won)
	}
	if pre.App() != nil {
		t.Error("the pre-auth session observed a payload")
	}
}

// TestAuthenticateClosesDisplacedSession: authenticating over an ALREADY
// authenticated (payload-bearing) session must close the displaced session's
// payload. Replace is the one store-removal path that does not run the close
// hook itself — before the fix the displaced UserContext's pools and
// process-wide budget slots leaked permanently on every re-login.
func TestAuthenticateClosesDisplacedSession(t *testing.T) {
	m := newTestManager()
	pre := m.Start(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))
	oldCloses := 0
	old, ok := m.Authenticate(httptest.NewRecorder(), pre, "old-payload", func() { oldCloses++ })
	if !ok {
		t.Fatal("first Authenticate failed")
	}

	newCloses := 0
	s, ok := m.Authenticate(httptest.NewRecorder(), old, "new-payload", func() { newCloses++ })
	if !ok || s == nil {
		t.Fatal("re-login Authenticate over a live authenticated session must succeed")
	}
	if oldCloses != 1 {
		t.Errorf("displaced session's close hook ran %d times, want exactly 1 (pool/budget leak otherwise)", oldCloses)
	}
	if newCloses != 0 {
		t.Error("the new session's payload must not be closed")
	}
	if old.App() != nil {
		t.Error("displaced session should have dropped its payload on close")
	}
	if s.App() != "new-payload" {
		t.Error("new session lost its payload")
	}
	// The displaced ID no longer loads; the new one does.
	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(&http.Cookie{Name: "test_session", Value: old.ID})
	if m.Load(r) != nil {
		t.Error("displaced session ID should be invalid after re-login")
	}
	r2 := httptest.NewRequest("GET", "/", nil)
	r2.AddCookie(&http.Cookie{Name: "test_session", Value: s.ID})
	if m.Load(r2) != s {
		t.Error("new session ID should load")
	}
}

func TestDestroyClosesAndClears(t *testing.T) {
	m := newTestManager()
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	pre := m.Start(w, r)
	closed := false
	s, ok := m.Authenticate(httptest.NewRecorder(), pre, "x", func() { closed = true })
	if !ok {
		t.Fatal("Authenticate failed")
	}

	w2 := httptest.NewRecorder()
	m.Destroy(w2, s)
	if !closed {
		t.Error("Destroy should run the close hook (release pools)")
	}
	r2 := httptest.NewRequest("GET", "/", nil)
	r2.AddCookie(&http.Cookie{Name: "test_session", Value: s.ID})
	if m.Load(r2) != nil {
		t.Error("destroyed session should not load")
	}
}

func TestIdleExpiry(t *testing.T) {
	m := NewManager(NewMemStore(), Config{CookieName: "s", IdleTimeout: 10 * time.Millisecond, AbsoluteTimeout: time.Hour})
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	closed := false
	pre := m.Start(w, r)
	s, ok := m.Authenticate(httptest.NewRecorder(), pre, "x", func() { closed = true })
	if !ok {
		t.Fatal("Authenticate failed")
	}
	time.Sleep(25 * time.Millisecond)

	r2 := httptest.NewRequest("GET", "/", nil)
	r2.AddCookie(&http.Cookie{Name: "s", Value: s.ID})
	if m.Load(r2) != nil {
		t.Error("idle-expired session should not load")
	}
	if !closed {
		t.Error("expired session should have its pools closed")
	}
}

// fakeClock is a mutex-guarded manual clock for Config.Now: the reaper
// goroutine reads it concurrently with the test's Advance calls.
type fakeClock struct {
	mu  sync.Mutex
	cur time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cur
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cur = c.cur.Add(d)
}

// TestAbsoluteTimeoutDeterministic covers 5.1: the ABSOLUTE timeout expires a
// session even while activity keeps refreshing LastSeen, driven entirely by
// the injected clock — no sleeps, no wall-clock race (its HTTP-level
// predecessor admitted past CI flakiness).
func TestAbsoluteTimeoutDeterministic(t *testing.T) {
	clock := &fakeClock{cur: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	m := NewManager(NewMemStore(), Config{
		CookieName:      "s",
		IdleTimeout:     time.Hour,
		AbsoluteTimeout: 2 * time.Hour,
		Now:             clock.Now,
	})
	defer m.Shutdown()

	pre := m.Start(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))
	closed := false
	s, ok := m.Authenticate(httptest.NewRecorder(), pre, "x", func() { closed = true })
	if !ok {
		t.Fatal("Authenticate failed")
	}
	load := func() *Session {
		r := httptest.NewRequest("GET", "/", nil)
		r.AddCookie(&http.Cookie{Name: "s", Value: s.ID})
		return m.Load(r)
	}

	// Keep touching the session in sub-idle steps: each Load refreshes
	// LastSeen, so only the absolute clock is ticking down.
	clock.Advance(50 * time.Minute)
	if load() == nil {
		t.Fatal("session expired at 50m despite activity")
	}
	clock.Advance(50 * time.Minute)
	if load() == nil {
		t.Fatal("session expired at 1h40m despite activity")
	}
	// 2h10m total, but only 30m idle: the ABSOLUTE timeout must expire it.
	clock.Advance(30 * time.Minute)
	if load() != nil {
		t.Error("session survived past the absolute timeout")
	}
	if !closed {
		t.Error("absolute expiry did not close the session's pools")
	}
}

// TestStoreEvictsPreAuthFirst covers #8: at the capacity cap a pre-auth flood
// evicts the oldest pre-auth sessions (FIFO) and never the logged-in user —
// the authenticated session enters through Replace, exactly as Authenticate
// inserts it in production.
func TestStoreEvictsPreAuthFirst(t *testing.T) {
	st := NewMemStore()

	// One authenticated session, entering via the production path: a pre-auth
	// Save then an atomic Replace into the auth bucket.
	pre := &Session{ID: "pre-login"}
	st.Save(pre)
	authedClosed := false
	authed := &Session{ID: "authed", app: "payload", closeFn: func() { authedClosed = true }}
	if !st.Replace(pre, authed) {
		t.Fatal("Replace of a live pre-auth session failed")
	}

	// Flood with pre-auth sessions a few past the cap (accounting for the one
	// authenticated slot already taken).
	for i := range maxSessions + 5 {
		st.Save(&Session{ID: "pre-" + strconv.Itoa(i)})
	}

	if _, ok := st.Get("authed"); !ok {
		t.Error("authenticated session was evicted by a pre-auth flood")
	}
	if authedClosed {
		t.Error("authenticated session's close hook ran during a pre-auth flood")
	}
	// The oldest pre-auth sessions are gone; the newest remain.
	if _, ok := st.Get("pre-0"); ok {
		t.Error("oldest pre-auth session should have been evicted first (FIFO)")
	}
	if _, ok := st.Get("pre-" + strconv.Itoa(maxSessions+4)); !ok {
		t.Error("newest pre-auth session should still be present")
	}
}

// TestStoreDeleteAndReapKeepListsConsistent guards the #8 bookkeeping: a session
// removed via Delete/Reap is also detached from its FIFO list, so it can never
// be returned by a later capacity eviction.
func TestStoreDeleteAndReapKeepListsConsistent(t *testing.T) {
	st := NewMemStore()
	a, b := &Session{ID: "a"}, &Session{ID: "b"}
	st.Save(a)
	st.Save(b)
	st.Delete("a")
	// Reap b; both lists should now be empty, so a subsequent fill evicts nothing
	// stale (a panic or a returned-but-already-deleted session would surface here).
	reaped := st.Reap(func(s *Session) bool { return s.ID == "b" })
	if len(reaped) != 1 || reaped[0].ID != "b" {
		t.Fatalf("Reap returned %v, want [b]", reaped)
	}
	if _, ok := st.Get("a"); ok {
		t.Error("deleted session still present")
	}
	// Fill past the cap: every eviction must be a still-live session, never a
	// dangling list element for the already-removed a/b.
	for i := range maxSessions + 2 {
		st.Save(&Session{ID: "x-" + strconv.Itoa(i)})
	}
}

// TestManagerShutdownIdempotent covers #6/#7: Shutdown must close every live
// session's pools exactly once and never panic on a second call (close of a
// closed channel).
func TestManagerShutdownIdempotent(t *testing.T) {
	m := newTestManager()
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	pre := m.Start(w, r)
	closes := 0
	if _, ok := m.Authenticate(httptest.NewRecorder(), pre, "x", func() { closes++ }); !ok {
		t.Fatal("Authenticate failed")
	}

	m.Shutdown()
	m.Shutdown() // must not panic, must not double-close

	if closes != 1 {
		t.Errorf("session close hook ran %d times, want exactly 1", closes)
	}
}

// TestDestroyClearsCookieWithoutSession covers: Destroy returned before
// clearing the cookie when s was nil, so a caller destroying an
// already-reaped session left the browser holding a dead cookie it would
// re-send on every request. The HTTP logout path happens to always hand
// Destroy a live session (sessionMW creates one when the cookie is stale), so
// only a direct call reaches the branch — which is exactly why it has to be
// right rather than incidentally unreachable.
func TestDestroyClearsCookieWithoutSession(t *testing.T) {
	m := newTestManager()
	w := httptest.NewRecorder()
	m.Destroy(w, nil)

	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("Destroy(nil) set %d cookies, want exactly the clearing one", len(cookies))
	}
	c := cookies[0]
	if c.Name != m.cookieName() {
		t.Errorf("cleared cookie name = %q, want %q", c.Name, m.cookieName())
	}
	if c.Value != "" || c.MaxAge >= 0 {
		t.Errorf("cookie was not cleared: value=%q MaxAge=%d", c.Value, c.MaxAge)
	}
}

// TestConsumeSSOHandshakeIsAtomic pins the single-serialization-point
// property the concurrent-callback race needs: many goroutines race to
// consume one handshake, and exactly ONE gets it — with the verified
// identity always preserved and a state MISMATCH leaving everything intact.
func TestConsumeSSOHandshakeIsAtomic(t *testing.T) {
	m := newTestManager()
	s := m.Start(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))
	s.SetSSO(SSO{State: "the-state", Nonce: "n", Verifier: "v", Subject: "sub", Email: "e@x", Name: "N"})

	// A mismatch consumes nothing.
	if _, _, _, ok := s.ConsumeSSOHandshake(func(stored string) bool { return stored == "wrong" }); ok {
		t.Fatal("a state mismatch consumed the handshake")
	}
	if got := s.SSO(); got.State != "the-state" || got.Subject != "sub" {
		t.Fatalf("a mismatch mutated the session: %+v", got)
	}

	const racers = 16
	var wins int64
	var wg sync.WaitGroup
	for range racers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			state, nonce, verifier, ok := s.ConsumeSSOHandshake(func(stored string) bool { return stored == "the-state" })
			if ok {
				atomicAdd(&wins, 1)
				if state != "the-state" || nonce != "n" || verifier != "v" {
					t.Errorf("winner got wrong fields: %q %q %q", state, nonce, verifier)
				}
			}
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Errorf("%d of %d racers consumed the handshake, want exactly 1", wins, racers)
	}
	// The handshake is spent; the verified identity survives.
	after := s.SSO()
	if after.State != "" || after.Nonce != "" || after.Verifier != "" {
		t.Errorf("the handshake was not cleared after consumption: %+v", after)
	}
	if after.Subject != "sub" || after.Email != "e@x" || after.Name != "N" {
		t.Errorf("the verified identity was lost: %+v", after)
	}
}

func atomicAdd(p *int64, d int64) { atomic.AddInt64(p, d) }
