package storage_test

import (
	"context"
	"log/slog"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/tablexdev/tablex/internal/session"
	"github.com/tablexdev/tablex/internal/storage"
)

// The session policy the tests apply. It mirrors what session.Manager does, so
// what is asserted here is the behaviour the manager will actually get.
const (
	testIdle     = 30 * time.Minute
	testAbsolute = 8 * time.Hour
)

// expiredBy builds the predicate session.Manager passes to Reap.
func expiredBy(now time.Time) func(*session.Session) bool {
	return func(s *session.Session) bool {
		return now.Sub(s.LastSeen) > testIdle || now.Sub(s.Created) > testAbsolute
	}
}

// clock is a settable clock for the touch-throttle tests.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// replica builds a durable session store over st, standing in for one TableX
// process. Two replicas over the same *storage.Store share the database and
// nothing else, which is exactly the situation behind a load balancer.
func replica(st *storage.Store) *storage.SessionStore {
	return storage.NewSessionStore(st, storage.SessionStoreConfig{IdleTimeout: testIdle})
}

// managerOn wires a real session.Manager onto a store, so the tests exercise the
// production call sequence (Start → Authenticate → Shutdown) rather than
// hand-rolled equivalents.
func managerOn(t *testing.T, store session.Store) *session.Manager {
	t.Helper()
	m := session.NewManager(store, session.Config{IdleTimeout: testIdle, AbsoluteTimeout: testAbsolute})
	t.Cleanup(m.Shutdown)
	return m
}

// startSession creates a pre-auth session through the manager and returns it.
func startSession(t *testing.T, m *session.Manager) *session.Session {
	t.Helper()
	return m.Start(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))
}

// TestSessionIdentitySurvivesARestart is the headline claim. The pools do not
// survive — they cannot — but the id and the CSRF token do, which is what lets a
// form issued before the restart still validate afterwards.
func TestSessionIdentitySurvivesARestart(t *testing.T) {
	st, path := openTemp(t)
	before := replica(st)
	m := managerOn(t, before)
	pre := startSession(t, m)
	id, csrf := pre.ID, pre.CSRF

	m.Shutdown()
	if err := st.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// A new process, on the same metadata database.
	after := replica(openAt(t, path))
	got, ok := after.Get(id)
	if !ok {
		t.Fatal("the session did not survive the restart")
	}
	if got.ID != id {
		t.Errorf("adopted id = %q, want %q", got.ID, id)
	}
	if got.Token() != csrf {
		t.Errorf("adopted CSRF = %q, want %q — a form issued before the restart would be rejected", got.Token(), csrf)
	}
	if got.App() != nil {
		t.Error("the adopted session carries a payload; the credentials and pools must NOT have been persisted")
	}
}

// TestAnotherReplicaAdoptsTheEnvelope is the load-balancer case: replica A
// issues a session, replica B has to accept the same id and token.
func TestAnotherReplicaAdoptsTheEnvelope(t *testing.T) {
	st, _ := openTemp(t)
	a, b := replica(st), replica(st)
	m := managerOn(t, a)
	pre := startSession(t, m)

	got, ok := b.Get(pre.ID)
	if !ok {
		t.Fatal("replica B does not know a session replica A created; a login posted to B would fail CSRF")
	}
	if got.Token() != pre.CSRF {
		t.Errorf("replica B's CSRF = %q, want %q", got.Token(), pre.CSRF)
	}
	// Adoption is local caching, not a second row.
	if n := countSessions(t, st); n != 1 {
		t.Errorf("stored sessions = %d, want 1 — adopting must not insert a row", n)
	}
	// And it is stable: the second lookup returns the same object.
	again, _ := b.Get(pre.ID)
	if again != got {
		t.Error("replica B adopted the session twice instead of caching it")
	}
}

// TestDeleteEndsTheSessionEverywhere pins the authority rule. A logout has to
// take effect on every replica, not just the one that handled it.
func TestDeleteEndsTheSessionEverywhere(t *testing.T) {
	st, _ := openTemp(t)
	a, b := replica(st), replica(st)
	m := managerOn(t, a)
	pre := startSession(t, m)

	if _, ok := b.Get(pre.ID); !ok {
		t.Fatal("fixture: replica B should see the session first")
	}
	b.Delete(pre.ID) // logout handled by B

	if _, ok := a.Get(pre.ID); ok {
		t.Error("replica A still accepts a session logged out on replica B")
	}
	if n := countSessions(t, st); n != 0 {
		t.Errorf("stored sessions = %d, want 0", n)
	}
}

// TestReplaceIsAtomicAcrossReplicas checks the anti-fixation swap. The in-memory
// store enforces it with an exact-pointer check, which cannot see another
// process; here the row DELETE is the check, so a duplicate login must fail
// wherever it lands.
func TestReplaceIsAtomicAcrossReplicas(t *testing.T) {
	st, _ := openTemp(t)
	a, b := replica(st), replica(st)
	m := managerOn(t, a)
	pre := startSession(t, m)

	// Replica B has adopted the pre-auth session, as it would after a
	// round-robin hop.
	adopted, ok := b.Get(pre.ID)
	if !ok {
		t.Fatal("fixture: replica B should see the pre-auth session")
	}

	first, ok := m.Authenticate(httptest.NewRecorder(), pre, "payload-A", func() {})
	if !ok {
		t.Fatal("the first login was refused")
	}
	if first.ID == pre.ID {
		t.Error("the authenticated session kept the pre-auth id — session fixation")
	}
	// The same pre-auth session, submitted again on the other replica.
	if b.Replace(adopted, session.Adopt(session.Envelope{ID: "other", CSRF: "other", Created: time.Now(), LastSeen: time.Now()})) {
		t.Error("a second login on the SAME pre-auth session succeeded on another replica")
	}
	if n := countSessions(t, st); n != 1 {
		t.Errorf("stored sessions = %d, want 1 (the authenticated one only)", n)
	}
	// And the winner is the one that is stored.
	if _, ok := b.Get(first.ID); !ok {
		t.Error("the authenticated session is not visible to the other replica")
	}
}

// TestReapReturnsASessionEndedElsewhere is why Reap reads the table at all. A
// logout on another replica leaves this process holding live pools that nothing
// else can close, so the row's absence has to be treated as "finished" even
// though the local policy says the session is fine.
func TestReapReturnsASessionEndedElsewhere(t *testing.T) {
	st, _ := openTemp(t)
	a, b := replica(st), replica(st)
	m := managerOn(t, a)
	pre := startSession(t, m)
	authed, ok := m.Authenticate(httptest.NewRecorder(), pre, "payload", func() {})
	if !ok {
		t.Fatal("login refused")
	}
	if a.Len() != 1 {
		t.Fatalf("fixture: replica A holds %d sessions, want 1", a.Len())
	}

	b.Delete(authed.ID) // logged out on the other replica

	// The policy says nothing is expired; only the missing row can end it.
	dead := a.Reap(func(*session.Session) bool { return false })
	if len(dead) != 1 {
		t.Fatalf("Reap returned %d sessions, want the one whose row is gone (its pools would leak)", len(dead))
	}
	if dead[0].ID != authed.ID {
		t.Errorf("Reap returned %q, want %q", dead[0].ID, authed.ID)
	}
	if a.Len() != 0 {
		t.Errorf("replica A still holds %d sessions after reaping", a.Len())
	}
}

// TestReapCollectsAbandonedRows covers the other half of the sweep: rows behind
// no live session at all, left by a process that died. Nobody else will
// necessarily collect them, so every node applies the policy to them.
//
// The margin matters as much as the collection. A stored last_seen lags real
// activity by up to the touch interval, so the sweep must treat it as a lower
// bound — reaping a row that is only just past the timeout would end a session
// another replica is actively using.
func TestReapCollectsAbandonedRows(t *testing.T) {
	st, _ := openTemp(t)
	a := replica(st)
	now := time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)

	// touchEvery is min(idle/4, 1m) = 1m for a 30m idle timeout.
	const touchEvery = time.Minute
	insert(t, st, "long-idle", "c", now.Add(-time.Hour), now.Add(-testIdle-2*touchEvery))
	insert(t, st, "just-past", "c", now.Add(-time.Hour), now.Add(-testIdle-touchEvery/2))
	insert(t, st, "active", "c", now.Add(-time.Hour), now.Add(-time.Minute))

	if dead := a.Reap(expiredBy(now)); len(dead) != 0 {
		t.Errorf("Reap returned %d local sessions, want 0 — none of these rows is held here", len(dead))
	}
	left := storedIDs(t, st)
	if left["long-idle"] {
		t.Error("a row idle well past the timeout was not collected")
	}
	if !left["just-past"] {
		t.Error("a row only just past the timeout was collected; the stored last_seen lags real activity, so this could have been a session another replica is using")
	}
	if !left["active"] {
		t.Error("an active session's row was collected")
	}
}

// TestShutdownLeavesTheRows is the session.Detacher contract, stated as
// behaviour: one replica restarting must not sign the cluster out. Routed
// through Reap with an always-true predicate — which is what Manager.Shutdown
// does for the in-memory store — this would delete every row.
func TestShutdownLeavesTheRows(t *testing.T) {
	st, _ := openTemp(t)
	a := replica(st)
	m := session.NewManager(a, session.Config{IdleTimeout: testIdle, AbsoluteTimeout: testAbsolute})
	pre := startSession(t, m)
	other := replica(st)
	if _, ok := other.Get(pre.ID); !ok {
		t.Fatal("fixture: the session should be stored")
	}

	m.Shutdown()

	if n := countSessions(t, st); n != 1 {
		t.Errorf("stored sessions after shutdown = %d, want 1 — a restart ended sessions belonging to every replica", n)
	}
	if a.Len() != 0 {
		t.Errorf("the shut-down replica still holds %d sessions", a.Len())
	}
	// Which means another replica carries on serving it.
	if _, ok := other.Get(pre.ID); !ok {
		t.Error("the surviving replica lost the session")
	}
}

// TestTouchIsThrottled: a live session's stored last_seen has to advance, or
// another replica's sweep would eventually judge it idle — but not once per page
// view.
func TestTouchIsThrottled(t *testing.T) {
	st, _ := openTemp(t)
	c := &clock{t: time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)}
	s := storage.NewSessionStore(st, storage.SessionStoreConfig{IdleTimeout: testIdle, Now: c.now})

	hourAgo := c.now().Add(-time.Hour)
	sess := session.Adopt(session.Envelope{ID: "sticky", CSRF: "csrf", Created: hourAgo, LastSeen: hourAgo})
	s.Save(sess)
	if got := storedLastSeen(t, st, "sticky"); !got.Equal(sess.LastSeen.Truncate(time.Microsecond)) {
		t.Fatalf("fixture: stored last_seen = %v, want %v", got, sess.LastSeen)
	}

	if _, ok := s.Get("sticky"); !ok {
		t.Fatal("Get missed a session it had just saved")
	}
	first := storedLastSeen(t, st, "sticky")
	if !first.Equal(c.now().Truncate(time.Microsecond)) {
		t.Errorf("after the first Get, stored last_seen = %v, want %v", first, c.now())
	}

	c.advance(time.Second) // well inside the throttle window
	if _, ok := s.Get("sticky"); !ok {
		t.Fatal("Get missed the session")
	}
	if got := storedLastSeen(t, st, "sticky"); !got.Equal(first) {
		t.Errorf("stored last_seen moved to %v one second later; the throttle is not working", got)
	}

	c.advance(2 * time.Minute) // past it
	if _, ok := s.Get("sticky"); !ok {
		t.Fatal("Get missed the session")
	}
	if got := storedLastSeen(t, st, "sticky"); !got.Equal(c.now().Truncate(time.Microsecond)) {
		t.Errorf("stored last_seen = %v after the throttle window, want %v", got, c.now())
	}
}

// TestErrorsDegradeToTheLocalView pins the failure policy: an unreachable
// metadata database must not log everybody out. What is left is TableX's own
// default configuration — this process's own sessions — and never anything
// weaker than that.
func TestErrorsDegradeToTheLocalView(t *testing.T) {
	st, _ := openTemp(t)
	s := replica(st)
	m := managerOn(t, s)
	pre := startSession(t, m)

	if err := st.Close(); err != nil { // the metadata database goes away
		t.Fatalf("close: %v", err)
	}

	got, ok := s.Get(pre.ID)
	if !ok {
		t.Fatal("a storage outage logged out a session this process is holding")
	}
	if got.ID != pre.ID {
		t.Errorf("degraded Get returned %q, want %q", got.ID, pre.ID)
	}
	// Not weaker than the in-memory store: an id this process never issued is
	// still refused.
	if _, ok := s.Get("never-issued"); ok {
		t.Error("a storage outage made an unknown session id acceptable")
	}
	// A login still works while degraded, on the local exact-pointer swap.
	authed, ok := m.Authenticate(httptest.NewRecorder(), pre, "payload", func() {})
	if !ok {
		t.Fatal("a storage outage blocked login entirely")
	}
	if _, ok := s.Get(authed.ID); !ok {
		t.Error("the session created while degraded is not usable")
	}
}

// --- helpers ------------------------------------------------------------------

func storedIDs(t *testing.T, st *storage.Store) map[string]bool {
	t.Helper()
	rows, err := st.DB().Query("SELECT " + st.Col("id") + " FROM " + st.Table(storage.SessionsTable))
	if err != nil {
		t.Fatalf("list stored sessions: %v", err)
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatalf("scan: %v", err)
		}
		out[id] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("list stored sessions: %v", err)
	}
	return out
}

func storedLastSeen(t *testing.T, st *storage.Store, id string) time.Time {
	t.Helper()
	var us int64
	err := st.DB().QueryRow("SELECT "+st.Col("last_seen")+" FROM "+st.Table(storage.SessionsTable)+
		" WHERE "+st.Col("id")+" = "+st.Placeholder(1), id).Scan(&us)
	if err != nil {
		t.Fatalf("read last_seen for %s: %v", id, err)
	}
	return storage.FromMicros(us)
}

// recordingHandler collects slog records so a test can assert on what was logged.
type recordingHandler struct {
	mu          sync.Mutex
	lines       int
	occurrences []int64
}

func (h *recordingHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *recordingHandler) WithAttrs([]slog.Attr) slog.Handler       { return h }
func (h *recordingHandler) WithGroup(string) slog.Handler            { return h }

func (h *recordingHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.lines++
	r.Attrs(func(a slog.Attr) bool {
		if a.Key == "occurrences" {
			h.occurrences = append(h.occurrences, a.Value.Int64())
		}
		return true
	})
	return nil
}

func (h *recordingHandler) snapshot() (int, []int64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.lines, append([]int64(nil), h.occurrences...)
}

// TestDegradationWarningIsThrottled: session lookup is on the request path, so an
// unreachable metadata database would otherwise log once per request — tens of
// thousands of lines over a short outage, burying the very context needed to
// diagnose it. The count carried on each line is what keeps the throttling from
// making the outage look smaller than it was.
func TestDegradationWarningIsThrottled(t *testing.T) {
	st, _ := openTemp(t)
	c := &clock{t: time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)}
	h := &recordingHandler{}
	s := storage.NewSessionStore(st, storage.SessionStoreConfig{
		IdleTimeout: testIdle, Now: c.now, Log: slog.New(h),
	})
	sess := session.Adopt(session.Envelope{ID: "held-here", CSRF: "csrf", Created: c.now(), LastSeen: c.now()})
	s.Save(sess)
	if lines, _ := h.snapshot(); lines != 0 {
		t.Fatalf("fixture: %d lines logged before the outage, want 0", lines)
	}

	if err := st.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	for range 5 {
		if _, ok := s.Get(sess.ID); !ok {
			t.Fatal("a storage outage logged out a session held by this process")
		}
	}
	lines, counts := h.snapshot()
	if lines != 1 {
		t.Errorf("five failed lookups logged %d lines, want 1", lines)
	}
	if len(counts) != 1 || counts[0] != 1 {
		t.Errorf("first line reported occurrences %v, want [1]", counts)
	}

	c.advance(time.Second) // still inside the throttle window
	for range 3 {
		s.Get(sess.ID)
	}
	if lines, _ := h.snapshot(); lines != 1 {
		t.Errorf("eight failed lookups logged %d lines, want still 1", lines)
	}

	c.advance(degradeWindowPlus) // past it
	s.Get(sess.ID)
	lines, counts = h.snapshot()
	if lines != 2 {
		t.Fatalf("after the throttle window, %d lines logged, want 2", lines)
	}
	// 4 suppressed from the first burst + 3 + this one.
	if counts[1] != 8 {
		t.Errorf("second line reported %d occurrences, want 8 — the throttle is under-reporting the outage", counts[1])
	}
}

// degradeWindowPlus is comfortably past the degradation-warning throttle window.
const degradeWindowPlus = 31 * time.Second

// TestASessionWeCouldNotStoreIsNotTreatedAsLoggedOut covers the interaction
// between the two policies, which is where a plausible implementation goes
// wrong.
//
// A login during a storage outage falls back to the local swap, so the session
// exists here and nowhere else. The moment storage answers again its row is
// missing — and "no row means the session is over" would then sign the user out
// on their very next request, for a blip that lasted a second. It must not: no
// other replica ever saw that session, so nobody could have ended it.
//
// The sweep repairs it, and only then does the ordinary rule apply again.
func TestASessionWeCouldNotStoreIsNotTreatedAsLoggedOut(t *testing.T) {
	st, _ := openTemp(t)
	s := replica(st)
	m := managerOn(t, s)

	// The outage: reads and writes both fail. Login falls back to the local swap.
	dropSessionsTable(t, st)
	pre := startSession(t, m)
	authed, ok := m.Authenticate(httptest.NewRecorder(), pre, "payload", func() {})
	if !ok {
		t.Fatal("a storage outage blocked login entirely")
	}

	// Storage comes back, with no row for that session because the write failed.
	createSessionsTable(t, st)
	if n := countSessions(t, st); n != 0 {
		t.Fatalf("fixture: %d stored sessions, want 0 — the outage should have prevented the write", n)
	}

	// The next request must not be a logout, and must still carry the payload:
	// the live object is here, only its row is missing.
	got, ok := s.Get(authed.ID)
	if !ok {
		t.Fatal("a session this process could not store was treated as logged out as soon as storage came back")
	}
	if got.App() == nil {
		t.Error("the recovered lookup lost the live payload; it re-adopted the envelope instead of returning the session held here")
	}

	// The sweep repairs it rather than ending it.
	if dead := s.Reap(func(*session.Session) bool { return false }); len(dead) != 0 {
		t.Errorf("the sweep ended %d sessions; nobody else ever saw this one, so nobody logged it out", len(dead))
	}
	if n := countSessions(t, st); n != 1 {
		t.Errorf("stored sessions after the sweep = %d, want 1 — the write was not retried, so the session stays a permanent local exception", n)
	}

	// And now the ordinary rule is back in force.
	other := replica(st)
	other.Delete(authed.ID)
	if _, ok := s.Get(authed.ID); ok {
		t.Error("after recovery, a session deleted on another replica is still accepted")
	}
}

// TestReapRepairsASessionItCouldNotStore isolates the sweep's retry: a session
// that was never written becomes durable again without a request touching it.
func TestReapRepairsASessionItCouldNotStore(t *testing.T) {
	st, _ := openTemp(t)
	s := replica(st)
	sess := session.Adopt(session.Envelope{ID: "written-later", CSRF: "csrf", Created: time.Now(), LastSeen: time.Now()})

	dropSessionsTable(t, st)
	s.Save(sess)
	if s.Len() != 1 {
		t.Fatalf("the session was not held locally after a failed write (Len = %d)", s.Len())
	}
	createSessionsTable(t, st)

	if dead := s.Reap(func(*session.Session) bool { return false }); len(dead) != 0 {
		t.Errorf("the sweep ended %d sessions, want 0", len(dead))
	}
	if n := countSessions(t, st); n != 1 {
		t.Errorf("stored sessions after the sweep = %d, want 1 — the write was not retried", n)
	}
	if _, ok := s.Get(sess.ID); !ok {
		t.Error("the repaired session is no longer usable")
	}
}

// dropSessionsTable / createSessionsTable simulate a metadata database that goes
// away and comes back. Dropping the table rather than closing the pool is what
// makes the outage RECOVERABLE: a closed *sql.DB stays closed, whereas a real
// outage ends.
func dropSessionsTable(t *testing.T, st *storage.Store) {
	t.Helper()
	if _, err := st.DB().Exec("DROP TABLE " + st.Table(storage.SessionsTable)); err != nil {
		t.Fatalf("drop the sessions table: %v", err)
	}
}

func createSessionsTable(t *testing.T, st *storage.Store) {
	t.Helper()
	if _, err := st.DB().Exec("CREATE TABLE " + st.Table(storage.SessionsTable) + " (" +
		st.Col("id") + " TEXT NOT NULL PRIMARY KEY, " + st.Col("csrf") + " TEXT NOT NULL, " +
		st.Col("created") + " INTEGER NOT NULL, " + st.Col("last_seen") + " INTEGER NOT NULL)"); err != nil {
		t.Fatalf("recreate the sessions table: %v", err)
	}
}
