package storage

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"math"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tablexdev/tablex/internal/session"
)

// SessionStore is a session.Store that keeps each session's ENVELOPE in the
// metadata database, so a session outlives the process that created it and is
// visible to every replica behind a load balancer.
//
// # What becomes durable, and what cannot
//
// The envelope is the id, the CSRF token and the two timestamps. The PAYLOAD —
// live connection pools and the password the user typed — is not stored and
// cannot be; this package's comment says why. What follows from that:
//
//   - A PRE-AUTH session works completely across replicas, which is the case
//     that actually mattered. Without a shared store, a login form rendered by
//     replica A carries a CSRF token replica B has never issued, so behind a
//     round-robin load balancer every login fails. This fixes that.
//   - An AUTHENTICATED session is node-bound. Another replica finds the row,
//     accepts the id and the token, finds no payload behind it, and shows the
//     login page. The user logs in again and is bound to that replica. Sticky
//     sessions avoid the extra login; nothing here depends on them for
//     CORRECTNESS, only for convenience.
//   - A restart is a logout in the same limited sense: the rows survive, the
//     pools do not.
//
// The honest summary is that this makes session identity durable and shared,
// not the connections. Making those shared would require persisting the
// credential, which is the one thing TableX does not do.
//
// # Errors degrade; answers are obeyed
//
// A metadata database that has gone away must not log out every user, so a
// storage ERROR falls back to this node's own view — which is precisely
// TableX's default configuration, the in-memory store, and never anything
// weaker. A storage ANSWER is authoritative: "no such row" means the session is
// over (logged out, reaped, or expired somewhere else) and is honoured as such.
//
// While degraded, a logout performed on another replica is not observed until
// storage returns. Both timeouts keep applying throughout, because they are
// evaluated against the envelope this node already holds.
type SessionStore struct {
	st    *Store
	local session.Store
	log   *slog.Logger
	now   func() time.Time

	sel, ins, del, upd, all, delIf string

	// admit serializes every mutation that can change the ROW COUNT, and every
	// publication, against each other. Lock order is
	// admission -> memStore.mu -> s.mu, which the three invariants below keep
	// acyclic:
	//
	//  1. The generation map's guard is s.mu, never this mutex, because Reap's
	//     predicate reads it while memStore.mu is held.
	//  2. This mutex is NEVER acquired from inside a local-store callback —
	//     there are two (Reap's expiry predicate and the eviction hook) and both
	//     take s.mu only.
	//  3. It is acquired BEFORE s.mu, never under it, and s.mu is never held
	//     across a local-store call. That constrains the s.mu -> local direction
	//     only; the reverse is rule 1's established order.
	admit sync.Mutex
	// maxRows caps the durable table (<= 0: uncapped). rows is this replica's
	// most recent count, guarded by admit: seeded once at construction and
	// reconciled from a fresh COUNT(*) on each successful sweep, then maintained
	// from RowsAffected. See rowCapReached.
	maxRows int
	rows    int

	// touchEvery bounds how often a live session's stored last_seen is
	// rewritten, and touched records when each id was last written. Without the
	// throttle every page view would cost a metadata UPDATE.
	touchEvery time.Duration
	mu         sync.Mutex
	touched    map[string]time.Time
	// unpersisted holds the ids this process could not write. They are exempt
	// from the "no row means the session is over" rule — see absenceIsFinal.
	//
	// Deliberately UNBOUNDED. It is tempting to cap it — it is per-id state an
	// anonymous request can fill — and it would be wrong: absenceIsFinal is
	// literally !unpersisted[id], so a session whose row was refused AND whose
	// entry was also refused reads as PERSISTED, its absence becomes final, and
	// the user is signed out mid-flood with a CSRF token that no longer matches.
	// What bounds it instead is the eviction hook (forget) plus the five
	// setPersisted(id, true) sites.
	unpersisted map[string]bool
	// generations records, per id, WHEN it became locally visible behind a row
	// that exists. Reap stamps each scan with the epoch it began at and treats a
	// missing row as final only for ids published before then — otherwise a
	// login completing after the scan's snapshot but before its sweep is retired
	// as "ended on another replica".
	//
	// A single GLOBAL epoch cannot serve: bumped by any Save, unrelated traffic
	// during a 30-second scan would invalidate every sweep, so the remote logouts
	// this exists to collect would never be collected.
	//
	// Guarded by s.mu (invariant 1 above), never by admit.
	gen         int64
	generations map[string]int64

	// capRefused / markerRefused count sessions turned away by the row cap and
	// by generation-marker capacity. Siblings of degradeTotal, never inputs to
	// it: a configured capacity policy must not raise the one metric that means
	// "durability is broken".
	capRefused    atomic.Int64
	markerRefused atomic.Int64
	// Degradation-warning throttle: when the last line was emitted, and how many
	// occurrences it has stood for since.
	degradeLogged time.Time
	degradeCount  int
	// degradeTotal is the monotonic count for /metrics. degradeCount cannot serve:
	// the throttle zeroes it on every line it emits, because what a log line needs
	// is "how many since the last one" and what a scraper needs is "how many ever".
	degradeTotal atomic.Int64
}

// Degradations reports how many operations have fallen back to this process's own
// view since startup — the number that says session durability is not currently
// being delivered. A nil receiver reads as zero, so a caller holding a
// session.Store it did not build can ask without knowing which kind it has.
func (s *SessionStore) Degradations() int64 {
	if s == nil {
		return 0
	}
	return s.degradeTotal.Load()
}

// CapRefusals reports how many sessions were denied a durable row because
// storage.max_sessions was reached, and MarkerRefusals how many were denied one
// because the generation map was full. Both are POLICY turn-aways, which is why
// they are separate from Degradations: that number means durability is broken,
// and a configured cap doing its job must not make it rise.
func (s *SessionStore) CapRefusals() int64 {
	if s == nil {
		return 0
	}
	return s.capRefused.Load()
}

// MarkerRefusals — see CapRefusals.
func (s *SessionStore) MarkerRefusals() int64 {
	if s == nil {
		return 0
	}
	return s.markerRefused.Load()
}

// Statement budgets. A session lookup is on the request path, so a wedged
// metadata database has to fail fast and let the caller degrade instead of
// holding the request open; the reaper's full scan is not on any request path
// and can afford more.
const (
	stmtTimeout  = 5 * time.Second
	sweepTimeout = 30 * time.Second
)

// maxTouchInterval caps the staleness of a stored last_seen regardless of how
// long the idle timeout is.
const maxTouchInterval = time.Minute

// maxTouchedEntries bounds the throttle bookkeeping. The local store evicts at
// its own capacity without telling us, so entries can outlive their session;
// clearing the map wholesale costs at most one extra UPDATE per live session and
// is simpler than tracking evictions.
const maxTouchedEntries = 20000

// maxGenerationEntries bounds the generation map. Generous by design: epoch
// pruning (see Reap) drops every marker published before the last completed
// scan, so the live set is "published during the last sweep" and stays far
// below this. Matches maxTouchedEntries.
const maxGenerationEntries = 20000

// noScan is the epoch to pass absenceIsFinal outside a sweep. It has to be the
// MAXIMUM, not zero: the test asks "was this published after the scan began",
// and with zero every stamped marker reads as newer, so absence would never be
// final and a remote logout would never be honoured.
const noScan = int64(math.MaxInt64)

// errAtCapacity and errNoMarkerSlot are POLICY refusals, not failures. They are
// distinct sentinels so Save can tell them from a storage error: routing either
// through degraded() would make tablex_storage_degraded_total — the one alarm
// meaning "sessions are not durable" — rise steadily under a working cap.
var (
	errAtCapacity   = errors.New("storage: session table at storage.max_sessions")
	errNoMarkerSlot = errors.New("storage: session generation map full")
)

// SessionStoreConfig tunes the durable store.
type SessionStoreConfig struct {
	// IdleTimeout is the manager's idle policy. It is used for one thing: how
	// often a live session's stored last_seen is refreshed — often enough that
	// another replica's reaper does not mistake an active session for an idle
	// one, rarely enough that a page view is not an extra write.
	IdleTimeout time.Duration
	// MaxSessions caps the DURABLE TABLE, per replica (<= 0: uncapped). Over it
	// a new session is refused a row and runs process-local, exactly as it does
	// when storage is unreachable.
	MaxSessions int
	// Log receives the degradation warnings. A nil Log discards them.
	Log *slog.Logger
	// Now replaces the clock (tests). It must be safe for concurrent use.
	Now func() time.Time
}

// NewSessionStore builds a durable session store over an open metadata database.
func NewSessionStore(st *Store, cfg SessionStoreConfig) *SessionStore {
	t := st.Table(SessionsTable)
	id, csrf := st.Col("id"), st.Col("csrf")
	created, lastSeen := st.Col("created"), st.Col("last_seen")
	ph := st.Placeholder

	touch := maxTouchInterval
	if q := cfg.IdleTimeout / 4; cfg.IdleTimeout > 0 && q < touch {
		touch = q
	}
	touch = max(touch, time.Second)

	s := &SessionStore{
		st:      st,
		log:     cfg.Log,
		now:     cfg.Now,
		maxRows: cfg.MaxSessions,

		sel:   "SELECT " + csrf + ", " + created + ", " + lastSeen + " FROM " + t + " WHERE " + id + " = " + ph(1),
		ins:   "INSERT INTO " + t + " (" + id + ", " + csrf + ", " + created + ", " + lastSeen + ") VALUES (" + ph(1) + ", " + ph(2) + ", " + ph(3) + ", " + ph(4) + ")",
		del:   "DELETE FROM " + t + " WHERE " + id + " = " + ph(1),
		upd:   "UPDATE " + t + " SET " + lastSeen + " = " + ph(1) + " WHERE " + id + " = " + ph(2),
		all:   "SELECT " + id + ", " + csrf + ", " + created + ", " + lastSeen + " FROM " + t,
		delIf: "DELETE FROM " + t + " WHERE " + id + " = " + ph(1) + " AND " + lastSeen + " = " + ph(2),

		touchEvery:  touch,
		touched:     map[string]time.Time{},
		unpersisted: map[string]bool{},
		generations: map[string]int64{},
	}
	if s.now == nil {
		s.now = time.Now
	}
	// The local store tells us when it evicts, so this wrapper's per-id maps
	// cannot outlive the sessions they describe. This is NOT the cap unpersisted
	// must never have: an eviction prune removes the entry for a session that no
	// longer exists here, which is observationally equivalent on every path —
	// after eviction Get(id) returns (nil, false) down both branches, and Reap's
	// predicate never runs for an id the local store does not hold.
	s.local = session.NewMemStoreWith(session.MemStoreConfig{OnEvict: s.forget})
	// Seeded once. A failure DEGRADES rather than refusing startup — every other
	// storage failure here degrades, NewSessionStore returns no error, and a
	// server that would not boot because one COUNT(*) timed out is a worse
	// outage than the one the cap prevents. It starts AT the cap, not at zero:
	// zero is fail-OPEN, handing this replica a fresh capful of inserts on top of
	// a table whose size is unknown, at the moment storage is already misbehaving.
	// The cost is bounded at one sweep of non-durable sessions, because a refused
	// row never refuses a session.
	if s.maxRows > 0 {
		if n, err := s.countRows(); err == nil {
			s.rows = n
		} else {
			s.degraded("counting stored sessions", err)
			s.rows = s.maxRows
		}
	}
	return s
}

// rowCapReached reports whether the durable table is at storage.max_sessions.
// Callers hold the admission mutex.
func (s *SessionStore) rowCapReached() bool {
	return s.maxRows > 0 && s.rows >= s.maxRows
}

// countRows reads the authoritative table size. Used for the seed and for the
// per-sweep reconcile, both under the admission mutex — which removes the
// boundary problem entirely rather than reasoning about it: admission serializes
// every counted mutation, so nothing local can interleave between the count and
// the assignment.
func (s *SessionStore) countRows() (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), sweepTimeout)
	defer cancel()
	var n int
	err := s.st.DB().QueryRowContext(ctx, "SELECT COUNT(*) FROM "+s.st.Table(SessionsTable)).Scan(&n)
	return n, err
}

// reserveGeneration stamps id with the CURRENT generation, taking a slot if it
// does not already hold one, and reports whether it got one.
//
// The slot is taken BEFORE the durable write, and that ordering is load-bearing.
// The admission mutex serializes publishers against each other, but Get's
// adoption takes no admission lock and is a publication in its own right — so a
// check-then-act loses the last slot to an adoption and leaves the publisher
// with a WRITTEN ROW CARRYING NO MARKER, which is exactly what an in-flight scan
// retires. Stamping early is always safe: the marker only has to precede local
// visibility.
func (s *SessionStore) reserveGeneration(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, held := s.generations[id]; !held && len(s.generations) >= maxGenerationEntries {
		return false
	}
	s.gen++
	s.generations[id] = s.gen
	return true
}

// releaseGeneration drops a reservation. Called ONLY for a known PRE-COMMIT
// failure: a commit whose response was lost may still have applied, and the two
// mistakes are not symmetric. A marker with no row behind it is harmless — it
// only keeps absence non-final until epoch pruning drops it — while a row with
// no marker is the publication a running scan retires.
func (s *SessionStore) releaseGeneration(id string) {
	s.mu.Lock()
	delete(s.generations, id)
	s.mu.Unlock()
}

// handOffGeneration moves a login's marker from the pre-auth id to the new one,
// stamping the CURRENT generation. It reports false only when no slot is free.
//
// The VALUE is re-stamped rather than moved: a pre-auth session may have been
// published minutes ago, and a scan begun after that publication but before this
// swap would find the new id absent with an old generation and retire a session
// that had just authenticated. Row-count neutrality holds unconditionally;
// marker neutrality does NOT — epoch pruning plus a one-minute reaper means the
// common login finds no old marker and must take a fresh slot.
func (s *SessionStore) handOffGeneration(oldID, newID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, hadOld := s.generations[oldID]
	_, hasNew := s.generations[newID]
	if !hasNew && !hadOld && len(s.generations) >= maxGenerationEntries {
		return false
	}
	delete(s.generations, oldID)
	s.gen++
	s.generations[newID] = s.gen
	return true
}

// scanEpoch snapshots the generation counter. A scan takes this BEFORE its
// query, so anything published afterwards is newer than the scan.
func (s *SessionStore) scanEpoch() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.gen
}

// pruneGenerations drops every marker published at or before epoch. Provably
// safe: a marker exists only to protect a publication that raced a scan, so once
// a scan starting later has FINISHED, no future scan can be affected by it. The
// retained set is exactly "published during the last scan".
//
// Pruning by epoch rather than by observation is what keeps the map from
// wedging: an id the local store evicted whose row was then deleted elsewhere
// appears in neither the row set nor the dead list, so a prune keyed on either
// would never reach it.
func (s *SessionStore) pruneGenerations(epoch int64) {
	s.mu.Lock()
	for id, g := range s.generations {
		if g <= epoch {
			delete(s.generations, id)
		}
	}
	s.mu.Unlock()
}

// isUnpersisted reports whether this process failed to write id.
func (s *SessionStore) isUnpersisted(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.unpersisted[id]
}

// Compile-time proof that the durable store satisfies both the required
// interface and the optional one that makes shutdown mean the right thing.
var (
	_ session.Store    = (*SessionStore)(nil)
	_ session.Detacher = (*SessionStore)(nil)
)

// Get resolves a session id. The metadata row is authoritative for EXISTENCE;
// the payload, when there is one, only ever lives in the local view.
func (s *SessionStore) Get(id string) (*session.Session, bool) {
	env, found, err := s.selectOne(id)
	if err != nil {
		s.degraded("looking up a session", err)
		return s.local.Get(id)
	}
	if !found {
		if s.absenceIsFinal(id, noScan) {
			return nil, false
		}
		// Never persisted, so it is this process's own — see absenceIsFinal.
		return s.local.Get(id)
	}
	live, ok := s.local.Get(id)
	if !ok {
		// First time this process has seen the session — it was created by
		// another replica, or by this one before a restart. Adopting it keeps
		// the id and the CSRF token, so a form issued elsewhere still validates.
		// THE THIRD PUBLICATION SITE, and the only purely cross-replica one.
		// Replica B creates the row at T1; this replica's scan took its snapshot
		// at T0 < T1, so the row is absent from it; the request arrives at T2 and
		// adopts correctly — and then the sweep finds the session locally, absent
		// from the snapshot, with nothing marking it, and retires it as "ended on
		// another replica". Stamping BEFORE it becomes locally visible is what
		// makes the predicate read the adoption as newer than the scan.
		//
		// NOT a setPersisted call: an adopted session IS persisted — its row is
		// what triggered the adoption — and marking it unpersisted would make its
		// absence never final, so a genuine remote logout would never be honoured.
		//
		// At marker capacity the adoption proceeds UNMARKED rather than being
		// refused: declining would sign out a session another replica owns, which
		// is the opposite of this store's purpose. Self-healing — the row is still
		// there, so the next request with that cookie adopts it again.
		s.reserveGeneration(id)
		live = session.Adopt(env)
		s.local.Save(live)
	}
	s.touch(id)
	return live, true
}

// absenceIsFinal reports whether a missing row means the session is over.
//
// It usually does, and that is the point of the durable store: a logout or an
// expiry on another replica has to take effect here. But a session this process
// tried and FAILED to write is a different thing — no other replica ever saw it,
// so nobody could have ended it, and treating its absence as a logout would
// mean a momentary storage failure during login silently signed the user out a
// minute later, once storage came back and the reaper noticed.
//
// Such a session is simply process-local, which is TableX's default
// configuration. Reap retries the write, so it stops being an exception as soon
// as storage answers again.
// The epoch argument folds in the second reason a missing row is not final: the
// session was PUBLISHED after this scan began. Pass noScan where no scan is in
// progress (Get), which reduces this to the unpersisted test alone — every
// marker is then "older", because there is no scan for it to be newer than.
func (s *SessionStore) absenceIsFinal(id string, epoch int64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.unpersisted[id] {
		return false
	}
	// Newer than the scan: the row exists, this snapshot simply predates it.
	return s.generations[id] <= epoch
}

// persisted records whether a write for id succeeded.
func (s *SessionStore) setPersisted(id string, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ok {
		delete(s.unpersisted, id)
		return
	}
	s.unpersisted[id] = true
}

// Save records a new session, subject to storage.max_sessions.
//
// Over the cap the durable write is REFUSED and the session falls back to
// process-local — the same graceful path an unreachable metadata database takes,
// and repersist picks it up once there is room. A refusal is not a degradation:
// it is a configured policy working, so it must not touch degradeTotal.
func (s *SessionStore) Save(sess *session.Session) {
	env := sess.Envelope()
	err := s.persistNew(env)
	switch {
	case errors.Is(err, errAtCapacity):
		s.capRefused.Add(1)
	case errors.Is(err, errNoMarkerSlot):
		s.markerRefused.Add(1)
	case err != nil:
		s.degraded("recording a new session", err)
	}
	s.setPersisted(env.ID, err == nil)
	// Saved locally either way: a process whose metadata database is down still
	// has to be able to serve a login form.
	s.local.Save(sess)
}

// persistNew writes a new session's row under the admission mutex.
//
// The Save-level FAST PATH exists because the in-transaction check is the
// expensive path at exactly the wrong moment: discovering "refuse" there costs a
// BeginTx, a DELETE and a rollback, so under the anonymous flood this cap exists
// to shed every REFUSED request would cost a database round trip.
//
// The predicate is sound, not merely cheap. The only production Save is
// Manager.Start with a freshly minted id, which cannot have a durable row; and
// the one case that looks like a counter-example — a session evicted locally
// whose row survives — never reaches Save at all, because Get adopts the
// surviving row and Start therefore does not create.
//
// It does narrow §6a's row-neutral exemption to "a re-Save of a LOCALLY HELD id",
// which is a decision rather than an oversight: local absence is not proof of
// durable absence, and preserving the broad contract would cost a SELECT on
// every otherwise-free refusal — reinstating the round trip this removes. The
// in-transaction check stays as the backstop for a locally-held id whose row was
// deleted on another replica.
func (s *SessionStore) persistNew(e session.Envelope) error {
	s.admit.Lock()
	defer s.admit.Unlock()
	if s.rowCapReached() {
		if _, held := s.local.Get(e.ID); !held {
			return errAtCapacity // refused with zero SQL
		}
	}
	if !s.reserveGeneration(e.ID) {
		return errNoMarkerSlot
	}
	return s.insert(e)
}

// Delete ends a session everywhere.
//
// It joins the admission protocol. Without that it could land between
// repersist's local.Get and its insert, and the insert would RECREATE the row
// for a session the user had just ended — the exact failure the durable store
// exists to prevent, since a logout on one replica must take effect everywhere.
func (s *SessionStore) Delete(id string) {
	s.admit.Lock()
	n, err := s.execN(s.del, id)
	switch {
	case err != nil:
		s.degraded("deleting a session", err)
	case n == 1:
		s.rows--
	}
	s.forget(id)
	s.admit.Unlock()
	s.local.Delete(id)
}

// Replace implements the atomic login swap. The row DELETE is the membership
// check: it either removes the one row and reports 1, or reports 0 because
// something else got there first. That is the same guarantee the in-memory
// store's exact-pointer check provides, extended across every replica — two
// simultaneous logins on one pre-auth session resolve to exactly one winner
// wherever they land.
func (s *SessionStore) Replace(old, new *session.Session) bool {
	env := new.Envelope()
	s.admit.Lock()
	defer s.admit.Unlock()

	// EXEMPT from the row cap: replaceRow deletes and inserts in one
	// transaction, so a login never grows the table and must never be refused by
	// storage.max_sessions. NOT exempt from needing a marker — it publishes a NEW
	// id, and an unmarked fresh row is exactly what an earlier scan retires.
	if !s.handOffGeneration(old.ID, env.ID) {
		s.markerRefused.Add(1)
		return s.replaceLocally(old, new, env)
	}
	swapped, err := s.replaceRow(old.ID, env)
	if err != nil {
		s.degraded("re-keying a session at login", err)
		// Errors degrade: fall back to the local atomic swap so a login still
		// works while the metadata database is unreachable. The new session is
		// process-local until Reap manages to write it (see absenceIsFinal).
		if !s.local.Replace(old, new) {
			return false
		}
		s.forget(old.ID)
		s.setPersisted(env.ID, false)
		return true
	}
	if !swapped {
		// Normally an answer, not an error: the pre-auth session is gone. But a
		// session this process never managed to WRITE has no row for the DELETE to
		// find, so its absence is no evidence of a competing winner — and refusing
		// here would fail the login under precisely the flood the row cap exists to
		// survive. Same "absence is not evidence" rule absenceIsFinal encodes.
		if !s.isUnpersisted(old.ID) {
			return false
		}
		if !s.local.Replace(old, new) {
			return false
		}
		s.forget(old.ID)
		// Nothing was written: replaceRow returns before its INSERT on n != 1.
		s.setPersisted(env.ID, false)
		return true
	}
	s.forget(old.ID)
	s.setPersisted(env.ID, true)
	s.local.Delete(old.ID)
	s.local.Save(new)
	return true
}

// replaceLocally is Replace at MARKER capacity: the new session runs
// process-local, so it needs no marker at all — with the generation test folded
// into absenceIsFinal, an unpersisted id can never have its absence treated as
// final. Markers protect PUBLISHED rows only, which is why no other session's
// marker is ever evicted to make room.
//
// The old row is DELETED first, deliberately. Skipping it would leave old.ID in
// the table with no local session behind it, holding a storage.max_sessions slot
// until the abandoned-row path collects it at idle timeout — and under the flood
// that exhausted the markers, those orphans are what keeps the row cap
// exhausted. The degraded branch above leaves the row only because storage is
// unreachable and the DELETE cannot be issued; here storage is up.
//
// It uses a row-count-returning delete rather than exec, because the DELETE IS
// the membership check: exec discards the result, so a delete that removed
// NOTHING would read as success and two replicas could each authenticate the
// same pre-auth session — the exact failure Replace's design prevents.
//
// This one path is not atomic, and that is the accepted cost: it is reachable
// only at marker exhaustion, the new session is process-local so no other
// replica can observe the intermediate state as a valid session, and case 3
// below preserves the single-winner property that actually matters.
//
// Caller holds the admission mutex.
func (s *SessionStore) replaceLocally(old, new *session.Session, env session.Envelope) bool {
	n, err := s.execN(s.del, old.ID)
	switch {
	case err != nil:
		s.degraded("re-keying a session at login", err)
	case n == 1:
		s.rows--
	case !s.isUnpersisted(old.ID):
		// A logout, a reap or a competing login got there first.
		return false
	}
	if !s.local.Replace(old, new) {
		return false
	}
	s.forget(old.ID)
	s.setPersisted(env.ID, false)
	return true
}

// Len reports how many sessions THIS PROCESS holds — the same meaning the
// in-memory store's Len has, which is what makes Manager.ActiveSessions a
// reliable "every pool is closed" signal in tests. It is not a cluster total.
func (s *SessionStore) Len() int { return s.local.Len() }

// Detach releases every session this process holds without ending any of them
// for other replicas (session.Detacher). It is what Manager.Shutdown wants: the
// rows stay, so a rolling restart does not sign the cluster out.
func (s *SessionStore) Detach() []*session.Session {
	dead := s.local.Reap(func(*session.Session) bool { return true })
	s.mu.Lock()
	s.touched = map[string]time.Time{}
	s.mu.Unlock()
	return dead
}

// Reap removes finished sessions and returns the ones this process was holding,
// so their pools can be closed. It sweeps in two halves.
//
// LOCAL: a session held here is finished when the policy says so, or when its
// row has gone — which is how a logout or an expiry performed on ANOTHER replica
// releases the pools this node is still holding. That second condition is the
// whole reason this method reads the table rather than just filtering the local
// map.
//
// SHARED: rows that no local session stands behind belong to another replica, or
// to a process that died without cleaning up. Nobody else will necessarily
// collect the second kind, so every node applies the same policy to them.
//
// Note that a wholesale predicate here would delete every row in the cluster.
// That is exactly why Manager.Shutdown goes through Detach instead, and why
// session.Detacher exists at all.
func (s *SessionStore) Reap(expired func(*session.Session) bool) []*session.Session {
	// BEFORE the query, so anything published while the scan runs is newer than
	// the scan. Both halves of that ordering are load-bearing: the epoch has to
	// precede the snapshot, and a marker has to be stamped before its session
	// becomes locally visible.
	epoch := s.scanEpoch()
	rows, err := s.selectAll()
	if err != nil {
		s.degraded("scanning sessions", err)
		// Errors degrade: sweep the local view on policy alone. Anything ended
		// elsewhere is collected by a later sweep once storage is back.
		return s.local.Reap(expired)
	}
	present := make(map[string]session.Envelope, len(rows))
	for _, e := range rows {
		present[e.ID] = e
	}
	// Reconciled HERE — after a successful scan, before repersist — from a fresh
	// COUNT(*) under the admission mutex. Not from len(rows): selectAll runs with
	// no admission lock and takes its own snapshot at an unknowable instant, so a
	// local mutation landing between the scan start and that snapshot is counted
	// twice. Both directions occur, and the undercount is fail-OPEN.
	//
	// Position does not affect correctness but does decide recovery speed:
	// repersist below skips inserts while the counter says full, so reconciling
	// afterwards would make the first sweep after a failed seed repersist NOTHING
	// and only then learn there was room. A failed reconcile RETAINS the current
	// value; assigning zero would turn one timed-out query into a fail-open cap.
	if s.maxRows > 0 {
		s.admit.Lock()
		if n, cerr := s.countRows(); cerr == nil {
			s.rows = n
		}
		s.admit.Unlock()
	}
	// Storage is answering, so retry anything this process failed to write. Until
	// that succeeds the session is process-local and the sweep below must judge it
	// on policy alone rather than on a missing row (see absenceIsFinal).
	s.repersist(present)

	dead := s.local.Reap(func(sess *session.Session) bool {
		if _, stored := present[sess.ID]; stored {
			return expired(sess)
		}
		if s.absenceIsFinal(sess.ID, epoch) {
			return true // ended on another replica
		}
		return expired(sess) // never persisted, or published after this scan began
	})
	for _, sess := range dead {
		id := sess.ID
		s.forget(id)
		if _, stillThere := present[id]; stillThere {
			s.admit.Lock()
			n, err := s.execN(s.del, id)
			switch {
			case err != nil:
				s.degraded("deleting an expired session", err)
			case n == 1:
				s.rows--
			}
			s.admit.Unlock()
			delete(present, id)
		}
	}

	for _, e := range present {
		if _, held := s.local.Get(e.ID); held {
			// Alive here: it survived the local sweep above, which judged it on
			// its live timestamps. Those are fresher than the row's, so the row
			// must not be second-guessed.
			continue
		}
		// A stored last_seen lags real activity by up to touchEvery, so it is a
		// LOWER bound. Add the known error before applying the policy: being
		// late to reap is harmless — any use of a stale row is rejected by
		// Manager.Load, which re-checks expiry on the envelope — whereas being
		// early would end a session another replica is actively using.
		lagged := e
		lagged.LastSeen = e.LastSeen.Add(s.touchEvery)
		if !expired(session.Adopt(lagged)) {
			continue
		}
		// Guarded on the last_seen that was read, so a session refreshed by its
		// own replica between the scan and now survives. A conditional delete, so
		// a zero-row result here is the race being lost benignly and routine
		// rather than exceptional — which is why only n == 1 moves the counter.
		s.admit.Lock()
		n, err := s.execN(s.delIf, e.ID, Micros(e.LastSeen))
		if err == nil && n == 1 {
			s.rows--
		}
		s.admit.Unlock()
		if err != nil {
			s.degraded("deleting an abandoned session", err)
			break // one failure means the rest will fail too
		}
	}
	// The scan is over, so every marker it could have been affected by is spent.
	pruneEpoch := epoch
	s.pruneGenerations(pruneEpoch)
	return dead
}

// repersist retries the writes this process could not complete earlier, adding
// each one that now succeeds to present so the sweep does not mistake it for a
// session ended elsewhere. Anything that still fails stays process-local.
func (s *SessionStore) repersist(present map[string]session.Envelope) {
	s.mu.Lock()
	pending := make([]string, 0, len(s.unpersisted))
	for id := range s.unpersisted {
		pending = append(pending, id)
	}
	s.mu.Unlock() // released before any local-store or session lock is taken

	s.admit.Lock()
	defer s.admit.Unlock()
	full := s.rowCapReached()
	for _, id := range pending {
		sess, held := s.local.Get(id)
		if !held {
			s.setPersisted(id, true) // gone from this process; nothing left to write
			continue
		}
		if _, stored := present[id]; stored {
			// Somebody wrote it after all — possibly another replica. Deliberately
			// NOT overwritten with this process's envelope: that would replace a
			// peer's row with a possibly staler view.
			s.setPersisted(id, true)
			continue
		}
		// "Stop on full" must not mean "break out of the loop": the two arms above
		// prune entries for ids that have left the local store, and breaking would
		// stop that cleanup for every id after the break point — precisely while
		// the table sits at cap. Keep iterating; skip only the inserts. With a
		// cached count this costs no round trip at all.
		if full {
			continue
		}
		env := sess.Envelope()
		if !s.reserveGeneration(id) {
			continue
		}
		if err := s.insert(env); err != nil {
			if s.rowCapReached() {
				full = true
			}
			continue
		}
		s.setPersisted(id, true)
		present[id] = env
	}
}

// --- statements ---------------------------------------------------------------

func (s *SessionStore) selectOne(id string) (session.Envelope, bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), stmtTimeout)
	defer cancel()
	var (
		e                 session.Envelope
		createdUS, seenUS int64
	)
	err := s.st.DB().QueryRowContext(ctx, s.sel, id).Scan(&e.CSRF, &createdUS, &seenUS)
	if errors.Is(err, sql.ErrNoRows) {
		return session.Envelope{}, false, nil
	}
	if err != nil {
		return session.Envelope{}, false, err
	}
	e.ID, e.Created, e.LastSeen = id, FromMicros(createdUS), FromMicros(seenUS)
	return e, true, nil
}

func (s *SessionStore) selectAll() ([]session.Envelope, error) {
	ctx, cancel := context.WithTimeout(context.Background(), sweepTimeout)
	defer cancel()
	rows, err := s.st.DB().QueryContext(ctx, s.all)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []session.Envelope
	for rows.Next() {
		var (
			e                 session.Envelope
			createdUS, seenUS int64
		)
		if err := rows.Scan(&e.ID, &e.CSRF, &createdUS, &seenUS); err != nil {
			return nil, err
		}
		e.Created, e.LastSeen = FromMicros(createdUS), FromMicros(seenUS)
		out = append(out, e)
	}
	return out, rows.Err()
}

// insert writes a session envelope, replacing any row that already carries the
// id. Save's contract permits re-saving an existing id, and the two statements
// run in one transaction so a failed insert cannot leave the earlier row
// deleted.
//
// REQUIRES THE ADMISSION MUTEX to be held — which is what makes reading the row
// counter here safe without a second lock, and it is here that the cap has to be
// applied. Deciding AFTER insert returns is after Commit: the row already
// exists. Deciding BEFORE calling it cannot work either, because "does this
// insert grow the table?" is only knowable from the DELETE's own row count, so a
// pre-call test would refuse the row-neutral re-Save that is deliberately exempt.
//
// It OWNS the row counter and the resolution of e.ID's generation reservation.
// One owner, one increment: the caller never touches either, which is why this
// returns a bare error rather than a `grew` flag — with the counter internal
// there is no second party that could double-count.
func (s *SessionStore) insert(e session.Envelope) error {
	ctx, cancel := context.WithTimeout(context.Background(), stmtTimeout)
	defer cancel()
	tx, err := s.st.DB().BeginTx(ctx, nil)
	if err != nil {
		// Two lines before the deferred rollback is even registered: no
		// transaction was opened, so there is nothing to undo.
		s.releaseGeneration(e.ID)
		return err
	}
	defer tx.Rollback() //nolint:errcheck // no-op after a successful Commit
	res, err := tx.ExecContext(ctx, s.del, e.ID)
	if err != nil {
		s.releaseGeneration(e.ID)
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		s.releaseGeneration(e.ID)
		return err
	}
	// Captured BEFORE the INSERT, and separately from what Commit returns. A
	// REPLACEMENT (n == 1) reaches the very same Commit, so a rule keyed on the
	// commit alone would count every replacement as a new row.
	grew := n == 0
	if grew && s.rowCapReached() {
		// The deferred rollback undoes the DELETE, which removed nothing anyway.
		s.releaseGeneration(e.ID)
		return errAtCapacity
	}
	if _, err := tx.ExecContext(ctx, s.ins, e.ID, e.CSRF, Micros(e.Created), Micros(e.LastSeen)); err != nil {
		s.releaseGeneration(e.ID)
		return err
	}
	err = tx.Commit()
	// WHATEVER Commit returned. A commit whose response was lost may still have
	// applied, so an error does not mean "no row": counting only the nil case
	// undercounts and lets the table grow past the cap until the next reconcile.
	// The cost is an overcount of at most one per ambiguous commit — refusing
	// slightly early, corrected on the next sweep — which is deliberately gentler
	// than jumping to cap on one uncertain outcome, and it ratchets anyway if
	// commits keep failing. The marker is kept for the same reason.
	if grew {
		s.rows++
	}
	return err
}

// replaceRow deletes oldID and inserts new in one transaction, reporting whether
// oldID was actually there. A false with no error means the pre-auth session had
// already been removed — by a logout, a reap, or a competing login.
func (s *SessionStore) replaceRow(oldID string, new session.Envelope) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), stmtTimeout)
	defer cancel()
	tx, err := s.st.DB().BeginTx(ctx, nil)
	if err != nil {
		s.releaseGeneration(new.ID)
		return false, err
	}
	defer tx.Rollback() //nolint:errcheck // no-op after a successful Commit
	res, err := tx.ExecContext(ctx, s.del, oldID)
	if err != nil {
		s.releaseGeneration(new.ID)
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		s.releaseGeneration(new.ID)
		return false, err
	}
	if n != 1 {
		// Nothing was written, so the new id's reservation is spent.
		s.releaseGeneration(new.ID)
		return false, nil
	}
	if _, err := tx.ExecContext(ctx, s.ins, new.ID, new.CSRF, Micros(new.Created), Micros(new.LastSeen)); err != nil {
		s.releaseGeneration(new.ID)
		return false, err
	}
	if err := tx.Commit(); err != nil {
		// The commit was REACHED, so the row may exist: the marker stays. Same
		// fail-closed signal insert uses for its counter.
		return false, err
	}
	return true, nil
}

// execN is exec that REPORTS how many rows the statement changed. Every counted
// mutation goes through it: exec discards the result, so a delete that removed
// nothing returns nil and reads as success — which is what would make both the
// row counter and Replace's membership check unsound. exec stays for the
// genuinely fire-and-forget last_seen refresh.
func (s *SessionStore) execN(stmt string, args ...any) (int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), stmtTimeout)
	defer cancel()
	res, err := s.st.DB().ExecContext(ctx, stmt, args...)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (s *SessionStore) exec(stmt string, args ...any) error {
	ctx, cancel := context.WithTimeout(context.Background(), stmtTimeout)
	defer cancel()
	_, err := s.st.DB().ExecContext(ctx, stmt, args...)
	return err
}

// touch refreshes a session's stored last_seen, at most once per touchEvery.
func (s *SessionStore) touch(id string) {
	now := s.now()
	s.mu.Lock()
	if last, seen := s.touched[id]; seen && now.Sub(last) < s.touchEvery {
		s.mu.Unlock()
		return
	}
	if len(s.touched) >= maxTouchedEntries {
		s.touched = map[string]time.Time{}
	}
	s.touched[id] = now
	s.mu.Unlock()
	if err := s.exec(s.upd, Micros(now), id); err != nil {
		s.degraded("refreshing a session's last activity", err)
	}
}

// forget drops ALL of a session's per-id bookkeeping in one place — touched,
// unpersisted and generations. Three maps written from Save, Replace, Delete,
// repersist, Reap, Get (touch and adopt), Detach and the local store's eviction
// hook is how lifecycle state ended up in more than one place to begin with.
//
// Clearing unpersisted here is HYGIENE, not a retry-storm fix: after a Delete
// the id is gone from the local store, so the next repersist hits the !held arm,
// calls setPersisted(id, true), drops the entry and attempts no write. It
// self-cleans in one pass. It is done because leaving lifecycle state in two
// places is the thing that produced the rest of this.
//
// It is also the local store's eviction hook, which runs under that store's
// lock, so it must take s.mu ONLY — never the admission mutex.
func (s *SessionStore) forget(id string) {
	s.mu.Lock()
	delete(s.touched, id)
	delete(s.unpersisted, id)
	delete(s.generations, id)
	s.mu.Unlock()
}

// degradeLogEvery throttles the degradation warning. Session lookup is on the
// request path, so an unreachable metadata database would otherwise emit one
// warning per request — tens of thousands over a short outage, burying the
// startup context and everything else an operator needs while diagnosing it.
const degradeLogEvery = 30 * time.Second

// degraded reports that the metadata database could not be reached and this
// process is falling back to its own view. A warning rather than an error,
// because the fallback is a supported mode of operation — but sessions have
// stopped being durable, which the operator has to be told.
//
// The first occurrence is logged immediately; after that at most one line per
// degradeLogEvery, carrying the number of occurrences it stands for so the
// throttling never makes an outage look smaller than it was.
func (s *SessionStore) degraded(what string, err error) {
	// Counted before the nil-log return: the total is for /metrics, and an
	// operator scraping a store with no logger configured still needs it.
	s.degradeTotal.Add(1)
	if s.log == nil {
		return
	}
	now := s.now()
	s.mu.Lock()
	s.degradeCount++
	if !s.degradeLogged.IsZero() && now.Sub(s.degradeLogged) < degradeLogEvery {
		s.mu.Unlock()
		return
	}
	n := s.degradeCount
	s.degradeLogged, s.degradeCount = now, 0
	s.mu.Unlock()
	s.log.Warn("session storage unavailable; using this process's own view",
		"operation", what, "err", err, "occurrences", n)
}
