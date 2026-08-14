package session

import (
	"container/list"
	"sync"
)

// maxSessions bounds the in-memory store so a flood of pre-auth session creation
// (an unauthenticated client hitting the server without cookies) cannot grow it
// without limit before the idle reaper runs. At the cap a session is evicted in
// O(1) — pre-auth (no payload) sessions first.
const maxSessions = 10000

// Store persists sessions server-side. The default implementation is an
// in-memory map; the interface lets a persistent/clustered backend be added
// later without touching the manager or handlers.
type Store interface {
	Get(id string) (*Session, bool)
	Save(s *Session)
	Delete(id string)
	// Replace atomically swaps old for new under one lock: it verifies old is
	// still a store member (EXACT pointer — a same-id re-insert does not
	// count), removes it, and inserts new into the authenticated bucket.
	// Reports false — inserting nothing — when old is absent (evicted, reaped
	// or destroyed since it was loaded). Manager.Authenticate composes it with
	// session construction so a login can never resurrect a removed session
	// or leave a payload-bearing session in the pre-auth bucket.
	Replace(old, new *Session) bool
	// Reap removes sessions for which expired(s) is true, returning them so the
	// caller can close their resources. Implementations must remove atomically.
	Reap(expired func(*Session) bool) []*Session
	// Len reports the number of sessions currently held (observability).
	Len() int
}

// Detacher is an optional Store capability for backends whose membership is
// shared with other processes — a database-backed store, where a row outlives
// the process that created it and is visible to every replica.
//
// Such a store has to distinguish two things the in-memory store conflates:
//
//	"release the resources I am holding"  → Detach, on shutdown
//	"this session is over for everyone"   → Delete / Reap
//
// Manager.Shutdown means the first. Routed through Reap with an always-true
// predicate — correct for a store that IS the only copy — it would delete every
// session belonging to every replica, so one node restarting would log out the
// whole cluster. A store that implements Detach gets asked properly; one that
// does not keeps today's behaviour exactly.
//
// Detach must return every session the process holds, having removed them from
// its local view, and must leave the shared record untouched.
type Detacher interface {
	Detach() []*Session
}

// listEntry tracks a session's position so it can be detached in O(1) without
// scanning either list (an element doesn't expose which list it belongs to).
type listEntry struct {
	el *list.Element
	l  *list.List
}

// memStore is a mutex-guarded in-memory Store. Capacity eviction is O(1): two
// FIFO lists hold sessions in save order — pre-auth (no payload) and
// authenticated — so a cookie-less flood evicts only other pre-auth sessions and
// can never push out a logged-in user while a pre-auth session exists. `entries`
// maps each id to its list element for O(1) removal on Delete/Reap.
//
// Eviction is FIFO by save order, not strict least-recently-seen: a session's
// list position is fixed when it enters the store (Start for pre-auth; the
// Replace of Authenticate for authenticated), and LastSeen updates on Load do
// not reorder it. This is the documented, accepted trade-off for O(1) eviction
// — it only matters at the 10k cap, and the pre-auth-first rule (the real
// flood protection) holds. Payloads only ever enter through Replace's
// authenticated-bucket insert, so a pre-auth entry never carries pools and
// evictOldestLocked needs no payload check.
type memStore struct {
	mu       sync.RWMutex
	sessions map[string]*Session
	entries  map[string]listEntry
	preAuth  *list.List // *Session, oldest at Front
	auth     *list.List // *Session, oldest at Front
	onEvict  func(id string)
}

// MemStoreConfig tunes the in-memory store.
type MemStoreConfig struct {
	// OnEvict, when set, is called with the id of a session dropped to make room
	// at maxSessions. It exists because eviction is otherwise SILENT: a wrapper
	// keeping per-id bookkeeping (the durable store's) would let those entries
	// outlive the sessions they describe, which is unbounded growth by another
	// name.
	//
	// It runs UNDER the store lock, at the eviction, so no concurrent Get can
	// observe the id in between and re-create state the hook is about to drop.
	// It must therefore be cheap and must not call back into this store.
	OnEvict func(id string)
}

// NewMemStore returns an empty in-memory store.
func NewMemStore() Store { return NewMemStoreWith(MemStoreConfig{}) }

// NewMemStoreWith is NewMemStore with configuration. Both forms exist so the
// callers that need no hook — and every test — stay untouched.
func NewMemStoreWith(cfg MemStoreConfig) Store {
	return &memStore{
		sessions: make(map[string]*Session),
		entries:  make(map[string]listEntry),
		preAuth:  list.New(),
		auth:     list.New(),
		onEvict:  cfg.OnEvict,
	}
}

func (m *memStore) Get(id string) (*Session, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.sessions[id]
	return s, ok
}

func (m *memStore) Len() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.sessions)
}

func (m *memStore) Save(s *Session) {
	// Snapshot the id via the locked accessor (IDs are fixed at construction
	// now that Authenticate replaces rather than re-keys, but the accessor
	// keeps a single read discipline). The store→session lock order is
	// preserved (snapshotID releases the session lock before m.mu is taken).
	id := s.snapshotID()
	var victim *Session
	m.mu.Lock()
	if _, exists := m.sessions[id]; exists {
		// Re-saving an existing id (rare): drop the stale element so the bucket is
		// recomputed from the current payload below.
		m.detachLocked(id)
	} else if len(m.sessions) >= maxSessions {
		victim = m.evictOldestLocked()
		if victim != nil && m.onEvict != nil {
			// UNDER m.mu, and deliberately not deferred to the close() below:
			// m.mu is released before that, and in the gap another request could
			// Get the evicted id, adopt its durable row and stamp fresh state
			// that the late hook would then erase. Holding the lock here means a
			// competing Get blocks in Get's RLock until the hook has finished.
			m.onEvict(victim.snapshotID())
		}
	}
	m.sessions[id] = s
	// Bucket by whether the session has logged in yet. App() takes the session
	// lock while we hold m.mu — the same store→session order the reaper uses.
	l := m.preAuth
	if s.App() != nil {
		l = m.auth
	}
	m.entries[id] = listEntry{el: l.PushBack(s), l: l}
	m.mu.Unlock()
	if victim != nil {
		victim.close() // release any pools outside the store lock
	}
}

// detachLocked removes a session's bookkeeping from its FIFO list and the entry
// map (it stays in m.sessions unless the caller also deletes it). Caller holds m.mu.
func (m *memStore) detachLocked(id string) {
	if e, ok := m.entries[id]; ok {
		e.l.Remove(e.el)
		delete(m.entries, id)
	}
}

// evictOldestLocked removes and returns the oldest evictable session, preferring
// pre-auth (no payload) sessions so a flood doesn't evict logged-in users while
// unauthenticated sessions are available. Caller holds m.mu.
func (m *memStore) evictOldestLocked() *Session {
	e := m.preAuth.Front()
	if e == nil {
		e = m.auth.Front() // every session is authenticated; evict the overall oldest saved
	}
	if e == nil {
		return nil
	}
	v := e.Value.(*Session)
	m.detachLocked(v.ID)
	delete(m.sessions, v.ID)
	return v
}

// Replace implements the Store contract: the membership check, removal of old
// and authenticated-bucket insert of new all happen under one m.mu hold, so a
// concurrent eviction/Reap/Destroy either wins entirely (Replace reports
// false) or loses entirely (it can no longer see old). A benign duplicate
// login submit on the same pre-auth session resolves the same way: the second
// Replace finds old absent and fails cleanly.
func (m *memStore) Replace(old, new *Session) bool {
	oldID, newID := old.snapshotID(), new.snapshotID()
	m.mu.Lock()
	cur, ok := m.sessions[oldID]
	if !ok || cur != old {
		m.mu.Unlock()
		return false
	}
	delete(m.sessions, oldID)
	m.detachLocked(oldID)
	m.detachLocked(newID) // vanishing-odds id collision: never leave a stale element
	m.sessions[newID] = new
	m.entries[newID] = listEntry{el: m.auth.PushBack(new), l: m.auth}
	m.mu.Unlock()
	return true
}

func (m *memStore) Delete(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, id)
	m.detachLocked(id)
}

func (m *memStore) Reap(expired func(*Session) bool) []*Session {
	m.mu.Lock()
	defer m.mu.Unlock()
	var dead []*Session
	for id, s := range m.sessions {
		if expired(s) {
			dead = append(dead, s)
			delete(m.sessions, id)
			m.detachLocked(id)
		}
	}
	return dead
}
