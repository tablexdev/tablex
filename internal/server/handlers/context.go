package handlers

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/tablexdev/tablex/internal/driver"
	"github.com/tablexdev/tablex/internal/session"
	"github.com/tablexdev/tablex/internal/view"
)

// UserContext is the per-session application payload. It owns the live database
// pools for one logged-in server connection, the user's preferences and the SQL
// console history. Credentials live here, in server-side memory only — never in
// the cookie, never logged, never persisted. Close() (wired to the session)
// releases every pool on logout or expiry.
type UserContext struct {
	ServerID   string
	ServerName string
	Engine     string

	dialect driver.Dialect
	// baseParams is the login params; Database is overridden per pool. It is
	// mutable — a DROP DATABASE on the login database rebinds Database to a
	// maintenance DB — so it is read/written only under uc.mu; readers that dial
	// outside the lock take a copy via snapshotParams.
	baseParams driver.ConnParams
	budget     *PoolBudget // process-wide pool budget (nil = unlimited)

	mu     sync.Mutex
	closed bool // set by Close; ConnFor/PinnedFor/ExportConnFor refuse afterwards
	// serverConn is the login pool (server-level ops). It is an atomic pointer so
	// reads stay lock-free at every site; it is normally set once, but a
	// successful DROP DATABASE on the login database rebinds it (under uc.mu) to a
	// maintenance-DB pool so the session survives.
	serverConn atomic.Pointer[driver.Connection]
	pools      map[string]*driver.Connection // per-database pools, keyed by db name
	opening    map[string]chan struct{}      // per-DB singleflight: closed when that dial finishes
	poolUse    map[string]int64              // last-use sequence per pool, for LRU eviction
	poolGen    map[string]int64              // per-DB generation; ClosePool bumps it to cancel an in-flight dial
	useSeq     int64

	rowsPerPage int
	history     []string
	flashes     []view.Flash // pending flashes shown on the next full render

	// queries is this session's statement allowance. It carries its own lock
	// rather than sharing uc.mu because it is charged while a script runs, and
	// uc.mu is held across pool dials — a script would otherwise stall behind an
	// unrelated connection attempt.
	queries queryBudget
}

// queryBudget is the per-session statement allowance (config
// session_query_budget). The policy — how many, over how long — is not stored
// here: it lives in the config the handlers already carry, and is passed to
// charge, so there is one copy of it and a running session cannot hold a stale
// one.
//
// The window is fixed rather than sliding: the count resets when the window
// rolls. A sliding window would need the timestamp of every charged statement,
// which is a per-session unbounded allocation to enforce a limit whose purpose is
// to bound resource use. The cost of the simpler choice is that a session can
// spend two budgets across a window boundary, which is documented on the config
// field rather than hidden here.
type queryBudget struct {
	mu    sync.Mutex
	start time.Time // when the current window opened; zero until first charged
	used  int
	// now replaces the clock (tests). Nil means time.Now.
	now func() time.Time
}

// charge takes one statement from a budget of limit statements per window. When
// it refuses, retryAfter is how long until the window rolls — always positive, so
// a caller can quote a real wait. A non-positive limit or window never refuses.
func (b *queryBudget) charge(limit int, window time.Duration) (retryAfter time.Duration, ok bool) {
	if limit <= 0 || window <= 0 {
		return 0, true
	}
	now := time.Now()
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.now != nil {
		now = b.now()
	}
	if b.start.IsZero() || !now.Before(b.start.Add(window)) {
		b.start, b.used = now, 0
	}
	if b.used >= limit {
		return b.start.Add(window).Sub(now), false
	}
	b.used++
	return 0, true
}

const (
	defaultRowsPerPage = 25
	maxHistory         = 50
)

// PoolBudget is the process-wide cap on cached per-database pools (config
// pool_cap), shared by every session. It bounds the unbounded dimension of
// connection growth: each session caches one pool (up to pool_max_conns
// connections) per database it touches, so without a budget N sessions × M
// databases would pile up pools indefinitely. The server-level login pools (one
// per session) are not counted — the session cap already bounds them — and the
// short-lived pinned/export connections are bounded by DBOpLimiter instead.
type PoolBudget struct {
	mu  sync.Mutex
	cap int
	n   int
}

// NewPoolBudget builds a budget allowing up to capacity cached per-database
// pools across all sessions; capacity <= 0 means unlimited.
func NewPoolBudget(capacity int) *PoolBudget { return &PoolBudget{cap: capacity} }

// tryAcquire reserves one pool slot, reporting false when the budget is spent.
// A nil budget or a non-positive cap never refuses.
func (b *PoolBudget) tryAcquire() bool {
	if b == nil || b.cap <= 0 {
		return true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.n >= b.cap {
		return false
	}
	b.n++
	return true
}

// release returns k pool slots to the budget.
func (b *PoolBudget) release(k int) {
	if b == nil || b.cap <= 0 || k <= 0 {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.n -= k
	if b.n < 0 {
		b.n = 0
	}
}

// InUse reports how many cached pools are currently charged to the budget, and
// Limit the ceiling (0 when unlimited). Both are for /metrics: pools approaching
// the cap is the leading indicator of the eviction pressure that makes browsing
// slow, and it is invisible from the outside.
func (b *PoolBudget) InUse() int {
	if b == nil || b.cap <= 0 {
		return 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.n
}

// Limit reports the pool ceiling, or 0 when unlimited.
func (b *PoolBudget) Limit() int {
	if b == nil {
		return 0
	}
	return max(b.cap, 0)
}

// DBOpLimiter caps how many requests may simultaneously hold a PRIVATE database
// connection — a streaming export, a SQL console script or a SQL import. Those
// deliberately open transient connections outside the cached-pool machinery
// (they must not share or evict a session pool), which put them outside
// PoolBudget as well; nothing else bounds them, and the server has no in-flight
// request cap, so enough parallel exports could exhaust the DATABASE's
// max_connections and take down every other client of that server.
//
// It refuses rather than queues: a caller that waited would hold an HTTP worker
// and its session while contributing nothing, and the client has no way to know
// the request is parked. 503 + Retry-After is the honest answer.
type DBOpLimiter struct {
	slots chan struct{} // nil = unlimited
	// refused counts the requests turned away, for /metrics. A cap that is being
	// hit is indistinguishable from one that is not without it: the in-flight
	// gauge sits at the ceiling in both the healthy-and-busy and the
	// refusing-work case, and only this number separates them.
	refused atomic.Int64
}

// NewDBOpLimiter allows up to n concurrent private-connection operations;
// n <= 0 means unlimited.
func NewDBOpLimiter(n int) *DBOpLimiter {
	if n <= 0 {
		return &DBOpLimiter{}
	}
	return &DBOpLimiter{slots: make(chan struct{}, n)}
}

// TryAcquire reserves a slot, returning a release func and true on success. The
// release func is idempotent, so `defer release()` is safe alongside an early
// explicit release. A nil limiter or an unlimited one always succeeds.
func (l *DBOpLimiter) TryAcquire() (release func(), ok bool) {
	if l == nil || l.slots == nil {
		return func() {}, true
	}
	select {
	case l.slots <- struct{}{}:
		var once sync.Once
		return func() { once.Do(func() { <-l.slots }) }, true
	default:
		l.refused.Add(1)
		return nil, false
	}
}

// InFlight reports how many slots are currently held (0 when unlimited).
func (l *DBOpLimiter) InFlight() int {
	if l == nil || l.slots == nil {
		return 0
	}
	return len(l.slots)
}

// Limit reports the concurrency ceiling, or 0 when unlimited.
func (l *DBOpLimiter) Limit() int {
	if l == nil || l.slots == nil {
		return 0
	}
	return cap(l.slots)
}

// Refused reports how many operations have been turned away since startup.
func (l *DBOpLimiter) Refused() int64 {
	if l == nil {
		return 0
	}
	return l.refused.Load()
}

// NewUserContext builds a context around an already-opened server connection.
// budget may be nil (no pool cap).
//
// d MUST be serverConn.Dialect() — the copy driver.Open routed through
// driver.Specialize, carrying the detected flavor, server version and sql_mode —
// and never the registered singleton returned by driver.Get. The singleton is the
// zero value, so every version/flavor gate reading uc.Dialect() fails closed:
// that is precisely how the SQL console came to classify MariaDB's
// `DELETE … RETURNING` as a non-row statement and discard its rows. (The
// parameter stays separate from serverConn because tests build connection-less
// contexts, and because a few deliberately pair a dialect with a stand-in
// connection of another engine.)
//
// The dialect is fixed for the session's lifetime and read without uc.mu. A later
// rebindServerConn does NOT refresh it: the maintenance database it swaps to
// lives on the same server, so the specialization is identical, and a mutable
// field would race every lock-free uc.Dialect() reader.
func NewUserContext(serverID, serverName string, d driver.Dialect, base driver.ConnParams, serverConn *driver.Connection, budget *PoolBudget) *UserContext {
	uc := &UserContext{
		ServerID:    serverID,
		ServerName:  serverName,
		Engine:      d.Name(),
		dialect:     d,
		baseParams:  base,
		budget:      budget,
		pools:       map[string]*driver.Connection{},
		opening:     map[string]chan struct{}{},
		poolUse:     map[string]int64{},
		poolGen:     map[string]int64{},
		rowsPerPage: defaultRowsPerPage,
	}
	uc.serverConn.Store(serverConn)
	return uc
}

// errSessionClosed is returned by connection accessors when the session was
// closed (logout or expiry reaping) while a request was still in flight.
var errSessionClosed = errors.New("this session has ended; please log in again")

// Dialect returns the engine dialect.
func (uc *UserContext) Dialect() driver.Dialect { return uc.dialect }

// Capabilities returns the engine capability flags.
func (uc *UserContext) Capabilities() driver.Capabilities { return uc.dialect.Capabilities() }

// ServerConn returns the server-level connection (no specific database). The
// read is a lock-free atomic load: the pointer is normally set once, but a
// successful DROP DATABASE on the login database rebinds it (under uc.mu) to a
// maintenance-DB pool. After Close the underlying pool is closed and any query
// on it returns database/sql's ErrDBClosed — a clean error, not a leak (only
// ConnFor could re-open pools, and its closed check prevents that).
func (uc *UserContext) ServerConn() *driver.Connection { return uc.serverConn.Load() }

// snapshotParams returns a copy of baseParams taken under uc.mu (only its
// Database string is ever mutated, and the shared Params map is never mutated in
// place), so a caller that dials outside the lock cannot tear the read against a
// concurrent login-database rebind. It reports errSessionClosed if the session
// has ended.
func (uc *UserContext) snapshotParams() (driver.ConnParams, error) {
	uc.mu.Lock()
	defer uc.mu.Unlock()
	if uc.closed {
		return driver.ConnParams{}, errSessionClosed
	}
	return uc.baseParams, nil
}

// redactErr renders a post-login connection-open error safe to show or log:
// it strips the session password and the DSN that embeds it (the same needles
// the login path builds) before redactConnError's first-line/length trim.
// Statement/introspection errors don't need this — they occur after a
// successful connect and cannot echo credentials — but a failed dial can.
func (uc *UserContext) redactErr(err error) string {
	uc.mu.Lock()
	p := uc.baseParams
	uc.mu.Unlock()
	secrets := []string{p.Password}
	if dsn, derr := uc.dialect.BuildDSN(p); derr == nil {
		secrets = append(secrets, dsn)
	}
	return redactConnError(err, secrets...)
}

// ClosePool closes and forgets the cached per-database pool for database (if
// any), releasing its budget slot, and bumps the database's generation so an
// in-flight ConnFor dial for it discards its fresh pool instead of re-caching a
// pool (and re-leaking a slot) for a database that is being dropped. Safe on
// every engine.
func (uc *UserContext) ClosePool(database string) {
	uc.mu.Lock()
	defer uc.mu.Unlock()
	uc.poolGen[database]++
	if c, ok := uc.pools[database]; ok {
		c.Close()
		delete(uc.pools, database)
		delete(uc.poolUse, database)
		uc.budget.release(1)
	}
}

// openMaintenanceConn opens a transient connection to a database other than
// target, for running a DROP DATABASE that the session cannot run on its own
// (target) connection. The candidate names and their preference order come from
// the dialect (driver.MaintenanceDatabaseLister); an engine without the
// capability fails here rather than having a name guessed for it. The caller
// owns the returned connection.
func (uc *UserContext) openMaintenanceConn(ctx context.Context, target string) (*driver.Connection, string, error) {
	lister, ok := uc.dialect.(driver.MaintenanceDatabaseLister)
	if !ok {
		return nil, "", errors.New("this engine has no maintenance database to connect to")
	}
	p, err := uc.snapshotParams()
	if err != nil {
		return nil, "", err
	}
	var lastErr error
	for _, cand := range lister.MaintenanceDatabases() {
		if cand == target {
			continue
		}
		mp := p
		mp.Database = cand
		c, err := driver.Open(ctx, uc.dialect, mp)
		if err == nil {
			return c, cand, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("no maintenance database available")
	}
	return nil, "", lastErr
}

// rebindServerConn swaps the login (server) connection to newConn and points
// baseParams.Database at db, then closes the old server pool. Used after dropping
// the database the session logged into so ServerConn()/ConnFor("") keep working.
// The swap+baseParams write happen under uc.mu with the closed-flag check, so the
// rebind cannot race Close (which also holds uc.mu) into a leaked pool; if the
// session ended, newConn is closed and errSessionClosed returned.
func (uc *UserContext) rebindServerConn(newConn *driver.Connection, db string) error {
	uc.mu.Lock()
	if uc.closed {
		uc.mu.Unlock()
		newConn.Close()
		return errSessionClosed
	}
	old := uc.serverConn.Swap(newConn)
	uc.baseParams.Database = db
	uc.mu.Unlock()
	if old != nil {
		old.Close() // in-flight queries fail cleanly — the DB is gone and FORCE terminated its backends
	}
	return nil
}

// ConnFor returns a connection bound to the given database, opening and caching
// a pool if necessary. Engines whose databases all live on the one server
// connection (Capabilities().DatabasesShareConnection — SQLite's single file)
// and the login database reuse the server connection; other databases get
// their own pool — required for PostgreSQL (one DB per connection) and
// convenient for MySQL console ergonomics.
func (uc *UserContext) ConnFor(ctx context.Context, database string) (*driver.Connection, error) {
	if database == "" || uc.Capabilities().DatabasesShareConnection || database == uc.serverConn.Load().Info().Database {
		// The server-connection path also honors the closed flag: a request
		// racing logout/expiry gets a clean error instead of a closed pool.
		uc.mu.Lock()
		defer uc.mu.Unlock()
		if uc.closed {
			return nil, errSessionClosed
		}
		return uc.serverConn.Load(), nil
	}
	for {
		uc.mu.Lock()
		if uc.closed {
			// Without this check a request racing logout/reap would re-open a pool
			// into a map nobody will ever close again — a pool + connectionOpener
			// goroutine leak per race.
			uc.mu.Unlock()
			return nil, errSessionClosed
		}
		if c, ok := uc.pools[database]; ok {
			uc.touchPoolLocked(database)
			uc.mu.Unlock()
			return c, nil
		}
		if ch, ok := uc.opening[database]; ok {
			// Another request is already dialing this database: wait for that dial
			// rather than stacking a second one, then re-check the cache.
			uc.mu.Unlock()
			select {
			case <-ch:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			continue
		}
		if !uc.budget.tryAcquire() {
			// Budget spent: make room by evicting this session's least-recently-used
			// idle pool. Other sessions' pools are never touched — a session must not
			// be able to kill a neighbour's connections.
			if !uc.evictIdlePoolLocked() || !uc.budget.tryAcquire() {
				uc.mu.Unlock()
				return nil, fmt.Errorf("open database pools are at the configured cap (pool_cap); retry later or raise pool_cap")
			}
		}
		ch := make(chan struct{})
		uc.opening[database] = ch
		// Snapshot the params and this database's generation while still holding
		// the lock, so the dial cannot tear against a concurrent rebind and a
		// ClosePool during the dial is detectable on re-lock.
		gen := uc.poolGen[database]
		p := uc.baseParams
		p.Database = database

		// Dial OUTSIDE the lock: holding uc.mu across a network dial (15s timeout)
		// would stall every other request of this session — including ones that
		// only need an already-cached pool — behind one hung connection attempt.
		uc.mu.Unlock()
		c, err := driver.Open(ctx, uc.dialect, p)

		uc.mu.Lock()
		delete(uc.opening, database)
		close(ch)
		if err != nil {
			uc.budget.release(1)
			uc.mu.Unlock()
			return nil, err
		}
		if uc.closed {
			// The session ended while we were dialing: don't leak the fresh pool.
			uc.mu.Unlock()
			c.Close()
			uc.budget.release(1)
			return nil, errSessionClosed
		}
		if uc.poolGen[database] != gen {
			// ClosePool ran while we were dialing (e.g. this database was just
			// dropped): don't cache a pool for it and re-leak the budget slot.
			// Close the fresh pool, release the slot, and retry — the re-dial then
			// fails cleanly because the database is gone.
			uc.mu.Unlock()
			c.Close()
			uc.budget.release(1)
			continue
		}
		uc.pools[database] = c
		uc.touchPoolLocked(database)
		uc.mu.Unlock()
		return c, nil
	}
}

// touchPoolLocked records a pool use for LRU ordering. Caller holds uc.mu.
func (uc *UserContext) touchPoolLocked(database string) {
	uc.useSeq++
	uc.poolUse[database] = uc.useSeq
}

// evictIdlePoolLocked closes this session's least-recently-used pool that has no
// connection checked out, releasing its budget slot. Caller holds uc.mu. It
// reports false when every pool is busy (nothing safely evictable). A request
// that still holds the evicted *Connection from an earlier ConnFor would see
// sql.ErrConnDone-style errors on its next query — acceptable at budget
// exhaustion, and the InUse check keeps the window to pools with no statement
// currently running.
func (uc *UserContext) evictIdlePoolLocked() bool {
	victim := ""
	var oldest int64
	for database, c := range uc.pools {
		if c.DB().Stats().InUse > 0 {
			continue
		}
		if seq := uc.poolUse[database]; victim == "" || seq < oldest {
			victim, oldest = database, seq
		}
	}
	if victim == "" {
		return false
	}
	uc.pools[victim].Close()
	delete(uc.pools, victim)
	delete(uc.poolUse, victim)
	uc.budget.release(1)
	return true
}

// rebindDatabase applies the dialect's database-rebinding policy for a dial
// bound to a specific logical database: by default the params' Database is
// replaced, but a dialect whose logical database does not map to a DSN
// parameter (driver.DatabaseRebinder — SQLite) keeps its params unchanged.
func rebindDatabase(d driver.Dialect, p driver.ConnParams, database string) driver.ConnParams {
	if r, ok := d.(driver.DatabaseRebinder); ok {
		return r.RebindDatabase(p, database)
	}
	p.Database = database
	return p
}

// PinnedFor opens a dedicated, transient single connection bound to the given
// database (or the login database when empty) for multi-statement script
// execution. Unlike ConnFor it never shares or caches: the caller owns the
// connection and must Close it when the script finishes, which discards any
// session state (SETs, PRAGMAs) the script established.
func (uc *UserContext) PinnedFor(ctx context.Context, database string) (*driver.Pinned, error) {
	p, err := uc.snapshotParams()
	if err != nil {
		return nil, err
	}
	if database != "" {
		p = rebindDatabase(uc.dialect, p, database)
	}
	return driver.OpenPinned(ctx, uc.dialect, p)
}

// ExportConnFor opens a dedicated, transient connection pool for a streaming
// export, bound to the given database (or the login database when empty). The
// caller owns it and must Close it when the export finishes — shared ConnFor
// pools must never be closed (they are cached per session). Dialect-owned
// export session pinning is applied via driver.ExportConnAdjuster (MySQL pins
// time_zone, sql_mode and sql_quote_show_create so dumps render
// restore-parsable); the hook clones the shared Params map before modifying.
func (uc *UserContext) ExportConnFor(ctx context.Context, database string) (*driver.Connection, error) {
	p, err := uc.snapshotParams()
	if err != nil {
		return nil, err
	}
	if database != "" {
		p = rebindDatabase(uc.dialect, p, database)
	}
	if a, ok := uc.dialect.(driver.ExportConnAdjuster); ok {
		p = a.ExportConnParams(p)
	}
	return driver.Open(ctx, uc.dialect, p)
}

// RowsPerPage returns the user's browse page size.
func (uc *UserContext) RowsPerPage() int {
	uc.mu.Lock()
	defer uc.mu.Unlock()
	if uc.rowsPerPage <= 0 {
		return defaultRowsPerPage
	}
	return uc.rowsPerPage
}

// SetRowsPerPage updates the browse page-size preference, clamping it to an
// allowed option so a poisoned or out-of-range value cannot persist.
func (uc *UserContext) SetRowsPerPage(n int) {
	uc.mu.Lock()
	defer uc.mu.Unlock()
	uc.rowsPerPage = clampRowsPerPage(n)
}

// maxHistoryEntry caps how much of one console statement is retained in history.
// The entry COUNT is bounded by maxHistory, but a single huge pasted script would
// otherwise be stored verbatim and re-embedded on every console render — so
// truncate long entries (a marker keeps them recognizable).
const maxHistoryEntry = 4096

// AddHistory records a SQL statement in the per-session console history
// (most-recent first, de-duplicated, bounded in count and per-entry size).
func (uc *UserContext) AddHistory(q string) {
	if q == "" {
		return
	}
	if len(q) > maxHistoryEntry {
		// Keep the documented BYTE cap (a rune-count cap could retain 4× the
		// bytes), but back up at most 3 bytes to a rune boundary so the cut
		// cannot split a multi-byte rune into a U+FFFD glyph.
		cut := maxHistoryEntry
		for cut > maxHistoryEntry-utf8.UTFMax && !utf8.RuneStart(q[cut]) {
			cut--
		}
		q = q[:cut] + " …(truncated)"
	}
	uc.mu.Lock()
	defer uc.mu.Unlock()
	// Drop an existing identical entry so it moves to the top.
	for i, h := range uc.history {
		if h == q {
			uc.history = append(uc.history[:i], uc.history[i+1:]...)
			break
		}
	}
	uc.history = append([]string{q}, uc.history...)
	if len(uc.history) > maxHistory {
		uc.history = uc.history[:maxHistory]
	}
}

// History returns a copy of the console history (most recent first).
func (uc *UserContext) History() []string {
	uc.mu.Lock()
	defer uc.mu.Unlock()
	out := make([]string, len(uc.history))
	copy(out, uc.history)
	return out
}

// AddFlash queues a flash message to show on the next full page render (used
// across HX-Location / 303 redirects, which start a fresh request).
func (uc *UserContext) AddFlash(f view.Flash) {
	uc.mu.Lock()
	defer uc.mu.Unlock()
	uc.flashes = append(uc.flashes, f)
}

// takeFlashes returns and clears the queued flashes.
func (uc *UserContext) takeFlashes() []view.Flash {
	uc.mu.Lock()
	defer uc.mu.Unlock()
	if len(uc.flashes) == 0 {
		return nil
	}
	out := uc.flashes
	uc.flashes = nil
	return out
}

// Close releases every pool. Wired to the session's close hook. The closed
// flag makes every later (or in-flight, racing) ConnFor/PinnedFor/ExportConnFor
// fail with errSessionClosed instead of re-opening pools nobody would close;
// a dial already in flight sees the flag when it re-locks and discards its
// fresh pool.
func (uc *UserContext) Close() {
	uc.mu.Lock()
	defer uc.mu.Unlock()
	uc.closed = true
	for _, c := range uc.pools {
		c.Close()
	}
	uc.budget.release(len(uc.pools))
	uc.pools = map[string]*driver.Connection{}
	uc.poolUse = map[string]int64{}
	// Load the current server pool (a rebind may have replaced it) and close it.
	// The store-under-mu rule serializes rebind against this critical section, so
	// exactly one of {rebind, Close} closes the connection each swaps in/out.
	if c := uc.serverConn.Load(); c != nil {
		c.Close()
	}
}

// userFromSession extracts the UserContext payload from a session, if logged in.
func userFromSession(s *session.Session) (*UserContext, bool) {
	if s == nil {
		return nil, false
	}
	uc, ok := s.App().(*UserContext)
	return uc, ok
}
