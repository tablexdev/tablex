package handlers

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"

	"github.com/tablexdev/tablex/internal/driver"
	_ "github.com/tablexdev/tablex/internal/driver/mysql"
)

// TestSQLiteConnLifecycles covers 3.6: the two distinct SQLite policies must
// survive the capability/hook refactor. ConnFor REUSES the cached server
// connection for every logical database (DatabasesShareConnection), while
// PinnedFor/ExportConnFor still open fresh PRIVATE connections — merely
// skipping the database rebind (RebindDatabase identity), never sharing.
func TestSQLiteConnLifecycles(t *testing.T) {
	d, _ := driver.Get("sqlite")
	server := openTestConn(t)
	uc := NewUserContext("srv", "srv", d, driver.ConnParams{FilePath: sqliteTestPath(t)}, server, nil)
	defer uc.Close()
	ctx := context.Background()

	for _, db := range []string{"", "main", "somewhere"} {
		conn, err := uc.ConnFor(ctx, db)
		if err != nil {
			t.Fatalf("ConnFor(%q): %v", db, err)
		}
		if conn != server {
			t.Errorf("ConnFor(%q) opened a new connection; SQLite must reuse the server connection", db)
		}
	}

	pinned, err := uc.PinnedFor(ctx, "main")
	if err != nil {
		t.Fatalf("PinnedFor: %v", err)
	}
	defer pinned.Close()
	if _, err := pinned.Exec(ctx, "SELECT 1"); err != nil {
		t.Errorf("pinned connection unusable: %v", err)
	}

	econn, err := uc.ExportConnFor(ctx, "main")
	if err != nil {
		t.Fatalf("ExportConnFor: %v", err)
	}
	defer econn.Close()
	if econn == server {
		t.Error("ExportConnFor must open a private connection, never the shared server connection")
	}
}

// TestMaintenanceConnNeedsCapability pins: the maintenance-database names
// come from the dialect, not from a list of PostgreSQL names embedded in
// generic session code. An engine that does not implement
// driver.MaintenanceDatabaseLister is refused outright — no name is guessed on
// its behalf, and the refusal happens before any connection is attempted.
func TestMaintenanceConnNeedsCapability(t *testing.T) {
	d, _ := driver.Get("sqlite")
	server := openTestConn(t)
	uc := NewUserContext("srv", "srv", d, driver.ConnParams{FilePath: sqliteTestPath(t)}, server, nil)
	defer uc.Close()

	conn, name, err := uc.openMaintenanceConn(context.Background(), "main")
	if err == nil {
		conn.Close()
		t.Fatalf("openMaintenanceConn succeeded on an engine without the capability (bound to %q)", name)
	}
	if !strings.Contains(err.Error(), "maintenance database") {
		t.Errorf("error does not explain the missing capability: %v", err)
	}
}

// sqliteTestPath creates an empty temp SQLite file and returns its path.
func sqliteTestPath(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ctx.db")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("create temp db file: %v", err)
	}
	return path
}

// TestAddHistoryRuneBoundary covers 1.5: the per-entry byte cap must land on a
// UTF-8 rune boundary — cutting mid-rune left a U+FFFD glyph in the console
// history. The cap stays a byte cap (backing up at most 3 bytes), never a
// rune-count cap that could retain 4× the documented bytes.
func TestAddHistoryRuneBoundary(t *testing.T) {
	d, _ := driver.Get("mysql")
	uc := NewUserContext("srv", "srv", d, driver.ConnParams{}, nil, nil)

	// Place a 3-byte rune (€, E2 82 AC) straddling the cap: bytes 4095..4097.
	q := strings.Repeat("a", maxHistoryEntry-1) + "€€€"
	uc.AddHistory(q)
	got := uc.History()[0]
	entry, _, ok := strings.Cut(got, " …(truncated)")
	if !ok {
		t.Fatalf("entry was not truncated: len=%d", len(got))
	}
	if !utf8.ValidString(entry) {
		t.Errorf("truncation split a rune: trailing bytes % x", entry[len(entry)-4:])
	}
	if len(entry) > maxHistoryEntry || len(entry) < maxHistoryEntry-3 {
		t.Errorf("cut landed at %d bytes, want within 3 of %d", len(entry), maxHistoryEntry)
	}

	// Pure-ASCII input still cuts at exactly the cap.
	uc.AddHistory(strings.Repeat("b", maxHistoryEntry+10))
	entry, _, _ = strings.Cut(uc.History()[0], " …(truncated)")
	if len(entry) != maxHistoryEntry {
		t.Errorf("ASCII cut = %d bytes, want exactly %d", len(entry), maxHistoryEntry)
	}
}

// TestUserContextCloseRace covers the concurrency contract around the login
// (server) connection. ServerConn() is a lock-free atomic load; a DROP DATABASE
// on the login database rebinds it (atomic Swap) and baseParams.Database (under
// uc.mu); ConnFor/snapshotParams read those; ClosePool bumps the per-database
// generation under uc.mu; and Close tears everything down. All of that must stay
// race-free and panic-free. Uses a non-sqlite engine so the pool/generation
// paths are exercised. Run under `go test -race` to actually exercise it.
func TestUserContextCloseRace(t *testing.T) {
	d, _ := driver.Get("mysql")
	// Pre-create the connections the rebinders swap in (t is not goroutine-safe,
	// so openTestConn cannot be called from the worker goroutines).
	rebinds := make([]*driver.Connection, 0, 16)
	for range 16 {
		rebinds = append(rebinds, openTestConn(t))
	}
	uc := NewUserContext("srv", "srv", d, driver.ConnParams{Host: "127.0.0.1", Port: 1}, openTestConn(t), nil)

	ctx := context.Background()
	var wg sync.WaitGroup
	for range 6 {
		wg.Go(func() {
			for range 200 {
				_ = uc.ServerConn() // lock-free read, concurrent with rebind/Close
				_ = uc.Capabilities()
				_, _ = uc.snapshotParams() // reads baseParams under mu vs rebind's write
				uc.ClosePool("db1")        // bumps poolGen under mu
				// ConnFor("") server path: the current server conn or errSessionClosed.
				if c, err := uc.ConnFor(ctx, ""); err != nil && !errors.Is(err, errSessionClosed) {
					t.Errorf("ConnFor during close = %v, want nil or errSessionClosed", err)
				} else {
					_ = c
				}
			}
		})
	}
	// Rebinder: swap in fresh maintenance connections, as a login-database drop
	// would. rebindServerConn closes each old conn (or the new one if the session
	// already ended), so every connection is closed exactly once.
	wg.Go(func() {
		for _, c := range rebinds {
			_ = uc.rebindServerConn(c, "maint")
		}
	})
	uc.Close()
	wg.Wait()

	if _, err := uc.ConnFor(ctx, ""); !errors.Is(err, errSessionClosed) {
		t.Errorf("ConnFor after Close = %v, want errSessionClosed", err)
	}
}

// TestClosePool pins ClosePool's contract (H2): it closes and forgets the cached
// pool, releases its budget slot, and bumps the per-database generation (which
// cancels an in-flight ConnFor dial) even for a database with no cached pool.
func TestClosePool(t *testing.T) {
	a := openTestConn(t)
	budget := NewPoolBudget(4)
	budget.tryAcquire() // account for the pool injected below
	uc := &UserContext{
		budget:  budget,
		pools:   map[string]*driver.Connection{"db1": a},
		poolUse: map[string]int64{"db1": 1},
		poolGen: map[string]int64{},
	}
	uc.ClosePool("db1")
	if _, ok := uc.pools["db1"]; ok {
		t.Error("ClosePool did not remove the pool")
	}
	if uc.poolGen["db1"] != 1 {
		t.Errorf("ClosePool did not bump the generation: got %d", uc.poolGen["db1"])
	}
	if err := a.Ping(context.Background()); err == nil {
		t.Error("ClosePool did not close the pool")
	}
	if !budget.tryAcquire() {
		t.Error("ClosePool did not release the budget slot")
	}
	// An absent pool still bumps the generation (to cancel an in-flight dial) but
	// releases no slot.
	uc.ClosePool("absent")
	if uc.poolGen["absent"] != 1 {
		t.Errorf("ClosePool(absent) did not bump the generation: got %d", uc.poolGen["absent"])
	}
}

func TestPoolBudgetArithmetic(t *testing.T) {
	b := NewPoolBudget(2)
	for i := range 2 {
		if !b.tryAcquire() {
			t.Fatalf("budget of 2 refused acquisition %d", i+1)
		}
	}
	if b.tryAcquire() {
		t.Error("budget of 2 allowed a third pool")
	}
	b.release(1)
	if !b.tryAcquire() {
		t.Error("released slot was not reusable")
	}
	// Over-release clamps at zero rather than going negative.
	b.release(100)
	if !b.tryAcquire() {
		t.Error("budget unusable after over-release")
	}

	// Unlimited modes never refuse.
	if !NewPoolBudget(0).tryAcquire() {
		t.Error("cap 0 should be unlimited")
	}
	var nilBudget *PoolBudget
	if !nilBudget.tryAcquire() {
		t.Error("nil budget should be unlimited")
	}
	nilBudget.release(1) // must not panic
}

// TestConnForAfterClose pins the logout/reap race fix: once Close has run,
// every connection accessor refuses with errSessionClosed instead of handing
// out the closed server pool or — worse — dialing a fresh per-database pool
// into a map nobody will ever close again.
func TestConnForAfterClose(t *testing.T) {
	d, ok := driver.Get("mysql") // a network engine, so ConnFor takes the pool path
	if !ok {
		t.Fatal("mysql dialect not registered")
	}
	serverConn := openTestConn(t) // any live *driver.Connection works as the login pool
	uc := NewUserContext("srv", "srv", d, driver.ConnParams{Host: "127.0.0.1", Port: 1}, serverConn, nil)
	uc.Close()

	ctx := context.Background()
	if _, err := uc.ConnFor(ctx, ""); !errors.Is(err, errSessionClosed) {
		t.Errorf("ConnFor(server path) after Close = %v, want errSessionClosed", err)
	}
	// The pool path must refuse BEFORE dialing (host/port above are unreachable;
	// a dial attempt would error differently and waste seconds).
	if _, err := uc.ConnFor(ctx, "otherdb"); !errors.Is(err, errSessionClosed) {
		t.Errorf("ConnFor(pool path) after Close = %v, want errSessionClosed", err)
	}
	if _, err := uc.PinnedFor(ctx, "otherdb"); !errors.Is(err, errSessionClosed) {
		t.Errorf("PinnedFor after Close = %v, want errSessionClosed", err)
	}
	if _, err := uc.ExportConnFor(ctx, "otherdb"); !errors.Is(err, errSessionClosed) {
		t.Errorf("ExportConnFor after Close = %v, want errSessionClosed", err)
	}
}

// TestEvictIdlePool exercises the LRU eviction ConnFor performs at budget
// exhaustion, using real (SQLite-backed) pools injected into the session.
func TestEvictIdlePool(t *testing.T) {
	a, b := openTestConn(t), openTestConn(t)
	budget := NewPoolBudget(2)
	budget.tryAcquire()
	budget.tryAcquire()

	uc := &UserContext{
		budget:  budget,
		pools:   map[string]*driver.Connection{"olddb": a, "newdb": b},
		poolUse: map[string]int64{"olddb": 1, "newdb": 2},
		useSeq:  2,
	}
	uc.mu.Lock()
	ok := uc.evictIdlePoolLocked()
	uc.mu.Unlock()
	if !ok {
		t.Fatal("eviction refused with two idle pools")
	}
	if _, still := uc.pools["olddb"]; still {
		t.Error("LRU eviction kept the least-recently-used pool")
	}
	if _, gone := uc.pools["newdb"]; !gone {
		t.Error("LRU eviction removed the most-recently-used pool")
	}
	if err := a.Ping(context.Background()); err == nil {
		t.Error("evicted pool was not closed")
	}
	if err := b.Ping(context.Background()); err != nil {
		t.Errorf("surviving pool unusable: %v", err)
	}
	if !budget.tryAcquire() {
		t.Error("eviction did not release the budget slot")
	}

	// With no pools left to evict, eviction reports failure instead of looping.
	uc.pools = map[string]*driver.Connection{}
	uc.mu.Lock()
	ok = uc.evictIdlePoolLocked()
	uc.mu.Unlock()
	if ok {
		t.Error("eviction claimed success with nothing to evict")
	}
}
