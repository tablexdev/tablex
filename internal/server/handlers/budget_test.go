package handlers

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tablexdev/tablex/internal/audit"
	"github.com/tablexdev/tablex/internal/config"
	"github.com/tablexdev/tablex/internal/view"
	"github.com/tablexdev/tablex/web"
)

// fakeClock is a hand-advanced clock, safe for concurrent reads because the
// budget is charged from whatever goroutine is running a script.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// TestQueryBudgetCharge covers the window arithmetic: the allowance is spent,
// then refused with a real wait, then restored when the window rolls.
func TestQueryBudgetCharge(t *testing.T) {
	clock := &fakeClock{t: time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)}
	b := &queryBudget{now: clock.now}
	const limit = 3
	const window = time.Minute

	for i := range limit {
		if _, ok := b.charge(limit, window); !ok {
			t.Fatalf("statement %d of %d was refused inside the budget", i+1, limit)
		}
	}
	retry, ok := b.charge(limit, window)
	if ok {
		t.Fatal("the statement past the budget was admitted")
	}
	// The quoted wait has to be real: zero would tell a client to retry
	// immediately into another refusal, and more than a window would overstate it.
	if retry <= 0 || retry > window {
		t.Errorf("retryAfter = %v, want a positive wait no longer than %v", retry, window)
	}

	// Partway through the window it is still refused, and the wait has shrunk.
	clock.advance(window - time.Second)
	shorter, ok := b.charge(limit, window)
	if ok {
		t.Error("the budget refilled before its window rolled")
	}
	if shorter >= retry {
		t.Errorf("retryAfter did not shrink as the window ran down: %v then %v", retry, shorter)
	}

	// Rolling the window restores the whole allowance.
	clock.advance(2 * time.Second)
	for i := range limit {
		if _, ok := b.charge(limit, window); !ok {
			t.Fatalf("statement %d refused in the new window", i+1)
		}
	}
	if _, ok := b.charge(limit, window); ok {
		t.Error("the new window admitted more than the budget")
	}
}

// TestQueryBudgetUnlimited: a non-positive limit or window never refuses, which
// is what makes the default configuration free of the whole mechanism.
func TestQueryBudgetUnlimited(t *testing.T) {
	for name, c := range map[string]struct {
		limit  int
		window time.Duration
	}{
		"no limit":        {0, time.Minute},
		"negative limit":  {-1, time.Minute},
		"no window":       {10, 0},
		"negative window": {10, -time.Minute},
	} {
		b := &queryBudget{}
		for i := range 50 {
			if _, ok := b.charge(c.limit, c.window); !ok {
				t.Errorf("%s: refused at statement %d", name, i+1)
				break
			}
		}
	}
}

// TestBudgetedIsAbsentWithoutConfig: with no budget configured, budgeted returns
// the runner unchanged — the point being that nothing per-statement is added to
// the default deployment, not merely that it always says yes.
func TestBudgetedIsAbsentWithoutConfig(t *testing.T) {
	var h Handlers
	uc := &UserContext{}
	calls := 0
	run := func(context.Context, scriptConn, string) consoleResult {
		calls++
		return consoleResult{}
	}
	if got := h.budgeted(uc, run); got == nil {
		t.Fatal("budgeted returned nil")
	}
	// The budget never touched the session's counter.
	h.budgeted(uc, run)(context.Background(), nil, "SELECT 1")
	if calls != 1 {
		t.Errorf("wrapped runner called %d times, want 1", calls)
	}
	uc.queries.mu.Lock()
	used := uc.queries.used
	uc.queries.mu.Unlock()
	if used != 0 {
		t.Errorf("an unconfigured budget charged %d statements", used)
	}
}

// TestBudgetedRefusesAndCounts: once the allowance is spent the wrapper answers
// with an error result instead of running the statement, names the setting, and
// records the refusal for /metrics.
func TestBudgetedRefusesAndCounts(t *testing.T) {
	h := &Handlers{Counters: &Counters{}}
	h.Cfg.SessionQueryBudget = 2
	h.Cfg.SessionQueryWindow = time.Minute
	uc := &UserContext{}
	ran := 0
	run := h.budgeted(uc, func(context.Context, scriptConn, string) consoleResult {
		ran++
		return consoleResult{SQL: "ok"}
	})

	for i := range 2 {
		if res := run(context.Background(), nil, "SELECT 1"); res.Error != "" {
			t.Fatalf("statement %d inside the budget errored: %s", i+1, res.Error)
		}
	}
	res := run(context.Background(), nil, "SELECT 2")
	if res.Error == "" {
		t.Fatal("the statement past the budget ran without complaint")
	}
	if ran != 2 {
		t.Errorf("the runner was invoked %d times, want 2 — the refused statement must NOT reach the database", ran)
	}
	if !strings.Contains(res.Error, "session_query_budget") {
		t.Errorf("refusal does not name the setting: %q", res.Error)
	}
	// The statement is echoed back so the console can show which one was refused.
	if res.SQL != "SELECT 2" {
		t.Errorf("refusal result SQL = %q, want the refused statement", res.SQL)
	}
	if got := h.Counters.Snapshot().QueryBudgetRefused; got != 1 {
		t.Errorf("query-budget refusals counted = %d, want 1", got)
	}
}

// TestBudgetIsPerSession: the allowance belongs to a session, not to the process,
// so one user exhausting theirs must not refuse anybody else's statement.
func TestBudgetIsPerSession(t *testing.T) {
	h := &Handlers{Counters: &Counters{}}
	h.Cfg.SessionQueryBudget = 1
	h.Cfg.SessionQueryWindow = time.Minute
	noop := func(context.Context, scriptConn, string) consoleResult { return consoleResult{} }

	spent, other := &UserContext{}, &UserContext{}
	if res := h.budgeted(spent, noop)(context.Background(), nil, "SELECT 1"); res.Error != "" {
		t.Fatalf("first session's only statement was refused: %s", res.Error)
	}
	if res := h.budgeted(spent, noop)(context.Background(), nil, "SELECT 1"); res.Error == "" {
		t.Fatal("first session got a second statement past a budget of 1")
	}
	if res := h.budgeted(other, noop)(context.Background(), nil, "SELECT 1"); res.Error != "" {
		t.Errorf("a second session was refused because the first had spent its budget: %s", res.Error)
	}
}

// TestAcquireDBOpRefusalIsAuditedAsDenied: a capacity 503 is the server declining
// work, not work failing. Left to the status code the audit trail would file it as
// an error and send whoever reads it hunting a fault that does not exist.
func TestAcquireDBOpRefusalIsAuditedAsDenied(t *testing.T) {
	renderer, err := view.New(web.FS)
	if err != nil {
		t.Fatalf("view.New: %v", err)
	}
	h := &Handlers{
		View:  renderer,
		Log:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		DBOps: NewDBOpLimiter(1),
		Cfg:   config.Default(),
	}
	if got := h.DBOps.Limit(); got != 1 {
		t.Errorf("Limit() = %d, want the configured 1", got)
	}

	r := httptest.NewRequest(http.MethodPost, "/db/x/export", nil)
	pending := &audit.Pending{}
	r = r.WithContext(audit.NewContext(r.Context(), pending))

	release, ok := h.acquireDBOp(httptest.NewRecorder(), r)
	if !ok {
		t.Fatal("first acquireDBOp refused")
	}
	defer release()
	if outcome, _ := pending.Outcome(); outcome != "" {
		t.Errorf("a SUCCESSFUL acquire set the audit outcome to %q; it must say nothing", outcome)
	}
	if got := h.DBOps.Refused(); got != 0 {
		t.Errorf("Refused() = %d before any refusal", got)
	}

	if _, ok := h.acquireDBOp(httptest.NewRecorder(), r); ok {
		t.Fatal("second acquireDBOp admitted past the cap of 1")
	}
	outcome, detail := pending.Outcome()
	if outcome != audit.OutcomeDenied {
		t.Errorf("audit outcome for a capacity refusal = %q, want %q", outcome, audit.OutcomeDenied)
	}
	if !strings.Contains(detail, "max_concurrent_db_ops") {
		t.Errorf("audit detail does not say why the request was refused: %q", detail)
	}
	if got := h.DBOps.Refused(); got != 1 {
		t.Errorf("Refused() = %d after one refusal, want 1", got)
	}
}

// TestPoolBudgetReporting: the gauges /metrics publishes have to mean what they
// say, including for the unlimited case, where "0 in use of 0" is the honest
// reading rather than a cap of zero.
func TestPoolBudgetReporting(t *testing.T) {
	b := NewPoolBudget(3)
	if got, want := b.Limit(), 3; got != want {
		t.Errorf("Limit() = %d, want %d", got, want)
	}
	if got := b.InUse(); got != 0 {
		t.Errorf("InUse() = %d on a fresh budget", got)
	}
	b.tryAcquire()
	b.tryAcquire()
	if got := b.InUse(); got != 2 {
		t.Errorf("InUse() = %d after two acquires, want 2", got)
	}
	b.release(2)
	if got := b.InUse(); got != 0 {
		t.Errorf("InUse() = %d after releasing both, want 0", got)
	}

	for name, unlimited := range map[string]*PoolBudget{
		"nil":      nil,
		"zero cap": NewPoolBudget(0),
		"negative": NewPoolBudget(-5),
	} {
		unlimited.tryAcquire()
		if got := unlimited.Limit(); got != 0 {
			t.Errorf("%s: Limit() = %d, want 0 to mean unlimited", name, got)
		}
		if got := unlimited.InUse(); got != 0 {
			t.Errorf("%s: InUse() = %d, want 0 (an unlimited budget charges nothing)", name, got)
		}
	}
}

// TestLoginCountersAreNilSafe: the counters are optional, and the many tests that
// build a bare &Handlers{} must not panic on a login.
func TestLoginCountersAreNilSafe(t *testing.T) {
	var c *Counters
	c.recordLoginSuccess()
	c.recordLoginRejected(http.StatusUnauthorized)
	c.recordQueryBudgetRefused()
	if snap := c.Snapshot(); snap != (CounterSnapshot{}) {
		t.Errorf("a nil Counters snapshot = %+v, want zeros", snap)
	}

	live := &Counters{}
	live.recordLoginSuccess()
	live.recordLoginRejected(http.StatusUnauthorized)
	live.recordLoginRejected(http.StatusUnauthorized)
	live.recordLoginRejected(http.StatusTooManyRequests)
	got := live.Snapshot()
	// The throttle split is the point: guessing passwords and being rate-limited
	// are different events an operator alarms on differently.
	want := CounterSnapshot{LoginsOK: 1, LoginsDenied: 2, LoginsThrottled: 1}
	if got != want {
		t.Errorf("counters = %+v, want %+v", got, want)
	}
}
