package handlers

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/tablexdev/tablex/internal/config"
	"github.com/tablexdev/tablex/internal/driver"
	"github.com/tablexdev/tablex/internal/view"
	"github.com/tablexdev/tablex/web"
)

// TestDBOpLimiter covers: exports, console scripts and imports open PRIVATE
// connections outside PoolBudget, and nothing bounded how many could run at
// once — enough parallel exports could exhaust the DATABASE's max_connections
// and take down every other client of that server.
func TestDBOpLimiter(t *testing.T) {
	l := NewDBOpLimiter(2)

	r1, ok := l.TryAcquire()
	if !ok {
		t.Fatal("first acquire refused on a limit of 2")
	}
	r2, ok := l.TryAcquire()
	if !ok {
		t.Fatal("second acquire refused on a limit of 2")
	}
	if got := l.InFlight(); got != 2 {
		t.Errorf("InFlight = %d, want 2", got)
	}
	if _, ok := l.TryAcquire(); ok {
		t.Error("third acquire admitted past the limit of 2")
	}

	// Releasing frees exactly one slot.
	r1()
	if got := l.InFlight(); got != 1 {
		t.Errorf("InFlight after one release = %d, want 1", got)
	}
	r3, ok := l.TryAcquire()
	if !ok {
		t.Fatal("acquire refused after a slot was released")
	}

	// Release is idempotent: the handlers pair `defer release()` with an early
	// explicit release on some paths, and a double release would over-credit the
	// limiter and let it admit past the cap forever.
	r1()
	r1()
	if got := l.InFlight(); got != 2 {
		t.Errorf("InFlight after repeated release of one slot = %d, want 2", got)
	}
	r2()
	r3()
	if got := l.InFlight(); got != 0 {
		t.Errorf("InFlight after all releases = %d, want 0", got)
	}
}

// TestDBOpLimiterUnlimited: a non-positive cap (and a nil limiter, which is what
// a test-constructed Handlers carries) never refuses.
func TestDBOpLimiterUnlimited(t *testing.T) {
	for name, l := range map[string]*DBOpLimiter{
		"nil":       nil,
		"zero":      NewDBOpLimiter(0),
		"negative":  NewDBOpLimiter(-1),
		"unlimited": NewDBOpLimiter(0),
	} {
		for i := range 50 {
			release, ok := l.TryAcquire()
			if !ok {
				t.Fatalf("%s limiter refused acquire %d", name, i)
			}
			release()
		}
		if got := l.InFlight(); got != 0 {
			t.Errorf("%s limiter InFlight = %d, want 0", name, got)
		}
	}
}

// TestDBOpLimiterConcurrent: the cap must hold under a real race. Run with
// -race, which the CI matrix does.
func TestDBOpLimiterConcurrent(t *testing.T) {
	const limit = 4
	l := NewDBOpLimiter(limit)

	var mu sync.Mutex
	held, peak := 0, 0
	var wg sync.WaitGroup
	for range 64 {
		wg.Go(func() {
			for range 50 {
				release, ok := l.TryAcquire()
				if !ok {
					continue
				}
				mu.Lock()
				held++
				peak = max(peak, held)
				mu.Unlock()

				mu.Lock()
				held--
				mu.Unlock()
				release()
			}
		})
	}
	wg.Wait()
	if peak > limit {
		t.Errorf("peak concurrent holders = %d, want at most %d", peak, limit)
	}
	if got := l.InFlight(); got != 0 {
		t.Errorf("InFlight after the race = %d, want 0", got)
	}
}

// TestAcquireDBOpRefusal pins the wire behaviour when the cap is reached: a
// 503 with Retry-After, not a queued request holding an HTTP worker and its
// session while the client waits with no way to know it is parked.
func TestAcquireDBOpRefusal(t *testing.T) {
	renderer, err := view.New(web.FS)
	if err != nil {
		t.Fatalf("view.New: %v", err)
	}
	h := &Handlers{
		View:  renderer,
		Log:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		DBOps: NewDBOpLimiter(1),
	}

	// The only slot goes to the first caller.
	w1 := httptest.NewRecorder()
	r1 := httptest.NewRequest(http.MethodPost, "/db/x/export", nil)
	release, ok := h.acquireDBOp(w1, r1)
	if !ok {
		t.Fatal("first acquireDBOp refused")
	}
	if w1.Code != http.StatusOK {
		t.Errorf("a successful acquire wrote status %d; it must write nothing", w1.Code)
	}

	// The second is refused on the wire.
	w2 := httptest.NewRecorder()
	r2 := httptest.NewRequest(http.MethodPost, "/db/x/export", nil)
	if _, ok := h.acquireDBOp(w2, r2); ok {
		t.Fatal("second acquireDBOp admitted past the cap of 1")
	}
	if w2.Code != http.StatusServiceUnavailable {
		t.Errorf("refusal status = %d, want 503", w2.Code)
	}
	if got := w2.Header().Get("Retry-After"); got == "" {
		t.Error("refusal carries no Retry-After header")
	}
	if body := w2.Body.String(); !strings.Contains(body, "max_concurrent_db_ops") {
		t.Errorf("refusal page does not name the knob to raise:\n%.800s", body)
	}

	// Releasing the first re-admits.
	release()
	w3 := httptest.NewRecorder()
	if _, ok := h.acquireDBOp(w3, r2); !ok {
		t.Errorf("acquireDBOp still refused after the slot was released (status %d)", w3.Code)
	}
}

// TestHandlersTuning pins that the operator's pool/timeout config reaches the
// driver, and that the driver defaults it sanely when unset.
func TestHandlersTuning(t *testing.T) {
	h := &Handlers{Cfg: config.Default()}
	got := h.tuning()
	if got.MaxOpenConns != config.Default().PoolMaxConns {
		t.Errorf("tuning MaxOpenConns = %d, want %d", got.MaxOpenConns, config.Default().PoolMaxConns)
	}
	if got.ReadStmtTimeout != config.Default().ReadStmtTimeout {
		t.Errorf("tuning ReadStmtTimeout = %v, want %v", got.ReadStmtTimeout, config.Default().ReadStmtTimeout)
	}

	// A zero config must not push zeros into the driver — Open resolves them.
	zero := (&Handlers{}).tuning()
	if zero != (driver.Tuning{}) {
		t.Errorf("tuning from a zero config = %+v, want the zero Tuning (driver defaults apply)", zero)
	}
}
