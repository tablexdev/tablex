package server

// Internal tests (package server): the thing under test is the composition
// s.recover(s.logging(next)) — logging's post-processing must survive the
// unwind a panicking handler causes, and the defer ordering between exactly
// those two middlewares decides what the access line, the metrics sample and
// the audit record say. Both are unexported, so this cannot be an external
// test; the full chain is avoided for the same reason compress_panic_test.go
// avoids it (csrf would refuse the request before the handler could panic).

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/tablexdev/tablex/internal/audit"
)

// memSink collects audit events in memory.
type memSink struct {
	mu     sync.Mutex
	events []audit.Event
}

func (m *memSink) Write(e audit.Event) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, e)
	return nil
}

func (m *memSink) Close() error { return nil }

func (m *memSink) all() []audit.Event {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]audit.Event(nil), m.events...)
}

// panicObservationServer builds a Server with a captive log, a live metrics
// struct and an in-memory audit sink, wrapped as recover(logging(handler)).
func panicObservationServer(handler http.Handler) (*Server, *bytes.Buffer, *memSink, *httptest.Server) {
	var logBuf bytes.Buffer
	sink := &memSink{}
	s := &Server{
		log:     slog.New(slog.NewTextHandler(&logBuf, nil)),
		audit:   audit.New(slog.New(slog.NewTextHandler(io.Discard, nil)), sink),
		metrics: &metrics{},
	}
	ts := httptest.NewServer(s.recover(s.logging(handler)))
	return s, &logBuf, sink, ts
}

// TestPanicStillObserved: a recovered panic used to leave NO access line, NO
// audit action record and NO metrics sample — logging's post-processing ran
// inline after next.ServeHTTP, so unwinding skipped it, and the 5xx counter
// never moved for exactly the case the recover middleware exists for. The
// post-processing now runs deferred: a mutating POST that panics before any
// write must be observed as a 500 everywhere, recover must still deliver the
// client's 500 (the defer must never write rec.status), and the in-flight
// gauge must return to zero.
func TestPanicStillObserved(t *testing.T) {
	s, logBuf, sink, ts := panicObservationServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("boom before any write")
	}))
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/db/main/table/widgets/operations",
		"application/x-www-form-urlencoded", strings.NewReader("action=drop"))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("client status = %d, want 500 — the deferred observer must not suppress recover's http.Error", resp.StatusCode)
	}

	if line := logBuf.String(); !strings.Contains(line, "status=500") {
		t.Errorf("access line must record the recovered-incomplete request as 500:\n%s", line)
	}
	if got := s.metrics.requests[methodIndex(http.MethodPost)][statusIndex(500)].Load(); got != 1 {
		t.Errorf("tablex_http_requests_total{POST,5xx} = %d, want 1 — the panic left no metrics sample", got)
	}
	if got := s.metrics.inFlight.Load(); got != 0 {
		t.Errorf("in-flight gauge = %d after the request, want 0", got)
	}
	var action *audit.Event
	for _, e := range sink.all() {
		if e.Kind == audit.KindAction {
			ev := e
			action = &ev
		}
	}
	if action == nil {
		t.Fatal("a mutating POST that panicked left no action record in the trail")
	}
	if action.Outcome != audit.OutcomeError {
		t.Errorf("panicked POST outcome = %q, want %q", action.Outcome, audit.OutcomeError)
	}
}

// TestPanickedLoginStillLeavesAnAuthEvent: auditAction deliberately skips
// /login — the login handler emits its own richer auth event — but a handler
// that PANICS emitted nothing, so the carve-out used to leave a credential
// submission (the one request class the trail most needs complete) with no
// trace at all. A panicked POST /login must land as a KindAuth error event;
// a login that completes normally must still be left to the handler.
func TestPanickedLoginStillLeavesAnAuthEvent(t *testing.T) {
	// The carve-out first: a NORMALLY completing /login leaves no middleware
	// event — without this half, emitting unconditionally would also pass.
	_, _, sink, ts := panicObservationServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusSeeOther)
	}))
	defer ts.Close()
	resp, err := http.Post(ts.URL+"/login", "application/x-www-form-urlencoded", strings.NewReader("user=x"))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if got := sink.all(); len(got) != 0 {
		t.Fatalf("a completed /login must leave the auth event to the handler; middleware emitted %+v", got)
	}

	_, _, sink2, ts2 := panicObservationServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("boom in the login handler")
	}))
	defer ts2.Close()
	resp2, err := http.Post(ts2.URL+"/login", "application/x-www-form-urlencoded", strings.NewReader("user=x"))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	io.Copy(io.Discard, resp2.Body)
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusInternalServerError {
		t.Fatalf("client status = %d, want 500", resp2.StatusCode)
	}
	events := sink2.all()
	if len(events) != 1 {
		t.Fatalf("a panicked POST /login left %d events (%+v), want exactly one", len(events), events)
	}
	e := events[0]
	if e.Kind != audit.KindAuth {
		t.Errorf("event kind = %q, want %q — a login submission is an auth event", e.Kind, audit.KindAuth)
	}
	if e.Outcome != audit.OutcomeError || e.Status != http.StatusInternalServerError || e.Path != "/login" {
		t.Errorf("event = %+v, want an error outcome on /login at 500", e)
	}
}

// TestPanicAfterPartialWriteKeepsTheRealStatus: a handler that wrote 200 and
// part of a body before panicking must NOT be re-stamped 500 — the client saw
// a 200, and the observability record must match the wire. Only the
// recovered-incomplete-with-no-header case substitutes 500.
func TestPanicAfterPartialWriteKeepsTheRealStatus(t *testing.T) {
	s, logBuf, _, ts := panicObservationServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "partial body")
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		panic("boom after a partial write")
	}))
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/db/main/sql", "application/x-www-form-urlencoded", strings.NewReader("x=1"))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("client status = %d; this test needs the partial 200 on the wire", resp.StatusCode)
	}
	if line := logBuf.String(); !strings.Contains(line, "status=200") || strings.Contains(line, "status=500") {
		t.Errorf("a panic AFTER a partial 200 write must keep the 200 the client saw:\n%s", line)
	}
	if got := s.metrics.requests[methodIndex(http.MethodPost)][statusIndex(200)].Load(); got != 1 {
		t.Errorf("tablex_http_requests_total{POST,2xx} = %d, want 1", got)
	}
}
