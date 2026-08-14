package handlers

import (
	"errors"
	"io"
	"log/slog"
	"net/http/httptest"
	"testing"

	"github.com/tablexdev/tablex/internal/view"
)

// TestRenderFailedDoesNotRestampAClientAbort pins the response-safe split
// every render caller shares: a CLIENT-side write failure (view.WriteError —
// an aborted large download, whose response is already partly on the wire)
// gets a log line and no further write, while a template failure keeps the
// 500. Re-stamping the abort used to falsify the access line, the 5xx metric
// and the audit status, plus net/http's "superfluous WriteHeader" at ERROR.
func TestRenderFailedDoesNotRestampAClientAbort(t *testing.T) {
	h := &Handlers{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	req := httptest.NewRequest("GET", "/db/main", nil)

	rec := httptest.NewRecorder()
	h.renderFailed(rec, req, &view.WriteError{Err: errors.New("broken pipe")}, "test page")
	if rec.Code != 200 || rec.Body.Len() != 0 {
		t.Errorf("a client write failure was re-stamped: code=%d body=%q", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	h.renderFailed(rec, req, errors.New("template exploded"), "test page")
	if rec.Code != 500 {
		t.Errorf("a template failure = %d, want 500", rec.Code)
	}
}
