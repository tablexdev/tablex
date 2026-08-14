package view

import (
	"bytes"
	"errors"
	"net/http"
	"testing"
)

// failWriter is a ResponseWriter whose body write always fails — the shape of
// a client that went away mid-download.
type failWriter struct{ h http.Header }

func (f *failWriter) Header() http.Header        { return f.h }
func (f *failWriter) Write([]byte) (int, error)  { return 0, errors.New("client went away") }
func (f *failWriter) WriteHeader(statusCode int) {}

// TestWriteBoundedTypesClientFailure: a failure while flushing an
// already-rendered page must come back as a *WriteError, so callers can tell
// an aborted download (log-and-move-on) from a template failure (500). The
// distinction is what keeps an aborted large export from being re-stamped 500
// in the access line, the 5xx metric and the audit record.
func TestWriteBoundedTypesClientFailure(t *testing.T) {
	var buf bytes.Buffer
	buf.WriteString("<p>rendered page</p>")
	err := writeBounded(&failWriter{h: http.Header{}}, &buf)
	if err == nil {
		t.Fatal("a failing writer produced no error")
	}
	if !IsWriteError(err) {
		t.Errorf("write failure is not typed as WriteError: %v", err)
	}
	// Wrapping survives errors.As through fmt-style wrapping too.
	if !IsWriteError(errWrap(err)) {
		t.Error("IsWriteError must see through wrapping")
	}
	// A template-style error is NOT a write error.
	if IsWriteError(errors.New("template exploded")) {
		t.Error("an ordinary error must not classify as a client write failure")
	}
}

func errWrap(err error) error { return &wrapped{err} }

type wrapped struct{ err error }

func (w *wrapped) Error() string { return "wrapped: " + w.err.Error() }
func (w *wrapped) Unwrap() error { return w.err }
