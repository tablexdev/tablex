package server

// Internal tests (package server): the thing under test is the composition
// s.recover(s.gzip(next)) — the defer ordering between exactly those two
// middlewares decides whether a panic mid-stream forges a gzip trailer — and
// both are unexported. The full s.chain is deliberately avoided: its csrf
// middleware would redirect an unauthenticated request long before the
// handler could panic.

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"
)

func compressTestServer() *Server {
	return &Server{log: slog.New(slog.NewTextHandler(io.Discard, nil))}
}

// TestPanicMidStreamDoesNotForgeAGzipTrailer: a streaming export that panics
// partway used to emit a WELL-FORMED gzip stream over the truncated dump at
// HTTP 200 with no Content-Length to contradict it — a corrupt backup
// indistinguishable from a good one, because the gzip middleware's deferred
// close (which writes the trailer) unwound before recover saw the panic. The
// fix aborts instead: the stream stays unterminated and gzip.Reader reports
// io.ErrUnexpectedEOF. Detectability IS the fix.
func TestPanicMidStreamDoesNotForgeAGzipTrailer(t *testing.T) {
	s := compressTestServer()
	payload := strings.Repeat("INSERT INTO widgets VALUES (1, 'bolt');\n", 512)
	h := s.recover(s.gzip(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// application/sql: the streaming export type, in the gzip allowlist.
		w.Header().Set("Content-Type", "application/sql")
		if _, err := io.WriteString(w, payload); err != nil {
			t.Errorf("write: %v", err)
		}
		if f, ok := w.(http.Flusher); ok {
			f.Flush() // per-chunk flush, as the real dump path does
		}
		panic("mid-export failure")
	})))
	ts := httptest.NewServer(h)
	defer ts.Close()

	req, err := http.NewRequest(http.MethodGet, ts.URL, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	// Set explicitly (rather than letting the transport add it) so net/http
	// does not transparently decompress — the raw bytes are the assertion.
	req.Header.Set("Accept-Encoding", "gzip")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if got := resp.Header.Get("Content-Encoding"); got != "gzip" {
		t.Fatalf("Content-Encoding = %q; this test is not exercising the compressed path", got)
	}
	// A transport-level read error is immaterial; the question is what the
	// bytes that DID arrive decode to.
	body, _ := io.ReadAll(resp.Body)
	zr, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		t.Fatalf("the flushed prefix is not a gzip stream at all: %v", err)
	}
	if _, derr := io.ReadAll(zr); derr == nil {
		t.Fatal("a panic mid-stream produced a cleanly-decodable gzip body: the trailer was forged over a truncated export")
	} else if !errors.Is(derr, io.ErrUnexpectedEOF) {
		t.Errorf("decode error = %v, want io.ErrUnexpectedEOF (an unterminated stream)", derr)
	}
}

// TestPanicBeforeAnyWriteStillYields500 is the permissive control on the same
// chain: with nothing written yet, recover must still turn the panic into a
// clean 500 — the abort path must not eat that.
func TestPanicBeforeAnyWriteStillYields500(t *testing.T) {
	s := compressTestServer()
	h := s.recover(s.gzip(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("before any write")
	})))
	ts := httptest.NewServer(h)
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodGet, ts.URL, nil)
	req.Header.Set("Accept-Encoding", "gzip")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("panic before any write = %d, want 500", resp.StatusCode)
	}
}

// TestVaryAccompaniesEveryResponse: the comment in WriteHeader has always said
// "Vary goes on every response, compressed or not" — but the middleware's
// early return for a client that did not advertise gzip skipped the wrapper
// entirely, so identity responses carried no Vary and a shared cache could
// hand the identity body to a gzip-capable client under the same key
// (RFC 9110 §12.5.5). Both paths are pinned here.
func TestVaryAccompaniesEveryResponse(t *testing.T) {
	s := compressTestServer()
	h := s.gzip(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, "<p>hello</p>")
	}))
	ts := httptest.NewServer(h)
	defer ts.Close()

	// Both cases set the header explicitly: with it UNSET, Go's transport
	// silently adds "Accept-Encoding: gzip" on the wire, so a bare request
	// exercises the compressed path while looking like the identity one.
	for _, tc := range []struct {
		name   string
		accept string
	}{
		{"identity", "identity"},
		{"compressed", "gzip"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodGet, ts.URL, nil)
			req.Header.Set("Accept-Encoding", tc.accept)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("GET: %v", err)
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if !slices.Contains(resp.Header.Values("Vary"), "Accept-Encoding") {
				t.Errorf("Vary = %v; every response for a compressible resource must carry Accept-Encoding", resp.Header.Values("Vary"))
			}
		})
	}
}

// TestFlushReachesTheConnectionThroughEveryWrapper: a flush has to survive the
// whole writer chain. The gzip writer holds bytes back by design and forwards a
// flush only through an http.Flusher assertion on what it wraps — so a wrapper
// in between that does not implement Flush silently swallows it, and a client
// streaming a compressed export waits for the dump to finish instead of seeing
// chunks. statusRecorder was exactly such a wrapper.
//
// Asserted on the BYTES the client can read before the handler returns, not on
// the wrappers' method sets: an interface check would pass against a Flush that
// does nothing.
//
// The whole request runs under a context deadline, because a swallowed flush
// strands the response HEADERS too — nothing at all reaches the wire — so the
// client blocks in Do() before it could ever block on the body. Without the
// deadline the regression reads as a hung package rather than a failed test.
func TestFlushReachesTheConnectionThroughEveryWrapper(t *testing.T) {
	for _, tc := range []struct {
		name   string
		accept string
	}{
		{"identity", "identity"},
		{"compressed", "gzip"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := compressTestServer()
			release := make(chan struct{})
			handlerDone := make(chan struct{})
			// The recorder is the wrapper under test; the real chain puts it
			// outside gzip, and asRecorder is how every request acquires one.
			inner := s.gzip(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				defer close(handlerDone)
				w.Header().Set("Content-Type", "application/sql")
				io.WriteString(w, "-- chunk one\n")
				f, ok := w.(http.Flusher)
				if !ok {
					t.Error("the handler's writer does not implement http.Flusher")
					return
				}
				f.Flush()
				<-release // hold the handler open: only a real flush can beat this
				io.WriteString(w, "-- chunk two\n")
			}))
			h := s.recover(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				inner.ServeHTTP(asRecorder(w), r)
			}))
			ts := httptest.NewServer(h)
			// Release the handler BEFORE closing the server (defers run last
			// in first out), or Close would wait on a handler still parked.
			defer ts.Close()
			defer close(release)

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL, nil)
			req.Header.Set("Accept-Encoding", tc.accept)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("no response while the handler was still streaming — the flush never reached the connection: %v", err)
			}
			defer resp.Body.Close()

			var body io.Reader = resp.Body
			if resp.Header.Get("Content-Encoding") == "gzip" {
				zr, err := gzip.NewReader(resp.Body)
				if err != nil {
					t.Fatalf("the flushed prefix is not a readable gzip stream: %v", err)
				}
				body = zr
			}
			buf := make([]byte, len("-- chunk one\n"))
			if _, err := io.ReadFull(body, buf); err != nil {
				t.Fatalf("the first chunk never reached the client while the handler was parked — a wrapper swallowed the flush: %v", err)
			}
			if got := string(buf); got != "-- chunk one\n" {
				t.Errorf("flushed prefix = %q, want the first chunk", got)
			}
			// The handler is still inside <-release: the bytes above arrived
			// because of the flush, not because the response completed.
			select {
			case <-handlerDone:
				t.Error("the handler finished before the assertion; the read proves nothing about flushing")
			default:
			}
		})
	}
}
