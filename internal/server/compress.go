package server

import (
	"compress/gzip"
	"mime"
	"net/http"
	"strings"
	"sync"
)

// TableX is designed to run standalone, with no reverse proxy in front of it, so
// nothing else will compress its responses. Uncompressed it ships ~639 KB of
// assets on a cold load, plus every browse page, SQL result set and dump —
// Bootstrap's stylesheet alone is 232 KB that gzips to about 30 KB. This is the
// largest cheap win available to the HTTP layer.
//
// On BREACH: a compression oracle needs attacker-controlled input reflected into
// the same response as a secret, plus a way to measure that response's size.
// TableX's session cookie is SameSite=Lax, so a cross-site subresource request
// (the practical way to measure many responses) carries no session and renders
// no CSRF token; dynamic responses are also Cache-Control: no-store. Compression
// is applied at the transport layer only, and no response mixes a secret with a
// reflected value that an off-site page can both control and measure.

// gzipMinTypes is the allowlist of compressible media types. It is an allowlist
// rather than a denylist so an unknown type is never re-compressed: images,
// fonts and archives are already compressed, and running them through gzip
// spends CPU to make them slightly larger.
var gzipMinTypes = map[string]bool{
	"text/html":              true,
	"text/css":               true,
	"text/plain":             true,
	"text/csv":               true,
	"text/javascript":        true,
	"text/xml":               true,
	"application/javascript": true,
	"application/json":       true,
	"application/sql":        true,
	"application/xml":        true,
	"image/svg+xml":          true,
}

// compressibleType reports whether a Content-Type header value names a type
// worth compressing. Parameters (charset) are ignored; an unparseable or empty
// value is not compressed.
func compressibleType(ct string) bool {
	if ct == "" {
		return false
	}
	mt, _, err := mime.ParseMediaType(ct)
	if err != nil {
		return false
	}
	return gzipMinTypes[strings.ToLower(mt)]
}

// gzipWriterPool recycles the compressor's ~64 KB of window and hash state
// across requests; without it every response would allocate it afresh.
var gzipWriterPool = sync.Pool{
	New: func() any { return gzip.NewWriter(nil) },
}

// gzipETagSuffix distinguishes the compressed representation of a resource from
// its identity representation. A strong ETag names ONE representation, so
// serving both under the same tag would let a cache hand a gzip body to a client
// that never asked for one. Requests carry the suffixed tag back, and
// stripAcceptEncodingETag normalizes it before the static handler compares it,
// so conditional GETs still answer 304.
const gzipETagSuffix = "-gzip"

// gzip wraps the handler chain so any compressible response is gzipped when the
// client advertises support. It is transparent to handlers: they write the same
// bytes either way.
func (s *Server) gzip(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !acceptsGzip(r) {
			// The origin still varies this resource's bytes by Accept-Encoding
			// even when this client gets the identity form, so the header goes
			// on the bypass path too (RFC 9110 §12.5.5) — without it a shared
			// cache that stored an identity response would serve it to a
			// gzip-capable client under the same key.
			w.Header().Add("Vary", "Accept-Encoding")
			next.ServeHTTP(w, r)
			return
		}
		stripAcceptEncodingETag(r)
		gw := &gzipResponseWriter{ResponseWriter: w}
		// The trailer belongs only on a response that ENDED. This defer
		// unwinds BEFORE the recover middleware sees a panic, so closing
		// unconditionally would seal a silently truncated streaming export
		// into a well-formed gzip stream at HTTP 200 — a corrupt backup
		// indistinguishable from a good one. On the non-completion path
		// (panic, runtime.Goexit) abort leaves the stream unterminated
		// instead, so gzip.Reader reports io.ErrUnexpectedEOF: the corruption
		// becomes detectable, which is the whole point. Buffered page renders
		// are unaffected — view.Render writes only after rendering fully.
		done := false
		defer func() {
			if done {
				gw.close()
			} else {
				gw.abort()
			}
		}()
		next.ServeHTTP(gw, r)
		done = true
	})
}

// acceptsGzip reports whether the client advertised gzip. It checks for the
// token rather than parsing q-values: a client that lists gzip with q=0 to
// refuse it is vanishingly rare, and the cost of getting it wrong is a
// compressed response the client can still decode. That is a DECIDED
// trade-off, re-examined and kept in the 2026-08 production-readiness review:
// do not re-flag the missing q-value parse. (The Vary-on-the-bypass-path gap
// in this file was the real defect, and is fixed.)
func acceptsGzip(r *http.Request) bool {
	for _, enc := range strings.Split(r.Header.Get("Accept-Encoding"), ",") {
		name, _, _ := strings.Cut(enc, ";")
		if strings.EqualFold(strings.TrimSpace(name), "gzip") {
			return true
		}
	}
	return false
}

// stripAcceptEncodingETag rewrites If-None-Match so the gzip suffix this
// middleware appended on the way out does not defeat the handler's comparison
// against its identity ETag on the way back in.
func stripAcceptEncodingETag(r *http.Request) {
	inm := r.Header.Get("If-None-Match")
	if inm == "" || !strings.Contains(inm, gzipETagSuffix) {
		return
	}
	parts := strings.Split(inm, ",")
	for i, p := range parts {
		p = strings.TrimSpace(p)
		if strings.HasSuffix(p, gzipETagSuffix+`"`) {
			p = strings.TrimSuffix(p, gzipETagSuffix+`"`) + `"`
		}
		parts[i] = p
	}
	r.Header.Set("If-None-Match", strings.Join(parts, ", "))
}

// gzipResponseWriter compresses the body when the response turns out to be a
// compressible type. The decision is deferred to WriteHeader because the
// Content-Type is not known until the handler sets it.
type gzipResponseWriter struct {
	http.ResponseWriter
	gz          *gzip.Writer
	wroteHeader bool
	compress    bool
}

func (g *gzipResponseWriter) WriteHeader(code int) {
	if g.wroteHeader {
		// A handler that calls WriteHeader twice (net/http logs a warning) must
		// not flip the encoding decision mid-response.
		return
	}
	g.wroteHeader = true
	h := g.ResponseWriter.Header()
	// Vary goes on every response, compressed or not: the same URL yields
	// different bytes per Accept-Encoding, and a shared cache must key on it.
	h.Add("Vary", "Accept-Encoding")

	if bodylessStatus(code) || h.Get("Content-Encoding") != "" || !compressibleType(h.Get("Content-Type")) {
		g.ResponseWriter.WriteHeader(code)
		return
	}
	g.compress = true
	h.Set("Content-Encoding", "gzip")
	// Any Content-Length the handler computed describes the identity body, and
	// a strong ETag now names a different representation.
	h.Del("Content-Length")
	if et := h.Get("ETag"); strings.HasSuffix(et, `"`) {
		h.Set("ETag", strings.TrimSuffix(et, `"`)+gzipETagSuffix+`"`)
	}
	g.gz = gzipWriterPool.Get().(*gzip.Writer)
	g.gz.Reset(g.ResponseWriter)
	g.ResponseWriter.WriteHeader(code)
}

func (g *gzipResponseWriter) Write(b []byte) (int, error) {
	if !g.wroteHeader {
		// net/http would sniff an unset Content-Type from the first write; do it
		// here so the compression decision sees the same type the client will.
		if g.ResponseWriter.Header().Get("Content-Type") == "" && len(b) > 0 {
			g.ResponseWriter.Header().Set("Content-Type", http.DetectContentType(b))
		}
		g.WriteHeader(http.StatusOK)
	}
	if g.compress {
		return g.gz.Write(b)
	}
	return g.ResponseWriter.Write(b)
}

// Flush pushes buffered compressed bytes to the client, then flushes the
// underlying writer. No handler flushes today — streaming exports rely on the
// transport's own chunking, and set write DEADLINES rather than flushing — so
// this is the contract for one that starts to: a compressor holds bytes back
// by design, and a flush that stopped at it would leave the client waiting for
// the dump to finish. Every writer in the chain therefore forwards Flush
// (statusRecorder included), or the assertion below fails and the flush is
// silently dropped.
func (g *gzipResponseWriter) Flush() {
	if g.compress && g.gz != nil {
		_ = g.gz.Flush()
	}
	if f, ok := g.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap exposes the wrapped writer so http.ResponseController reaches the real
// connection — the buffered page write and the streaming export both set write
// deadlines through it.
func (g *gzipResponseWriter) Unwrap() http.ResponseWriter { return g.ResponseWriter }

// close finishes the gzip stream (writing the trailer) and returns the
// compressor to the pool. Safe to call when nothing was compressed.
func (g *gzipResponseWriter) close() {
	if g.gz == nil {
		return
	}
	_ = g.gz.Close()
	gzipWriterPool.Put(g.gz)
	g.gz = nil
}

// abort releases the compressor WITHOUT writing the trailer, for a response
// that did not run to completion. The stream stays deliberately unterminated —
// that is what makes the truncation detectable downstream — and the writer is
// dropped rather than pooled: only Close or Reset leave a gzip.Writer safe to
// recycle, and one lost allocation on a path that is already failing beats a
// pooled writer with a dead connection in its state. Safe to call when
// nothing was compressed, and idempotent like close.
func (g *gzipResponseWriter) abort() {
	if g.gz == nil {
		return
	}
	g.gz = nil
}

// bodylessStatus reports statuses that carry no body, where a gzip trailer
// would be a protocol violation.
func bodylessStatus(code int) bool {
	return code < http.StatusOK || code == http.StatusNoContent || code == http.StatusNotModified
}
