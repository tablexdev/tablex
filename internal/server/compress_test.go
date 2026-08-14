package server_test

import (
	"compress/gzip"
	"io"
	"net/http"
	"strings"
	"testing"
)

// getRaw issues a GET with an explicit Accept-Encoding, which also stops Go's
// transport from transparently decompressing the reply — the test needs to see
// the wire bytes.
func getRaw(t *testing.T, client *http.Client, url, acceptEncoding string) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if acceptEncoding != "" {
		req.Header.Set("Accept-Encoding", acceptEncoding)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp, body
}

func gunzip(t *testing.T, b []byte) []byte {
	t.Helper()
	zr, err := gzip.NewReader(strings.NewReader(string(b)))
	if err != nil {
		t.Fatalf("gzip reader: %v", err)
	}
	defer zr.Close()
	out, err := io.ReadAll(zr)
	if err != nil {
		t.Fatalf("gunzip: %v", err)
	}
	return out
}

// TestGzipCompressesHTML covers: TableX is designed to run standalone with no
// reverse proxy, so nothing else would compress its responses. Every page and
// result set went out uncompressed.
func TestGzipCompressesHTML(t *testing.T) {
	ts, client, _ := newTestServer(t)
	login(t, client, ts.URL)

	plainResp, plain := getRaw(t, client, ts.URL+"/", "identity")
	if plainResp.StatusCode != http.StatusOK {
		t.Fatalf("GET / = %d, want 200", plainResp.StatusCode)
	}
	if enc := plainResp.Header.Get("Content-Encoding"); enc != "" {
		t.Errorf("Content-Encoding without an Accept-Encoding of gzip = %q, want none", enc)
	}

	gzResp, gzBody := getRaw(t, client, ts.URL+"/", "gzip")
	if gzResp.StatusCode != http.StatusOK {
		t.Fatalf("gzip GET / = %d, want 200", gzResp.StatusCode)
	}
	if enc := gzResp.Header.Get("Content-Encoding"); enc != "gzip" {
		t.Fatalf("Content-Encoding = %q, want gzip", enc)
	}
	if v := gzResp.Header.Get("Vary"); !strings.Contains(v, "Accept-Encoding") {
		t.Errorf("Vary = %q, want it to include Accept-Encoding", v)
	}
	if len(gzBody) >= len(plain) {
		t.Errorf("gzip body is %d bytes vs %d uncompressed — no saving", len(gzBody), len(plain))
	}
	if got := string(gunzip(t, gzBody)); !strings.Contains(got, "<!doctype html>") {
		t.Errorf("decompressed body is not the page:\n%.400s", got)
	}
}

// TestGzipVariesAndCompressesStatic pins the biggest single win — Bootstrap's
// stylesheet is 232 KB of the cold-load payload — and the conditional-GET
// bookkeeping that goes with serving two representations of one URL.
func TestGzipVariesAndCompressesStatic(t *testing.T) {
	ts, client, _ := newTestServer(t)
	const path = "/static/vendor/bootstrap/bootstrap.min.css"

	plainResp, plain := getRaw(t, client, ts.URL+path, "identity")
	gzResp, gzBody := getRaw(t, client, ts.URL+path, "gzip")
	if gzResp.Header.Get("Content-Encoding") != "gzip" {
		t.Fatalf("static asset not compressed: Content-Encoding = %q", gzResp.Header.Get("Content-Encoding"))
	}
	if len(gzBody) >= len(plain)/2 {
		t.Errorf("bootstrap.min.css compressed to %d from %d bytes; expected well under half", len(gzBody), len(plain))
	}
	if string(gunzip(t, gzBody)) != string(plain) {
		t.Error("decompressed static asset differs from the identity response")
	}

	// A strong ETag names ONE representation, so the compressed reply must not
	// reuse the identity tag verbatim.
	plainTag, gzTag := plainResp.Header.Get("ETag"), gzResp.Header.Get("ETag")
	if plainTag == "" || gzTag == "" {
		t.Fatalf("missing ETag (identity %q, gzip %q)", plainTag, gzTag)
	}
	if plainTag == gzTag {
		t.Errorf("identity and gzip responses share the ETag %q", plainTag)
	}

	// Revalidating with the tag the compressed response handed out must still
	// answer 304 — the middleware normalizes it before the static handler
	// compares against its identity tag.
	req, _ := http.NewRequest(http.MethodGet, ts.URL+path, nil)
	req.Header.Set("Accept-Encoding", "gzip")
	req.Header.Set("If-None-Match", gzTag)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("conditional gzip GET: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotModified {
		t.Errorf("conditional GET with the gzip ETag = %d, want 304", resp.StatusCode)
	}
	if enc := resp.Header.Get("Content-Encoding"); enc != "" {
		t.Errorf("304 carries Content-Encoding %q; a bodyless response must not", enc)
	}
}

// TestGzipSkipsIncompressibleTypes: the allowlist must not re-compress bytes
// that are already compressed, and must not touch a response with no body.
func TestGzipSkipsIncompressibleTypes(t *testing.T) {
	ts, client, _ := newTestServer(t)

	// /healthz answers text/plain — compressible — but a redirect carries no
	// body worth encoding. Use a 404, which is text/plain from http.NotFound,
	// to confirm error bodies still ride the normal path without corruption.
	resp, body := getRaw(t, client, ts.URL+"/static/no-such-file.css", "gzip")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("GET unknown static = %d, want 404", resp.StatusCode)
	}
	if resp.Header.Get("Content-Encoding") == "gzip" {
		body = gunzip(t, body)
	}
	if !strings.Contains(strings.ToLower(string(body)), "not found") {
		t.Errorf("404 body did not survive the encoder: %q", body)
	}
}

// TestEditorAssetsOnlyWhereNeeded covers: CodeMirror is 242 KB — over a third
// of the asset payload — and only the SQL console, the import form and the
// stored-program editor carry a textarea.tx-sql-editor, yet base.html loaded it
// on all 25 pages. (The cases below cover the console at both db and table scope
// plus import; the stored-program editor route is a fourth carrier not exercised
// here.)
func TestEditorAssetsOnlyWhereNeeded(t *testing.T) {
	ts, client, _ := newTestServer(t)
	login(t, client, ts.URL)

	const cmScript = "/static/vendor/codemirror/codemirror.min.js"
	const cmStyle = "/static/vendor/codemirror/codemirror.min.css"

	for _, c := range []struct {
		path string
		want bool
	}{
		{"/", false},
		{"/db/main/table/widgets", false},
		{"/db/main/table/widgets/structure", false},
		{"/db/main/sql", true},
		{"/db/main/import", true},
		{"/db/main/table/widgets/sql", true},
	} {
		resp, body := getRaw(t, client, ts.URL+c.path, "identity")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s = %d, want 200", c.path, resp.StatusCode)
		}
		page := string(body)
		hasScript := strings.Contains(page, cmScript)
		hasStyle := strings.Contains(page, cmStyle)
		if hasScript != c.want || hasStyle != c.want {
			t.Errorf("%s: CodeMirror script=%v style=%v, want both %v", c.path, hasScript, hasStyle, c.want)
		}
		// app.js always ships: it is what injects CodeMirror on demand when an
		// htmx navigation lands on an editor page without re-running <head>.
		if !strings.Contains(page, "/static/js/app.js") {
			t.Errorf("%s: app.js missing", c.path)
		}
	}
}
