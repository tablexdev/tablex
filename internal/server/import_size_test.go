package server_test

import (
	"bytes"
	"io"
	"mime/multipart"
	"net/http"
	"runtime"
	"strings"
	"testing"

	"github.com/tablexdev/tablex/internal/auth"
	"github.com/tablexdev/tablex/internal/server/handlers"
)

// postImport uploads body as an SQL file to the database-scoped importer and
// returns the status. The payload is a run of SQL comments: it exercises the
// whole upload → cap → parse → spill → splitter path at realistic size without
// asking a test database to execute megabytes of DDL.
func postImport(t *testing.T, base string, client *http.Client, csrf string, size int) int {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	_ = mw.WriteField("csrf_token", csrf)
	_ = mw.WriteField("format", "sql")
	fw, err := mw.CreateFormFile("file", "big.sql")
	if err != nil {
		t.Fatalf("CreateFormFile: %v", err)
	}
	const line = "-- padding padding padding padding padding padding padding\n"
	for written := 0; written < size; written += len(line) {
		if _, err := io.WriteString(fw, line); err != nil {
			t.Fatalf("write payload: %v", err)
		}
	}
	mw.Close()

	req, err := http.NewRequest(http.MethodPost, base+"/db/main/import", &buf)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	// Send the token in the HEADER, as the htmx import does. That is the path
	// where the handler performs the first body parse and so the one where the
	// size cap surfaces as 413. With the token in the form body instead, the
	// csrf middleware's own bounded parse fails first and the request fails
	// closed at 403 — deliberate, and covered separately below.
	req.Header.Set(auth.CSRFHeader, csrf)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST /import: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode
}

// TestImportSizeBoundary pins the upload cap from both sides: an upload over
// MaxImportBytes must be refused with 413, one comfortably under it must be
// accepted, and the accepted one must not balloon the heap — the importer used
// to pass the 32 MiB SIZE cap as ParseMultipartForm's in-memory THRESHOLD, so
// every upload was buffered whole in RAM.
func TestImportSizeBoundary(t *testing.T) {
	if testing.Short() {
		t.Skip("allocates tens of megabytes")
	}
	ts, client, _ := newTestServer(t)
	login(t, client, ts.URL)
	csrf := csrfFrom(t, client, ts.URL+"/")

	// Over the cap: refused before the handler ever sees a byte of it.
	if got := postImport(t, ts.URL, client, csrf, handlers.MaxImportBytes+(8<<20)); got != http.StatusRequestEntityTooLarge {
		t.Errorf("40 MiB import = %d, want 413", got)
	}

	// Under the cap: accepted, and the heap does not grow by the payload size.
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)

	const under = 20 << 20
	if got := postImport(t, ts.URL, client, csrf, under); got != http.StatusOK {
		t.Errorf("20 MiB import = %d, want 200", got)
	}

	runtime.GC()
	runtime.ReadMemStats(&after)
	// Generous headroom: the point is that the upload SPILLS rather than being
	// retained whole, not a precise allocation budget. Retaining it would show
	// as at least the payload size still live after a GC.
	if grew := int64(after.HeapAlloc) - int64(before.HeapAlloc); grew > under/2 {
		t.Errorf("heap grew %d bytes across a %d-byte upload; the body is being retained in memory", grew, under)
	}
}

// TestImportRouteCapIsTighterThanGlobal pins the route-aware body cap on the
// NO-JS path, where the token rides the form body: the csrf middleware performs
// the first (bounded) parse, so an oversized import fails closed at the CSRF
// check rather than reaching the handler. The important property is that it is
// refused at all — under the looser global cap the middleware would have
// happily parsed 64 MiB before anyone looked at the size.
func TestImportRouteCapIsTighterThanGlobal(t *testing.T) {
	ts, client, _ := newTestServer(t)
	login(t, client, ts.URL)
	csrf := csrfFrom(t, client, ts.URL+"/")

	body := "csrf_token=" + csrf + "&format=sql&sql_script=" +
		strings.Repeat("a", handlers.MaxImportBytes+1024)
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/db/main/import", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden && resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized form-encoded import = %d, want 403 (fails closed at CSRF) or 413", resp.StatusCode)
	}

	// A body UNDER the cap on the same path still works, so the refusal above
	// is the size and not the encoding.
	body = "csrf_token=" + csrf + "&format=sql&sql_script=" + strings.Repeat("-", 1024)
	req, _ = http.NewRequest(http.MethodPost, ts.URL+"/db/main/import", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("small form-encoded import = %d, want 200", resp.StatusCode)
	}
}
