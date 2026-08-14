package server_test

// Compressed export files, and importing them straight back.
//
// This is a gzip FILE, not the transport gzip the middleware already does: the
// browser undoes Content-Encoding before saving, so only an explicitly
// compressed body reaches the disk as a .gz. The two must not be confused, and
// they must not both apply — a doubly-gzipped download is unopenable.

import (
	"bytes"
	"compress/gzip"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// postRaw posts a pre-built body, returning the response and its RAW (still
// encoded) bytes — the default client would transparently gunzip a
// Content-Encoding: gzip response and hide exactly what this is testing.
func postRaw(t *testing.T, client *http.Client, u, contentType string, body []byte, acceptEncoding string) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", contentType)
	if acceptEncoding != "" {
		req.Header.Set("Accept-Encoding", acceptEncoding)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", u, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read %s: %v", u, err)
	}
	return resp, b
}

// TestExportGzipProducesAGzipFile — the download is a real gzip stream, named
// .gz, and is NOT additionally compressed by the transport middleware even when
// the client advertises gzip.
func TestExportGzipProducesAGzipFile(t *testing.T) {
	ts, client, path := newTestServer(t)
	seedThreeWidgets(t, path)
	login(t, client, ts.URL)

	form := url.Values{
		"csrf_token":  {csrfFrom(t, client, ts.URL+"/")},
		"format":      {"sql"},
		"structure":   {"1"},
		"data":        {"1"},
		"compression": {"gzip"},
	}
	// Ask for transport gzip too. If the middleware also compressed this, the
	// body would be gzip-of-gzip and the single decode below would yield binary
	// rather than SQL.
	resp, body := postRaw(t, client, ts.URL+"/db/main/table/widgets/export",
		"application/x-www-form-urlencoded", []byte(form.Encode()), "gzip")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("gzip export = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/gzip" {
		t.Errorf("Content-Type = %q, want application/gzip (no charset on a binary file)", ct)
	}
	if cd := resp.Header.Get("Content-Disposition"); !strings.Contains(cd, "widgets.sql.gz") {
		t.Errorf("Content-Disposition = %q, want a .sql.gz filename", cd)
	}
	if enc := resp.Header.Get("Content-Encoding"); enc != "" {
		t.Errorf("Content-Encoding = %q; a gzip FILE must not also be a gzip transfer encoding — the browser would decode it and save a .gz that is not gzipped", enc)
	}

	zr, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		t.Fatalf("the download is not a gzip stream: %v", err)
	}
	plain, err := io.ReadAll(zr)
	if err != nil {
		t.Fatalf("decompressing the download: %v (a missing trailer means the writer was not closed)", err)
	}
	got := string(plain)
	if !strings.Contains(got, "CREATE TABLE") || !strings.Contains(got, "alpha") {
		t.Errorf("decompressed dump is not the expected SQL:\n%.500s", got)
	}
}

// TestExportGzipRoundTripsThroughImport — the whole point: a compressed export
// can be handed straight back to Import, which detects it from the bytes.
func TestExportGzipRoundTripsThroughImport(t *testing.T) {
	ts, client, path := newTestServer(t)
	seedThreeWidgets(t, path)
	login(t, client, ts.URL)

	form := url.Values{
		"csrf_token": {csrfFrom(t, client, ts.URL+"/")},
		"format":     {"sql"}, "structure": {"1"}, "data": {"1"}, "drop": {"1"},
		"compression": {"gzip"},
	}
	_, gzBody := postRaw(t, client, ts.URL+"/db/main/table/widgets/export",
		"application/x-www-form-urlencoded", []byte(form.Encode()), "")
	if len(gzBody) == 0 {
		t.Fatal("empty export")
	}

	// Wreck the table, then restore it from the compressed dump.
	execSQLite(t, path, `DROP TABLE widgets`)
	code, body := postUpload(t, client, ts.URL+"/db/main/import",
		csrfFrom(t, client, ts.URL+"/"), "widgets.sql.gz", gzBody, nil)
	if code != http.StatusOK {
		t.Fatalf("import = %d, want 200\n%.800s", code, body)
	}
	if strings.Contains(body, "tx-alert-error") {
		t.Fatalf("the compressed dump failed to import:\n%.1500s", body)
	}
	got := widgetRows(t, path)
	want := []string{"1:alpha:10", "2:bravo:20", "3:charlie:30"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("after restoring the gzipped dump rows = %v, want %v", got, want)
	}
}

// TestImportRefusesDecompressionBomb — the guard that matters. A small upload
// that expands without bound must be refused, and refused by MEASURING the
// output rather than by trusting the gzip trailer, which the uploader writes.
func TestImportRefusesDecompressionBomb(t *testing.T) {
	ts, client, _ := newTestServer(t)
	login(t, client, ts.URL)

	// ~1 GiB of zero bytes compresses to about a megabyte: well under the upload
	// cap, far over any sane expansion budget.
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	chunk := make([]byte, 1<<20)
	for i := 0; i < 1024; i++ {
		if _, err := zw.Write(chunk); err != nil {
			t.Fatalf("building the bomb: %v", err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("closing the bomb: %v", err)
	}
	if buf.Len() > 32<<20 {
		t.Fatalf("the bomb is %d bytes; it must be under the upload cap or this tests the wrong guard", buf.Len())
	}

	code, body := postUpload(t, client, ts.URL+"/db/main/import",
		csrfFrom(t, client, ts.URL+"/"), "bomb.sql.gz", buf.Bytes(), nil)
	if code == http.StatusOK && !strings.Contains(body, "expands to more than") {
		t.Fatalf("a decompression bomb was accepted (status %d):\n%.800s", code, body)
	}
}

// TestImportSniffsGzipFromBytesNotName — the format is decided by the content.
// A .gz that is not gzipped, and a gzip file without the extension, must both
// behave sensibly.
func TestImportSniffsGzipFromBytesNotName(t *testing.T) {
	ts, client, path := newTestServer(t)
	login(t, client, ts.URL)

	// Plain SQL under a .gz name: not gzip magic, so it imports as-is.
	code, body := postUpload(t, client, ts.URL+"/db/main/import",
		csrfFrom(t, client, ts.URL+"/"),
		"lying.sql.gz", []byte(`INSERT INTO widgets (name, qty) VALUES ('sniffed', 1)`), nil)
	if code != http.StatusOK || strings.Contains(body, "tx-alert-error") {
		t.Fatalf("plain SQL named .gz did not import (%d):\n%.800s", code, body)
	}
	found := false
	for _, r := range widgetRows(t, path) {
		if strings.Contains(r, "sniffed") {
			found = true
		}
	}
	if !found {
		t.Error("the row from the mis-named plain-SQL upload is missing")
	}

	// A gzip stream under a plain .sql name: decompressed anyway.
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write([]byte(`INSERT INTO widgets (name, qty) VALUES ('unnamed_gz', 2)`)); err != nil {
		t.Fatalf("write: %v", err)
	}
	zw.Close()
	code, body = postUpload(t, client, ts.URL+"/db/main/import",
		csrfFrom(t, client, ts.URL+"/"), "plain.sql", buf.Bytes(), nil)
	if code != http.StatusOK || strings.Contains(body, "tx-alert-error") {
		t.Fatalf("a gzip stream named .sql was not decompressed (%d):\n%.800s", code, body)
	}
	found = false
	for _, r := range widgetRows(t, path) {
		if strings.Contains(r, "unnamed_gz") {
			found = true
		}
	}
	if !found {
		t.Error("the row from the gzip-without-.gz upload is missing")
	}
}

// postUpload posts a multipart file upload with the CSRF token in the form.
func postUpload(t *testing.T, client *http.Client, u, csrf, filename string, content []byte, extra map[string]string) (int, string) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	if err := mw.WriteField("csrf_token", csrf); err != nil {
		t.Fatalf("csrf field: %v", err)
	}
	for k, v := range extra {
		if err := mw.WriteField(k, v); err != nil {
			t.Fatalf("field %s: %v", k, err)
		}
	}
	fw, err := mw.CreateFormFile("file", filename)
	if err != nil {
		t.Fatalf("form file: %v", err)
	}
	if _, err := fw.Write(content); err != nil {
		t.Fatalf("write upload: %v", err)
	}
	if err := mw.Close(); err != nil {
		t.Fatalf("close multipart: %v", err)
	}
	resp, body := postRaw(t, client, u, mw.FormDataContentType(), buf.Bytes(), "")
	return resp.StatusCode, string(body)
}
