package server_test

// XML export over HTTP. The unit tests in internal/dump pin the escaping; these
// pin that the format is reachable, labelled correctly, and composes with the
// row filter, row range and gzip that the other formats already have.

import (
	"bytes"
	"compress/gzip"
	"encoding/xml"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func mustParseXML(t *testing.T, s string) {
	t.Helper()
	dec := xml.NewDecoder(strings.NewReader(s))
	for {
		_, err := dec.Token()
		if err == io.EOF {
			return
		}
		if err != nil {
			t.Fatalf("export is not well-formed XML: %v\n%.800s", err, s)
		}
	}
}

func TestExportXML(t *testing.T) {
	ts, client, path := newTestServer(t)
	execSQLite(t, path, `DELETE FROM widgets`)
	execSQLite(t, path, `INSERT INTO widgets (id, name, qty) VALUES (1,'a<b>&c',10)`)
	execSQLite(t, path, `INSERT INTO widgets (id, name, qty) VALUES (2,'plain',NULL)`)
	login(t, client, ts.URL)

	// The format is offered on the form.
	_, form := getBody(t, client, ts.URL+"/db/main/table/widgets/export")
	if !strings.Contains(form, `name="format" value="xml"`) {
		t.Fatalf("the export form does not offer XML:\n%.2000s", form)
	}

	csrf := csrfFrom(t, client, ts.URL+"/")
	code, body := postTo(t, client, ts.URL+"/db/main/table/widgets/export", url.Values{
		"csrf_token": {csrf}, "format": {"xml"},
	})
	if code != http.StatusOK {
		t.Fatalf("xml export = %d\n%.600s", code, body)
	}
	mustParseXML(t, body)
	if !strings.Contains(body, `<table name="widgets">`) {
		t.Errorf("no table element:\n%.800s", body)
	}
	// Markup in the data is escaped, and NULL stays distinct from empty.
	if strings.Contains(body, "a<b>&c") {
		t.Errorf("raw markup survived into the document:\n%.800s", body)
	}
	if !strings.Contains(body, `null="true"`) {
		t.Errorf("NULL was not marked:\n%.800s", body)
	}

	// It composes with the row range...
	code, body = postTo(t, client, ts.URL+"/db/main/table/widgets/export", url.Values{
		"csrf_token": {csrf}, "format": {"xml"}, "row_limit": {"1"},
	})
	if code != http.StatusOK {
		t.Fatalf("xml + limit = %d", code)
	}
	mustParseXML(t, body)
	if n := strings.Count(body, "<row>"); n != 1 {
		t.Errorf("row_limit=1 produced %d rows:\n%.800s", n, body)
	}

	// ...and with gzip, producing a .xml.gz that decompresses to valid XML.
	form2 := url.Values{"csrf_token": {csrf}, "format": {"xml"}, "compression": {"gzip"}}
	resp, raw := postRaw(t, client, ts.URL+"/db/main/table/widgets/export",
		"application/x-www-form-urlencoded", []byte(form2.Encode()), "gzip")
	if cd := resp.Header.Get("Content-Disposition"); !strings.Contains(cd, "widgets.xml.gz") {
		t.Errorf("Content-Disposition = %q, want a .xml.gz filename", cd)
	}
	zr, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("gzipped XML export is not a gzip stream: %v", err)
	}
	plain, err := io.ReadAll(zr)
	if err != nil {
		t.Fatalf("decompressing: %v", err)
	}
	mustParseXML(t, string(plain))
}

// TestExportXMLHonoursRowSelection — the "with selected" filter reaches the XML
// writer too. Same narrowing property as the other formats.
func TestExportXMLHonoursRowSelection(t *testing.T) {
	ts, client, path := newTestServer(t)
	execSQLite(t, path, `DELETE FROM widgets`)
	execSQLite(t, path, `INSERT INTO widgets (id, name, qty) VALUES (1,'alpha',1)`)
	execSQLite(t, path, `INSERT INTO widgets (id, name, qty) VALUES (2,'bravo',2)`)
	login(t, client, ts.URL)

	tokens := browseRowTokens(t, client, ts.URL, "widgets")
	code, body := postTo(t, client, ts.URL+"/db/main/table/widgets/export", url.Values{
		"csrf_token": {csrfFrom(t, client, ts.URL+"/")},
		"format":     {"xml"}, "rows[]": {tokens[0]},
	})
	if code != http.StatusOK {
		t.Fatalf("xml + selection = %d", code)
	}
	mustParseXML(t, body)
	if !strings.Contains(body, "alpha") {
		t.Errorf("the selected row is missing:\n%.800s", body)
	}
	if strings.Contains(body, "bravo") {
		t.Errorf("an unselected row was exported:\n%.800s", body)
	}
}
