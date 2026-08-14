package server_test

// "With selected" export, end to end. The property that matters is NARROWING:
// a selected-rows export must contain the selected rows and NOTHING ELSE. The
// failure mode worth guarding is not an error — it is a request that quietly
// falls back to dumping the whole table under a "selected rows" label, so every
// negative case here asserts the absent rows are absent, not merely that the
// status was 400.

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

// encodeTestRowKey mints a well-formed row-identity token, mirroring the
// handler's encoding. Used to submit a token that DECODES cleanly but names a
// column the table does not have — the case a garbage string cannot reach.
func encodeTestRowKey(t *testing.T, col, val string) string {
	t.Helper()
	b, err := json.Marshal([]map[string]any{{"c": col, "v": val}})
	if err != nil {
		t.Fatalf("encode row key: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

var rowTokenRE = regexp.MustCompile(`name="rows\[\]" value="([^"]+)"`)

// browseRowTokens returns the browse grid's row-identity tokens, in row order.
func browseRowTokens(t *testing.T, client *http.Client, base, table string) []string {
	t.Helper()
	code, body := getBody(t, client, base+"/db/main/table/"+table)
	if code != http.StatusOK {
		t.Fatalf("browse %s = %d, want 200", table, code)
	}
	var out []string
	for _, m := range rowTokenRE.FindAllStringSubmatch(body, -1) {
		out = append(out, m[1])
	}
	if len(out) == 0 {
		t.Fatalf("no row tokens on the %s grid:\n%.2000s", table, body)
	}
	return out
}

// postTo posts a form and returns the status and body.
func postTo(t *testing.T, client *http.Client, u string, form url.Values) (int, string) {
	t.Helper()
	resp, err := client.PostForm(u, form)
	if err != nil {
		t.Fatalf("POST %s: %v", u, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read %s: %v", u, err)
	}
	return resp.StatusCode, string(b)
}

// TestBulkExportSelectionReachesTheForm — the grid's Export button cannot
// download on its own: the format and structure/data choices live on the export
// form. So it hands the selection to that form, which must carry every token
// through to the download POST.
func TestBulkExportSelectionReachesTheForm(t *testing.T) {
	ts, client, path := newTestServer(t)
	seedManyRows(t, path, 6)
	login(t, client, ts.URL)

	tokens := browseRowTokens(t, client, ts.URL, "widgets")
	csrf := csrfFrom(t, client, ts.URL+"/")

	// The bulk bar offers it at all.
	_, browse := getBody(t, client, ts.URL+"/db/main/table/widgets")
	if !strings.Contains(browse, `hx-vals='{"action": "export"}'`) {
		t.Errorf("the bulk bar has no Export action:\n%.2000s", browse)
	}
	if !strings.Contains(browse, `formaction="/db/main/table/widgets/rows"`) {
		t.Error("the bulk Export button has no formaction, so it does nothing without JavaScript")
	}

	code, body := postTo(t, client, ts.URL+"/db/main/table/widgets/rows", url.Values{
		"csrf_token": {csrf},
		"action":     {"export"},
		"rows[]":     {tokens[0], tokens[1], tokens[2]},
	})
	if code != http.StatusOK {
		t.Fatalf("bulk export = %d, want 200\n%.1000s", code, body)
	}
	if n := len(rowTokenRE.FindAllString(body, -1)); n != 3 {
		t.Errorf("the export form carries %d of 3 selected rows; the rest would be lost on submit:\n%.2000s", n, body)
	}
	if !strings.Contains(body, "Exporting 3 selected row(s)") {
		t.Errorf("the form does not say it is a partial export:\n%.2000s", body)
	}
	// It is still the ordinary export form — format and contents must be choosable.
	if !strings.Contains(body, `name="format" value="csv"`) {
		t.Error("the selection form dropped the format choice")
	}
}

// TestBulkExportEmitsOnlySelectedRows is the feature, in all three formats.
func TestBulkExportEmitsOnlySelectedRows(t *testing.T) {
	ts, client, path := newTestServer(t)
	// Distinct, searchable values so "did row 4 leak in" is a substring check.
	execSQLite(t, path, `DELETE FROM widgets`)
	for _, s := range []string{
		`INSERT INTO widgets (id, name, qty) VALUES (1,'alpha',1)`,
		`INSERT INTO widgets (id, name, qty) VALUES (2,'bravo',2)`,
		`INSERT INTO widgets (id, name, qty) VALUES (3,'charlie',3)`,
		`INSERT INTO widgets (id, name, qty) VALUES (4,'delta',4)`,
	} {
		execSQLite(t, path, s)
	}
	login(t, client, ts.URL)

	tokens := browseRowTokens(t, client, ts.URL, "widgets")
	if len(tokens) != 4 {
		t.Fatalf("got %d row tokens, want 4", len(tokens))
	}
	csrf := csrfFrom(t, client, ts.URL+"/")

	for _, tc := range []struct{ format, name string }{
		{"csv", "CSV"}, {"json", "JSON"}, {"sql", "SQL"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, body := postTo(t, client, ts.URL+"/db/main/table/widgets/export", url.Values{
				"csrf_token": {csrf},
				"format":     {tc.format},
				"structure":  {"1"},
				"data":       {"1"},
				"rows[]":     {tokens[0], tokens[2]}, // alpha and charlie
			})
			if code != http.StatusOK {
				t.Fatalf("%s export = %d\n%.1000s", tc.format, code, body)
			}
			for _, want := range []string{"alpha", "charlie"} {
				if !strings.Contains(body, want) {
					t.Errorf("%s export is missing selected row %q:\n%.1500s", tc.format, want, body)
				}
			}
			for _, unwanted := range []string{"bravo", "delta"} {
				if strings.Contains(body, unwanted) {
					t.Errorf("%s export leaked unselected row %q — the selection did not narrow the data:\n%.1500s",
						tc.format, unwanted, body)
				}
			}
			// SQL keeps the whole table's structure: a filtered dump still has to
			// restore into a real table.
			if tc.format == "sql" && !strings.Contains(body, "CREATE TABLE") {
				t.Error("a selected-rows SQL export dropped the structure")
			}
		})
	}

	// Without a selection the same endpoint still exports everything — the
	// filter is opt-in, and this is what proves the negative cases above are
	// testing the filter rather than a broken export.
	code, body := postTo(t, client, ts.URL+"/db/main/table/widgets/export", url.Values{
		"csrf_token": {csrf}, "format": {"csv"},
	})
	if code != http.StatusOK {
		t.Fatalf("unfiltered export = %d", code)
	}
	for _, want := range []string{"alpha", "bravo", "charlie", "delta"} {
		if !strings.Contains(body, want) {
			t.Errorf("unfiltered export is missing %q; the filter is leaking into unselected exports", want)
		}
	}
}

// TestBulkExportRefusesUnresolvableSelection — the dangerous failure. A stale or
// hostile token must not degrade into "no filter", which would hand back the
// WHOLE table in response to a request that asked for two rows.
func TestBulkExportRefusesUnresolvableSelection(t *testing.T) {
	ts, client, path := newTestServer(t)
	execSQLite(t, path, `DELETE FROM widgets`)
	execSQLite(t, path, `INSERT INTO widgets (id, name, qty) VALUES (1,'alpha',1)`)
	execSQLite(t, path, `INSERT INTO widgets (id, name, qty) VALUES (2,'bravo',2)`)
	login(t, client, ts.URL)
	csrf := csrfFrom(t, client, ts.URL+"/")

	for _, tok := range []string{
		"not-base64-at-all!!",
		// Well-formed token naming a column this table does not have.
		encodeTestRowKey(t, "no_such_column", "1"),
	} {
		code, body := postTo(t, client, ts.URL+"/db/main/table/widgets/export", url.Values{
			"csrf_token": {csrf}, "format": {"csv"}, "rows[]": {tok},
		})
		if code != http.StatusBadRequest {
			t.Errorf("export with token %q = %d, want 400", tok, code)
		}
		// The point: no data came back, not merely a non-200.
		for _, leaked := range []string{"alpha", "bravo"} {
			if strings.Contains(body, leaked) {
				t.Errorf("an unresolvable selection exported %q — it fell back to a full-table dump:\n%.1000s", leaked, body)
			}
		}
	}
}

// TestBulkExportBindsRowValues — the row-identity values reach the export
// stream as bound parameters. A key whose text is itself SQL must match the one
// row that literally holds that text, and nothing else.
func TestBulkExportBindsRowValues(t *testing.T) {
	ts, client, path := newTestServer(t)
	execSQLite(t, path, `CREATE TABLE quoted (k TEXT PRIMARY KEY, v TEXT)`)
	// The payload is chosen so that CONCATENATING it produces VALID SQL that
	// matches every row (k = 'a' OR 'x'='x'). A payload that merely breaks the
	// statement would prove only that something went wrong, not that the whole
	// table came back.
	execSQLite(t, path, `INSERT INTO quoted (k, v) VALUES ('a'' OR ''x''=''x', 'PICKED')`)
	execSQLite(t, path, `INSERT INTO quoted (k, v) VALUES ('ordinary', 'NOTPICKED')`)
	login(t, client, ts.URL)

	tokens := browseRowTokens(t, client, ts.URL, "quoted")
	if len(tokens) != 2 {
		t.Fatalf("got %d row tokens, want 2", len(tokens))
	}
	csrf := csrfFrom(t, client, ts.URL+"/")

	// The injection-shaped key is row 1 (k sorts before 'ordinary').
	code, body := postTo(t, client, ts.URL+"/db/main/table/quoted/export", url.Values{
		"csrf_token": {csrf}, "format": {"csv"}, "rows[]": {tokens[0]},
	})
	if code != http.StatusOK {
		t.Fatalf("export = %d\n%.1000s", code, body)
	}
	if !strings.Contains(body, "PICKED") {
		t.Errorf("the row keyed by SQL-shaped text did not export:\n%.1000s", body)
	}
	if strings.Contains(body, "NOTPICKED") {
		t.Errorf("the key was concatenated, not bound — its OR clause matched every row:\n%.1000s", body)
	}
}

// TestBulkActionsRequireASelection — an empty or oversized selection is answered
// with a flash, not a stack trace or a full-table action.
func TestBulkActionsRequireASelection(t *testing.T) {
	ts, client, _ := newTestServer(t)
	login(t, client, ts.URL)
	csrf := csrfFrom(t, client, ts.URL+"/")

	code, _ := postTo(t, client, ts.URL+"/db/main/table/widgets/rows", url.Values{
		"csrf_token": {csrf}, "action": {"export"},
	})
	if code != http.StatusSeeOther {
		t.Errorf("empty selection = %d, want 303 back to browse", code)
	}

	// An unknown verb is refused rather than silently treated as one of the
	// real ones.
	code, _ = postTo(t, client, ts.URL+"/db/main/table/widgets/rows", url.Values{
		"csrf_token": {csrf}, "action": {"obliterate"}, "rows[]": {"x"},
	})
	if code != http.StatusBadRequest {
		t.Errorf("unknown bulk action = %d, want 400", code)
	}
}
