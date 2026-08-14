package server_test

// Per-object export selection, end to end. As with the row selection, the
// property under test is NARROWING — the unselected tables must be absent, not
// merely the selected ones present.

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

var objectTokenRE = regexp.MustCompile(`name="objects\[\]" value="([^"]+)"`)

// TestDBExportOffersPerTableSelection — the form lists the database's tables,
// pre-checked, so the default is still "export everything".
func TestDBExportOffersPerTableSelection(t *testing.T) {
	ts, client, path := newTestServer(t)
	execSQLite(t, path, `CREATE TABLE gadgets (id INTEGER PRIMARY KEY, label TEXT)`)
	login(t, client, ts.URL)

	code, body := getBody(t, client, ts.URL+"/db/main/export")
	if code != http.StatusOK {
		t.Fatalf("db export form = %d", code)
	}
	toks := objectTokenRE.FindAllStringSubmatch(body, -1)
	if len(toks) != 2 {
		t.Fatalf("the form offers %d tables, want widgets and gadgets:\n%.2500s", len(toks), body)
	}
	// Pre-checked: an untouched form must export the whole database, as it did
	// before there was a picker at all.
	if strings.Count(body, `name="objects[]"`) != strings.Count(body, `name="objects[]" value="`) {
		t.Error("malformed object inputs")
	}
	for _, m := range objectTokenRE.FindAllString(body, -1) {
		idx := strings.Index(body, m)
		if !strings.Contains(body[idx:idx+len(m)+20], "checked") {
			t.Errorf("object checkbox %q is not pre-checked; the default would silently narrow the export", m)
		}
	}
	// The table-scope form has no picker — there is nothing to choose.
	if _, tbody := getBody(t, client, ts.URL+"/db/main/table/widgets/export"); objectTokenRE.MatchString(tbody) {
		t.Error("the table-scope export form offers a table picker")
	}
}

// TestDBExportHonoursSelection — checking one table exports one table.
func TestDBExportHonoursSelection(t *testing.T) {
	ts, client, path := newTestServer(t)
	execSQLite(t, path, `CREATE TABLE gadgets (id INTEGER PRIMARY KEY, label TEXT)`)
	execSQLite(t, path, `INSERT INTO gadgets (label) VALUES ('gizmo')`)
	login(t, client, ts.URL)

	_, form := getBody(t, client, ts.URL+"/db/main/export")
	var gadgetTok string
	for _, m := range objectTokenRE.FindAllStringSubmatch(form, -1) {
		if strings.Contains(m[1], "gadgets") {
			gadgetTok = m[1]
		}
	}
	if gadgetTok == "" {
		t.Fatalf("no token for gadgets:\n%.2000s", form)
	}
	csrf := csrfFrom(t, client, ts.URL+"/")

	code, body := postTo(t, client, ts.URL+"/db/main/export", url.Values{
		"csrf_token": {csrf}, "format": {"sql"}, "structure": {"1"}, "data": {"1"},
		"objects[]": {gadgetTok},
	})
	if code != http.StatusOK {
		t.Fatalf("selective export = %d\n%.800s", code, body)
	}
	if !strings.Contains(body, "gadgets") || !strings.Contains(body, "gizmo") {
		t.Errorf("the selected table is missing from the dump:\n%.1200s", body)
	}
	if strings.Contains(body, "widgets") || strings.Contains(body, "bolt") {
		t.Errorf("an unselected table was exported anyway:\n%.1200s", body)
	}

	// No selection at all still means everything.
	code, body = postTo(t, client, ts.URL+"/db/main/export", url.Values{
		"csrf_token": {csrf}, "format": {"sql"}, "structure": {"1"}, "data": {"1"},
	})
	if code != http.StatusOK {
		t.Fatalf("unfiltered export = %d", code)
	}
	for _, want := range []string{"widgets", "gadgets"} {
		if !strings.Contains(body, want) {
			t.Errorf("an unselective export dropped %q", want)
		}
	}
}

// TestDBExportRejectsSelectionOfNothingReal — a selection naming only tables
// that do not exist must be refused, not silently widened back to everything.
func TestDBExportRejectsSelectionOfNothingReal(t *testing.T) {
	ts, client, _ := newTestServer(t)
	login(t, client, ts.URL)

	code, body := postTo(t, client, ts.URL+"/db/main/export", url.Values{
		"csrf_token": {csrfFrom(t, client, ts.URL+"/")},
		"format":     {"sql"}, "structure": {"1"}, "data": {"1"},
		"objects[]": {"0:ghost", "not-a-token"},
	})
	if code != http.StatusBadRequest {
		t.Errorf("selection of only unknown tables = %d, want 400", code)
	}
	if strings.Contains(body, "CREATE TABLE") || strings.Contains(body, "bolt") {
		t.Errorf("an unresolvable selection exported the whole database:\n%.800s", body)
	}
}
