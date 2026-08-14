package server_test

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

// editWhereRE pulls a valid, decodable row-key token out of a base table's browse
// page so the edit routes can be exercised against a VIEW: the edit guard lives
// inside mutationConn, which runs AFTER the where-token decode, so a garbage
// token would 400 at decoding and never reach the read-only-view check.
var editWhereRE = regexp.MustCompile(`/widgets/edit\?where=([^"&]+)`)

// createView creates a queryable SQLite view over the seeded widgets table via
// the SQL console, so the read-only-view policy can be exercised end to end.
func createView(t *testing.T, client *http.Client, base string) {
	t.Helper()
	csrf := csrfFrom(t, client, base+"/")
	body := url.Values{"sql_query": {"CREATE VIEW v_widgets AS SELECT id, name, qty FROM widgets"}}.Encode()
	req, _ := http.NewRequest(http.MethodPost, base+"/db/main/sql", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-CSRF-Token", csrf)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("create view: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode >= 400 {
		t.Fatalf("create view status = %d", resp.StatusCode)
	}
}

// TestReadOnlyViewRejectsMutations pins: all seven mutating table routes reject
// a VIEW server-side (a full-page request gets the real 400, not the htmx panel
// at 200), even though the routes stay registered. Hiding the tabs/links is not
// the enforcement — requireWritableTable is.
func TestReadOnlyViewRejectsMutations(t *testing.T) {
	ts, client, _ := newTestServer(t)
	login(t, client, ts.URL)
	createView(t, client, ts.URL)
	csrf := csrfFrom(t, client, ts.URL+"/")

	// A valid where-token, harvested from the base table's browse page.
	_, widgets := getBody(t, client, ts.URL+"/db/main/table/widgets")
	m := editWhereRE.FindStringSubmatch(widgets)
	if len(m) < 2 {
		t.Fatalf("no edit where-token in widgets browse page")
	}
	whereEnc := m[1]                             // as it appears in the href (URL-encoded)
	whereTok, err := url.QueryUnescape(whereEnc) // decoded, for POST form fields
	if err != nil {
		t.Fatalf("decode where token: %v", err)
	}

	// Each mutating route on the view must 400 with the read-only-view message.
	post := func(path string, form url.Values) *http.Response {
		t.Helper()
		form.Set("csrf_token", csrf)
		req, _ := http.NewRequest(http.MethodPost, ts.URL+path, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("X-CSRF-Token", csrf)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("POST %s: %v", path, err)
		}
		return resp
	}
	assertViewRejected := func(name string, resp *http.Response) {
		t.Helper()
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s on a view = %d, want 400 (full-page)", name, resp.StatusCode)
		}
	}

	// GET forms.
	assertViewRejected("GET insert form", getResp(t, client, ts.URL+"/db/main/table/v_widgets/insert"))
	assertViewRejected("GET edit form", getResp(t, client, ts.URL+"/db/main/table/v_widgets/edit?where="+whereEnc))
	assertViewRejected("GET table import", getResp(t, client, ts.URL+"/db/main/table/v_widgets/import"))

	// POST mutations.
	assertViewRejected("POST insert", post("/db/main/table/v_widgets/insert", url.Values{"v_name": {"x"}}))
	assertViewRejected("POST edit", post("/db/main/table/v_widgets/edit", url.Values{"where_token": {whereTok}, "v_name": {"x"}}))
	assertViewRejected("POST delete", post("/db/main/table/v_widgets/delete", url.Values{"row": {whereTok}}))
	assertViewRejected("POST table import", post("/db/main/table/v_widgets/import", url.Values{"sql_script": {"SELECT 1"}}))
}

// TestReadOnlyViewBrowseHidesMutations pins that a view's Browse grid renders
// without the mutating surface (row checkboxes, edit/copy/delete actions, the
// Insert bulk-bar link) and that its context tabs drop Insert/Import — while the
// base table keeps all of them.
func TestReadOnlyViewBrowseHidesMutations(t *testing.T) {
	ts, client, _ := newTestServer(t)
	login(t, client, ts.URL)
	createView(t, client, ts.URL)

	code, viewPage := getBody(t, client, ts.URL+"/db/main/table/v_widgets")
	if code != http.StatusOK {
		t.Fatalf("browse view = %d, want 200", code)
	}
	// The view lists rows, so any mutating surface WOULD render if not gated.
	if !strings.Contains(viewPage, "bolt") {
		t.Fatalf("view browse should list the underlying rows")
	}
	for _, forbidden := range []string{
		`name="rows[]"`,           // row select checkbox
		"Insert new row",          // bulk-bar insert link
		`aria-label="Edit row `,   // per-row edit action
		"/table/v_widgets/insert", // Insert tab / link
		"/table/v_widgets/import", // Import tab / link
	} {
		if strings.Contains(viewPage, forbidden) {
			t.Errorf("view browse must not contain %q (read-only-view policy)", forbidden)
		}
	}

	// The base table keeps the full surface (guards the assertions above against
	// a template that silently dropped it for everyone).
	_, tablePage := getBody(t, client, ts.URL+"/db/main/table/widgets")
	for _, wanted := range []string{`name="rows[]"`, "Insert new row", "/table/widgets/insert", "/table/widgets/import"} {
		if !strings.Contains(tablePage, wanted) {
			t.Errorf("base-table browse should contain %q", wanted)
		}
	}
}

// TestDBStructureNoInsertLinkForView pins that the database structure page renders
// an Insert action for a base table but NOT for a listed view.
func TestDBStructureNoInsertLinkForView(t *testing.T) {
	ts, client, _ := newTestServer(t)
	login(t, client, ts.URL)
	createView(t, client, ts.URL)

	code, structure := getBody(t, client, ts.URL+"/db/main")
	if code != http.StatusOK {
		t.Fatalf("db structure = %d, want 200", code)
	}
	if !strings.Contains(structure, "v_widgets") {
		t.Fatalf("db structure should list the view")
	}
	if !strings.Contains(structure, `aria-label="Insert into widgets"`) {
		t.Error("db structure should offer Insert for the base table")
	}
	if strings.Contains(structure, `aria-label="Insert into v_widgets"`) {
		t.Error("db structure must not offer Insert for a view")
	}
}
