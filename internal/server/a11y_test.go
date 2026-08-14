package server_test

import (
	"net/http"
	"regexp"
	"strings"
	"testing"
)

// The accessibility pass. These are the assertions the docs have
// been promising and did not have: before this file the whole suite contained
// three aria-* checks.

var (
	h1RE    = regexp.MustCompile(`(?s)<h1[^>]*>(.*?)</h1>`)
	theadRE = regexp.MustCompile(`(?s)<thead\b.*?</thead>`)
	thRE    = regexp.MustCompile(`<th(?:\s[^>]*)?>`)
	titleRE = regexp.MustCompile(`<title[^>]*>(.*?) · TableX</title>`)
)

// a11yPages are routes that render a full document. Kept broad on purpose: the defect
// existed because the heading was a per-page decision, and a per-page decision
// is exactly what a spot check misses.
var a11yPages = []string{
	"/",
	"/db/main",
	"/db/main/sql",
	"/db/main/search",
	"/db/main/export",
	"/db/main/import",
	"/db/main/operations",
	"/db/main/qbe",
	"/db/main/designer",
	"/db/main/routines",
	"/db/main/triggers",
	"/db/main/events",
	"/db/main/create-table",
	"/db/main/table/widgets",
	"/db/main/table/widgets/structure",
	"/db/main/table/widgets/search",
	"/db/main/table/widgets/insert",
	"/db/main/table/widgets/operations",
	"/db/main/table/widgets/export",
	"/server",
	"/server/variables",
	"/server/processes",
	"/server/users",
}

// Exactly one <h1>, and it names the page. Two pages had no heading element
// at all before this — including Browse, the screen the tool is mostly used on.
func TestEveryPageHasExactlyOneH1NamingIt(t *testing.T) {
	ts, client, _ := newTestServer(t)

	// The login page renders through the same layout and had no heading either.
	code, body := getBody(t, client, ts.URL+"/login")
	if code != http.StatusOK {
		t.Fatalf("GET /login = %d, want 200", code)
	}
	assertSingleH1(t, "/login", body)

	login(t, client, ts.URL)
	for _, path := range a11yPages {
		code, body := getBody(t, client, ts.URL+path)
		if code != http.StatusOK {
			t.Errorf("GET %s = %d, want 200", path, code)
			continue
		}
		assertSingleH1(t, path, body)
	}
}

func assertSingleH1(t *testing.T, path, body string) {
	t.Helper()
	found := h1RE.FindAllStringSubmatch(body, -1)
	if len(found) != 1 {
		t.Errorf("%s has %d <h1> elements, want exactly 1", path, len(found))
		return
	}
	heading := strings.TrimSpace(found[0][1])
	if heading == "" {
		t.Errorf("%s: the <h1> is empty", path)
		return
	}
	// The heading has to say what the page is, so it tracks <title> rather than
	// being a constant that happens to satisfy the count above.
	if m := titleRE.FindStringSubmatch(body); m == nil {
		t.Errorf("%s: no <title> to compare the heading against", path)
	} else if got := strings.TrimSpace(m[1]); got != heading {
		t.Errorf("%s: <h1> is %q but <title> says %q — the heading should name the page", path, heading, got)
	}
}

// Every column header carries a scope. There were none at all in the app
// before this was addressed, and the ones present when this test was written
// covered a third of the tables.
func TestEveryColumnHeaderHasAScope(t *testing.T) {
	ts, client, _ := newTestServer(t)
	login(t, client, ts.URL)

	var checked int
	for _, path := range a11yPages {
		code, body := getBody(t, client, ts.URL+path)
		if code != http.StatusOK {
			continue
		}
		for _, head := range theadRE.FindAllString(body, -1) {
			for _, th := range thRE.FindAllString(head, -1) {
				checked++
				if !strings.Contains(th, `scope="col"`) && !strings.Contains(th, `scope="colgroup"`) {
					t.Errorf("%s: header cell without a scope: %s", path, th)
				}
			}
		}
	}
	// A scope check that found no headers would pass while every table lost its
	// <thead>. The floor is calibrated to the SQLite fixture, which renders 51 of
	// them — pages whose tables are empty show an empty-state instead, and SQLite
	// has no user accounts to list.
	if checked < 45 {
		t.Fatalf("only %d header cells inspected across %d pages; the tables or the "+
			"regexps have changed", checked, len(a11yPages))
	}
}

// Every control on the row editor has an accessible name. This was the worst
// of the findings in practice — the primary data-editing screen announced every
// field as "edit text, blank", because the column name sat in a plain <td> that
// nothing associated with the input.
func TestRowEditorControlsAreNamed(t *testing.T) {
	ts, client, _ := newTestServer(t)
	login(t, client, ts.URL)

	// The edit form needs a real row: the browse page hands out an opaque token
	// per row, and the editor is reachable only through one.
	_, browse := getBody(t, client, ts.URL+"/db/main/table/widgets")
	tok := regexp.MustCompile(`where=([A-Za-z0-9_-]+)`).FindStringSubmatch(browse)
	if tok == nil {
		t.Fatalf("no row token on the browse page")
	}

	for _, path := range []string{
		"/db/main/table/widgets/insert",
		"/db/main/table/widgets/edit?where=" + tok[1],
	} {
		code, body := getBody(t, client, ts.URL+path)
		if code != http.StatusOK {
			t.Errorf("GET %s = %d, want 200", path, code)
			continue
		}
		// The column name is a row header, so the table reads as rows of columns.
		if !strings.Contains(body, `<th scope="row" class="tx-tbl-name">`) {
			t.Errorf("%s: the column-name cell is not a row header", path)
		}
		// And every value control is named in its own right.
		for _, control := range namedControls(body) {
			if !strings.Contains(control, "aria-label=") {
				t.Errorf("%s: unnamed control in the row editor: %s", path, control)
			}
		}
		if n := len(namedControls(body)); n == 0 {
			t.Errorf("%s: no value controls found; the editor did not render", path)
		}
	}
}

var editControlRE = regexp.MustCompile(`<(?:input|textarea|select)(?:\s[^>]*)?>`)

// namedControls returns the form controls inside the row-editor table, which is
// the only table on those pages, skipping the hidden bookkeeping fields (they
// carry no user-visible affordance to name) and the CSRF token.
func namedControls(body string) []string {
	start := strings.Index(body, `<table class="tx-edit-table">`)
	if start < 0 {
		return nil
	}
	end := strings.Index(body[start:], "</table>")
	if end < 0 {
		return nil
	}
	var out []string
	for _, c := range editControlRE.FindAllString(body[start:start+end], -1) {
		if strings.Contains(c, `type="hidden"`) {
			continue
		}
		out = append(out, c)
	}
	return out
}

// The forms whose contents are expensive to retype declare what would be
// lost, so the prompt can name it. Asserted server-side because the guard is an
// attribute on rendered markup — the JS half is only reachable through it.
func TestCostlyFormsDeclareWhatWouldBeLost(t *testing.T) {
	ts, client, _ := newTestServer(t)
	login(t, client, ts.URL)

	_, browse := getBody(t, client, ts.URL+"/db/main/table/widgets")
	tok := regexp.MustCompile(`where=([A-Za-z0-9_-]+)`).FindStringSubmatch(browse)
	if tok == nil {
		t.Fatalf("no row token on the browse page")
	}

	for _, tc := range []struct{ path, want string }{
		{"/db/main/sql", "the SQL you typed"},
		{"/db/main/table/widgets/insert", "your changes to this row"},
		{"/db/main/table/widgets/edit?where=" + tok[1], "your changes to this row"},
		{"/db/main/create-table", "the table you were defining"},
	} {
		code, body := getBody(t, client, ts.URL+tc.path)
		if code != http.StatusOK {
			t.Errorf("GET %s = %d, want 200", tc.path, code)
			continue
		}
		if !strings.Contains(body, `data-tx-guard="`+tc.want+`"`) {
			t.Errorf("%s: form is not guarded with %q — leaving the page would "+
				"discard it silently", tc.path, tc.want)
		}
	}

	// Negative control: a page with nothing costly on it must NOT be guarded, or
	// the prompt appears where nothing is at stake and gets dismissed unread.
	if _, body := getBody(t, client, ts.URL+"/db/main/table/widgets"); strings.Contains(body, "data-tx-guard") {
		t.Error("the browse page carries an unsaved-changes guard; its controls are " +
			"navigation, not work")
	}
}

// The live region has to exist in the shell BEFORE the text lands in it, and
// must not be inside the swapped region — a region replaced by the same swap that
// fills it is a region no screen reader watches.
func TestLiveRegionIsPermanentAndOutsideTheSwap(t *testing.T) {
	ts, client, _ := newTestServer(t)
	login(t, client, ts.URL)

	const page = "/db/main/table/widgets"
	code, full := getBody(t, client, ts.URL+page)
	if code != http.StatusOK {
		t.Fatalf("GET %s = %d, want 200", page, code)
	}
	if n := strings.Count(full, `id="tx-announce"`); n != 1 {
		t.Errorf("full page has %d live regions, want exactly 1", n)
	}
	for _, attr := range []string{`aria-live="polite"`, `aria-atomic="true"`, `role="status"`} {
		if !strings.Contains(full, attr) {
			t.Errorf("the live region is missing %s", attr)
		}
	}
	if frag := fragmentBody(t, client, ts.URL+page); strings.Contains(frag, "tx-announce") {
		t.Error("the live region is inside the htmx fragment; a swap would replace " +
			"the very region it is meant to announce into")
	}
}
