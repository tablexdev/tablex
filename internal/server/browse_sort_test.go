package server_test

// Multi-column sort, end to end. The unit tests in internal/server/handlers pin
// the URL algebra; these pin that a two-key sort actually reaches the ORDER BY
// — which only shows up as ROW ORDER, so that is what they assert.

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"github.com/tablexdev/tablex/internal/driver"
)

// cellRE pulls the rendered data cells out of a browse grid, in row order.
var cellRE = regexp.MustCompile(`<td class="tx-cell[^"]*">(?:<em[^>]*>NULL</em>|<span[^>]*>([^<]*)</span>|([^<]*))</td>`)

// browseCells returns the grid's cell text in document order.
func browseCells(t *testing.T, body string) []string {
	t.Helper()
	var out []string
	for _, m := range cellRE.FindAllStringSubmatch(body, -1) {
		v := m[1] + m[2]
		out = append(out, strings.TrimSpace(v))
	}
	return out
}

// seedSortRows replaces the widgets fixture with rows whose single-column and
// two-column orderings genuinely differ. Without that, a test "passes" no
// matter which keys reached the ORDER BY.
func seedSortRows(t *testing.T, path string) {
	t.Helper()
	d, _ := driver.Get("sqlite")
	conn, err := driver.Open(context.Background(), d, driver.ConnParams{FilePath: path})
	if err != nil {
		t.Fatalf("seed open: %v", err)
	}
	defer conn.Close()
	for _, s := range []string{
		`DELETE FROM widgets`,
		// name ascending alone gives a,a,b,b — the qty key is what decides
		// within each name, and it decides differently ascending vs descending.
		`INSERT INTO widgets (id, name, qty) VALUES (1,'a',2), (2,'a',1), (3,'b',2), (4,'b',1)`,
	} {
		if _, err := conn.Exec(context.Background(), s); err != nil {
			t.Fatalf("seed %q: %v", s, err)
		}
	}
}

// seedManyRows fills widgets so a page-size of 25 leaves a next page, which is
// what makes the pagination links render as links rather than disabled spans.
func seedManyRows(t *testing.T, path string, n int) {
	t.Helper()
	d, _ := driver.Get("sqlite")
	conn, err := driver.Open(context.Background(), d, driver.ConnParams{FilePath: path})
	if err != nil {
		t.Fatalf("seed open: %v", err)
	}
	defer conn.Close()
	ctx := context.Background()
	if _, err := conn.Exec(ctx, `DELETE FROM widgets`); err != nil {
		t.Fatalf("seed clear: %v", err)
	}
	for i := range n {
		if _, err := conn.Exec(ctx, fmt.Sprintf(
			`INSERT INTO widgets (id, name, qty) VALUES (%d, 'n%d', %d)`, i+1, i%5, i)); err != nil {
			t.Fatalf("seed row %d: %v", i, err)
		}
	}
}

// TestBrowseMultiColumnSort is the point of the feature: ORDER BY name, qty and
// ORDER BY name, qty DESC must produce different row orders, and both must
// differ from ORDER BY name alone.
func TestBrowseMultiColumnSort(t *testing.T) {
	ts, client, path := newTestServer(t)
	seedSortRows(t, path)
	login(t, client, ts.URL)

	// id is the first column, so its cell sequence identifies the row order.
	ids := func(q string) string {
		t.Helper()
		code, body := getBody(t, client, ts.URL+"/db/main/table/widgets"+q)
		if code != http.StatusOK {
			t.Fatalf("browse%s = %d, want 200", q, code)
		}
		cells := browseCells(t, body)
		var out []string
		for i := 0; i+2 < len(cells)+1 && i < len(cells); i += 3 {
			out = append(out, cells[i])
		}
		return strings.Join(out, ",")
	}

	asc := ids("?order=name&dir=asc&order=qty&dir=asc")
	desc := ids("?order=name&dir=asc&order=qty&dir=desc")
	if asc != "2,1,4,3" {
		t.Errorf("ORDER BY name, qty gave %q, want 2,1,4,3", asc)
	}
	if desc != "1,2,3,4" {
		t.Errorf("ORDER BY name, qty DESC gave %q, want 1,2,3,4", desc)
	}
	if asc == desc {
		t.Error("the second sort key did not reach the query")
	}
}

// TestBrowseSortLinksCarryEveryKey — the rendered page must let a user keep
// browsing without silently losing a key. Every link is checked, because it
// only takes one that forgets.
func TestBrowseSortLinksCarryEveryKey(t *testing.T) {
	ts, client, path := newTestServer(t)
	seedManyRows(t, path, 60) // enough for a second page at the smallest option
	login(t, client, ts.URL)

	code, body := getBody(t, client, ts.URL+
		"/db/main/table/widgets?rows=25&order=name&dir=asc&order=qty&dir=desc")
	if code != http.StatusOK {
		t.Fatalf("browse = %d, want 200", code)
	}
	// The summary tells the user what is active.
	if !strings.Contains(body, "name, then qty DESC") {
		t.Errorf("no sort summary:\n%.1500s", body)
	}
	// The PAGINATION links are the ones that must preserve the sort verbatim.
	// The header and "add key" links deliberately rewrite it, and are
	// identified here by their aria-label rather than by their query string —
	// a sort-changing link also carries pos=0, so the query cannot tell them
	// apart.
	navRE := regexp.MustCompile(`href="(/db/main/table/widgets\?[^"]*)"[^>]*aria-label="(?:First|Previous|Next|Last) page"`)
	found := 0
	for _, m := range navRE.FindAllStringSubmatch(body, -1) {
		u := strings.ReplaceAll(m[1], "&amp;", "&")
		found++
		if strings.Count(u, "order=") != 2 {
			t.Errorf("pagination link dropped a sort key: %s", u)
		}
	}
	if found == 0 {
		t.Fatalf("no pagination links were checked; the assertion is vacuous:\n%.2000s", body)
	}
	// The page-size form carries the sort as hidden inputs, so changing it
	// without JavaScript keeps the ordering.
	if strings.Count(body, `<input type="hidden" name="order"`) != 2 {
		t.Errorf("the page-size form does not carry both sort keys:\n%.1500s", body)
	}
}

// TestBrowseSortRejectsUnknownColumn — a stale or hostile ?order must not reach
// the quoting layer; the page still renders, unsorted.
func TestBrowseSortRejectsUnknownColumn(t *testing.T) {
	ts, client, _ := newTestServer(t)
	login(t, client, ts.URL)

	for _, q := range []string{
		"?order=nope",
		"?order=name%3B+DROP+TABLE+widgets",
		"?order=(SELECT+1)",
		"?order=name&order=nope&dir=asc&dir=asc",
	} {
		code, body := getBody(t, client, ts.URL+"/db/main/table/widgets"+q)
		if code != http.StatusOK {
			t.Errorf("browse%s = %d, want 200 (an unknown key is dropped, not refused)", q, code)
			continue
		}
		if strings.Contains(body, "DROP TABLE") {
			t.Errorf("browse%s echoed the injection attempt", q)
		}
	}
	// The table is still there.
	if code, _ := getBody(t, client, ts.URL+"/db/main/table/widgets"); code != http.StatusOK {
		t.Fatal("widgets is gone")
	}
}

// TestBrowseShowAll: rows=all replaces the page size with one bounded fetch,
// suppresses the pager, and — crucially — is NOT remembered as the session's
// page size. One look at everything must not make every later table load
// everything.
func TestBrowseShowAll(t *testing.T) {
	ts, client, path := newTestServer(t)
	seedManyRows(t, path, 60)
	login(t, client, ts.URL)

	code, body := getBody(t, client, ts.URL+"/db/main/table/widgets?rows=25")
	if code != http.StatusOK {
		t.Fatalf("browse = %d", code)
	}
	if !strings.Contains(body, "Show all") {
		t.Error("the Show all control is missing")
	}
	if n := strings.Count(body, `class="tx-row"`); n != 25 {
		t.Errorf("paginated page rendered %d rows, want 25", n)
	}

	code, body = getBody(t, client, ts.URL+"/db/main/table/widgets?rows=all")
	if code != http.StatusOK {
		t.Fatalf("show all = %d", code)
	}
	if n := strings.Count(body, `class="tx-row"`); n != 60 {
		t.Errorf("Show all rendered %d rows, want all 60", n)
	}
	// No pager: there is no page to be on.
	if strings.Contains(body, `aria-label="Next page"`) {
		t.Error("Show all still renders pagination")
	}
	if !strings.Contains(body, "Paginate") {
		t.Error("Show all does not offer a way back to pagination")
	}

	// Back to a normal browse: the remembered page size is still 25, not "all".
	_, body = getBody(t, client, ts.URL+"/db/main/table/widgets")
	if n := strings.Count(body, `class="tx-row"`); n != 25 {
		t.Errorf("after Show all the default page rendered %d rows; the session page size was clobbered", n)
	}
}

// TestBrowseSortByKey — every index becomes a ready-made multi-column sort.
// This is the payoff from the sort being a key list: a composite index could
// previously have been offered only as its first column.
func TestBrowseSortByKey(t *testing.T) {
	ts, client, path := newTestServer(t)
	seedSortRows(t, path)
	execSQLite(t, path, `CREATE INDEX idx_name_qty ON widgets (name, qty DESC)`)
	login(t, client, ts.URL)

	code, body := getBody(t, client, ts.URL+"/db/main/table/widgets")
	if code != http.StatusOK {
		t.Fatalf("browse = %d", code)
	}
	if !strings.Contains(body, "Sort by key") {
		t.Fatalf("the sort-by-key control is missing:\n%.2000s", body)
	}
	// The option must describe what the key actually does, both columns.
	if !strings.Contains(body, "idx_name_qty (name, then qty DESC)") {
		t.Errorf("the index option does not describe its full key order:\n%.2000s", body)
	}
	// And its URL must carry BOTH keys, not just the leading column.
	m := regexp.MustCompile(`<option value="([^"]*order=[^"]*)"[^>]*>idx_name_qty`).FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no URL for idx_name_qty:\n%.2000s", body)
	}
	u := strings.ReplaceAll(m[1], "&amp;", "&")
	if strings.Count(u, "order=") != 2 {
		t.Errorf("sort-by-key URL carries %d keys, want 2: %s", strings.Count(u, "order="), u)
	}
	// Following it produces the index's order.
	code, body = getBody(t, client, ts.URL+u)
	if code != http.StatusOK {
		t.Fatalf("sort by key = %d", code)
	}
	if !strings.Contains(body, "name, then qty DESC") {
		t.Errorf("following the key did not apply its order:\n%.1500s", body)
	}
}

// TestBrowseColumnVisibility: hiding is presentational. The column disappears
// from the grid but the row keeps its identity — a hidden PRIMARY KEY must not
// cost a row its Edit/Copy/Delete links, which is exactly what filtering the
// SELECT instead of the render would have done.
func TestBrowseColumnVisibility(t *testing.T) {
	ts, client, _ := newTestServer(t)
	login(t, client, ts.URL)

	_, body := getBody(t, client, ts.URL+"/db/main/table/widgets")
	if !strings.Contains(body, `aria-label="Hide column qty"`) {
		t.Fatalf("no hide affordance:\n%.1500s", body)
	}
	editLinks := strings.Count(body, `aria-label="Edit row `)
	if editLinks == 0 {
		t.Fatal("no edit links to begin with")
	}

	// Hide the PRIMARY KEY, the worst case.
	_, body = getBody(t, client, ts.URL+"/db/main/table/widgets?hide=id")
	if strings.Contains(body, `aria-label="Hide column id"`) {
		t.Error("the hidden column still has a header")
	}
	if !strings.Contains(body, `aria-label="Show column id"`) {
		t.Error("no way to bring the hidden column back")
	}
	if !strings.Contains(body, "Show all columns") {
		t.Error("no restore-everything link")
	}
	if got := strings.Count(body, `aria-label="Edit row `); got != editLinks {
		t.Errorf("hiding the primary key cost %d edit links; hiding must be presentational",
			editLinks-got)
	}
	// The value is gone from the grid but the row is still addressable.
	if !strings.Contains(body, "bolt") {
		t.Error("the remaining columns stopped rendering")
	}

	// Hiding every column is refused: a grid with no columns is not a view of
	// anything, and there would be no header left to click to get one back.
	_, body = getBody(t, client, ts.URL+"/db/main/table/widgets?hide=id&hide=name&hide=qty")
	if !strings.Contains(body, "bolt") && !strings.Contains(body, `class="tx-tbl-name"`) {
		if strings.Count(body, `class="column_heading`) == 0 {
			t.Error("every column was hidden; at least one must survive")
		}
	}
	if n := strings.Count(body, `class="column_heading`); n < 1 {
		t.Errorf("%d columns visible, want at least 1", n)
	}

	// An unknown column is dropped rather than 400ing a bookmarked link.
	if code, _ := getBody(t, client, ts.URL+"/db/main/table/widgets?hide=nope"); code != http.StatusOK {
		t.Errorf("hide=nope = %d, want 200", code)
	}
}
