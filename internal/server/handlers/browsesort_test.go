package handlers

// Browse sort algebra. Two properties matter and neither is visible from a
// rendered page: that a hostile or stale ?order never reaches the quoting
// layer, and that every browse link carries the WHOLE sort — the bug this
// replaced was client-side URL assembly that could only round-trip one key.

import (
	"net/url"
	"strings"
	"testing"

	"github.com/tablexdev/tablex/internal/driver"
	"github.com/tablexdev/tablex/internal/model"
)

var sortCols = []model.Column{{Name: "id"}, {Name: "name"}, {Name: "qty"}, {Name: "tag"}, {Name: "extra"}}

func sortKey(sorts []driver.Sort) string {
	parts := make([]string, len(sorts))
	for i, s := range sorts {
		parts[i] = s.Column + ":" + sortDirOf(s)
	}
	return strings.Join(parts, ",")
}

func TestParseSorts(t *testing.T) {
	for _, tc := range []struct {
		name string
		q    url.Values
		want string
	}{
		{"none", url.Values{}, ""},
		{"single", url.Values{"order": {"name"}, "dir": {"asc"}}, "name:asc"},
		{"single desc", url.Values{"order": {"name"}, "dir": {"desc"}}, "name:desc"},
		// The pair is positional: the Nth dir belongs to the Nth order.
		{"two keys", url.Values{"order": {"name", "qty"}, "dir": {"asc", "desc"}}, "name:asc,qty:desc"},
		{"order preserved", url.Values{"order": {"qty", "name"}, "dir": {"desc", "asc"}}, "qty:desc,name:asc"},
		// A missing dir defaults to ascending rather than shifting the pairing.
		{"missing dirs", url.Values{"order": {"name", "qty"}, "dir": {"desc"}}, "name:desc,qty:asc"},
		{"no dirs at all", url.Values{"order": {"name", "qty"}}, "name:asc,qty:asc"},
		// An unknown column is DROPPED, not refused: a bookmarked link outlives
		// a renamed column, and the rest of the sort is still meaningful.
		{"unknown dropped", url.Values{"order": {"nope", "qty"}, "dir": {"asc", "asc"}}, "qty:asc"},
		{"all unknown", url.Values{"order": {"nope"}}, ""},
		{"empty name", url.Values{"order": {"", "qty"}}, "qty:asc"},
		// ORDER BY a, a is never what was meant; the FIRST occurrence wins, so
		// the user's intended precedence survives.
		{"duplicate dropped", url.Values{"order": {"qty", "qty"}, "dir": {"desc", "asc"}}, "qty:desc"},
		// Injection attempts are simply not columns.
		{"injection", url.Values{"order": {"id; DROP TABLE t", "id) --"}}, ""},
		{"dir garbage means asc", url.Values{"order": {"id"}, "dir": {"'; DROP"}}, "id:asc"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := sortKey(parseSorts(tc.q, sortCols)); got != tc.want {
				t.Errorf("parseSorts = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestParseSortsCap: a hand-written URL must not turn one page render into an
// ORDER BY over an unbounded key list.
func TestParseSortsCap(t *testing.T) {
	q := url.Values{"order": {"id", "name", "qty", "tag", "extra"}}
	got := parseSorts(q, sortCols)
	if len(got) != maxSortKeys {
		t.Errorf("got %d keys, want the cap of %d", len(got), maxSortKeys)
	}
	// The cap keeps the FIRST keys — the most significant ones.
	if got[0].Column != "id" {
		t.Errorf("the cap dropped from the wrong end: %v", sortKey(got))
	}
}

func TestPrimarySortToggle(t *testing.T) {
	// Clicking an unsorted column sorts by it ascending, alone.
	if got := sortKey(primarySortToggle(nil, "name")); got != "name:asc" {
		t.Errorf("first click = %q", got)
	}
	// Clicking the ascending primary reverses it.
	asc := []driver.Sort{{Column: "name"}}
	if got := sortKey(primarySortToggle(asc, "name")); got != "name:desc" {
		t.Errorf("second click = %q", got)
	}
	// Clicking the descending primary goes back to ascending (a 2-state toggle).
	desc := []driver.Sort{{Column: "name", Descending: true}}
	if got := sortKey(primarySortToggle(desc, "name")); got != "name:asc" {
		t.Errorf("third click = %q", got)
	}
	// Clicking a DIFFERENT column replaces the whole sort — the append
	// affordance is the other link.
	multi := []driver.Sort{{Column: "name"}, {Column: "qty", Descending: true}}
	if got := sortKey(primarySortToggle(multi, "qty")); got != "qty:asc" {
		t.Errorf("clicking a secondary key = %q; it must become the sole key", got)
	}
	// And a column that is currently the DESCENDING secondary still starts
	// ascending as a new primary: the toggle keys on the primary alone.
	if got := sortKey(primarySortToggle(multi, "tag")); got != "tag:asc" {
		t.Errorf("clicking an unsorted column = %q", got)
	}
}

func TestAppendSortKey(t *testing.T) {
	base := []driver.Sort{{Column: "name"}}
	if got := sortKey(appendSortKey(base, "qty")); got != "name:asc,qty:asc" {
		t.Errorf("append = %q", got)
	}
	// Appending a key already in the list FLIPS it in place — otherwise a
	// secondary key's direction would be unreachable.
	two := []driver.Sort{{Column: "name"}, {Column: "qty"}}
	if got := sortKey(appendSortKey(two, "qty")); got != "name:asc,qty:desc" {
		t.Errorf("flip secondary = %q", got)
	}
	if got := sortKey(appendSortKey(two, "name")); got != "name:desc,qty:asc" {
		t.Errorf("flip primary = %q", got)
	}
	// The input must not be mutated: the caller builds one URL per column from
	// the same slice, so an in-place append would corrupt every later link.
	before := sortKey(base)
	_ = appendSortKey(base, "qty")
	if sortKey(base) != before {
		t.Errorf("appendSortKey mutated its input: %q → %q", before, sortKey(base))
	}
	// The cap applies here too, and a full list is returned unchanged rather
	// than silently dropping the oldest key.
	full := []driver.Sort{{Column: "id"}, {Column: "name"}, {Column: "qty"}, {Column: "tag"}}
	if got := sortKey(appendSortKey(full, "extra")); got != sortKey(full) {
		t.Errorf("appending past the cap = %q, want it unchanged", got)
	}
}

// TestBrowseQueryCarriesEveryKey is the regression the whole file exists for: a
// link that changes the page must not quietly reduce a two-key sort to one.
func TestBrowseQueryCarriesEveryKey(t *testing.T) {
	bq := browseQuery{
		Pos:   50,
		Rows:  25,
		Sorts: []driver.Sort{{Column: "name"}, {Column: "qty", Descending: true}},
		Exact: true,
	}
	q := bq.values(url.Values{"pos": {"75"}})
	if got := sortKey(parseSorts(q, sortCols)); got != "name:asc,qty:desc" {
		t.Errorf("the sort did not survive a pagination link: %q", got)
	}
	if q.Get("pos") != "75" {
		t.Errorf("pos override = %q", q.Get("pos"))
	}
	if q.Get("rows") != "25" || q.Get("exact") != "1" {
		t.Errorf("rows/exact lost: %v", q)
	}
	// Round-tripping through an encoded URL keeps the pairing.
	parsed, err := url.ParseQuery(q.Encode())
	if err != nil {
		t.Fatalf("encode/parse: %v", err)
	}
	if got := sortKey(parseSorts(parsed, sortCols)); got != "name:asc,qty:desc" {
		t.Errorf("encoding scrambled the sort: %q", got)
	}
}

// TestBrowseQueryWithSortsResetsPosition — row 500 of one ordering has nothing
// to do with row 500 of another, so changing the sort must return to page one.
func TestBrowseQueryWithSortsResetsPosition(t *testing.T) {
	bq := browseQuery{Pos: 500, Rows: 25}
	got := bq.withSorts([]driver.Sort{{Column: "name"}})
	if got.Pos != 0 {
		t.Errorf("changing the sort left the offset at %d", got.Pos)
	}
	if got.Rows != 25 {
		t.Errorf("withSorts clobbered the page size: %d", got.Rows)
	}
	// The receiver is a value: the original is untouched.
	if bq.Pos != 500 || len(bq.Sorts) != 0 {
		t.Error("withSorts mutated its receiver")
	}
}

func TestSortRankAndSummary(t *testing.T) {
	sorts := []driver.Sort{{Column: "name"}, {Column: "qty", Descending: true}}
	if r, d := sortRankOf(sorts, "name"); r != 1 || d {
		t.Errorf("name rank = %d, desc = %v", r, d)
	}
	if r, d := sortRankOf(sorts, "qty"); r != 2 || !d {
		t.Errorf("qty rank = %d, desc = %v", r, d)
	}
	if r, _ := sortRankOf(sorts, "tag"); r != 0 {
		t.Errorf("an unsorted column has rank %d, want 0", r)
	}
	if got := sortSummary(sorts); got != "name, then qty DESC" {
		t.Errorf("summary = %q", got)
	}
	if got := sortSummary(nil); got != "" {
		t.Errorf("empty summary = %q", got)
	}
}
