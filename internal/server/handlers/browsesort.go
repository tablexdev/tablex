// Browse sort: parsing the order/dir query pair into a validated key list, and
// building the links that manipulate it. Everything here operates on
// url.Values and []model.Column — no request, no ResponseWriter — so the URL
// algebra is testable on its own, which matters because a browse URL that
// loses part of the sort loses it silently.

package handlers

import (
	"net/url"
	"strconv"
	"strings"

	"github.com/tablexdev/tablex/internal/driver"
	"github.com/tablexdev/tablex/internal/model"
)

// sortKeyOption is one entry in the "Sort by key" select: an index, and the URL
// that sorts by exactly the columns it covers.
type sortKeyOption struct {
	Name     string
	Columns  string // "name, qty DESC" — what sorting by this key actually does
	URL      string
	Selected bool
}

// maxSortKeys bounds the sort key list. The cap is not an engine limit — it is
// what keeps a hand-written URL from turning one page render into an ORDER BY
// over a hundred columns. Four is past the point where an extra key changes any
// real result set.
const maxSortKeys = 4

// parseSorts reads the repeated order/dir pair into a validated key list, in
// the order the URL gives them: ?order=a&dir=asc&order=b&dir=desc sorts by a,
// then b descending.
//
// Every column is matched exactly against introspection, so nothing that is not
// a real column reaches the quoting layer. An unknown column is DROPPED rather
// than refused: a browse link is easy to keep after a column is renamed, and
// silently sorting by what remains beats a 400 on a page the user can still
// read. A repeated column is dropped too — "ORDER BY a, a" is never what was
// meant, and keeping the first occurrence preserves the user's intended
// precedence.
func parseSorts(q url.Values, cols []model.Column) []driver.Sort {
	orders, dirs := q["order"], q["dir"]
	var out []driver.Sort
	seen := map[string]bool{}
	for i, name := range orders {
		if len(out) == maxSortKeys {
			break
		}
		if name == "" || seen[name] || !columnExists(cols, name) {
			continue
		}
		seen[name] = true
		desc := i < len(dirs) && dirs[i] == "desc"
		out = append(out, driver.Sort{Column: name, Descending: desc})
	}
	return out
}

// sortParams renders a key list back into query parameters. It is the single
// place that spelling lives, so a pagination link, a page-size change and a
// header link cannot disagree about how the sort is encoded.
func sortParams(sorts []driver.Sort) url.Values {
	q := url.Values{}
	for _, s := range sorts {
		q.Add("order", s.Column)
		q.Add("dir", sortDirOf(s))
	}
	return q
}

func sortDirOf(s driver.Sort) string {
	if s.Descending {
		return "desc"
	}
	return "asc"
}

// browseQuery is the state every browse link carries: where you are, how many
// rows, how you are sorting, and whether the count is exact. Building links
// through one struct is what stopped the sort from being dropped by whichever
// link forgot to re-add it.
type browseQuery struct {
	Pos   int64
	Rows  int
	Sorts []driver.Sort
	Exact bool
	// ShowAll replaces the page size with "as many rows as we are willing to
	// render at once" (the classic "Show all"). It is spelled rows=all rather
	// than a huge number so it cannot be confused with a page size, and it is
	// never persisted as the session's rows-per-page — one look at everything
	// should not make every later table load everything.
	ShowAll bool
	// Hidden are columns the grid does not render. This is PRESENTATIONAL only
	// — the query stays SELECT * — because the row-identity token is built from
	// the key columns' values, so a hidden primary key would otherwise take
	// every Edit, Copy and Delete link with it.
	Hidden []string
}

// showAllRowCap bounds "Show all". Without a ceiling the control would be an
// invitation to pull a ten-million-row table into one page; with it, the grid
// reports the truncation the same way any other capped result does.
const showAllRowCap = 10000

// showAllByteBudget bounds the cumulative retained TEXT of one "Show all" page,
// independent of the row cap. The row cap alone no longer holds: MaxCellBytes
// was sized against "a 500-row page" (result.go), but Show all raises the row
// ceiling 20x to showAllRowCap, so 10 000 rows of wide text could retain far
// more than that sizing assumed. 64 MiB bounds one page's retained text
// regardless of row/column shape — a generous ~6.5 KiB per row at the 10 000-row
// cap, so it bites only on genuinely large text. It is whole-ROW (see
// driver.Pagination.ByteBudget): a single row larger than the whole budget is
// kept anyway rather than rendering an empty grid, so the budget is a soft
// ceiling that always shows at least one row.
const showAllByteBudget = 64 << 20 // 64 MiB

// rowsParam renders the rows= value for this state.
func (b browseQuery) rowsParam() string {
	if b.ShowAll {
		return "all"
	}
	return strconv.Itoa(b.Rows)
}

// values renders the whole browse state, with the caller's overrides applied
// last. Overrides use Set, so a single-valued key replaces cleanly; the sort is
// multi-valued and is therefore never overridden this way — callers pass a
// different Sorts instead.
func (b browseQuery) values(override url.Values) url.Values {
	q := sortParams(b.Sorts)
	for _, h := range b.Hidden {
		q.Add("hide", h)
	}
	q.Set("pos", strconv.FormatInt(b.Pos, 10))
	q.Set("rows", b.rowsParam())
	if b.Exact {
		q.Set("exact", "1")
	}
	for k, vs := range override {
		q.Del(k)
		for _, v := range vs {
			q.Add(k, v)
		}
	}
	return q
}

// withSorts returns a copy sorting by the given keys, back at the first page.
// Changing the order invalidates the offset: row 500 of one ordering has
// nothing to do with row 500 of another, and staying put would look like the
// data changed.
func (b browseQuery) withSorts(sorts []driver.Sort) browseQuery {
	b.Sorts, b.Pos = sorts, 0
	return b
}

// primarySortToggle returns the key list for clicking column name as the SOLE
// sort key: descending if it is already the ascending primary, ascending
// otherwise. This is the plain "sort by this column" click, and it deliberately
// discards the other keys — the append affordance is the separate link.
func primarySortToggle(sorts []driver.Sort, name string) []driver.Sort {
	desc := false
	if len(sorts) > 0 && sorts[0].Column == name && !sorts[0].Descending {
		desc = true
	}
	return []driver.Sort{{Column: name, Descending: desc}}
}

// appendSortKey returns the key list with name added as the LAST key, or — if
// it is already in the list — with that key's direction flipped in place. The
// second case is what makes a multi-key sort adjustable at all: without it the
// only way to reverse the second key would be to rebuild the whole sort.
func appendSortKey(sorts []driver.Sort, name string) []driver.Sort {
	out := make([]driver.Sort, len(sorts))
	copy(out, sorts)
	for i := range out {
		if out[i].Column == name {
			out[i].Descending = !out[i].Descending
			return out
		}
	}
	if len(out) >= maxSortKeys {
		return out
	}
	return append(out, driver.Sort{Column: name})
}

// sortRankOf returns the 1-based position of name in the key list, and whether
// it is sorted descending. rank 0 means "not a sort key".
func sortRankOf(sorts []driver.Sort, name string) (rank int, desc bool) {
	for i, s := range sorts {
		if s.Column == name {
			return i + 1, s.Descending
		}
	}
	return 0, false
}

// sortsForIndex turns an index into the sort key list that reproduces its
// order: its key columns, in key order, each carrying the direction the index
// itself declares. Expression key parts are skipped — the browse sort addresses
// columns by name, and there is no column to name for an expression — so an
// index that is entirely expressions yields nothing and is not offered.
//
// This is what makes "sort by key" nearly free now that the sort is a LIST: a
// composite index IS a multi-column sort, and before that it could only ever
// have been approximated by its first column.
func sortsForIndex(idx model.Index, cols []model.Column) []driver.Sort {
	var out []driver.Sort
	for _, c := range idx.Columns {
		if c.Name == "" || !columnExists(cols, c.Name) {
			return nil // an expression or a stale key part: offer nothing rather than a partial order
		}
		if len(out) == maxSortKeys {
			break
		}
		out = append(out, driver.Sort{Column: c.Name, Descending: c.Descending})
	}
	return out
}

// parseHidden reads the repeated hide= parameter into a validated set of
// column names. Unknown names are dropped (a bookmarked link outlives a
// renamed column), duplicates collapse, and the LAST column can never be
// hidden — a grid with no columns is not a view of anything, and the user
// would have no header left to click to get one back.
func parseHidden(q url.Values, cols []model.Column) []string {
	seen := map[string]bool{}
	var out []string
	for _, name := range q["hide"] {
		if name == "" || seen[name] || !columnExists(cols, name) {
			continue
		}
		if len(out)+1 >= len(cols) {
			break // keep at least one column visible
		}
		seen[name] = true
		out = append(out, name)
	}
	return out
}

// withHidden returns a copy hiding exactly these columns. Unlike a sort change
// this keeps the offset: hiding a column does not reorder anything, so the
// user stays on the page they were reading.
func (b browseQuery) withHidden(hidden []string) browseQuery {
	b.Hidden = hidden
	return b
}

// hidePlus returns the hidden set with name added; hideMinus, with it removed.
// Both copy, because the caller builds one link per column from the same slice.
func hidePlus(hidden []string, name string) []string {
	out := make([]string, 0, len(hidden)+1)
	out = append(out, hidden...)
	return append(out, name)
}

func hideMinus(hidden []string, name string) []string {
	out := make([]string, 0, len(hidden))
	for _, h := range hidden {
		if h != name {
			out = append(out, h)
		}
	}
	return out
}

func isHidden(hidden []string, name string) bool {
	for _, h := range hidden {
		if h == name {
			return true
		}
	}
	return false
}

// sortKeyOptions builds the "Sort by key" choices from the table's indexes.
// Indexes whose key parts cannot be expressed as column sorts are skipped, and
// so is the one whose order is already active (it is marked Selected instead).
func sortKeyOptions(sc reqScope, bq browseQuery, idxs []model.Index, cols []model.Column, active []driver.Sort) []sortKeyOption {
	var out []sortKeyOption
	for _, idx := range idxs {
		keys := sortsForIndex(idx, cols)
		if len(keys) == 0 {
			continue
		}
		out = append(out, sortKeyOption{
			Name:     idx.Name,
			Columns:  sortSummary(keys),
			URL:      browseURL(sc, bq.withSorts(keys).values(nil)),
			Selected: sameSorts(active, keys),
		})
	}
	return out
}

// sameSorts reports whether two key lists are identical, column and direction.
func sameSorts(a, b []driver.Sort) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// sortSummary describes the active sort for the browse toolbar, e.g.
// "name, then qty DESC". Empty when nothing is sorted.
func sortSummary(sorts []driver.Sort) string {
	if len(sorts) == 0 {
		return ""
	}
	parts := make([]string, 0, len(sorts))
	for _, s := range sorts {
		p := s.Column
		if s.Descending {
			p += " DESC"
		}
		parts = append(parts, p)
	}
	return strings.Join(parts, ", then ")
}
