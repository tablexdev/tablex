package handlers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"math"
	"net/http"
	"net/url"
	"strconv"

	"github.com/tablexdev/tablex/internal/driver"
	"github.com/tablexdev/tablex/internal/model"
	"github.com/tablexdev/tablex/internal/view"
)

// rowsPerPageOptions is the classic page-size ladder.
var rowsPerPageOptions = []int{25, 50, 100, 250, 500}

// maxBrowseOffset bounds the OFFSET when the row count is unknown (CountRows
// failed), so a hostile ?pos cannot push the engine into scanning an unbounded
// prefix of a table.
const maxBrowseOffset = 1_000_000

// clampBrowsePos bounds a requested browse position (attacker-controlled up
// to MaxInt64 via ?pos): never negative, snapped to the last page start when
// the EXACT total is known, and capped at maxBrowseOffset when it is not (so
// a hostile position cannot drive an unbounded scan). An approximate total is
// treated like an unknown one — a statistics estimate is often an undercount,
// and snapping to its "last page" would make the real tail rows unreachable.
// Rows beyond maxBrowseOffset stay reachable via the exact-count link: this is
// a deliberate safety trade-off, since a hostile ?pos must never drive an
// unbounded offset scan. All int64: a 32-bit build must not truncate a >2^31
// position into a negative offset.
func clampBrowsePos(total int64, approx bool, pos int64, limit int) int64 {
	switch {
	case pos < 0:
		return 0
	case total < 0 || approx:
		return min(pos, maxBrowseOffset)
	case total == 0:
		return 0
	case pos >= total:
		return ((total - 1) / int64(limit)) * int64(limit)
	}
	return pos
}

// browseNav is the derived pagination state for one browse render. Every form
// avoids overflow even at MaxInt64 positions: the page count by quotient
// ((total-1)/limit + 1, never total+limit-1), the has-next test by
// subtraction (never offset+limit), and the next position by saturating
// addition. Last is (Pages-1)*limit ≤ total-1, which cannot overflow.
type browseNav struct {
	Pages, Page             int64
	HasPrev, HasNext        bool
	First, Prev, Next, Last int64
}

// browseNavFor derives the navigation state from an already-clamped offset.
// hasMore is the probe result (the +1 fetch, run when the total is unknown OR
// approximate): when set it is the definitive has-next answer — an estimate
// that undercounts must not hide real tail rows behind a disabled Next link.
// The estimate still drives the approximate page-count display (Pages/Last).
func browseNavFor(total, offset int64, limit int, approx, hasMore bool) browseNav {
	l := int64(limit)
	nav := browseNav{
		HasPrev: offset > 0,
		Prev:    max(0, offset-l),
		Next:    satAddInt64(offset, l),
	}
	if total < 0 {
		nav.HasNext = hasMore
		return nav
	}
	if total > 0 {
		nav.Pages = (total-1)/l + 1
		nav.Page = offset/l + 1
		nav.Last = (nav.Pages - 1) * l
	}
	if approx {
		nav.HasNext = hasMore
		return nav
	}
	nav.HasNext = total-offset > l
	return nav
}

// satAddInt64 returns a+b saturating at MaxInt64 (both non-negative).
func satAddInt64(a, b int64) int64 {
	if a > math.MaxInt64-b {
		return math.MaxInt64
	}
	return a + b
}

// clampRowsPerPage snaps a requested page size to the nearest allowed option,
// so a hostile, stale, or zero/negative value can neither request a huge page
// (memory/DoS) nor cause a divide-by-zero in the pagination math. The result is
// always one of rowsPerPageOptions.
func clampRowsPerPage(n int) int {
	if n <= 0 {
		return defaultRowsPerPage
	}
	best, bestDiff := rowsPerPageOptions[0], math.MaxInt // MaxInt, not 1<<62 (overflows a 32-bit int)
	for _, o := range rowsPerPageOptions {
		d := o - n
		if d < 0 {
			d = -d
		}
		if d < bestDiff {
			best, bestDiff = o, d
		}
	}
	return best
}

// tableRowCount resolves a relation's row count for display. Returns
// approx=true when total is an estimate or a lower bound rather than the exact
// figure, and total=-1 when no count could be obtained (permissions, a broken
// view).
//
// costly marks a relation whose count cannot be answered cheaply no matter how
// small it turns out to be, because COUNT(*) re-runs an arbitrary query: a
// VIEW. Every engine's EstimateRows returns -1 for one, and -1 fails the
// `est > max_exact_count` test exactly as a genuinely tiny table does — so the
// estimate branch never fired and every Browse and Structure render of a view
// paid a full, unbounded scan. Such a relation is counted with a ceiling
// instead, reported as approximate.
//
// The order of preference otherwise: the caller's explicit exact request wins
// (the one deliberate unbounded scan, reached through the "(count exact)"
// link); then a statistics estimate above the threshold; then a real COUNT(*),
// which the estimate has already shown to be cheap.
func (h *Handlers) tableRowCount(ctx context.Context, conn *driver.Connection, ref driver.TableRef, forceExact, costly bool) (total int64, approx bool) {
	exactCount := func() (int64, bool) {
		n, err := conn.CountRows(ctx, ref)
		if err != nil {
			return -1, false
		}
		return n, false
	}
	if forceExact || h.Cfg.MaxExactCount <= 0 {
		return exactCount()
	}
	max := int64(h.Cfg.MaxExactCount)
	est, err := conn.EstimateRows(ctx, ref)
	if err != nil {
		// Falling back is right — an unavailable estimate is not a failed page —
		// but it must not be silent. Without this, a broken statistics query and
		// a table that has simply never been ANALYZEd take the identical path,
		// and the degradation shows up only as a slow render nobody can explain.
		h.Log.Warn("row estimate unavailable, falling back to counting",
			"db", ref.Database, "schema", ref.Schema, "table", ref.Table, "err", err)
	}
	switch {
	case err == nil && est > max:
		return est, true
	case err == nil && est >= 0:
		return exactCount() // estimated small: the exact count is cheap
	}
	if !costly {
		// No estimate, but a plain heap/table scan — the pre-existing behavior,
		// and the only answer for engines that keep no statistics at all.
		return exactCount()
	}
	n, exact, err := conn.CountRowsBounded(ctx, ref, max)
	if err != nil {
		return -1, false
	}
	return n, !exact
}

// --- row identity --------------------------------------------------------------

// rowKeyEntry is one (column, value) pair identifying a row. A nil Val means the
// column is NULL. Encoded into an opaque token carried by Edit/Delete links; the
// receiving handler validates the columns against live introspection and binds
// the values as parameters, so this never becomes SQL injection.
type rowKeyEntry struct {
	Col string  `json:"c"`
	Val *string `json:"v"`
}

func encodeRowKey(entries []rowKeyEntry) string {
	b, _ := json.Marshal(entries)
	return base64.RawURLEncoding.EncodeToString(b)
}

func decodeRowKey(token string) ([]rowKeyEntry, error) {
	b, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return nil, err
	}
	var entries []rowKeyEntry
	if err := json.Unmarshal(b, &entries); err != nil {
		return nil, err
	}
	return entries, nil
}

// keyColumns returns the column names that identify a row: the primary key if
// present, otherwise all columns (best effort for keyless tables).
func keyColumns(cols []model.Column) []string {
	var pk []string
	for _, c := range cols {
		if c.IsPrimaryKey {
			pk = append(pk, c.Name)
		}
	}
	if len(pk) > 0 {
		return pk
	}
	all := make([]string, len(cols))
	for i, c := range cols {
		all[i] = c.Name
	}
	return all
}

// maxRowKeyLen caps the encoded row-identity token. A keyless table's token
// embeds every column value, so wide rows would otherwise inflate each render
// site (Edit/Copy links, delete buttons — 5 per row) and produce absurd URLs.
// The token cannot be hashed or truncated: the edit/delete handlers rebuild the
// parameterized WHERE from the decoded values, so it must stay invertible.
const maxRowKeyLen = 2048

// rowKeyFor builds the identity token for one result row, given the key column
// names and a name→cell lookup.
func rowKeyFor(keyCols []string, cellByName map[string]driver.Value) string {
	entries := make([]rowKeyEntry, 0, len(keyCols))
	for _, name := range keyCols {
		cell, ok := cellByName[name]
		if !ok {
			// A missing key column would build a PARTIAL key whose WHERE could match
			// several rows — fail safe: no token, so the row renders without (unsafe)
			// Edit/Copy/Delete actions rather than targeting the wrong row.
			return ""
		}
		// A binary cell only carries a "[BLOB N]" placeholder in Str, not the real
		// bytes, so it can't identify the row. Drop the key so the row renders
		// without (broken) Edit/Copy/Delete actions instead of targeting nothing.
		if cell.Binary {
			return ""
		}
		// A truncated cell holds only a PREFIX of the stored value (capCell cut it
		// at MaxCellBytes). Rebuilding a WHERE from a prefix could match a
		// different row sharing it, so degrade exactly as the binary case does.
		// Today MaxCellBytes (1 MiB) always exceeds maxRowKeyLen (2 KiB) so the
		// oversized-token check below would drop it anyway; this makes the reason
		// explicit and survives any future cap change.
		if cell.Truncated {
			return ""
		}
		e := rowKeyEntry{Col: name}
		if !cell.Null {
			v := cell.Str
			e.Val = &v
		}
		entries = append(entries, e)
	}
	token := encodeRowKey(entries)
	// Same degrade as the binary case: an oversized token (keyless table with
	// huge text values) drops the row's actions rather than ballooning the page.
	if len(token) > maxRowKeyLen {
		return ""
	}
	return token
}

// --- browse view model ---------------------------------------------------------

type browseCol struct {
	Name       string
	Numeric    bool
	IsPrimary  bool
	SortURL    string // sort by THIS column alone (toggling its direction)
	AddSortURL string // add it as a further key, or flip it if it already is one
	SortedAsc  bool
	SortedDesc bool
	// SortRank is the 1-based position in the sort key list, 0 when the column
	// is not sorted. MultiSorted is true only when more than one key is active,
	// so a single-column sort renders exactly as it always did.
	SortRank    int
	MultiSorted bool
	// HideURL removes this column from the grid. Empty when hiding it would
	// leave none visible.
	HideURL string
}

// browseHiddenCol is a column the grid is not showing, and the link that brings
// it back. Hidden columns are still SELECTed and still identify the row.
type browseHiddenCol struct {
	Name    string
	ShowURL string
}

// visibleCells drops the cells of hidden columns. visible mirrors the result
// set's column list, so the surviving cells stay aligned with body.Columns.
func visibleCells(row []driver.Value, visible []bool) []driver.Value {
	out := make([]driver.Value, 0, len(row))
	for i, v := range row {
		if i < len(visible) && visible[i] {
			out = append(out, v)
		}
	}
	return out
}

type browseRow struct {
	Cells    []driver.Value
	EditURL  string
	CopyURL  string
	KeyToken string
	HasKey   bool
	// KeyTruncated is true when this row has no usable key SPECIFICALLY because
	// a key column's value was truncated for display (capCell). It lets the grid
	// explain the missing Edit/Copy/Delete actions rather than dropping them
	// silently — distinct from a keyless table or a binary key, which are
	// structural and permanent.
	KeyTruncated bool
}

type browseBody struct {
	Scope   reqScope
	Columns []browseCol
	Rows    []browseRow
	Total   int64
	// Positions and page numbers are int64 end-to-end: a >2^31-row table must
	// paginate correctly on a 32-bit build (see clampBrowsePos/browseNavFor).
	Offset      int64
	Limit       int
	Page        int64
	Pages       int64
	ShowingFrom int64
	ShowingTo   int64
	// Sorts is the active key list, in key order; SortSummary renders it for the
	// toolbar ("name, then qty DESC"). ClearSortURL is set only when something
	// is sorted.
	Sorts        []driver.Sort
	SortSummary  string
	ClearSortURL string
	// SortKeys offers each index as a ready-made multi-column sort. Empty when
	// the index listing failed or no index maps onto plain columns.
	SortKeys []sortKeyOption
	// ShowAll: this render is a "Show all" (rows=all), so there is no page to
	// navigate and the toolbar says so.
	ShowAll    bool
	ShowAllURL string // enter Show all, keeping the sort
	// WholeResult: every row of this table is on screen, so a client-side
	// filter over the rendered rows filters the whole result and cannot
	// mislead. A filter offered over ONE PAGE of a paginated grid can: a value
	// that exists in the table but not on this page reads as absent. That is
	// why an earlier pass deleted the old row filter outright, and why this one
	// is gated instead of relabelled.
	WholeResult bool
	// HiddenColumns are the columns this render is not showing, each with the
	// link that brings it back; ShowAllColumnsURL restores every one at once.
	HiddenColumns     []browseHiddenCol
	ShowAllColumnsURL string
	Options           []int
	// Truncated: rows were omitted (row cap OR byte budget). BudgetTruncated
	// discriminates the byte-budget cause so the banner can say the rows were
	// large rather than merely numerous — the rows-per-page control is the fix
	// for one, filtering/pagination for the other.
	Truncated       bool
	BudgetTruncated bool
	IsView          bool
	Approx          bool   // Total is a statistics estimate, not an exact count
	Exact           bool   // this request ran in exact mode (?exact=1); URLs keep it
	ExactURL        string // re-render with an exact COUNT(*) (set when Approx)

	BaseURL                             string
	FirstURL, PrevURL, NextURL, LastURL string
	InsertURL, DeleteURL                string
	// RowsURL is the "with selected" hub every bulk action posts to, carrying
	// the checked row keys plus an action verb.
	RowsURL          string
	HasPrev, HasNext bool
}

// browseURL builds a browse link for this table with the given query overrides.
func browseURL(sc reqScope, q url.Values) string {
	base := urlTable(sc.DB, sc.Schema, sc.Table, "browse")
	// urlTable may already append ?schema=...; merge query parts.
	if sc.Schema != "" {
		q.Set("schema", sc.Schema)
	}
	if enc := q.Encode(); enc != "" {
		return urlTable(sc.DB, "", sc.Table, "browse") + "?" + enc
	}
	return base
}

// TableBrowse renders the Browse grid (GET /db/{db}/table/{table}).
func (h *Handlers) TableBrowse(w http.ResponseWriter, r *http.Request) {
	uc, ok := h.requireUser(w, r)
	if !ok {
		return
	}
	sc := h.resolveScope(r).withSchemaDefault(uc.Capabilities())
	h.showBrowse(w, r, uc, sc, nil)
}

// showBrowse queries and renders the browse grid, optionally with flash
// messages (used after a successful insert/edit/delete to re-render in place).
func (h *Handlers) showBrowse(w http.ResponseWriter, r *http.Request, uc *UserContext, sc reqScope, flashes []view.Flash) {
	ref := sc.tableRef()
	ctx := r.Context()

	conn, err := uc.ConnFor(ctx, sc.DB)
	if err != nil {
		h.connError(w, r, uc, err)
		return
	}
	if !h.requireDataTable(w, r, conn, sc) {
		return
	}
	cols, err := conn.Columns(ctx, ref)
	if err != nil {
		h.dbError(w, r, err, "")
		return
	}

	// Sort: a validated key LIST. driver.Sort was always a slice here; only the
	// parser was single-valued, so "ORDER BY a, b DESC" was unreachable from the
	// UI even though everything below it was ready for it.
	sorts := parseSorts(r.URL.Query(), cols)
	hidden := parseHidden(r.URL.Query(), cols)

	// Pagination. The page size is clamped to an allowed option before use (so
	// limit is always > 0) and persisted only after clamping; the position is
	// parsed and clamped in int64 (see clampBrowsePos).
	// "Show all" (rows=all) replaces the page size with showAllRowCap and is
	// deliberately NOT persisted as the session's page size: one look at
	// everything must not make every later table load everything.
	showAll := r.URL.Query().Get("rows") == "all"
	limit := clampRowsPerPage(intParam(r, "rows", uc.RowsPerPage()))
	if showAll {
		limit = showAllRowCap
	} else {
		uc.SetRowsPerPage(limit)
	}

	// exact=1 persists for the whole browsing session once entered (the sort,
	// pagination and page-size URLs all carry it) — otherwise the very next
	// click would silently fall back to the approximate count.
	exact := r.URL.Query().Get("exact") == "1"
	// Resolve the view flag first: it suppresses the mutating surface below, and
	// the row count needs it to know whether COUNT(*) may cost an unbounded
	// re-run of the view's query. The listing is memoized by requireDataTable
	// above, so this costs no extra query.
	isView := false
	if tbl, found, lerr := h.lookupTable(ctx, conn, sc); lerr == nil && found {
		isView = tbl.IsView()
	}
	total, approx := h.tableRowCount(ctx, conn, ref, exact, isView)
	offset := clampBrowsePos(total, approx, int64Param(r, "pos", 0), limit)
	if showAll {
		offset = 0 // "all" starts at the beginning; there is no page to be on
	}

	// When the row count is unknown (total < 0) or approximate we can't derive
	// HasNext from a total (the old "len == limit" heuristic falsely reports a
	// next page when the rows happen to be an exact multiple of the page size,
	// and an estimate can undercount). Fetch one extra row instead: if it comes
	// back there is definitely a next page. Render only `limit` rows; the probe
	// row is trimmed below.
	fetchLimit := limit
	if total < 0 || approx || showAll {
		// showAll probes too, but for a different reason: the +1 is how the grid
		// learns it hit showAllRowCap and must say so rather than present a
		// truncated table as the whole thing.
		fetchLimit = limit + 1
	}
	pag := driver.Pagination{Limit: fetchLimit, Offset: offset}
	if showAll {
		// Show all raises the row ceiling 20x, so cap the retained text too — a
		// whole-row byte budget, scoped to this path only (paginated browse and
		// the console stay unbudgeted). See showAllByteBudget.
		pag.ByteBudget = showAllByteBudget
	}
	rs, err := conn.Browse(ctx, ref, pag, sorts)
	if err != nil {
		h.dbError(w, r, err, "")
		return
	}
	hasMore := false
	if (total < 0 || approx || showAll) && len(rs.Rows) > limit {
		hasMore = true
		rs.Rows = rs.Rows[:limit] // drop the probe row; show exactly `limit`
		if showAll {
			rs.Truncated = true // "all" was more than we will render at once
		}
	}

	bq := browseQuery{Pos: offset, Rows: limit, Sorts: sorts, Exact: exact, ShowAll: showAll, Hidden: hidden}
	if showAll {
		bq.Rows = uc.RowsPerPage() // what leaving Show all returns to
	}
	body := h.buildBrowseBody(sc, cols, rs, total, offset, limit, bq, approx, hasMore)
	body.ShowAll = showAll
	// Sort-by-key: each index is a ready-made multi-column sort. Failure is not
	// fatal — the select simply is not offered, exactly as the structure page
	// degrades when the index listing is unavailable.
	if idxs, ierr := conn.Indexes(ctx, ref); ierr == nil {
		body.SortKeys = sortKeyOptions(sc, bq, idxs, cols, sorts)
	}
	// Flag views so the template suppresses the mutating surface (row checkboxes,
	// edit/copy/delete actions, the Insert bulk-bar link); the mutating routes
	// are also rejected server-side by requireWritableTable.
	body.IsView = isView
	if approx {
		body.ExactURL = browseURL(sc, bq.values(url.Values{"exact": {"1"}}))
	}

	p := h.newLoggedPage(r, uc, sc.Table+" · Browse")
	p.Breadcrumb = h.buildBreadcrumb(uc, sc)
	p.Tabs = h.tableTabs(ctx, uc, sc, "browse", conn)
	p.Flashes = append(p.Flashes, flashes...)
	p.Body = body
	h.render(w, r, "table_browse", p)
}

func (h *Handlers) buildBrowseBody(sc reqScope, cols []model.Column, rs *driver.ResultSet, total, offset int64, limit int, bq browseQuery, approx, hasMore bool) browseBody {
	modelByName := map[string]model.Column{}
	for _, c := range cols {
		modelByName[c.Name] = c
	}

	body := browseBody{
		Scope:           sc,
		Total:           total,
		Offset:          offset,
		Limit:           limit,
		Sorts:           bq.Sorts,
		SortSummary:     sortSummary(bq.Sorts),
		Options:         rowsPerPageOptions,
		Truncated:       rs.Truncated,
		BudgetTruncated: rs.BudgetTruncated,
		Approx:          approx,
		Exact:           bq.Exact,
		BaseURL:         urlTable(sc.DB, sc.Schema, sc.Table, "browse"),
		InsertURL:       urlTable(sc.DB, sc.Schema, sc.Table, "insert"),
		DeleteURL:       urlTable(sc.DB, sc.Schema, sc.Table, "delete"),
		RowsURL:         urlTable(sc.DB, sc.Schema, sc.Table, "rows"),
	}
	if len(bq.Sorts) > 0 {
		body.ClearSortURL = browseURL(sc, bq.withSorts(nil).values(nil))
	}
	// Show all keeps the sort and returns to the top; leaving it restores the
	// session's page size, which is why bq.Rows still holds it.
	showAllQ := bq
	showAllQ.ShowAll, showAllQ.Pos = !bq.ShowAll, 0
	body.ShowAllURL = browseURL(sc, showAllQ.values(nil))

	// Column headers. Two links per column, because they do different things:
	// the header itself sorts by that column ALONE (the familiar click), while
	// the rank badge adds it as a further key — or flips it if it is already
	// one. Both are plain <a href>, so a multi-key sort is reachable without
	// JavaScript and survives being bookmarked.
	// visible[i] mirrors rs.Columns and decides which CELLS render. Hiding is
	// presentational: the row keeps every value it was fetched with, so the
	// row-identity token (and the Edit/Copy/Delete links built from it) is
	// unaffected by what the grid chooses to show.
	visible := make([]bool, len(rs.Columns))
	for i, rc := range rs.Columns {
		if isHidden(bq.Hidden, rc.Name) {
			body.HiddenColumns = append(body.HiddenColumns, browseHiddenCol{
				Name:    rc.Name,
				ShowURL: browseURL(sc, bq.withHidden(hideMinus(bq.Hidden, rc.Name)).values(nil)),
			})
			continue
		}
		visible[i] = true
		mc := modelByName[rc.Name]
		bc := browseCol{Name: rc.Name, Numeric: rc.Numeric || mc.IsNumeric(), IsPrimary: mc.IsPrimaryKey}
		rank, desc := sortRankOf(bq.Sorts, rc.Name)
		bc.SortRank = rank
		bc.SortedAsc = rank > 0 && !desc
		bc.SortedDesc = rank > 0 && desc
		bc.MultiSorted = rank > 0 && len(bq.Sorts) > 1
		bc.SortURL = browseURL(sc, bq.withSorts(primarySortToggle(bq.Sorts, rc.Name)).values(nil))
		bc.AddSortURL = browseURL(sc, bq.withSorts(appendSortKey(bq.Sorts, rc.Name)).values(nil))
		// Hiding the second-to-last visible column would leave none; parseHidden
		// refuses that, so the link is simply not offered.
		if len(bq.Hidden)+1 < len(rs.Columns) {
			bc.HideURL = browseURL(sc, bq.withHidden(hidePlus(bq.Hidden, rc.Name)).values(nil))
		}
		body.Columns = append(body.Columns, bc)
	}
	if len(body.HiddenColumns) > 0 {
		body.ShowAllColumnsURL = browseURL(sc, bq.withHidden(nil).values(nil))
	}

	keyCols := keyColumns(cols)
	for _, row := range rs.Rows {
		cellByName := map[string]driver.Value{}
		for i, rc := range rs.Columns {
			if i < len(row) {
				cellByName[rc.Name] = row[i]
			}
		}
		// The token is built from the FULL row, before any column is dropped
		// for display — hiding a primary key must not cost the row its
		// Edit/Copy/Delete links.
		token := rowKeyFor(keyCols, cellByName)
		br := browseRow{
			Cells:    visibleCells(row, visible),
			KeyToken: token,
			HasKey:   token != "",
		}
		if !br.HasKey {
			// Explain a truncation-caused drop specifically: a key column whose
			// display value was capped can no longer identify the row exactly.
			for _, name := range keyCols {
				if cell, ok := cellByName[name]; ok && cell.Truncated {
					br.KeyTruncated = true
					break
				}
			}
		}
		if br.HasKey {
			q := url.Values{}
			q.Set("where", token)
			br.EditURL = urlTable(sc.DB, "", sc.Table, "edit") + "?" + withSchema(q, sc).Encode()
			cq := url.Values{}
			cq.Set("where", token)
			cq.Set("copy", "1")
			br.CopyURL = urlTable(sc.DB, "", sc.Table, "insert") + "?" + withSchema(cq, sc).Encode()
		}
		body.Rows = append(body.Rows, br)
	}

	// Pagination derived values — overflow-safe int64 forms (browseNavFor).
	nav := browseNavFor(total, offset, limit, approx, hasMore)
	body.Pages, body.Page = nav.Pages, nav.Page
	body.HasPrev, body.HasNext = nav.HasPrev, nav.HasNext
	// Nothing before and nothing after, and nothing dropped at the cap: this
	// grid IS the result, so filtering the rendered rows filters all of them.
	body.WholeResult = !nav.HasPrev && !nav.HasNext && !rs.Truncated && len(rs.Rows) > 0
	if total > 0 {
		body.ShowingFrom = satAddInt64(offset, 1)
		body.ShowingTo = satAddInt64(offset, int64(len(rs.Rows)))
	}

	// Pagination links carry the whole browse state — sort keys included, and
	// exact mode, which persists across pagination.
	mk := func(pos int64) string {
		return browseURL(sc, bq.values(url.Values{"pos": {strconv.FormatInt(pos, 10)}}))
	}
	body.FirstURL = mk(nav.First)
	body.PrevURL = mk(nav.Prev)
	body.NextURL = mk(nav.Next)
	if nav.Pages > 0 {
		body.LastURL = mk(nav.Last)
	}
	return body
}

func withSchema(q url.Values, sc reqScope) url.Values {
	if sc.Schema != "" {
		q.Set("schema", sc.Schema)
	}
	return q
}

func columnExists(cols []model.Column, name string) bool {
	_, ok := findColumn(cols, name)
	return ok
}

// findColumn returns the column with the given exact name, if present.
func findColumn(cols []model.Column, name string) (model.Column, bool) {
	for _, c := range cols {
		if c.Name == name {
			return c, true
		}
	}
	return model.Column{}, false
}
