package handlers

import (
	"context"
	"errors"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tablexdev/tablex/internal/config"
	"github.com/tablexdev/tablex/internal/driver"
	_ "github.com/tablexdev/tablex/internal/driver/sqlite"
	"github.com/tablexdev/tablex/internal/model"
)

func TestClampRowsPerPage(t *testing.T) {
	cases := []struct{ in, want int }{
		{0, 25},      // non-positive falls back to the default
		{-5, 25},     // negative falls back too
		{25, 25},     // an exact option is kept
		{50, 50},     // an exact option is kept
		{500, 500},   // the maximum option is kept
		{30, 25},     // out-of-set snaps to the nearest option
		{99999, 500}, // a hostile huge value clamps to the max
		{1, 25},      // a tiny value snaps to the smallest option
	}
	for _, c := range cases {
		if got := clampRowsPerPage(c.in); got != c.want {
			t.Errorf("clampRowsPerPage(%d) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestLikeContains(t *testing.T) {
	cases := []struct{ in, want string }{
		{"abc", "%abc%"},
		{"50%", "%50|%%"}, // a literal % is escaped
		{"a_b", "%a|_b%"}, // a literal _ is escaped
		{"a|b", "%a||b%"}, // the escape char itself is escaped
		{"", "%%"},        // empty term matches anything
	}
	for _, c := range cases {
		if got := likeContains(c.in); got != c.want {
			t.Errorf("likeContains(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestRowKeyForLengthCap(t *testing.T) {
	cell := func(s string) driver.Value { return driver.Value{Str: s} }

	small := rowKeyFor([]string{"id"}, map[string]driver.Value{"id": cell("42")})
	if small == "" {
		t.Fatal("small key unexpectedly dropped")
	}
	if entries, err := decodeRowKey(small); err != nil || len(entries) != 1 || entries[0].Col != "id" {
		t.Fatalf("decode small key: %v %+v", err, entries)
	}

	// A keyless table keys on every column; huge text must drop the actions
	// (empty token) exactly like the binary-cell case — never hash or truncate,
	// the edit/delete handlers rebuild the WHERE from the decoded values.
	huge := strings.Repeat("x", 2*maxRowKeyLen)
	if got := rowKeyFor([]string{"a", "b"}, map[string]driver.Value{"a": cell(huge), "b": cell("1")}); got != "" {
		t.Errorf("oversized key = %d bytes, want dropped", len(got))
	}

	if got := rowKeyFor([]string{"a"}, map[string]driver.Value{"a": {Binary: true, Str: "[BLOB 3 B]"}}); got != "" {
		t.Errorf("binary key = %q, want dropped", got)
	}

	// A truncated key cell (capCell cut it to a prefix) must drop the actions
	// too: rebuilding a WHERE from a prefix could match a different row sharing
	// it. Same degrade as the binary case, independent of the length cap — the
	// Str here is short, so only the flag can trigger the drop.
	if got := rowKeyFor([]string{"a"}, map[string]driver.Value{"a": {Str: "prefix", Truncated: true}}); got != "" {
		t.Errorf("truncated key = %q, want dropped", got)
	}
	// A non-key column being truncated does not disarm the key.
	full := rowKeyFor([]string{"id"}, map[string]driver.Value{
		"id":   cell("7"),
		"blob": {Str: "prefix", Truncated: true},
	})
	if full == "" {
		t.Error("a truncated NON-key column dropped the key; only key components should")
	}
}

// TestBrowseByteBudget covers #44's plumbing end-to-end: Pagination.ByteBudget
// flows through Browse into a budgeted scan and flags BudgetTruncated, while an
// unbudgeted Browse (the paginated/console path) returns every row untouched.
func TestBrowseByteBudget(t *testing.T) {
	conn := openTestConn(t)
	mustExec(t, conn, "CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)")
	val := strings.Repeat("x", 1000)
	for i := 0; i < 6; i++ {
		mustExec(t, conn, "INSERT INTO t (v) VALUES ('"+val+"')")
	}
	ref := driver.TableRef{Table: "t"}
	ctx := context.Background()

	// Each row retains ~1001 bytes (a 1-digit id plus 1000-byte text), so a
	// 2500-byte budget stops well short of all six rows.
	rs, err := conn.Browse(ctx, ref, driver.Pagination{Limit: 100, ByteBudget: 2500}, nil)
	if err != nil {
		t.Fatalf("budgeted browse: %v", err)
	}
	if !rs.Truncated || !rs.BudgetTruncated {
		t.Errorf("budgeted browse: Truncated=%v BudgetTruncated=%v, want true/true", rs.Truncated, rs.BudgetTruncated)
	}
	if len(rs.Rows) == 0 || len(rs.Rows) >= 6 {
		t.Errorf("budgeted browse returned %d rows, want a truncated subset of 6", len(rs.Rows))
	}

	// No budget: every row, no flags — the console path is never budgeted.
	rs2, err := conn.Browse(ctx, ref, driver.Pagination{Limit: 100}, nil)
	if err != nil {
		t.Fatalf("unbudgeted browse: %v", err)
	}
	if rs2.Truncated || rs2.BudgetTruncated || len(rs2.Rows) != 6 {
		t.Errorf("unbudgeted browse: rows=%d Truncated=%v Budget=%v, want 6/false/false", len(rs2.Rows), rs2.Truncated, rs2.BudgetTruncated)
	}
}

// TestBuildBrowseBodyBudgetTruncation covers #44's view-model half: both
// truncation causes propagate into the body, and NEITHER may report WholeResult
// (a truncated grid must not offer the whole-result row filter, which would
// promise "all N rows shown" over an incomplete result).
func TestBuildBrowseBodyBudgetTruncation(t *testing.T) {
	h := &Handlers{}
	cols := []model.Column{{Name: "id"}}
	sc := reqScope{DB: "d", Table: "t"}
	mk := func(trunc, budget bool) browseBody {
		rs := &driver.ResultSet{
			Columns:         []driver.ResultColumn{{Name: "id"}},
			Rows:            make([][]driver.Value, 3),
			Truncated:       trunc,
			BudgetTruncated: budget,
		}
		// Show all: offset 0 (no prev), truncated (no next probe).
		return h.buildBrowseBody(sc, cols, rs, -1, 0, showAllRowCap, browseQuery{Rows: 25, ShowAll: true}, false, false)
	}

	// Byte-budget stop: both flags set, and NOT WholeResult.
	b := mk(true, true)
	if !b.Truncated || !b.BudgetTruncated {
		t.Errorf("budget body: Truncated=%v BudgetTruncated=%v, want true/true", b.Truncated, b.BudgetTruncated)
	}
	if b.WholeResult {
		t.Error("a budget-truncated Show all must not report WholeResult")
	}

	// Row-cap stop: aggregate flag set, cause NOT — the banner picks plain wording.
	b = mk(true, false)
	if !b.Truncated || b.BudgetTruncated {
		t.Errorf("row-cap body: Truncated=%v BudgetTruncated=%v, want true/false", b.Truncated, b.BudgetTruncated)
	}
	if b.WholeResult {
		t.Error("a row-capped Show all must not report WholeResult")
	}
}

// openTestConn opens a throwaway SQLite connection for handler-internal tests.
func openTestConn(t *testing.T) *driver.Connection {
	t.Helper()
	d, ok := driver.Get("sqlite")
	if !ok {
		t.Fatal("sqlite dialect not registered")
	}
	path := filepath.Join(t.TempDir(), "t.db")
	// BuildDSN does not auto-create a missing database file; an empty file is a
	// valid empty SQLite database.
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("create temp db file: %v", err)
	}
	conn, err := driver.Open(context.Background(), d, driver.ConnParams{FilePath: path})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

func mustExec(t *testing.T, conn *driver.Connection, sql string) {
	t.Helper()
	if _, err := conn.Exec(context.Background(), sql); err != nil {
		t.Fatalf("exec %s: %v", sql, err)
	}
}

// TestBuildBrowseBodyHasNext covers #5: with an unknown row count, HasNext must
// be the definitive probe result (hasMore), not "len(rows) == limit" — a full
// last page (rows == an exact multiple of the page size) must NOT show a phantom
// Next. With a known total, HasNext is derived from the total.
func TestBuildBrowseBodyHasNext(t *testing.T) {
	h := &Handlers{}
	cols := []model.Column{{Name: "id"}}
	full := &driver.ResultSet{
		Columns: []driver.ResultColumn{{Name: "id"}},
		Rows:    make([][]driver.Value, 25), // a full page
	}
	sc := reqScope{DB: "d", Table: "t"}

	// Unknown count, full page, no extra row probed => NO next page.
	if b := h.buildBrowseBody(sc, cols, full, -1, 0, 25, browseQuery{Rows: 25}, false, false); b.HasNext {
		t.Error("unknown count + full page + no probe row must not report HasNext (phantom next)")
	}
	// Unknown count, full page, extra row was probed => next page exists.
	if b := h.buildBrowseBody(sc, cols, full, -1, 0, 25, browseQuery{Rows: 25}, false, true); !b.HasNext {
		t.Error("unknown count + probed extra row must report HasNext")
	}
	// Known count: derived from total, ignoring hasMore.
	if b := h.buildBrowseBody(sc, cols, full, 100, 0, 25, browseQuery{Rows: 25}, false, false); !b.HasNext {
		t.Error("known count with more rows beyond the page must report HasNext")
	}
	if b := h.buildBrowseBody(sc, cols, full, 25, 0, 25, browseQuery{Rows: 25}, false, false); b.HasNext {
		t.Error("known count equal to one page must not report HasNext")
	}
}

// TestBrowsePaginationInt64 covers 1.4: positions and derived pagination are
// int64 end-to-end with overflow-proof forms — exercised at the int32
// boundaries, at MaxInt64 (?pos is attacker-controlled), and on the
// unknown-count path. These cases EXECUTE on the GOARCH=386 CI job, where the
// old int-based math truncated/overflowed.
func TestBrowsePaginationInt64(t *testing.T) {
	const maxI64 = math.MaxInt64

	clampCases := []struct {
		name       string
		total, pos int64
		limit      int
		want       int64
	}{
		{"negative pos", 100, -5, 25, 0},
		{"in range", 100, 50, 25, 50},
		{"past end snaps to last page", 100, 100, 25, 75},
		{"maxint64 pos snaps to last page", 100, maxI64, 25, 75},
		{"total beyond int32", int64(3_000_000_000), int64(2_999_999_999), 25, 2_999_999_999},
		{"maxint64 pos on huge table", int64(3_000_000_000), maxI64, 25, ((3_000_000_000 - 1) / 25) * 25},
		{"empty table", 0, maxI64, 25, 0},
		{"unknown count capped", -1, maxI64, 25, maxBrowseOffset},
		{"unknown count in range", -1, 500, 25, 500},
		{"int32 boundary pos", int64(math.MaxInt32) + 1, int64(math.MaxInt32), 25, int64(math.MaxInt32)},
	}
	for _, c := range clampCases {
		if got := clampBrowsePos(c.total, false, c.pos, c.limit); got != c.want {
			t.Errorf("clampBrowsePos(%s: total=%d pos=%d limit=%d) = %d, want %d",
				c.name, c.total, c.pos, c.limit, got, c.want)
		}
	}

	// Known huge total: page numbers and positions stay exact past int32.
	total := int64(3_000_000_000)
	offset := clampBrowsePos(total, false, total-1, 25)
	nav := browseNavFor(total, offset, 25, false, false)
	wantPages := (total-1)/25 + 1
	if nav.Pages != wantPages || nav.Page != wantPages {
		t.Errorf("huge-table nav = pages %d page %d, want both %d", nav.Pages, nav.Page, wantPages)
	}
	if nav.HasNext {
		t.Error("last page of a huge table must not report HasNext")
	}
	if nav.Last != (wantPages-1)*25 || nav.Last < 0 {
		t.Errorf("Last = %d (must be non-negative last-page start)", nav.Last)
	}
	if nav.Prev != offset-25 {
		t.Errorf("Prev = %d, want %d", nav.Prev, offset-25)
	}

	// MaxInt64-adjacent offsets: no additive form may wrap negative.
	nav = browseNavFor(maxI64, maxI64-10, 25, false, false)
	if nav.Next < 0 || nav.Prev < 0 || nav.Last < 0 || nav.Pages < 0 {
		t.Errorf("nav wrapped negative at MaxInt64: %+v", nav)
	}
	if nav.HasNext {
		t.Error("total-offset <= limit must not report HasNext (subtraction form)")
	}

	// Unknown-count path: probe decides HasNext; Next saturates instead of wrapping.
	nav = browseNavFor(-1, maxBrowseOffset, 25, false, true)
	if !nav.HasNext || nav.Next != maxBrowseOffset+25 {
		t.Errorf("unknown-count nav = %+v", nav)
	}
	if got := satAddInt64(maxI64-1, 25); got != maxI64 {
		t.Errorf("satAddInt64 near MaxInt64 = %d, want saturation", got)
	}
}

// TestBrowseApproxPagination covers #10: an APPROXIMATE total is an estimate
// (often an undercount), so pagination must treat it like an unknown count —
// never snap ?pos back to the estimate-derived last page, and let the +1 probe
// (hasMore) drive HasNext — while the estimate still feeds the approximate
// page-count display.
func TestBrowseApproxPagination(t *testing.T) {
	// clamp: approx never snaps to the estimate's last page; the cap is
	// maxBrowseOffset exactly as in the unknown-count case.
	if got := clampBrowsePos(100, true, 200, 25); got != 200 {
		t.Errorf("approx clamp snapped pos 200 to %d; tail rows beyond the estimate must stay reachable", got)
	}
	if got := clampBrowsePos(100, true, math.MaxInt64, 25); got != maxBrowseOffset {
		t.Errorf("approx clamp = %d, want the maxBrowseOffset cap", got)
	}
	// exact totals still snap.
	if got := clampBrowsePos(100, false, 200, 25); got != 75 {
		t.Errorf("exact clamp = %d, want last-page snap 75", got)
	}

	// nav: the probe decides HasNext in approx mode — an offset at/past the
	// estimate with a probed extra row must still page forward…
	nav := browseNavFor(100, 100, 25, true, true)
	if !nav.HasNext {
		t.Error("approx nav must trust the probe (HasNext) over the low estimate")
	}
	// …and without a probe row there is genuinely no next page, even when the
	// (over)estimate claims more.
	nav = browseNavFor(100, 50, 25, true, false)
	if nav.HasNext {
		t.Error("approx nav must not invent a next page the probe disproved")
	}
	// The estimate still drives the approximate page-count display.
	if nav.Pages != 4 || nav.Page != 3 {
		t.Errorf("approx nav pages/page = %d/%d, want 4/3 (estimate-driven display)", nav.Pages, nav.Page)
	}
}

// TestBrowseExactModePersists covers #10's second half: once the user enters
// exact mode, every sort and pagination URL must carry exact=1 — otherwise the
// very next click falls back to the approximate count.
func TestBrowseExactModePersists(t *testing.T) {
	h := &Handlers{}
	cols := []model.Column{{Name: "id"}}
	rs := &driver.ResultSet{
		Columns: []driver.ResultColumn{{Name: "id"}},
		Rows:    make([][]driver.Value, 25),
	}
	sc := reqScope{DB: "d", Table: "t"}

	b := h.buildBrowseBody(sc, cols, rs, 100, 25, 25, browseQuery{Pos: 25, Rows: 25, Sorts: []driver.Sort{{Column: "id"}}, Exact: true}, false, false)
	for name, u := range map[string]string{
		"sort": b.Columns[0].SortURL, "first": b.FirstURL, "prev": b.PrevURL,
		"next": b.NextURL, "last": b.LastURL,
	} {
		if !strings.Contains(u, "exact=1") {
			t.Errorf("exact mode: %s URL %q dropped exact=1", name, u)
		}
	}

	// Without exact mode no URL carries the flag.
	b = h.buildBrowseBody(sc, cols, rs, 100, 25, 25, browseQuery{Pos: 25, Rows: 25, Sorts: []driver.Sort{{Column: "id"}}}, false, false)
	if strings.Contains(b.NextURL, "exact=1") || strings.Contains(b.Columns[0].SortURL, "exact=1") {
		t.Error("non-exact mode must not emit exact=1")
	}
}

func TestTableRowCountExactFallback(t *testing.T) {
	conn := openTestConn(t)
	ctx := context.Background()
	mustExec(t, conn, "CREATE TABLE t (id INTEGER PRIMARY KEY)")
	mustExec(t, conn, "INSERT INTO t VALUES (1),(2),(3)")

	// SQLite has no RowEstimator: even a threshold of 1 must fall back to the
	// exact count rather than inventing an estimate.
	h := &Handlers{Cfg: config.Config{MaxExactCount: 1}}
	ref := driver.TableRef{Table: "t"}
	if n, approx := h.tableRowCount(ctx, conn, ref, false, false); n != 3 || approx {
		t.Errorf("tableRowCount = (%d, %v), want (3, false)", n, approx)
	}
	if n, approx := h.tableRowCount(ctx, conn, ref, true, false); n != 3 || approx {
		t.Errorf("forceExact tableRowCount = (%d, %v), want (3, false)", n, approx)
	}
	// A failing count (missing table) reports -1, like the old CountRows path.
	if n, _ := h.tableRowCount(ctx, conn, driver.TableRef{Table: "missing"}, false, false); n != -1 {
		t.Errorf("missing table count = %d, want -1", n)
	}
}

// TestTableRowCountViewIsBounded covers: a view's COUNT(*) re-runs its whole
// underlying query, and EstimateRows returns -1 for one on every engine — which
// fails the `est > max_exact_count` test exactly as a tiny table does, so the
// estimate branch never fired and every Browse/Structure render paid an
// unbounded scan. A view is now counted with a ceiling and reported approximate.
func TestTableRowCountViewIsBounded(t *testing.T) {
	conn := openTestConn(t)
	ctx := context.Background()
	mustExec(t, conn, "CREATE TABLE base (id INTEGER PRIMARY KEY)")
	mustExec(t, conn, "INSERT INTO base VALUES (1),(2),(3),(4),(5)")
	mustExec(t, conn, "CREATE VIEW v AS SELECT * FROM base")

	ref := driver.TableRef{Table: "v"}
	h := &Handlers{Cfg: config.Config{MaxExactCount: 2}}

	// Over the ceiling: a lower bound, flagged approximate so the UI offers the
	// "(count exact)" link.
	if n, approx := h.tableRowCount(ctx, conn, ref, false, true); n != 2 || !approx {
		t.Errorf("bounded view count = (%d, %v), want (2, true)", n, approx)
	}
	// The exact affordance still runs the real COUNT(*).
	if n, approx := h.tableRowCount(ctx, conn, ref, true, true); n != 5 || approx {
		t.Errorf("forceExact view count = (%d, %v), want (5, false)", n, approx)
	}
	// Under the ceiling the bounded count is exact, so no "≈" is shown for the
	// small views that are the common case.
	h = &Handlers{Cfg: config.Config{MaxExactCount: 50}}
	if n, approx := h.tableRowCount(ctx, conn, ref, false, true); n != 5 || approx {
		t.Errorf("small view count = (%d, %v), want (5, false)", n, approx)
	}
	// A costly relation that does not exist still reports the -1 sentinel.
	if n, _ := h.tableRowCount(ctx, conn, driver.TableRef{Table: "nope"}, false, true); n != -1 {
		t.Errorf("missing view count = %d, want -1", n)
	}
}

// TestCountRowsBounded pins the driver primitive directly, including the
// max<=0 degradation and the exact/lower-bound boundary.
func TestCountRowsBounded(t *testing.T) {
	conn := openTestConn(t)
	ctx := context.Background()
	mustExec(t, conn, "CREATE TABLE b (id INTEGER PRIMARY KEY)")
	mustExec(t, conn, "INSERT INTO b VALUES (1),(2),(3),(4)")
	ref := driver.TableRef{Table: "b"}

	for _, c := range []struct {
		max       int64
		wantN     int64
		wantExact bool
	}{
		{max: 10, wantN: 4, wantExact: true}, // room to spare
		{max: 4, wantN: 4, wantExact: true},  // exactly at the ceiling is still exact
		{max: 3, wantN: 3, wantExact: false}, // one over: a lower bound
		{max: 1, wantN: 1, wantExact: false},
		{max: 0, wantN: 4, wantExact: true}, // <= 0 degrades to a plain COUNT(*)
	} {
		n, exact, err := conn.CountRowsBounded(ctx, ref, c.max)
		if err != nil {
			t.Fatalf("CountRowsBounded(max=%d): %v", c.max, err)
		}
		if n != c.wantN || exact != c.wantExact {
			t.Errorf("CountRowsBounded(max=%d) = (%d, %v), want (%d, %v)", c.max, n, exact, c.wantN, c.wantExact)
		}
	}
}

func TestBodyTooLarge(t *testing.T) {
	if !bodyTooLarge(&http.MaxBytesError{Limit: 10}) {
		t.Error("a MaxBytesError should be detected as a too-large body")
	}
	if bodyTooLarge(errors.New("some other error")) {
		t.Error("an unrelated error must not be flagged as too large")
	}
	if bodyTooLarge(nil) {
		t.Error("nil must not be flagged as too large")
	}
}
