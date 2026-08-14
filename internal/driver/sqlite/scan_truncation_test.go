package sqlite

import (
	"context"
	"strings"
	"testing"

	"github.com/tablexdev/tablex/internal/driver"
)

// TestScanResultMarksTruncatedCell covers the #43 producer half end-to-end: a
// display scan (driver.ScanResult) that caps an oversized text cell must flag it
// Truncated, so the row grid can degrade its Edit/Delete actions rather than
// build an invertible WHERE from a prefix. A small cell is never flagged, and
// the verbatim scan (the row-edit prefill) never caps, so it never flags.
func TestScanResultMarksTruncatedCell(t *testing.T) {
	db := openViaDialect(t, nil)
	ctx := context.Background()
	if _, err := db.ExecContext(ctx, "CREATE TABLE t (id INTEGER PRIMARY KEY, big TEXT, small TEXT)"); err != nil {
		t.Fatalf("create: %v", err)
	}
	big := strings.Repeat("z", driver.MaxCellBytes+512)
	if _, err := db.ExecContext(ctx, "INSERT INTO t (id, big, small) VALUES (1, ?, ?)", big, "ok"); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// Display scan: the oversized cell is capped and flagged; the small one is not.
	rows, err := db.QueryContext(ctx, "SELECT big, small FROM t")
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	rs, err := driver.ScanResult(rows, 0)
	if err != nil {
		t.Fatalf("ScanResult: %v", err)
	}
	if len(rs.Rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(rs.Rows))
	}
	bigCell, smallCell := rs.Rows[0][0], rs.Rows[0][1]
	if !bigCell.Truncated {
		t.Error("oversized cell not flagged Truncated")
	}
	if len(bigCell.Str) != driver.MaxCellBytes {
		t.Errorf("oversized cell kept %d bytes, want %d", len(bigCell.Str), driver.MaxCellBytes)
	}
	if smallCell.Truncated {
		t.Error("small cell wrongly flagged Truncated")
	}

	// Verbatim scan never caps, so it never flags — the row-edit prefill must
	// round-trip the full value.
	rows2, err := db.QueryContext(ctx, "SELECT big FROM t")
	if err != nil {
		t.Fatalf("query 2: %v", err)
	}
	rsv, err := driver.ScanResultVerbatim(rows2, 0)
	if err != nil {
		t.Fatalf("ScanResultVerbatim: %v", err)
	}
	if rsv.Rows[0][0].Truncated {
		t.Error("verbatim scan flagged a cell Truncated; it must never cap")
	}
	if len(rsv.Rows[0][0].Str) != len(big) {
		t.Errorf("verbatim scan kept %d bytes, want the full %d", len(rsv.Rows[0][0].Str), len(big))
	}
}

// TestScanResultBudget covers #44's scan mechanics: ScanResultBudget stops at a
// WHOLE-row boundary once the retained text exceeds the budget, always keeps at
// least one row (even one larger than the whole budget), and sets both the
// aggregate Truncated flag and the BudgetTruncated cause. A zero budget (the
// console/paginated path) is never affected.
func TestScanResultBudget(t *testing.T) {
	db := openViaDialect(t, nil)
	ctx := context.Background()
	if _, err := db.ExecContext(ctx, "CREATE TABLE t (v TEXT)"); err != nil {
		t.Fatalf("create: %v", err)
	}
	const cell = 1000 // one TEXT column, so each row's retained bytes == len(v)
	val := strings.Repeat("x", cell)
	for i := 0; i < 5; i++ {
		if _, err := db.ExecContext(ctx, "INSERT INTO t (v) VALUES (?)", val); err != nil {
			t.Fatalf("seed %d: %v", i, err)
		}
	}
	scan := func(budget int) *driver.ResultSet {
		t.Helper()
		rows, err := db.QueryContext(ctx, "SELECT v FROM t")
		if err != nil {
			t.Fatalf("query: %v", err)
		}
		rs, err := driver.ScanResultBudget(rows, 0, budget)
		if err != nil {
			t.Fatalf("ScanResultBudget: %v", err)
		}
		return rs
	}

	// Exact boundary: a budget of exactly 3 cells keeps 3 rows; one byte less
	// keeps 2 — the row that would cross the budget is dropped whole.
	if rs := scan(3 * cell); len(rs.Rows) != 3 || !rs.Truncated || !rs.BudgetTruncated {
		t.Errorf("budget=3*cell: rows=%d Truncated=%v Budget=%v, want 3/true/true", len(rs.Rows), rs.Truncated, rs.BudgetTruncated)
	}
	if rs := scan(3*cell - 1); len(rs.Rows) != 2 {
		t.Errorf("budget=3*cell-1: rows=%d, want 2 (whole-row stop)", len(rs.Rows))
	}

	// No budget keeps every row and never flags BudgetTruncated.
	if rs := scan(0); len(rs.Rows) != 5 || rs.Truncated || rs.BudgetTruncated {
		t.Errorf("no budget: rows=%d Truncated=%v Budget=%v, want 5/false/false", len(rs.Rows), rs.Truncated, rs.BudgetTruncated)
	}

	// A single row larger than the whole budget is kept anyway (never an empty
	// grid), and not flagged since nothing was dropped.
	if _, err := db.ExecContext(ctx, "DELETE FROM t"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	huge := strings.Repeat("y", 5*cell)
	if _, err := db.ExecContext(ctx, "INSERT INTO t (v) VALUES (?)", huge); err != nil {
		t.Fatalf("seed huge: %v", err)
	}
	if rs := scan(100); len(rs.Rows) != 1 || rs.Truncated || rs.BudgetTruncated {
		t.Errorf("single oversized row: rows=%d Truncated=%v Budget=%v, want 1/false/false", len(rs.Rows), rs.Truncated, rs.BudgetTruncated)
	}

	// Two oversized rows: the first is kept, the second (which would cross the
	// budget) stops the scan — one row, truncated by budget.
	if _, err := db.ExecContext(ctx, "INSERT INTO t (v) VALUES (?)", huge); err != nil {
		t.Fatalf("seed huge 2: %v", err)
	}
	if rs := scan(100); len(rs.Rows) != 1 || !rs.Truncated || !rs.BudgetTruncated {
		t.Errorf("two oversized rows: rows=%d Truncated=%v Budget=%v, want 1/true/true", len(rs.Rows), rs.Truncated, rs.BudgetTruncated)
	}
}
