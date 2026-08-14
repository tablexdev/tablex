package driver

import (
	"context"
	"database/sql"
)

// --- Generic query / exec ------------------------------------------------------

// sqlExecutor abstracts the two statement runners — a *sql.DB pool
// (Connection) and a checked-out *sql.Conn (Pinned) — so Query/Exec/Explain
// share one implementation instead of duplicating it per runner.
type sqlExecutor interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// runQuery runs a row-returning statement on ex and scans up to limit rows.
func runQuery(ctx context.Context, ex sqlExecutor, query string, limit int) (*ResultSet, error) {
	rows, err := ex.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	return ScanResult(rows, limit)
}

// runQueryBudget is runQuery with a cumulative byte budget on the scan (Browse's
// "Show all"). It stays off runQuery/Query so the console path is never budgeted.
func runQueryBudget(ctx context.Context, ex sqlExecutor, query string, limit, byteBudget int) (*ResultSet, error) {
	rows, err := ex.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	return ScanResultBudget(rows, limit, byteBudget)
}

// runExec runs a non-row statement on ex and reports affected rows.
func runExec(ctx context.Context, ex sqlExecutor, query string) (ExecResult, error) {
	res, err := ex.ExecContext(ctx, query)
	if err != nil {
		return ExecResult{}, err
	}
	stats, statErr := resultStats(res)
	if statErr != nil {
		// The statement itself SUCCEEDED — ExecContext returned no error. Only
		// the affected-row count is unavailable (a comment-only script, or a
		// driver that does not track it), so report zero rather than failing a
		// statement that really ran. The decision is made here, at the call
		// site, instead of vanishing inside the helper.
		return ExecResult{}, nil
	}
	return stats, nil
}

// runExplain runs the dialect's EXPLAIN form for query on ex, if supported.
func runExplain(ctx context.Context, d Dialect, ex sqlExecutor, query string, analyze bool) (*ResultSet, error) {
	stmt, ok := d.ExplainSQL(query, analyze)
	if !ok {
		return nil, ErrUnsupported
	}
	return runQuery(ctx, ex, stmt, 10000)
}
