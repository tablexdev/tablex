package driver

// The statement-observer seam: how the audit trail sees each statement a
// connection runs. Split from driver.go by role (the file-size ratchet keeps
// it that way).

import (
	"context"
	"database/sql"
	"time"
)

// StatementObserver is notified after a statement runs. It is the seam the audit
// trail hangs on, and it exists here — as a plain callback rather than an import
// of internal/audit — so this package keeps knowing nothing about the
// application above it.
//
// WHICH statements are reported is deliberately asymmetric:
//
//   - On a shared pool (Connection), only MUTATIONS — Exec and ExecScript. The
//     row-returning paths are how Browse, introspection and every count run, so
//     reporting them would bury the trail in reads TableX generated for its own
//     rendering.
//   - On a pinned connection (Pinned), EVERYTHING. A pinned connection exists
//     only to run a script the user wrote themselves — the SQL console and SQL
//     import — so a SELECT there is as much a user action as a DROP, and an
//     auditor wants both.
//
// It must not block: it runs on the request's goroutine, immediately after the
// statement it describes.
type StatementObserver func(ctx context.Context, ev StatementEvent)

// StatementEvent is one statement, as the observer sees it.
type StatementEvent struct {
	// SQL is the statement as it was sent. The caller bounds its length before
	// recording it: an import statement can be megabytes.
	SQL string
	// Rows is the affected-row count for a mutation, or -1 where the engine or
	// the code path does not report one.
	Rows     int64
	Duration time.Duration
	// Err is the statement's error, or nil. A statement error may echo the
	// statement itself — including any secret embedded in it — so an observer
	// must apply Redact to the error text exactly as it does to SQL.
	Err error
	// UserSQL distinguishes SQL the USER wrote (the console, an import) from SQL
	// TableX generated on their behalf (the Drop button, the structure editor).
	// An auditor reading "DROP TABLE orders" wants to know which it was.
	UserSQL bool
	// Redact lists secret needles the observer MUST strip from both SQL and
	// Err.Error() before recording either — a DCL statement embeds the
	// account's password (raw and engine-quoted forms both ride here, since an
	// engine error can echo either). Entries are non-empty by construction
	// (see redactSecrets), but an observer must still skip an empty needle: a
	// ReplaceAll of "" would blank-redact the whole statement.
	Redact []string
}

// --- Observed parameterized execution -------------------------------------------
//
// The observed helpers below exist because the handlers' row DML — insert,
// edit, delete, bulk apply, CSV import — is PARAMETERIZED, which Exec and
// ExecScript (no-args by design) cannot run; reaching for the bare pool
// (Connection.DB) instead meant `audit.statements = true` recorded DDL but no
// row-level data change at all. Only the SQL text is ever reported: the bound
// argument values are row DATA and never belong in the trail.

// ExecArgs runs one parameterized non-row statement on the shared pool,
// reporting it to the statement observer.
func (c *Connection) ExecArgs(ctx context.Context, query string, args ...any) (sql.Result, error) {
	if c.observe == nil {
		return c.db.ExecContext(ctx, query, args...)
	}
	start := time.Now()
	res, err := c.db.ExecContext(ctx, query, args...)
	c.observe(ctx, StatementEvent{SQL: query, Rows: observedRows(res, err), Duration: time.Since(start), Err: err})
	return res, err
}

// Tx is a transaction whose statements are reported to the statement
// observer. Statements are recorded AS THEY EXECUTE, each with its own error.
// How the transaction's OUTCOME is represented in the trail: any transaction
// that does not commit emits an explicit "ROLLBACK" event once observed
// statements exist, so recorded-but-undone work is never read as applied.
// That covers the explicit rollback, the deferred rollback after a FAILED
// Commit (the engine has already rolled back, so the call itself returns
// sql.ErrTxDone — the marker carries the commit error as its Err), and a
// context-cancel abort. Commit emits nothing on success (applied is the
// default reading of a recorded statement), and the deferred
// rollback-after-successful-commit pattern emits nothing either.
type Tx struct {
	tx   *sql.Tx
	conn *Connection
	// ctx is the transaction's request context, held ONLY so Rollback and
	// Stmt.Close — which take no context, matching database/sql — can hand the
	// observer its per-request audit state. The Tx never outlives the request.
	ctx       context.Context
	stmts     int
	committed bool
	// commitErr is a failed Commit's error, carried on the ROLLBACK marker the
	// deferred Rollback then emits — without it the trail would show the
	// statements errorless and the rollback causeless.
	commitErr error
	// done means the rollback outcome has been resolved (marker emitted or
	// nothing to mark), so a second deferred Rollback cannot double-mark.
	done bool
}

// BeginObserved starts a transaction whose statements reach the observer.
func (c *Connection) BeginObserved(ctx context.Context) (*Tx, error) {
	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	return &Tx{tx: tx, conn: c, ctx: ctx}, nil
}

// Exec runs one parameterized statement inside the transaction.
func (t *Tx) Exec(ctx context.Context, query string, args ...any) (sql.Result, error) {
	if t.conn.observe == nil {
		return t.tx.ExecContext(ctx, query, args...)
	}
	start := time.Now()
	res, err := t.tx.ExecContext(ctx, query, args...)
	t.stmts++
	t.conn.observe(ctx, StatementEvent{SQL: query, Rows: observedRows(res, err), Duration: time.Since(start), Err: err})
	return res, err
}

// Commit commits the transaction. On failure the engine has rolled the work
// back; the deferred Rollback emits the ROLLBACK marker carrying this error.
func (t *Tx) Commit() error {
	err := t.tx.Commit()
	if err == nil {
		t.committed = true
	} else {
		t.commitErr = err
	}
	return err
}

// Rollback rolls the transaction back, emitting the explicit "ROLLBACK" event
// when observed statements exist and the transaction did not commit (see Tx).
// The marker is emitted regardless of what the underlying call returns: after
// a failed Commit or a context-cancel abort it is sql.ErrTxDone, and in every
// such case the work is equally undone — gating the marker on a nil error is
// exactly how a failed commit's statements used to read as applied. Safe as a
// deferred safety net: after a SUCCESSFUL Commit it emits nothing.
func (t *Tx) Rollback() error {
	err := t.tx.Rollback()
	if t.conn.observe != nil && !t.committed && !t.done && t.stmts > 0 {
		t.conn.observe(t.ctx, StatementEvent{SQL: "ROLLBACK", Rows: -1, Err: t.commitErr})
	}
	t.done = true
	return err
}

// Prepare returns an observed prepared statement on the transaction.
// Executions are AGGREGATED into one statement event, emitted at Close: a CSV
// import runs the same INSERT tens of thousands of times, and one event per
// row would bury the trail the observer exists to keep readable (the same
// reasoning as the pool/pinned reporting asymmetry). A failing execution is
// reported immediately as its own event — errors are rare, and they are what
// an auditor reads the trail for.
func (t *Tx) Prepare(ctx context.Context, query string) (*Stmt, error) {
	stmt, err := t.tx.PrepareContext(ctx, query)
	if err != nil {
		return nil, err
	}
	return &Stmt{stmt: stmt, tx: t, query: query}, nil
}

// Stmt is a prepared statement on an observed Tx (see Tx.Prepare).
type Stmt struct {
	stmt  *sql.Stmt
	tx    *Tx
	query string
	execs int
	rows  int64
	dur   time.Duration
}

// Exec runs the prepared statement with the given arguments.
func (s *Stmt) Exec(ctx context.Context, args ...any) (sql.Result, error) {
	if s.tx.conn.observe == nil {
		return s.stmt.ExecContext(ctx, args...)
	}
	start := time.Now()
	res, err := s.stmt.ExecContext(ctx, args...)
	d := time.Since(start)
	if err != nil {
		// The error event reports THIS execution's duration alone, and the
		// failed time is not folded into s.dur: the aggregate at Close covers
		// the successful executions, so sharing the accumulator would report a
		// phantom slow statement here and double-count the batch's time there.
		s.tx.stmts++
		s.tx.conn.observe(ctx, StatementEvent{SQL: s.query, Rows: -1, Duration: d, Err: err})
		return res, err
	}
	s.dur += d
	s.execs++
	if n := observedRows(res, err); n > 0 {
		s.rows += n
	}
	return res, err
}

// Close closes the statement and emits the aggregate event for its successful
// executions (none ran, nothing is emitted). Safe to defer alongside a
// failing import: the failing execution already reported itself.
func (s *Stmt) Close() error {
	err := s.stmt.Close()
	if s.tx.conn.observe != nil && s.execs > 0 {
		s.tx.stmts++
		s.tx.conn.observe(s.tx.ctx, StatementEvent{SQL: s.query, Rows: s.rows, Duration: s.dur})
		s.execs = 0 // idempotent: a second Close emits nothing
	}
	return err
}

// observedRows extracts an affected-row count for the observer, or -1 when the
// driver, the failure, or the result leaves it unknown.
func observedRows(res sql.Result, err error) int64 {
	if err != nil || res == nil {
		return -1
	}
	if stats, serr := resultStats(res); serr == nil {
		return stats.RowsAffected
	}
	return -1
}
