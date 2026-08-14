package driver

import (
	"context"
	"database/sql"
	"time"
)

// Pinned is a dedicated single physical database connection for running
// multi-statement scripts (SQL imports, the console). Pool execution would
// let successive statements land on different physical connections, so
// session-scoped state (SET sql_mode / time_zone, FOREIGN_KEY_CHECKS=0,
// PRAGMA foreign_keys=OFF) would neither reliably apply to later statements
// nor be cleaned up when a script stops at the first error. A Pinned
// connection guarantees both: every statement runs on the one connection,
// and Close discards it (together with its private pool) instead of
// returning dirty session state to a shared pool.
type Pinned struct {
	db      *sql.DB
	conn    *sql.Conn
	dialect Dialect
	// observe reports EVERY statement to the audit trail, reads included: a
	// pinned connection exists only to run a script the user wrote, so a SELECT
	// here is as much a user action as a DROP. See StatementObserver.
	observe StatementObserver
}

// OpenPinned dials a dedicated connection using the dialect and params. A
// MaxOpenConns(1) pool alone would not be enough — a pool may still recycle
// the physical session mid-script — so the single connection is checked out
// up front and held until Close.
//
// Like Open, it loads ServerInfo and routes the dialect through Specialize:
// Pinned.Dialect feeds driver.ProfileOf, which gates the console/import
// splitter's RETURNING classification on the detected flavor and version. An
// unspecialized dialect reports the registered zero value, so MariaDB's
// `DELETE … RETURNING` would run as an Exec and its rows be discarded. Reading
// the facts from THIS session (rather than inheriting the login pool's) is also
// the more correct answer for the session-scoped ones — MySQL's sql_mode.
func OpenPinned(ctx context.Context, d Dialect, p ConnParams) (*Pinned, error) {
	db, err := openPool(d, p)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	dialCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	// ServerInfo runs BEFORE the checkout below: with MaxOpenConns(1) the pool is
	// exhausted once the connection is held, so a query through db would block
	// until the 15s budget expires. MaxIdleConns(1) keeps the returned connection
	// in the pool, so the checkout gets the very session that was just measured.
	info, err := d.ServerInfo(dialCtx, db)
	if err != nil {
		db.Close()
		return nil, err
	}
	d = Specialize(d, info)
	conn, err := db.Conn(dialCtx)
	if err != nil {
		db.Close()
		return nil, err
	}
	return &Pinned{db: db, conn: conn, dialect: d, observe: p.OnStatement}, nil
}

// Engine returns the dialect name ("mysql", "postgres", "sqlite").
func (p *Pinned) Engine() string { return p.dialect.Name() }

// Dialect returns the engine dialect.
func (p *Pinned) Dialect() Dialect { return p.dialect }

// Query runs a row-returning statement and scans up to limit rows.
func (p *Pinned) Query(ctx context.Context, query string, limit int) (*ResultSet, error) {
	if p.observe == nil {
		return runQuery(ctx, p.conn, query, limit)
	}
	start := time.Now()
	rs, err := runQuery(ctx, p.conn, query, limit)
	// Rows SCANNED, not affected — and capped by limit, so it is what the user
	// was shown rather than what the query matched. That is the honest number for
	// a read, and the reason it is not called "affected".
	rows := int64(-1)
	if rs != nil {
		rows = int64(len(rs.Rows))
	}
	p.observe(ctx, StatementEvent{SQL: query, Rows: rows, Duration: time.Since(start), Err: err, UserSQL: true})
	return rs, err
}

// Exec runs a non-row statement and reports affected rows.
func (p *Pinned) Exec(ctx context.Context, query string) (ExecResult, error) {
	if p.observe == nil {
		return runExec(ctx, p.conn, query)
	}
	start := time.Now()
	res, err := runExec(ctx, p.conn, query)
	p.observe(ctx, StatementEvent{SQL: query, Rows: res.RowsAffected, Duration: time.Since(start), Err: err, UserSQL: true})
	return res, err
}

// Explain runs EXPLAIN for a query if the engine supports it.
func (p *Pinned) Explain(ctx context.Context, query string, analyze bool) (*ResultSet, error) {
	return runExplain(ctx, p.dialect, p.conn, query, analyze)
}

// ExplainSQL returns the exact statement Explain would execute, so the console
// can label the result with what really ran.
func (p *Pinned) ExplainSQL(query string, analyze bool) (string, bool) {
	return p.dialect.ExplainSQL(query, analyze)
}

// Close releases the pinned connection and its private pool, discarding the
// physical connection along with any session state the script left behind.
func (p *Pinned) Close() error {
	_ = p.conn.Close()
	return p.db.Close()
}
