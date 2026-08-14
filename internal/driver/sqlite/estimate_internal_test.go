package sqlite

import (
	"context"
	"database/sql"
	sqldriver "database/sql/driver"
	"errors"
	"io"
	"sync/atomic"
	"testing"

	"github.com/tablexdev/tablex/internal/driver"
)

// EstimateRows runs two queries: "does sqlite_stat1 exist" and "what does it say
// about this table". A failure of the SECOND used to be reported as "-1, nil" —
// the ordinary no-estimate answer — because the !stat.Valid test ran ahead of
// the error test, and Row.Scan leaves a NullString invalid on any failure.
//
// Real SQLite cannot reproduce that: sqlite_ tables cannot be user-created, so
// there is no way to make the existence probe succeed and the stat read fail.
// This registers the smallest database/sql driver that can — the first query
// succeeds with one row, every query after it fails. It is the only stub driver
// in the tree, and it exists for this one asymmetry.

var errStatQueryFailed = errors.New("stub: statistics query failed")

type failAfterFirstQuery struct{ queries atomic.Int32 }

func (d *failAfterFirstQuery) Open(string) (sqldriver.Conn, error) {
	return &failAfterFirstConn{drv: d}, nil
}

type failAfterFirstConn struct{ drv *failAfterFirstQuery }

func (c *failAfterFirstConn) Prepare(string) (sqldriver.Stmt, error) {
	return nil, errors.New("stub: Prepare unsupported (the queries under test go through QueryContext)")
}
func (c *failAfterFirstConn) Close() error { return nil }
func (c *failAfterFirstConn) Begin() (sqldriver.Tx, error) {
	return nil, errors.New("stub: Begin unsupported")
}

func (c *failAfterFirstConn) QueryContext(context.Context, string, []sqldriver.NamedValue) (sqldriver.Rows, error) {
	if c.drv.queries.Add(1) == 1 {
		return &singleIntRow{}, nil
	}
	return nil, errStatQueryFailed
}

// singleIntRow yields exactly one row holding the integer 1 — enough for the
// existence probe's `SELECT 1`.
type singleIntRow struct{ done bool }

func (r *singleIntRow) Columns() []string { return []string{"c"} }
func (r *singleIntRow) Close() error      { return nil }
func (r *singleIntRow) Next(dest []sqldriver.Value) error {
	if r.done {
		return io.EOF
	}
	r.done = true
	dest[0] = int64(1)
	return nil
}

func init() { sql.Register("tablex-stub-fail-after-first-query", &failAfterFirstQuery{}) }

func TestEstimateRowsReportsAFailedStatisticsQuery(t *testing.T) {
	db, err := sql.Open("tablex-stub-fail-after-first-query", "")
	if err != nil {
		t.Fatalf("open stub driver: %v", err)
	}
	defer db.Close()

	got, err := dialect{}.EstimateRows(context.Background(), db, driver.TableRef{Database: "main", Table: "widgets"})
	if err == nil {
		t.Fatalf("EstimateRows swallowed the statistics-query failure: got (%d, nil), want a non-nil error", got)
	}
	if !errors.Is(err, errStatQueryFailed) {
		t.Errorf("EstimateRows returned %v, want the underlying query error", err)
	}
	if got != -1 {
		t.Errorf("EstimateRows returned %d alongside its error, want the -1 no-estimate sentinel", got)
	}
}
