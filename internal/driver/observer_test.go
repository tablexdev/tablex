package driver_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/tablexdev/tablex/internal/driver"
)

// observedConn opens a SQLite connection whose statement observer appends into
// the returned recorder.
type eventRecorder struct {
	mu     sync.Mutex
	events []driver.StatementEvent
}

func (r *eventRecorder) record(_ context.Context, ev driver.StatementEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, ev)
}

func (r *eventRecorder) all() []driver.StatementEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]driver.StatementEvent(nil), r.events...)
}

func observedConn(t *testing.T) (*driver.Connection, *eventRecorder) {
	t.Helper()
	d, ok := driver.Get("sqlite")
	if !ok {
		t.Fatal("sqlite dialect not registered")
	}
	path := filepath.Join(t.TempDir(), "obs.db")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("create db file: %v", err)
	}
	rec := &eventRecorder{}
	conn, err := driver.Open(context.Background(), d, driver.ConnParams{FilePath: path, OnStatement: rec.record})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	if _, err := conn.DB().ExecContext(context.Background(), "CREATE TABLE obs (id INTEGER PRIMARY KEY, v TEXT)"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	rec.mu.Lock()
	rec.events = nil // the seed is not under test
	rec.mu.Unlock()
	return conn, rec
}

// TestObservedRowDML pins the observed parameterized paths the row handlers
// use — ExecArgs, the observed Tx, and the aggregated prepared statement —
// including the two contract points that matter most: bound ARGUMENT VALUES
// never reach an event, and a rollback leaves its explicit marker so
// recorded-but-undone work is never read as applied.
func TestObservedRowDML(t *testing.T) {
	ctx := context.Background()
	conn, rec := observedConn(t)
	const secret = "secret-cell-value-91x"

	// ExecArgs: one event, SQL text only.
	if _, err := conn.ExecArgs(ctx, "INSERT INTO obs (v) VALUES (?)", secret); err != nil {
		t.Fatalf("ExecArgs: %v", err)
	}
	events := rec.all()
	if len(events) != 1 || !strings.Contains(events[0].SQL, "INSERT INTO obs") || events[0].Rows != 1 {
		t.Fatalf("ExecArgs events = %+v, want one INSERT with Rows=1", events)
	}

	// Observed Tx, committed: each statement recorded, NO rollback marker.
	tx, err := conn.BeginObserved(ctx)
	if err != nil {
		t.Fatalf("BeginObserved: %v", err)
	}
	if _, err := tx.Exec(ctx, "UPDATE obs SET v = ? WHERE v = ?", "updated", secret); err != nil {
		t.Fatalf("tx.Exec: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	_ = tx.Rollback() // the deferred-safety-net pattern: after Commit it must emit nothing

	// Observed Tx, rolled back: the statement AND the ROLLBACK marker.
	tx, err = conn.BeginObserved(ctx)
	if err != nil {
		t.Fatalf("BeginObserved: %v", err)
	}
	if _, err := tx.Exec(ctx, "DELETE FROM obs WHERE v = ?", "updated"); err != nil {
		t.Fatalf("tx.Exec: %v", err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatalf("Rollback: %v", err)
	}

	// Prepared statement: N executions aggregate into ONE event with the
	// summed row count; Close is idempotent.
	tx, err = conn.BeginObserved(ctx)
	if err != nil {
		t.Fatalf("BeginObserved: %v", err)
	}
	stmt, err := tx.Prepare(ctx, "INSERT INTO obs (v) VALUES (?)")
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	for i := range 5 {
		if _, err := stmt.Exec(ctx, secret+string(rune('a'+i))); err != nil {
			t.Fatalf("stmt.Exec %d: %v", i, err)
		}
	}
	if err := stmt.Close(); err != nil {
		t.Fatalf("stmt.Close: %v", err)
	}
	_ = stmt.Close()
	if err := tx.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	var sqls []string
	for _, e := range rec.all() {
		sqls = append(sqls, e.SQL)
		if strings.Contains(e.SQL, secret) || (e.Err != nil && strings.Contains(e.Err.Error(), secret)) {
			t.Errorf("a bound argument value leaked into a statement event: %+v", e)
		}
	}
	want := []string{
		"INSERT INTO obs (v) VALUES (?)",
		"UPDATE obs SET v = ? WHERE v = ?",
		"DELETE FROM obs WHERE v = ?",
		"ROLLBACK",
		"INSERT INTO obs (v) VALUES (?)",
	}
	if len(sqls) != len(want) {
		t.Fatalf("events = %v, want %v", sqls, want)
	}
	for i := range want {
		if sqls[i] != want[i] {
			t.Errorf("event %d = %q, want %q", i, sqls[i], want[i])
		}
	}
	// The aggregate prepared event carries the summed count.
	if agg := rec.all()[4]; agg.Rows != 5 {
		t.Errorf("aggregated prepared event Rows = %d, want 5", agg.Rows)
	}
}

// TestObservedTxFailedCommitMarksRollback: a transaction whose COMMIT fails has
// had its work rolled back by the engine, and the trail must say so. A deferred
// foreign key surfaces its violation at COMMIT — the same shape a PostgreSQL
// deferred constraint or serialization failure takes on the importer/bulk-apply
// paths — and the deferred-Rollback safety net then sees sql.ErrTxDone, which
// used to suppress the ROLLBACK marker: the recorded statements read as applied.
// The marker must fire, carry the commit error, and fire exactly once.
func TestObservedTxFailedCommitMarksRollback(t *testing.T) {
	ctx := context.Background()
	conn, rec := observedConn(t)
	for _, ddl := range []string{
		"CREATE TABLE parent (id INTEGER PRIMARY KEY)",
		"CREATE TABLE child (id INTEGER PRIMARY KEY, pid INTEGER REFERENCES parent(id) DEFERRABLE INITIALLY DEFERRED)",
	} {
		if _, err := conn.DB().ExecContext(ctx, ddl); err != nil {
			t.Fatalf("seed %q: %v", ddl, err)
		}
	}
	rec.mu.Lock()
	rec.events = nil
	rec.mu.Unlock()

	tx, err := conn.BeginObserved(ctx)
	if err != nil {
		t.Fatalf("BeginObserved: %v", err)
	}
	st, err := tx.Prepare(ctx, "INSERT INTO child (pid) VALUES (?)")
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	for i := range 3 {
		if _, err := st.Exec(ctx, 900+i); err != nil {
			t.Fatalf("deferred-FK insert %d failed at exec time — this test needs the violation to surface at COMMIT: %v", i, err)
		}
	}
	commitErr := tx.Commit()
	if commitErr == nil {
		t.Fatal("Commit succeeded; the deferred FK did not defer, so this test proves nothing")
	}
	// The canonical caller unwind order (LIFO defers): the prepared statement's
	// Close runs BEFORE the rollback safety net, so the aggregate lands before
	// the marker and the trail reads work-then-undone, not undone-then-work.
	if err := st.Close(); err != nil {
		t.Fatalf("st.Close: %v", err)
	}
	_ = tx.Rollback()
	_ = tx.Rollback() // a second safety net must not double-mark

	events := rec.all()
	if len(events) != 2 {
		t.Fatalf("events = %+v, want exactly [aggregate INSERT, ROLLBACK]", events)
	}
	agg, mark := events[0], events[1]
	if !strings.Contains(agg.SQL, "INSERT INTO child") || agg.Rows != 3 || agg.Err != nil {
		t.Errorf("aggregate event = %+v, want the 3-row INSERT errorless", agg)
	}
	if mark.SQL != "ROLLBACK" {
		t.Fatalf("final event SQL = %q, want the ROLLBACK marker", mark.SQL)
	}
	if mark.Err == nil || !strings.Contains(mark.Err.Error(), commitErr.Error()) {
		t.Errorf("ROLLBACK marker Err = %v, want it to carry the commit error %q", mark.Err, commitErr)
	}
}

// TestExecScriptTxRollbackMarker: execScript's transactional branch is the
// OTHER observed transaction runner (the structure editor's multi-statement
// DDL, every PostgreSQL/SQLite DCL script), and it owes the trail the same
// ROLLBACK marker as the observed Tx — without it, a script whose statement 2
// fails leaves statement 1 in the trail reading as applied while the deferred
// rollback silently undoes it.
func TestExecScriptTxRollbackMarker(t *testing.T) {
	ctx := context.Background()
	conn, rec := observedConn(t)

	// The shown case first: a script that commits emits NO marker.
	if err := conn.ExecScript(ctx, []string{"INSERT INTO obs (v) VALUES ('kept')"}, true); err != nil {
		t.Fatalf("committing script: %v", err)
	}
	for _, e := range rec.all() {
		if e.SQL == "ROLLBACK" {
			t.Fatalf("a committed script emitted a ROLLBACK marker: %+v", rec.all())
		}
	}
	rec.mu.Lock()
	rec.events = nil
	rec.mu.Unlock()

	err := conn.ExecScript(ctx, []string{
		"INSERT INTO obs (v) VALUES ('undone')",
		"INSERT INTO no_such_table (v) VALUES ('x')",
	}, true)
	if err == nil {
		t.Fatal("script unexpectedly succeeded")
	}
	events := rec.all()
	if len(events) != 3 {
		t.Fatalf("events = %+v, want [ok INSERT, failed INSERT, ROLLBACK]", events)
	}
	if events[0].Err != nil || events[1].Err == nil {
		t.Errorf("statement errors misplaced: first = %v, second = %v", events[0].Err, events[1].Err)
	}
	if events[2].SQL != "ROLLBACK" || events[2].Err != nil {
		t.Errorf("final event = %+v, want a plain ROLLBACK marker (the failing statement already carries its own error)", events[2])
	}
	// The marker tells the truth: the first statement's row is gone.
	var n int
	if err := conn.DB().QueryRowContext(ctx, "SELECT COUNT(*) FROM obs WHERE v = 'undone'").Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 0 {
		t.Errorf("rolled-back row still present (n=%d); the marker would be lying the other way", n)
	}
}
