package handlers

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/tablexdev/tablex/internal/driver"
)

// fakeScriptConn is a scriptConn stub for the console/import runners: every Exec
// reports 1 row affected; a statement containing "BOOM" errors. Query/Explain
// are unused by these tests (all statements are non-query DML).
type fakeScriptConn struct{ engine string }

func (f fakeScriptConn) Dialect() driver.Dialect {
	d, ok := driver.Get(f.engine)
	if !ok {
		panic("fakeScriptConn: dialect not registered: " + f.engine)
	}
	return d
}
func (f fakeScriptConn) Query(context.Context, string, int) (*driver.ResultSet, error) {
	return &driver.ResultSet{}, nil
}
func (f fakeScriptConn) Exec(_ context.Context, q string) (driver.ExecResult, error) {
	if strings.Contains(q, "BOOM") {
		return driver.ExecResult{}, errors.New("boom")
	}
	return driver.ExecResult{RowsAffected: 1}, nil
}
func (f fakeScriptConn) Explain(context.Context, string, bool) (*driver.ResultSet, error) {
	return &driver.ResultSet{}, nil
}
func (f fakeScriptConn) ExplainSQL(query string, _ bool) (string, bool) {
	return "EXPLAIN " + query, true
}

// TestRunConsoleCapsResults covers: the interactive console runs every
// statement but keeps at most consoleMaxResults per-statement results, reporting
// the true total so the template can note "showing first N of M".
func TestRunConsoleCapsResults(t *testing.T) {
	var h Handlers
	var b strings.Builder
	const n = consoleMaxResults + 50
	for i := 0; i < n; i++ {
		b.WriteString("DELETE FROM t;\n")
	}
	results, total := h.runConsole(context.Background(), &UserContext{}, fakeScriptConn{engine: "sqlite"}, b.String())
	if total != n {
		t.Errorf("total = %d, want %d", total, n)
	}
	if len(results) != consoleMaxResults {
		t.Errorf("kept %d results, want cap %d", len(results), consoleMaxResults)
	}
}

// TestRunConsoleStopsAtError confirms stop-at-first-error and the reported total.
func TestRunConsoleStopsAtError(t *testing.T) {
	var h Handlers
	script := "DELETE FROM a;\nDELETE FROM BOOM;\nDELETE FROM c;\n"
	results, total := h.runConsole(context.Background(), &UserContext{}, fakeScriptConn{engine: "sqlite"}, script)
	if total != 2 { // stops after the failing second statement
		t.Errorf("total = %d, want 2", total)
	}
	if len(results) == 0 || results[len(results)-1].Error == "" {
		t.Errorf("expected the last kept result to carry the error, got %+v", results)
	}
}

// TestSummarizeImport covers the aggregate import summary and its failure class.
func TestSummarizeImport(t *testing.T) {
	ok := summarizeImport(importResult{Statements: 12, Affected: 34})
	if ok.Failed || !strings.Contains(ok.Message, "12 statement") || !strings.Contains(ok.Message, "34 row") {
		t.Errorf("success summary = %+v", ok)
	}
	bad := summarizeImport(importResult{Statements: 3, Failed: true, Error: "boom", ErrorSQL: "DELETE FROM BOOM"})
	if !bad.Failed || !strings.Contains(bad.Message, "boom") || bad.Detail != "DELETE FROM BOOM" {
		t.Errorf("failure summary = %+v", bad)
	}
}

// countingScriptConn records every statement that reached Exec, so a test can
// assert that an over-limit script ran NOTHING rather than a prefix.
type countingScriptConn struct {
	fakeScriptConn
	ran *int
}

func (c countingScriptConn) Exec(ctx context.Context, q string) (driver.ExecResult, error) {
	*c.ran++
	return c.fakeScriptConn.Exec(ctx, q)
}

// TestScriptStatementCapRefusesWholeScript covers M1. The splitter materializes
// every statement of a script BEFORE the first one runs, so a 128 MiB upload of
// bare `a;` is tens of millions of entries and over a gigabyte of slice — and a
// Go allocation failure is not something the panic middleware can recover.
//
// A count cap is only a fix if it FAILS CLOSED. Truncating would execute a
// prefix, which for an import means committing half a restore: worse than the
// exhaustion it prevents. So the assertion that matters is not "it was refused"
// but "nothing ran".
func TestScriptStatementCapRefusesWholeScript(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 10; i++ {
		b.WriteString("DELETE FROM t;\n")
	}
	script := b.String()

	h := &Handlers{}
	h.Cfg.MaxScriptStatements = 4
	ran := 0
	conn := countingScriptConn{fakeScriptConn{engine: "sqlite"}, &ran}

	results, total := h.runConsole(context.Background(), &UserContext{}, conn, script)
	if ran != 0 {
		t.Errorf("%d statements executed before the script was refused; an over-limit script must run none", ran)
	}
	if total != 0 {
		t.Errorf("total = %d, want 0", total)
	}
	if len(results) != 1 || results[0].Error == "" {
		t.Fatalf("expected one failed result carrying the refusal, got %+v", results)
	}
	// The message names the setting, so an operator can raise it.
	if !strings.Contains(results[0].Error, "max_script_statements") {
		t.Errorf("refusal does not name the setting: %q", results[0].Error)
	}

	// Under the cap nothing changes, including at the limit exactly.
	h.Cfg.MaxScriptStatements = 10
	ran = 0
	if _, total := h.runConsole(context.Background(), &UserContext{}, conn, script); total != 10 || ran != 10 {
		t.Errorf("at the limit: total = %d, executed = %d; want 10 and 10", total, ran)
	}
	// And <= 0 removes the cap, matching every other cap in the config.
	h.Cfg.MaxScriptStatements = 0
	ran = 0
	if _, total := h.runConsole(context.Background(), &UserContext{}, conn, script); total != 10 || ran != 10 {
		t.Errorf("uncapped: total = %d, executed = %d; want 10 and 10", total, ran)
	}
}
