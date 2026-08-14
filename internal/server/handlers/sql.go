package handlers

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/tablexdev/tablex/internal/driver"
	"github.com/tablexdev/tablex/internal/sqlscript"
)

const consoleRowCap = 1000

// consoleMaxResults bounds how many per-statement results the interactive
// console keeps (and the template re-renders). A script with more statements
// still runs in full — only the displayed detail is capped, with a
// "showing first N of M" note. The import path keeps no per-statement result at
// all (see runRestoreScript / importResult).
const consoleMaxResults = 100

// consoleResult is the outcome of one executed statement.
type consoleResult struct {
	SQL      string
	Set      *driver.ResultSet
	IsQuery  bool
	Affected int64
	Duration string
	Error    string
}

type consoleBody struct {
	Scope   reqScope
	Level   string // server | db | table
	Query   string
	Results []consoleResult
	Total   int // statements executed (>= len(Results) when capped)
	History []string
	PostURL string
	Ran     bool
}

// ServerSQL is the server-level SQL console (GET/POST /server/sql).
func (h *Handlers) ServerSQL(w http.ResponseWriter, r *http.Request) { h.console(w, r, "server") }

// DBSQL is the database-level SQL console (GET/POST /db/{db}/sql).
func (h *Handlers) DBSQL(w http.ResponseWriter, r *http.Request) { h.console(w, r, "db") }

// TableSQL is the table-level SQL console (GET/POST /db/{db}/table/{t}/sql).
func (h *Handlers) TableSQL(w http.ResponseWriter, r *http.Request) { h.console(w, r, "table") }

// console renders and runs the SQL console at the given level. The console
// executes the user's own SQL under their own credentials — the widest of the
// intentional places raw user SQL reaches the database. The others are SQL
// import, a stored program's body, and a partial index's WHERE predicate;
// allow_console = false closes all four. See docs/security.md §4.
func (h *Handlers) console(w http.ResponseWriter, r *http.Request, level string) {
	uc, ok := h.requireUser(w, r)
	if !ok {
		return
	}
	sc := h.resolveScope(r).withSchemaDefault(uc.Capabilities())
	ctx := r.Context()

	conn := uc.ServerConn()
	var err error
	if level != "server" && sc.DB != "" {
		conn, err = uc.ConnFor(ctx, sc.DB)
		if err != nil {
			h.connError(w, r, uc, err)
			return
		}
	}
	if level == "table" && !h.requireDataTable(w, r, conn, sc) {
		return
	}

	postURL, title, tabs := h.levelChrome(ctx, uc, sc, level, "sql", "SQL", conn)
	body := consoleBody{Scope: sc, Level: level, History: uc.History(), PostURL: postURL}

	// Initial query: prefill from a query param, or a sensible default for tables.
	body.Query = r.URL.Query().Get("sql_query")
	if body.Query == "" && level == "table" && r.Method == http.MethodGet {
		body.Query = "SELECT * FROM " + conn.QualifiedName(sc.tableRef()) + "\n" +
			conn.Dialect().LimitClause(100, 0) + ";"
	}

	if r.Method == http.MethodPost {
		// Gate on a bounded, 413-aware parse so an oversized or malformed body
		// surfaces an error instead of silently reading sql_query as "" (an htmx
		// console POST carries its token in the X-CSRF-Token header, so the csrf
		// middleware did not pre-parse the body).
		if !h.parseFormOr400(w, r) {
			return
		}
		script := strings.TrimSpace(r.PostFormValue("sql_query"))
		body.Query = script
		if script != "" {
			// Scripts run on a dedicated pinned connection: session-scoped SETs
			// apply to every following statement and are discarded afterwards
			// instead of leaking back into the shared pool.
			db := ""
			if level != "server" {
				db = sc.DB
			}
			// A pinned connection is private and sits outside PoolBudget; reserve
			// an in-flight slot so parallel scripts cannot exhaust the database's
			// max_connections. Held for the whole script, not just the dial.
			release, ok := h.acquireDBOp(w, r)
			if !ok {
				return
			}
			defer release()
			pinned, err := uc.PinnedFor(ctx, db)
			if err != nil {
				h.connError(w, r, uc, err)
				return
			}
			// Deferred so a panic in the runner cannot permanently leak the
			// checked-out connection (the recover keeps the process alive).
			defer pinned.Close()
			if r.PostFormValue("explain") != "" {
				body.Results, body.Total = h.runExplain(ctx, uc, pinned, script)
			} else {
				body.Results, body.Total = h.runConsole(ctx, uc, pinned, script)
			}
			body.Ran = true
			uc.AddHistory(script)
			body.History = uc.History()
		}
	}

	p := h.newLoggedPage(r, uc, title)
	p.Breadcrumb = h.buildBreadcrumb(uc, sc)
	p.Tabs = tabs
	p.NeedsEditor = true // this page carries a textarea.tx-sql-editor
	p.Body = body
	h.render(w, r, "sql_console", p)
}

// scriptConn is the connection surface the console/import script runner
// needs. Both *driver.Connection and *driver.Pinned satisfy it; scripts run
// on a Pinned connection (see PinnedFor) so session-scoped state sticks to
// the script and dies with it. Dialect feeds the splitter's lexer profile
// (driver.ProfileOf) — the runner never branches on an engine name.
type scriptConn interface {
	Dialect() driver.Dialect
	Query(ctx context.Context, query string, limit int) (*driver.ResultSet, error)
	Exec(ctx context.Context, query string) (driver.ExecResult, error)
	Explain(ctx context.Context, query string, analyze bool) (*driver.ResultSet, error)
	ExplainSQL(query string, analyze bool) (string, bool)
}

// metaCommandResult is the shared rejection for a psql meta-command that reaches
// the SQL engine (only \connect is honored, and only by the server-scope import
// before the script reaches here).
func metaCommandResult(stmt string) consoleResult {
	return consoleResult{SQL: stmt, Error: `psql meta-commands are not supported here (only \connect, in a server-scope import)`}
}

// statementRunner executes one statement and reports the outcome. The console,
// EXPLAIN and the import path each supply one, and h.budgeted wraps whichever is
// chosen with the session's query budget.
type statementRunner func(ctx context.Context, conn scriptConn, stmt string) consoleResult

// forEachStatement splits script and runs each statement on conn, invoking fn
// with the outcome, stopping at the first error (or an unhandled psql
// meta-command). It accumulates nothing itself, so the caller decides how much
// to retain — the interactive console keeps a capped slice, the import path
// keeps only running totals. onMarker, when non-nil, receives each validated
// TableX db-collation marker at its position in the stream (the import path
// verifies these against the target database; the console passes nil and the
// markers stay inert comments). Returns the number of statements processed.
func forEachStatement(ctx context.Context, conn scriptConn, script string, max int, run statementRunner, fn func(consoleResult), onMarker func(driver.DumpMarker)) (int, error) {
	total := 0
	// Lexed WHOLE and up front, so the cap has to be applied here rather than as
	// the loop runs: by the time the first statement executes the entire slice
	// already exists. An over-limit script runs nothing at all.
	events, err := sqlscript.ScanLimit(script, driver.ProfileOf(conn.Dialect()), max)
	if err != nil {
		return 0, err
	}
	for _, ev := range events {
		if ev.Marker != nil {
			if onMarker != nil {
				onMarker(*ev.Marker)
			}
			continue
		}
		stmt := ev.Stmt
		total++
		if strings.HasPrefix(stmt, `\`) {
			fn(metaCommandResult(stmt))
			break
		}
		res := run(ctx, conn, stmt)
		fn(res)
		if res.Error != "" {
			break
		}
	}
	return total, nil
}

// scriptTooLong renders an over-limit script as a single failed result. It is
// the same shape a rejected statement takes, so the console and the import page
// both surface it without a second path — and it is the whole script's refusal,
// not a per-statement one: nothing was executed.
func (h *Handlers) scriptTooLong(err error) consoleResult {
	if !errors.Is(err, sqlscript.ErrTooManyStatements) {
		return consoleResult{Error: err.Error()}
	}
	return consoleResult{Error: fmt.Sprintf(
		"This script contains more than %d statements (max_script_statements), so it was not run. Split it into smaller files.",
		h.Cfg.MaxScriptStatements)}
}

// execConsoleStatement runs one statement, choosing Query vs Exec by classifier.
func execConsoleStatement(ctx context.Context, conn scriptConn, stmt string) consoleResult {
	res := consoleResult{SQL: stmt}
	start := time.Now()
	if sqlscript.IsQuery(stmt, driver.ProfileOf(conn.Dialect())) {
		rs, err := conn.Query(ctx, stmt, consoleRowCap)
		if err != nil {
			res.Error = err.Error()
		} else {
			res.Set = rs
			res.IsQuery = true
		}
	} else {
		er, err := conn.Exec(ctx, stmt)
		if err != nil {
			res.Error = err.Error()
		} else {
			res.Affected = er.RowsAffected
		}
	}
	res.Duration = time.Since(start).Round(time.Millisecond).String()
	return res
}

// execExplainStatement runs EXPLAIN for one statement.
func execExplainStatement(ctx context.Context, conn scriptConn, stmt string) consoleResult {
	// Label the result with the statement actually executed (e.g. SQLite's
	// "EXPLAIN QUERY PLAN …"), not a generic "EXPLAIN …" that never ran.
	label := "EXPLAIN " + stmt
	if s, ok := conn.ExplainSQL(stmt, false); ok {
		label = s
	}
	res := consoleResult{SQL: label}
	start := time.Now()
	rs, err := conn.Explain(ctx, stmt, false)
	if err != nil {
		res.Error = err.Error()
	} else {
		res.Set = rs
		res.IsQuery = true
	}
	res.Duration = time.Since(start).Round(time.Millisecond).String()
	return res
}

// budgeted wraps a statement runner with the session's query budget
// (config session_query_budget), or returns it unchanged when no budget is
// configured — so the default deployment does not so much as read a clock.
//
// It wraps the RUNNER rather than gating the request, which is what makes the
// refusal land in the one channel every caller already handles: a spent budget
// becomes that statement's error, so the console shows it beside the statements
// that did run, forEachStatement stops there exactly as it does on a SQL error,
// and the import path records it as the failure it is. A script is therefore
// truncated at the budget, never silently dropped whole.
//
// What is charged is SQL the user WROTE — the console, EXPLAIN, a SQL import.
// Generated reads are not: one page render costs several introspection queries,
// so charging them would spend a browsing user's budget on navigation, and they
// are already bounded per request by read_stmt_timeout and the pool caps.
func (h *Handlers) budgeted(uc *UserContext, run statementRunner) statementRunner {
	limit, window := h.Cfg.SessionQueryBudget, h.Cfg.SessionQueryWindow
	if limit <= 0 || window <= 0 {
		return run
	}
	return func(ctx context.Context, conn scriptConn, stmt string) consoleResult {
		retryAfter, ok := uc.queries.charge(limit, window)
		if ok {
			return run(ctx, conn, stmt)
		}
		h.Counters.recordQueryBudgetRefused()
		// The setting is named for the same reason restricted mode names its own:
		// the limit is the operator's, and a user who cannot see which knob to ask
		// about reads this as TableX being broken.
		return consoleResult{SQL: stmt, Error: fmt.Sprintf(
			"This session has used its budget of %d statements per %s (session_query_budget). Try again in %s.",
			limit, window, retryAfter.Round(time.Second).String())}
	}
}

// runExplain runs EXPLAIN for each statement, keeping at most consoleMaxResults
// (the second return is the true statement total). All built-in engines support
// EXPLAIN; conn.Explain returns ErrUnsupported otherwise, surfaced per statement.
func (h *Handlers) runExplain(ctx context.Context, uc *UserContext, conn scriptConn, script string) ([]consoleResult, int) {
	var results []consoleResult
	total, err := forEachStatement(ctx, conn, script, h.Cfg.MaxScriptStatements, h.budgeted(uc, execExplainStatement), func(res consoleResult) {
		if len(results) < consoleMaxResults {
			results = append(results, res)
		}
	}, nil)
	if err != nil {
		return []consoleResult{h.scriptTooLong(err)}, 0
	}
	return results, total
}

// runConsole executes each statement, stopping at the first error, keeping at
// most consoleMaxResults per-statement results (the second return is the true
// total, so the template can note "showing first N of M").
func (h *Handlers) runConsole(ctx context.Context, uc *UserContext, conn scriptConn, script string) ([]consoleResult, int) {
	var results []consoleResult
	total, err := forEachStatement(ctx, conn, script, h.Cfg.MaxScriptStatements, h.budgeted(uc, execConsoleStatement), func(res consoleResult) {
		if len(results) < consoleMaxResults {
			results = append(results, res)
		}
	}, nil)
	if err != nil {
		return []consoleResult{h.scriptTooLong(err)}, 0
	}
	return results, total
}
