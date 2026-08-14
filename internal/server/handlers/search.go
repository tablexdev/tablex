package handlers

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/tablexdev/tablex/internal/driver"
	"github.com/tablexdev/tablex/internal/model"
)

// dbSearchBudget bounds the whole-database search, which runs a COUNT(*) per
// table; without it a search over a large schema could run unbounded.
const dbSearchBudget = 20 * time.Second

// likeContains builds a "contains" LIKE pattern, escaping the LIKE
// metacharacters %, _ and the escape character itself with '|' so a user's
// literal % or _ matches itself. Callers MUST emit `LIKE ? ESCAPE '|'`: SQLite
// (the primary tested engine) has no default LIKE escape, and MySQL's own docs
// use ESCAPE '|', so a non-backslash escape works across all three engines.
//
// It performs no case folding of its own, and deliberately: LIKE's case
// sensitivity is the ENGINE's, decided by the column's collation, so a search
// behaves like every other comparison against that column. In practice that
// means MySQL/MariaDB and SQLite match case-INSENSITIVELY under their usual
// collations (SQLite for ASCII only), while PostgreSQL matches case-SENSITIVELY
// unless the column is citext or a case-insensitive ICU collation. Folding both
// sides with lower() would contradict MySQL's own semantics and put a function
// on the column, defeating any index the predicate could otherwise use.
func likeContains(term string) string {
	r := strings.NewReplacer("|", "||", "%", "|%", "_", "|_")
	return "%" + r.Replace(term) + "%"
}

// searchOperators is the whitelist of comparison operators the search form may
// use; anything else is rejected (operators are never taken raw from input).
var searchOperators = map[string]bool{
	"=": true, "!=": true, "<": true, "<=": true, ">": true, ">=": true,
	"LIKE": true, "NOT LIKE": true,
}

// searchColumn is one column's search state, carrying the submitted operator and
// value so the form stays sticky after a POST (mirrors the QBE builder).
type searchColumn struct {
	Column model.Column
	Op     string
	Value  string
}

type tableSearchBody struct {
	Scope   reqScope
	Columns []searchColumn
	PostURL string
	Ran     bool
	Result  *driver.ResultSet
	SQL     string
	Error   string
}

// TableSearch searches a table by per-column conditions (GET form, POST run).
func (h *Handlers) TableSearch(w http.ResponseWriter, r *http.Request) {
	uc, sc, conn, ok := h.requireConn(w, r)
	if !ok {
		return
	}
	if !h.requireDataTable(w, r, conn, sc) {
		return
	}
	cols, err := conn.Columns(r.Context(), sc.tableRef())
	if err != nil {
		h.dbError(w, r, err, "")
		return
	}
	scols := make([]searchColumn, len(cols))
	for i, c := range cols {
		scols[i] = searchColumn{Column: c, Op: "="}
	}
	body := tableSearchBody{
		Scope:   sc,
		Columns: scols,
		PostURL: urlTable(sc.DB, sc.Schema, sc.Table, "search"),
	}

	if r.Method == http.MethodPost {
		if !h.parseFormOr400(w, r) {
			return
		}
		sb := newSQLBuilder(conn.Dialect())
		conds := 0
		for i, c := range cols {
			op := strings.ToUpper(strings.TrimSpace(r.PostFormValue("op_" + c.Name)))
			if !searchOperators[op] {
				op = "="
			}
			val := strings.TrimSpace(r.PostFormValue("val_" + c.Name))
			scols[i].Op, scols[i].Value = op, val // keep the form sticky after submit
			if val == "" {
				continue
			}
			if conds > 0 {
				sb.raw(" AND ")
			}
			sb.condition(conn, c, op, val)
			conds++
		}
		query := "SELECT * FROM " + conn.QualifiedName(sc.tableRef())
		if conds > 0 {
			query += " WHERE " + sb.String()
		}
		// Fetch one more than the display cap so ScanResult(500) can flag the
		// result as truncated — a LIMIT == scan cap would never trip it.
		query += " " + conn.Dialect().LimitClause(501, 0)
		body.SQL = query
		// Generated read: time-bound it like the Connection wrappers (this site
		// binds args, so it can't use Connection.Query).
		qctx, cancel := conn.WithReadTimeout(r.Context())
		rows, err := conn.DB().QueryContext(qctx, query, sb.args...)
		if err != nil {
			body.Error = err.Error()
		} else if rs, err := driver.ScanResult(rows, 500); err != nil {
			body.Error = err.Error()
		} else {
			body.Result = rs
		}
		cancel()
		body.Ran = true
	}

	p := h.newLoggedPage(r, uc, sc.Table+" · Search")
	p.Breadcrumb = h.buildBreadcrumb(uc, sc)
	p.Tabs = h.tableTabs(r.Context(), uc, sc, "search", conn)
	p.Body = body
	h.render(w, r, "table_search", p)
}

type dbSearchHit struct {
	Table     string
	Count     int64
	BrowseURL string
}

type dbSearchBody struct {
	Scope   reqScope
	Term    string
	PostURL string
	Ran     bool
	Hits    []dbSearchHit
	Total   int64
	Partial bool // the search budget expired before every table was scanned
	Skipped int  // tables that errored (permission/connectivity) and were skipped
}

// DBSearch searches every table's text columns for a term (GET form, POST run),
// reporting per-table match counts.
func (h *Handlers) DBSearch(w http.ResponseWriter, r *http.Request) {
	uc, sc, conn, ok := h.requireConn(w, r)
	if !ok {
		return
	}
	body := dbSearchBody{Scope: sc, PostURL: urlDB(sc.DB, sc.Schema, "search")}

	if r.Method == http.MethodPost {
		if !h.parseFormOr400(w, r) {
			return
		}
		term := strings.TrimSpace(r.PostFormValue("term"))
		body.Term = term
		body.Ran = true
		if term != "" {
			// Bound the whole sweep so a search over a large schema can't run away.
			ctx, cancel := context.WithTimeout(r.Context(), dbSearchBudget)
			defer cancel()
			tables, err := h.tableNames(ctx, conn, sc.scope())
			if err != nil {
				h.dbError(w, r, err, "")
				return
			}
			// Bulk fast path (driver.BulkIntrospector): one schema-wide columns
			// query instead of one per table (two per table on PostgreSQL). A bulk
			// FAILURE is NOT fatal — useBulk stays false and the loop falls back to
			// the per-table Columns call below, whose existing partial-failure
			// handling (Skipped / Partial) then reports it. This mirrors Designer's
			// degrade exactly; treating a bulk error as fatal would turn one bad
			// table into a total search failure.
			bulkCols, haveBulk, errBulk := conn.BulkColumns(ctx, sc.scope())
			useBulk := haveBulk && errBulk == nil
			for _, t := range tables {
				if ctx.Err() != nil {
					body.Partial = true
					break
				}
				if t.IsView() || t.IsSequence() {
					continue
				}
				ref := driver.TableRef{Database: sc.DB, Schema: sc.Schema, Table: t.Name}
				cols, err := searchTableCols(ctx, conn, bulkCols, useBulk, ref)
				if err != nil {
					// A mid-call budget timeout means "ran out of time", not a skip:
					// the top-of-loop guard would otherwise mis-attribute it to
					// Skipped (and miss it entirely on the last table). Report Partial
					// and stop, matching the top-of-loop guard.
					if errors.Is(err, context.DeadlineExceeded) {
						body.Partial = true
						break
					}
					// A permission/connectivity failure here must not look like
					// "no matches" — count it so the UI can say so.
					body.Skipped++
					continue
				}
				sb := newSQLBuilder(conn.Dialect())
				n := 0
				for _, c := range cols {
					if c.IsNumeric() || isTemporalType(c) {
						continue
					}
					if n > 0 {
						sb.raw(" OR ")
					}
					// LIKE via the shared builder: SearchExpr (PG: ::text cast) keeps
					// uuid/json/bool/enum/inet/array columns from erroring the whole
					// table's COUNT query (which silently dropped the table from the
					// results), and it re-applies likeContains to the term per column.
					sb.condition(conn, c, "LIKE", term)
					n++
				}
				if n == 0 {
					continue
				}
				q := "SELECT COUNT(*) FROM " + conn.QualifiedName(ref) + " WHERE " + sb.String()
				var count int64
				if err := conn.DB().QueryRowContext(ctx, q, sb.args...).Scan(&count); err != nil {
					if errors.Is(err, context.DeadlineExceeded) {
						body.Partial = true
						break
					}
					body.Skipped++
					continue
				}
				if count > 0 {
					body.Hits = append(body.Hits, dbSearchHit{Table: t.Name, Count: count, BrowseURL: urlTable(sc.DB, sc.Schema, t.Name, "browse")})
					body.Total += count
				}
			}
		}
	}

	p := h.newLoggedPage(r, uc, sc.DB+" · Search")
	p.Breadcrumb = h.buildBreadcrumb(uc, sc)
	p.Tabs = h.dbTabs(uc, sc, "search")
	p.Body = body
	h.render(w, r, "db_search", p)
}

// searchTableCols resolves one table's columns for the database search: the
// bulk map when it covers the table, the per-table read otherwise — INCLUDING
// a table the bulk snapshot misses (dropped or renamed between the listing
// and the bulk query, or a zero-column relation). Without that fallback a
// missing entry read as nil columns with a nil error, so the table silently
// vanished from the results as "no text columns" while the Skipped/Partial
// accounting — the whole reason the per-table path discriminates its errors —
// never heard about it.
func searchTableCols(ctx context.Context, conn *driver.Connection, bulkCols map[string][]model.Column, useBulk bool, ref driver.TableRef) ([]model.Column, error) {
	if useBulk {
		if cols, ok := bulkCols[ref.Table]; ok {
			return cols, nil
		}
	}
	return conn.Columns(ctx, ref)
}
