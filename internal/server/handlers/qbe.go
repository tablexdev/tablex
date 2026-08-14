package handlers

import (
	"context"
	"net/http"
	"slices"
	"strings"

	"github.com/tablexdev/tablex/internal/driver"
	"github.com/tablexdev/tablex/internal/model"
)

// qbeColumn is one column's query-by-example state: whether to project it and an
// optional per-column criterion (operator + value).
type qbeColumn struct {
	Column model.Column
	Show   bool
	Op     string
	Value  string
}

type qbeBody struct {
	Scope   reqScope
	PostURL string
	Tables  []string
	Table   string
	Columns []qbeColumn
	Ran     bool
	Result  *driver.ResultSet
	SQL     string
	Error   string
}

const qbeRowCap = 500

// DBQBE is a single-table query-by-example builder (GET form, POST run): pick a
// table, choose which columns to project and per-column criteria, and run a
// parameterized SELECT. It reuses the Search operator whitelist and the same
// parameter-binding/LIKE-escaping rules — no value is ever concatenated.
func (h *Handlers) DBQBE(w http.ResponseWriter, r *http.Request) {
	uc, sc, conn, ok := h.requireConn(w, r)
	if !ok {
		return
	}
	body := qbeBody{Scope: sc, PostURL: urlDB(sc.DB, sc.Schema, "qbe")}

	// Base-table choices.
	if list, err := h.tableNames(r.Context(), conn, sc.scope()); err == nil {
		for _, t := range list {
			if !t.IsView() && !t.IsSequence() {
				body.Tables = append(body.Tables, t.Name)
			}
		}
	} else {
		h.Log.Warn("qbe: list tables", "err", err, "reqid", RequestID(r.Context()))
	}

	// The chosen table comes from the form (POST) or the query (GET); it must be a
	// real base table before any of its columns are referenced.
	var table string
	if r.Method == http.MethodPost {
		if !h.parseFormOr400(w, r) {
			return
		}
		table = strings.TrimSpace(r.PostFormValue("table"))
	} else {
		table = strings.TrimSpace(r.URL.Query().Get("table"))
	}
	if table != "" && slices.Contains(body.Tables, table) {
		body.Table = table
		ref := driver.TableRef{Database: sc.DB, Schema: sc.Schema, Table: table}
		// A selected table's columns must load to build (or run) the form. Unlike
		// the table-list load above (warning-only, so the empty form still renders),
		// a failure here is surfaced — the form cannot render without them.
		cols, err := conn.Columns(r.Context(), ref)
		if err != nil {
			h.dbError(w, r, err, "")
			return
		}
		for _, c := range cols {
			qc := qbeColumn{Column: c, Op: "=", Show: r.Method != http.MethodPost}
			if r.Method == http.MethodPost {
				qc.Show = r.PostForm["show_"+c.Name] != nil
				if op := strings.ToUpper(strings.TrimSpace(r.PostFormValue("op_" + c.Name))); searchOperators[op] {
					qc.Op = op
				}
				qc.Value = strings.TrimSpace(r.PostFormValue("val_" + c.Name))
			}
			body.Columns = append(body.Columns, qc)
		}
		if r.Method == http.MethodPost {
			h.runQBE(r.Context(), conn, ref, &body)
		}
	}

	p := h.newLoggedPage(r, uc, sc.DB+" · Query")
	p.Breadcrumb = h.buildBreadcrumb(uc, sc)
	p.Tabs = h.dbTabs(uc, sc, "qbe")
	p.Body = body
	h.render(w, r, "qbe", p)
}

// runQBE builds and executes the QBE SELECT from the (already validated) column
// criteria in body.Columns.
func (h *Handlers) runQBE(ctx context.Context, conn *driver.Connection, ref driver.TableRef, body *qbeBody) {
	d := conn.Dialect()
	sb := newSQLBuilder(d)
	var projected []string
	conds := 0
	for _, qc := range body.Columns {
		if qc.Show {
			projected = append(projected, d.QuoteIdent(qc.Column.Name))
		}
		if qc.Value == "" {
			continue
		}
		if conds > 0 {
			sb.raw(" AND ")
		}
		sb.condition(conn, qc.Column, qc.Op, qc.Value)
		conds++
	}
	sel := "*"
	if len(projected) > 0 {
		sel = strings.Join(projected, ", ")
	}
	query := "SELECT " + sel + " FROM " + conn.QualifiedName(ref)
	if conds > 0 {
		query += " WHERE " + sb.String()
	}
	// Fetch one more than the display cap so ScanResult(cap) can detect (and flag
	// as Truncated) that more rows exist — a LIMIT == cap would never trip it.
	query += " " + d.LimitClause(qbeRowCap+1, 0)
	body.SQL = query
	body.Ran = true
	// Generated read: time-bound it (this site binds args, so it bypasses the
	// Connection.Query wrapper).
	ctx, cancel := conn.WithReadTimeout(ctx)
	defer cancel()
	rows, err := conn.DB().QueryContext(ctx, query, sb.args...)
	if err != nil {
		body.Error = err.Error()
		return
	}
	rs, err := driver.ScanResult(rows, qbeRowCap)
	if err != nil {
		body.Error = err.Error()
		return
	}
	body.Result = rs
}
