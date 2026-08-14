package handlers

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/tablexdev/tablex/internal/driver"
	"github.com/tablexdev/tablex/internal/model"
	"github.com/tablexdev/tablex/internal/view"
)

// errRowNotFound signals that a row-identity WHERE matched no row — the row was
// deleted or changed since the browse grid was rendered.
var errRowNotFound = errors.New("the row no longer exists")

// sqlBuilder accumulates a parameterized statement with engine-correct
// placeholders ("?" or "$n"). Values always go through param() so they are
// bound, never concatenated; identifiers go through ident() (QuoteIdent).
type sqlBuilder struct {
	d    driver.Dialect
	b    strings.Builder
	args []any
}

func newSQLBuilder(d driver.Dialect) *sqlBuilder { return &sqlBuilder{d: d} }
func (s *sqlBuilder) raw(str string)             { s.b.WriteString(str) }
func (s *sqlBuilder) ident(name string)          { s.b.WriteString(s.d.QuoteIdent(name)) }
func (s *sqlBuilder) param(v any) {
	s.args = append(s.args, v)
	s.b.WriteString(s.d.Placeholder(len(s.args)))
}
func (s *sqlBuilder) String() string { return s.b.String() }

// condition appends a single parameterized "<col> <op> <value>" predicate. LIKE
// and NOT LIKE route through the dialect SearchExpr with a "contains" pattern
// (case sensitivity is the column collation's — see likeContains) and ESCAPE
// '|' — so PostgreSQL casts LIKE-incompatible
// column types (uuid/json/bool/enum/inet/array) to ::text and a literal %/_ in
// the value matches itself rather than acting as a wildcard. Everything else
// quotes the identifier and binds a type-coerced value. This keeps the
// SearchExpr/ESCAPE invariant — shared by TableSearch, DBSearch and QBE — in one
// place; the caller emits any AND/OR separator before calling.
func (s *sqlBuilder) condition(conn *driver.Connection, col model.Column, op, val string) {
	if op == "LIKE" || op == "NOT LIKE" {
		s.raw(conn.SearchExpr(col.Name))
		s.raw(" " + op + " ")
		s.param(likeContains(val))
		s.raw(" ESCAPE '|'")
		return
	}
	s.ident(col.Name)
	s.raw(" " + op + " ")
	s.param(coerceValue(col, val))
}

// colSet indexes columns by name for O(1) validation.
func colSet(cols []model.Column) map[string]model.Column {
	m := make(map[string]model.Column, len(cols))
	for _, c := range cols {
		m[c.Name] = c
	}
	return m
}

// coerceValue converts a textual form/key value to a Go type appropriate for the
// column, so strict drivers (pgx) bind it correctly. Unparseable values fall
// back to the string (the engine reports a clear error if truly invalid).
//
// The integer/float spellings here (including the PostgreSQL aliases, reachable
// via SQLite's verbatim declared-type names — see model.Column.IsNumeric) mirror
// that predicate but are intentionally NOT the same list: decimal/numeric/dec/
// fixed/money are omitted here on purpose so they bind as strings and preserve
// full precision (a float64 round-trip would lose it). Do not merge the two.
func coerceValue(c model.Column, s string) any {
	switch c.BaseType {
	case "tinyint", "smallint", "mediumint", "int", "integer", "bigint",
		"int2", "int4", "int8", "serial", "bigserial", "smallserial":
		if n, err := strconv.ParseInt(s, 10, 64); err == nil {
			return n
		}
	case "bool", "boolean":
		if b, err := strconv.ParseBool(s); err == nil {
			return b
		}
	case "float", "double", "real", "float4", "float8", "double precision":
		if f, err := strconv.ParseFloat(s, 64); err == nil {
			return f
		}
	}
	return s
}

// buildWhereInto appends a parameterized WHERE body identifying a row from key
// entries, validating each column against introspection. NULL values become
// "col IS NULL"; others bind a type-coerced parameter.
//
// Caveat: row keys are carried as text and coerced back per column, so a row
// keyed only by a float or high-precision temporal column may not re-match
// exactly (text round-trip). Tables with a real primary key are unaffected; the
// 0-rows-affected result is surfaced as a warning, not silent success.
func buildWhereInto(sb *sqlBuilder, byName map[string]model.Column, entries []rowKeyEntry) error {
	if len(entries) == 0 {
		return fmt.Errorf("no row identity provided")
	}
	for i, e := range entries {
		col, ok := byName[e.Col]
		if !ok {
			return fmt.Errorf("unknown column %q", e.Col)
		}
		if i > 0 {
			sb.raw(" AND ")
		}
		sb.ident(e.Col)
		if e.Val == nil {
			sb.raw(" IS NULL")
		} else {
			sb.raw(" = ")
			sb.param(coerceValue(col, *e.Val))
		}
	}
	return nil
}

// maxSelectedRows caps a "with selected" bulk action. It is not an engine limit
// but a shape limit: the export path turns the selection into one WHERE with a
// key-column-count parameter per row (PostgreSQL binds at most 65535), and the
// bulk edit form renders one full row form per selection. Past a thousand rows
// both stop being the right tool — a whole-table export and a Search-driven
// UPDATE are — so the handler says so instead of building something absurd.
const maxSelectedRows = 1000

// rowKeyResolvable reports whether every column a row key names still exists.
// Checked BEFORE the key is appended to a shared builder: buildWhereInto
// validates as it writes, so a key that fails halfway would leave a partial
// predicate (and its bound args) in a statement that is still being built.
func rowKeyResolvable(byName map[string]model.Column, entries []rowKeyEntry) bool {
	if len(entries) == 0 {
		return false
	}
	for _, e := range entries {
		if _, ok := byName[e.Col]; !ok {
			return false
		}
	}
	return true
}

// buildRowSetWhere appends "(<key>) OR (<key>) …" matching exactly the rows the
// given tokens identify, and reports how many keys it used and how many it
// skipped as undecodable or stale. Values are bound, never concatenated — this
// is the same row identity the Edit and Delete paths take, reaching the export
// stream instead of an UPDATE.
//
// Duplicate tokens collapse: a page can submit the same row twice (a checkbox
// plus a re-post), and an OR of identical predicates is only waste.
func buildRowSetWhere(sb *sqlBuilder, byName map[string]model.Column, tokens []string) (used, skipped int, err error) {
	seen := make(map[string]bool, len(tokens))
	for _, token := range tokens {
		if seen[token] {
			continue
		}
		seen[token] = true
		entries, decErr := decodeRowKey(token)
		if decErr != nil || !rowKeyResolvable(byName, entries) {
			skipped++
			continue
		}
		if used > 0 {
			sb.raw(" OR ")
		}
		sb.raw("(")
		if err := buildWhereInto(sb, byName, entries); err != nil {
			// Unreachable: rowKeyResolvable already proved every column exists and
			// that the list is non-empty. Reported rather than skipped, because by
			// now a half-written predicate is in the builder — the whole statement
			// has to be abandoned, not patched up.
			return used, skipped, err
		}
		sb.raw(")")
		used++
	}
	return used, skipped, nil
}

// fetchRow loads a single row identified by entries into a name→value map.
func (h *Handlers) fetchRow(ctx context.Context, conn *driver.Connection, sc reqScope, byName map[string]model.Column, entries []rowKeyEntry) (map[string]driver.Value, error) {
	sb := newSQLBuilder(conn.Dialect())
	sb.raw("SELECT * FROM ")
	sb.raw(conn.QualifiedName(sc.tableRef()))
	sb.raw(" WHERE ")
	if err := buildWhereInto(sb, byName, entries); err != nil {
		return nil, err
	}
	// Generated read: time-bound it (binds args, so it bypasses Connection.Query).
	ctx, cancel := conn.WithReadTimeout(ctx)
	defer cancel()
	rows, err := conn.DB().QueryContext(ctx, sb.String(), sb.args...)
	if err != nil {
		return nil, err
	}
	// Verbatim: this row prefills the edit form and is posted back as the row's
	// new value, so the display-path cell cap would silently truncate a long
	// TEXT column on save.
	rs, err := driver.ScanResultVerbatim(rows, 1)
	if err != nil {
		return nil, err
	}
	if len(rs.Rows) == 0 {
		return nil, errRowNotFound
	}
	out := map[string]driver.Value{}
	for i, rc := range rs.Columns {
		if i < len(rs.Rows[0]) {
			out[rc.Name] = rs.Rows[0][i]
		}
	}
	return out, nil
}

// --- view model ---------------------------------------------------------------

type editField struct {
	Column   model.Column
	Value    string
	IsNull   bool
	IsBinary bool // binary/BLOB cell: value shown read-only; only the NULL checkbox can change it (nullable columns)
	ReadOnly bool // generated column: shown read-only, never written back
}

// editFieldsFor builds one row's form fields from its current values (an empty
// map for a blank insert form). Shared by the single-row and bulk forms so the
// two cannot drift on read-only handling or on the auto-increment rule below.
//
// forInsert blanks auto-increment columns: on a Copy the prefill carries the
// SOURCE row's key, and rendering it would make the INSERT collide with the very
// row being copied. The engine assigns the next value instead.
func editFieldsFor(cols []model.Column, row map[string]driver.Value, forInsert bool) []editField {
	out := make([]editField, 0, len(cols))
	for _, c := range cols {
		f := editField{Column: c, ReadOnly: c.IsGenerated}
		if v, ok := row[c.Name]; ok && !(forInsert && c.IsAutoIncrement) {
			f.Value, f.IsNull, f.IsBinary = v.Str, v.Null, v.Binary
		}
		out = append(out, f)
	}
	return out
}

// hasPrimaryKey reports whether any column is part of the primary key. Used to
// warn when a keyless edit/delete may have matched duplicate rows.
func hasPrimaryKey(cols []model.Column) bool {
	for _, c := range cols {
		if c.IsPrimaryKey {
			return true
		}
	}
	return false
}

// editRowVM is ONE row's worth of form fields plus the name prefix its inputs
// carry. The prefix is "" for the single-row form — which keeps its field names
// exactly as they were — and "r<i>_" for each row of the bulk form, so N rows
// coexist in one submission without colliding.
type editRowVM struct {
	Prefix string
	Mode   string // insert | edit — decides whether the dirty-tracking hidden inputs render
	Fields []editField
	// WhereToken identifies the row this fieldset edits; empty when inserting.
	WhereToken string
	// Label names the fieldset in the bulk form ("Row 1 of 3").
	Label string
}

type editBody struct {
	Scope      reqScope
	Mode       string // insert | edit
	Row        editRowVM
	WhereToken string
	PostURL    string
	BrowseURL  string
}

// bulkEditBody is the multi-row form: one editRowVM per selected row, applied
// together in a single transaction.
type bulkEditBody struct {
	Scope     reqScope
	Mode      string // edit (UPDATE each row) | copy (INSERT each as new)
	Rows      []editRowVM
	PostURL   string
	BrowseURL string
}

// TableInsertForm renders the insert form (GET .../insert). With ?copy=1&where=
// it prefills from an existing row.
func (h *Handlers) TableInsertForm(w http.ResponseWriter, r *http.Request) {
	uc, sc, conn, ok := h.requireConn(w, r)
	if !ok {
		return
	}
	if !h.requireWritableTable(w, r, conn, sc) {
		return
	}
	cols, err := conn.Columns(r.Context(), sc.tableRef())
	if err != nil {
		h.dbError(w, r, err, "")
		return
	}

	prefill := map[string]driver.Value{}
	if r.URL.Query().Get("copy") == "1" {
		if token := r.URL.Query().Get("where"); token != "" {
			// Both failures used to fall through to a BLANK insert form the
			// user would silently retype into. Same refusals as TableEditForm:
			// a bad token is a bad request, a vanished row is a normal race
			// that deserves its own message, and anything else is a real
			// fetch failure.
			entries, err := decodeRowKey(token)
			if err != nil {
				h.renderError(w, r, http.StatusBadRequest, "Invalid row reference.", "")
				return
			}
			prefill, err = h.fetchRow(r.Context(), conn, sc, colSet(cols), entries)
			if err != nil {
				if errors.Is(err, errRowNotFound) {
					h.renderError(w, r, http.StatusNotFound, "The row you are copying no longer exists — it may have been deleted since the page was loaded.", "")
					return
				}
				h.dbError(w, r, err, "")
				return
			}
		}
	}

	body := editBody{
		Scope:     sc,
		Mode:      "insert",
		PostURL:   urlTable(sc.DB, sc.Schema, sc.Table, "insert"),
		BrowseURL: urlTable(sc.DB, sc.Schema, sc.Table, "browse"),
	}
	body.Row = editRowVM{Mode: "insert", Fields: editFieldsFor(cols, prefill, true)}
	h.renderEdit(w, r, uc, sc, "insert", body, conn)
}

// TableEditForm renders the edit form for one row (GET .../edit?where=token).
func (h *Handlers) TableEditForm(w http.ResponseWriter, r *http.Request) {
	uc, ok := h.requireUser(w, r)
	if !ok {
		return
	}
	sc := h.resolveScope(r).withSchemaDefault(uc.Capabilities())
	token := r.URL.Query().Get("where")
	entries, err := decodeRowKey(token)
	if err != nil {
		h.renderError(w, r, http.StatusBadRequest, "Invalid row reference.", "")
		return
	}
	conn, cols, ok := h.mutationConn(w, r, uc, sc)
	if !ok {
		return
	}
	row, err := h.fetchRow(r.Context(), conn, sc, colSet(cols), entries)
	if err != nil {
		if errors.Is(err, errRowNotFound) {
			h.renderError(w, r, http.StatusNotFound, "The row no longer exists — it may have been deleted or changed since the page was loaded.", "")
			return
		}
		h.dbError(w, r, err, "")
		return
	}

	body := editBody{
		Scope:      sc,
		Mode:       "edit",
		WhereToken: token,
		PostURL:    urlTable(sc.DB, sc.Schema, sc.Table, "edit"),
		BrowseURL:  urlTable(sc.DB, sc.Schema, sc.Table, "browse"),
	}
	body.Row = editRowVM{Mode: "edit", WhereToken: token, Fields: editFieldsFor(cols, row, false)}
	h.renderEdit(w, r, uc, sc, "edit", body, conn)
}

func (h *Handlers) renderEdit(w http.ResponseWriter, r *http.Request, uc *UserContext, sc reqScope, mode string, body editBody, conn *driver.Connection) {
	title := sc.Table + " · Insert"
	active := "insert"
	if mode == "edit" {
		title, active = sc.Table+" · Edit", "browse"
	}
	p := h.newLoggedPage(r, uc, title)
	p.Breadcrumb = h.buildBreadcrumb(uc, sc)
	p.Tabs = h.tableTabs(r.Context(), uc, sc, active, conn)
	p.Body = body
	h.render(w, r, "table_edit", p)
}

// readRowValues reads per-column form values, returning the columns to write and
// their (type-coerced) bound values. A checked null_<col> sets NULL. Columns the
// form did not submit are left untouched. An empty value for a numeric/temporal
// column is skipped (the user uses the NULL box to clear it), avoiding datatype
// mismatches; empty text values are kept as empty strings.
//
// Dirty tracking (edit form): each editable field also carries its original
// rendered value in a hidden orig_<col> input (plus orignull_<col> when the
// cell was NULL). A field whose submitted state equals its original is skipped
// entirely, so values whose display rendering is lossy — a PostgreSQL
// timestamptz shown as a fixed-offset wall clock, trailing fractional zeros —
// are never rewritten (and silently shifted) just because the form was saved.
// prefix namespaces one row's fields inside a multi-row submission; it is ""
// for the single-row forms, whose field names are therefore unchanged.
func readRowValues(form url.Values, prefix string, cols []model.Column, forInsert bool) (names []string, values []any) {
	for _, c := range cols {
		if c.IsGenerated {
			continue // generated columns are computed by the engine; never write them
		}
		submittedNull := form[prefix+"null_"+c.Name] != nil
		raw, present := form[prefix+"v_"+c.Name]
		val := ""
		if len(raw) > 0 {
			val = raw[0]
		}
		if !forInsert {
			if orig, hasOrig := form[prefix+"orig_"+c.Name]; hasOrig && len(orig) > 0 {
				wasNull := form[prefix+"orignull_"+c.Name] != nil
				if submittedNull && wasNull {
					continue // NULL before and after
				}
				// Browsers submit textarea content CRLF-normalized while the hidden
				// original keeps the rendered LF; compare with uniform newlines so an
				// untouched multi-line text field is not treated as dirty (which
				// would also rewrite its line endings).
				if !submittedNull && !wasNull && present && normalizeNewlines(val) == normalizeNewlines(orig[0]) {
					continue // value unchanged
				}
			}
		}
		if submittedNull {
			names = append(names, c.Name)
			values = append(values, nil)
			continue
		}
		if !present {
			continue // column not submitted: don't touch it
		}
		if val == "" {
			// Omit empty numerics/temporals (and auto-increment/defaulted columns
			// on insert) so the engine applies defaults rather than failing.
			if c.IsNumeric() || isTemporalType(c) {
				continue
			}
			if forInsert && (c.IsAutoIncrement || c.Default != nil) {
				continue
			}
		}
		names = append(names, c.Name)
		values = append(values, coerceValue(c, val))
	}
	return names, values
}

// buildInsertInto and buildUpdateInto write the two row-writing statements from
// a (names, values) pair. Identifiers are quoted, values bound. They exist as
// functions rather than inline blocks because the single-row and bulk forms both
// emit them, and a drift between the two would be a drift in how user data is
// written.
func buildInsertInto(sb *sqlBuilder, qualified string, names []string, values []any) {
	sb.raw("INSERT INTO ")
	sb.raw(qualified)
	sb.raw(" (")
	for i, n := range names {
		if i > 0 {
			sb.raw(", ")
		}
		sb.ident(n)
	}
	sb.raw(") VALUES (")
	for i, v := range values {
		if i > 0 {
			sb.raw(", ")
		}
		sb.param(v)
	}
	sb.raw(")")
}

// buildUpdateInto writes "UPDATE <t> SET …"; the caller appends its own WHERE.
func buildUpdateInto(sb *sqlBuilder, qualified string, names []string, values []any) {
	sb.raw("UPDATE ")
	sb.raw(qualified)
	sb.raw(" SET ")
	for i, n := range names {
		if i > 0 {
			sb.raw(", ")
		}
		sb.ident(n)
		sb.raw(" = ")
		sb.param(values[i])
	}
}

// normalizeNewlines maps CRLF to LF for dirty comparison (form submission
// CRLF-normalizes textarea content; the rendered original uses LF).
func normalizeNewlines(s string) string {
	return strings.ReplaceAll(s, "\r\n", "\n")
}

// isTemporalType reports whether the column holds a date/time value.
func isTemporalType(c model.Column) bool {
	switch c.BaseType {
	case "date", "time", "timetz", "datetime", "timestamp", "timestamptz",
		"timestamp with time zone", "timestamp without time zone",
		"time with time zone", "time without time zone", "year":
		return true
	}
	return false
}

// mutationScope is the POST-only first stage every row-scoped POST handler
// shares: requireUser → parseFormOr400 → resolveScope. ok=false means the
// response was already written. The dial stage (mutationConn) is deliberately
// separate: the sites validate request tokens between the two (edit's row-key
// decode, delete's token collection), and that validation must keep running
// BEFORE any dial — a single eager helper would reorder it.
func (h *Handlers) mutationScope(w http.ResponseWriter, r *http.Request) (*UserContext, reqScope, bool) {
	uc, ok := h.requireUser(w, r)
	if !ok {
		return nil, reqScope{}, false
	}
	if !h.parseFormOr400(w, r) {
		return nil, reqScope{}, false
	}
	return uc, h.resolveScope(r).withSchemaDefault(uc.Capabilities()), true
}

// mutationConn is the shared dial stage: ConnFor → Columns, with the same
// error rendering every site spelled out. The GET edit form reuses only this
// stage — it parses no form and decodes its query token before dialing.
func (h *Handlers) mutationConn(w http.ResponseWriter, r *http.Request, uc *UserContext, sc reqScope) (*driver.Connection, []model.Column, bool) {
	conn, err := uc.ConnFor(r.Context(), sc.DB)
	if err != nil {
		h.connError(w, r, uc, err)
		return nil, nil, false
	}
	if !h.requireWritableTable(w, r, conn, sc) {
		return nil, nil, false
	}
	cols, err := conn.Columns(r.Context(), sc.tableRef())
	if err != nil {
		h.dbError(w, r, err, "")
		return nil, nil, false
	}
	return conn, cols, true
}

// TableInsert performs the insert (POST .../insert).
func (h *Handlers) TableInsert(w http.ResponseWriter, r *http.Request) {
	uc, sc, ok := h.mutationScope(w, r)
	if !ok {
		return
	}
	conn, cols, ok := h.mutationConn(w, r, uc, sc)
	if !ok {
		return
	}
	names, values := readRowValues(r.PostForm, "", cols, true)
	if len(names) == 0 {
		h.afterMutation(w, r, uc, sc, view.Flash{Kind: "warning", Message: "Nothing to insert."})
		return
	}
	sb := newSQLBuilder(conn.Dialect())
	buildInsertInto(sb, conn.QualifiedName(sc.tableRef()), names, values)
	// ExecArgs, not the bare pool: the statement must reach the audit
	// observer (SQL text only, never the bound row values).
	if _, err := conn.ExecArgs(r.Context(), sb.String(), sb.args...); err != nil {
		h.dbError(w, r, err, sb.String())
		return
	}
	h.afterMutation(w, r, uc, sc, view.Flash{Kind: "success", Message: "Row inserted."})
}

// TableEdit performs the update (POST .../edit).
func (h *Handlers) TableEdit(w http.ResponseWriter, r *http.Request) {
	uc, sc, ok := h.mutationScope(w, r)
	if !ok {
		return
	}
	// Token validation stays BETWEEN the stages: a bad row key must fail
	// before any dial.
	entries, err := decodeRowKey(r.PostFormValue("where_token"))
	if err != nil {
		h.renderError(w, r, http.StatusBadRequest, "Invalid row reference.", "")
		return
	}
	conn, cols, ok := h.mutationConn(w, r, uc, sc)
	if !ok {
		return
	}
	byName := colSet(cols)
	names, values := readRowValues(r.PostForm, "", cols, false)
	if len(names) == 0 {
		h.afterMutation(w, r, uc, sc, view.Flash{Kind: "info", Message: "No changes to save — the row was left untouched."})
		return
	}
	sb := newSQLBuilder(conn.Dialect())
	buildUpdateInto(sb, conn.QualifiedName(sc.tableRef()), names, values)
	sb.raw(" WHERE ")
	if err := buildWhereInto(sb, byName, entries); err != nil {
		h.renderError(w, r, http.StatusBadRequest, err.Error(), "")
		return
	}
	res, err := conn.ExecArgs(r.Context(), sb.String(), sb.args...)
	if err != nil {
		h.dbError(w, r, err, sb.String())
		return
	}
	n, rowsErr := res.RowsAffected()
	if rowsErr != nil {
		// The UPDATE itself succeeded (ExecContext returned no error); the driver
		// just can't report the affected count. Report a plain success rather than
		// falling through to the n==0 "nothing matched" path, which would be a lie.
		h.afterMutation(w, r, uc, sc, view.Flash{Kind: "success", Message: "Row updated."})
		return
	}
	flash := view.Flash{Kind: "success", Message: fmt.Sprintf("Row updated (%d affected).", n)}
	switch {
	case n == 0:
		flash.Kind = "warning"
		if conn.Capabilities().ExecReportsChangedRows {
			// RowsAffected counts CHANGED rows, not matched (MySQL), so 0 can also
			// mean the row matched but already held these values — don't falsely
			// claim it matched nothing (fixing this app-wide would need
			// ClientFoundRows).
			flash.Message = "No changes were saved — the row either matched nothing or already held these values."
		} else {
			flash.Message = "No row was updated — nothing matched the row key."
		}
	case n > 1 && !hasPrimaryKey(cols):
		flash.Kind = "warning"
		flash.Message = fmt.Sprintf("Updated %d rows — this table has no primary key, so all identical rows were changed.", n)
	}
	h.afterMutation(w, r, uc, sc, flash)
}

// TableDelete deletes the selected rows (POST .../delete). Each token targets one
// row by its validated key, with values bound as parameters.
func (h *Handlers) TableDelete(w http.ResponseWriter, r *http.Request) {
	uc, sc, ok := h.mutationScope(w, r)
	if !ok {
		return
	}
	// The per-row delete button submits a single "row" token; it takes
	// precedence over "rows[]" because the button lives inside the bulk form
	// and any checked checkboxes ride along in the same request. The token
	// check stays BETWEEN the stages: an empty selection must not dial.
	tokens := r.PostForm["rows[]"]
	if row := r.PostForm.Get("row"); row != "" {
		tokens = []string{row}
	}
	if len(tokens) == 0 {
		h.afterMutation(w, r, uc, sc, view.Flash{Kind: "warning", Message: "No rows selected."})
		return
	}
	conn, cols, ok := h.mutationConn(w, r, uc, sc)
	if !ok {
		return
	}
	byName := colSet(cols)
	hadPK := hasPrimaryKey(cols)
	if !h.requireConfirm(w, r, uc, sc, fmt.Sprintf("Delete %d selected row(s) from %q?", len(tokens), sc.Table),
		urlTable(sc.DB, sc.Schema, sc.Table, "browse"), "Delete") {
		return
	}
	// All-or-nothing: run every DELETE in one transaction so a mid-loop failure
	// rolls the whole request back instead of silently committing a partial
	// delete. Observed, so each DELETE reaches the audit trail (SQL text only)
	// and a rollback leaves its own marker.
	tx, err := conn.BeginObserved(r.Context())
	if err != nil {
		h.dbError(w, r, err, "")
		return
	}
	defer tx.Rollback()
	var total int64
	skipped := 0
	multi := false
	countKnown := true
	for _, token := range tokens {
		entries, err := decodeRowKey(token)
		if err != nil {
			skipped++ // undecodable row key
			continue
		}
		sb := newSQLBuilder(conn.Dialect())
		sb.raw("DELETE FROM ")
		sb.raw(conn.QualifiedName(sc.tableRef()))
		sb.raw(" WHERE ")
		if err := buildWhereInto(sb, byName, entries); err != nil {
			skipped++ // key referenced an unknown column / couldn't build a WHERE
			continue
		}
		res, err := tx.Exec(r.Context(), sb.String(), sb.args...)
		if err != nil {
			h.dbError(w, r, err, sb.String()) // deferred Rollback undoes prior deletes
			return
		}
		if n, err := res.RowsAffected(); err == nil {
			total += n
			if n > 1 && !hadPK {
				multi = true
			}
		} else {
			// The DELETE ran (ExecContext returned no error); the driver just
			// cannot report its count. Without remembering that, total stays
			// low and the flash claims "nothing matched" after committed
			// deletes — the same trap TableEdit's countless arm documents.
			countKnown = false
		}
	}
	if err := tx.Commit(); err != nil {
		h.dbError(w, r, err, "")
		return
	}
	h.afterMutation(w, r, uc, sc, deleteFlash(total, skipped, len(tokens), multi, countKnown))
}

// deleteFlash decides TableDelete's outcome message. Pure, so the
// countless-driver arm is testable without a driver that cannot count.
func deleteFlash(total int64, skipped, selected int, multi, countKnown bool) view.Flash {
	// allSkipped means every selected key was invalid/unusable, so no DELETE was
	// ever attempted — distinct from "some keys ran but matched nothing".
	allSkipped := skipped > 0 && skipped == selected
	flash := view.Flash{Kind: "success", Message: fmt.Sprintf("%d row(s) deleted.", total)}
	switch {
	case allSkipped:
		flash.Kind = "warning"
		flash.Message = fmt.Sprintf("No rows were deleted — all %d selected row key(s) were invalid and skipped.", skipped)
	case !countKnown:
		// The DELETEs committed; the count is unavailable, not zero. An
		// honest countless success — never the "nothing matched" lie below.
		flash.Message = "The selected row(s) were deleted — this driver does not report how many rows were affected."
		if total > 0 {
			flash.Message = fmt.Sprintf("The selected row(s) were deleted (at least %d) — this driver does not report every affected count.", total)
		}
		// A warning that is still true must not be suppressed by the unknown
		// count: multi was established from the counts that DID report.
		if multi {
			flash.Kind = "warning"
			flash.Message += " This table has no primary key, so identical rows were removed together."
		}
	case total == 0:
		flash.Kind = "warning"
		flash.Message = "No rows were deleted — nothing matched the selected row keys."
	case multi:
		flash.Kind = "warning"
		flash.Message = fmt.Sprintf("%d row(s) deleted — this table has no primary key, so identical rows were removed together.", total)
	}
	// When some (but not all) keys were skipped, a real delete was still attempted,
	// so append a note — otherwise the user can't tell "skipped an invalid key"
	// from "didn't match". The all-skipped case already says so above.
	if skipped > 0 && !allSkipped {
		flash.Kind = "warning"
		flash.Message += fmt.Sprintf(" %d selected row key(s) were skipped as invalid.", skipped)
	}
	return flash
}

// afterMutation returns the user to the browse grid with a flash. For htmx it
// re-renders in place and updates the address bar; otherwise it redirects.
func (h *Handlers) afterMutation(w http.ResponseWriter, r *http.Request, uc *UserContext, sc reqScope, flash view.Flash) {
	browse := urlTable(sc.DB, sc.Schema, sc.Table, "browse")
	if view.IsHTMX(r) {
		w.Header().Set("HX-Push-Url", browse)
		h.showBrowse(w, r, uc, sc, []view.Flash{flash})
		return
	}
	// No-JS fallback: store the flash so the post-redirect GET picks it up
	// (takeFlashes via newLoggedPage) — same contract as redirectTo.
	uc.AddFlash(flash)
	http.Redirect(w, r, browse, http.StatusSeeOther)
}
