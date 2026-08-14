// The browse grid's "with selected" actions. Every one of them starts the same
// way — a POST carrying the checked rows' identity tokens plus a verb — so they
// share one route and one entry point instead of a route per verb, each with its
// own copy of the selection handling.
//
// Delete is deliberately NOT here: it is reachable from the per-row button as
// well as the bulk bar, and it already owns .../delete.

package handlers

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/tablexdev/tablex/internal/view"
)

// TableBulkRows dispatches a "with selected" action (POST .../rows). The action
// verb is a form field rather than a route segment because the browse grid is
// ONE form: a second submit button can add a verb, but it cannot change the
// form's method or re-check the boxes.
func (h *Handlers) TableBulkRows(w http.ResponseWriter, r *http.Request) {
	uc, sc, ok := h.mutationScope(w, r)
	if !ok {
		return
	}
	tokens := r.PostForm["rows[]"]
	if len(tokens) == 0 {
		h.afterMutation(w, r, uc, sc, view.Flash{Kind: "warning", Message: "No rows selected."})
		return
	}
	if len(tokens) > maxSelectedRows {
		h.afterMutation(w, r, uc, sc, view.Flash{
			Kind:    "warning",
			Message: "Too many rows selected for a bulk action — select fewer, or use the whole-table Export and Search instead.",
		})
		return
	}
	switch action := r.PostFormValue("action"); action {
	case "export":
		conn, err := uc.ConnFor(r.Context(), sc.DB)
		if err != nil {
			h.connError(w, r, uc, err)
			return
		}
		// Straight to the export options page with the selection attached. The
		// download itself cannot happen here: it needs a format and the
		// structure/data choices, and those live on that form.
		h.renderExportForm(w, r, uc, sc, conn, "table", tokens)
	case "edit", "copy":
		h.bulkEditForm(w, r, uc, sc, tokens, action)
	default:
		h.renderError(w, r, http.StatusBadRequest, "Unknown bulk action.", "")
	}
}

// maxBulkFormRows caps the multi-row edit/copy form. It is deliberately tighter
// than maxSelectedRows: this form costs one round trip AND one full row form per
// selected row, so the ceiling is what a human can actually review before
// pressing Save, not what the database can bind.
const maxBulkFormRows = 100

// bulkEditForm renders one editable fieldset per selected row. mode "edit"
// prefills for UPDATE (with the dirty-tracking originals); mode "copy" prefills
// the same values for INSERT, so the rows are duplicated rather than changed.
func (h *Handlers) bulkEditForm(w http.ResponseWriter, r *http.Request, uc *UserContext, sc reqScope, tokens []string, mode string) {
	if len(tokens) > maxBulkFormRows {
		h.afterMutation(w, r, uc, sc, view.Flash{
			Kind: "warning",
			Message: fmt.Sprintf("%d rows selected; the bulk form handles at most %d at a time. Narrow the selection, or use Search and the SQL console for a sweeping change.",
				len(tokens), maxBulkFormRows),
		})
		return
	}
	conn, cols, ok := h.mutationConn(w, r, uc, sc)
	if !ok {
		return
	}
	byName := colSet(cols)
	body := bulkEditBody{
		Scope:     sc,
		Mode:      mode,
		PostURL:   urlTable(sc.DB, sc.Schema, sc.Table, "rows/apply"),
		BrowseURL: urlTable(sc.DB, sc.Schema, sc.Table, "browse"),
	}
	// One fetch per row rather than one OR-set SELECT. The form needs VERBATIM
	// values (a display-capped value posted back would truncate the column on
	// save), while the row-identity tokens were built from the DISPLAY scan — so
	// a single query could not both prefill correctly and be matched back to its
	// token. maxBulkFormRows is what keeps that bounded.
	skipped := 0
	for _, token := range tokens {
		entries, err := decodeRowKey(token)
		if err != nil {
			skipped++
			continue
		}
		row, err := h.fetchRow(r.Context(), conn, sc, byName, entries)
		if err != nil {
			if errors.Is(err, errRowNotFound) {
				skipped++ // deleted or changed since the grid was rendered
				continue
			}
			h.dbError(w, r, err, "")
			return
		}
		body.Rows = append(body.Rows, editRowVM{
			Prefix:     fmt.Sprintf("r%d_", len(body.Rows)),
			Mode:       map[string]string{"edit": "edit", "copy": "insert"}[mode],
			WhereToken: token,
			Label:      fmt.Sprintf("Row %d", len(body.Rows)+1),
			Fields:     editFieldsFor(cols, row, mode == "copy"),
		})
	}
	if len(body.Rows) == 0 {
		h.afterMutation(w, r, uc, sc, view.Flash{
			Kind:    "warning",
			Message: "None of the selected rows could be loaded — they may have been deleted or changed since the page was loaded.",
		})
		return
	}
	if skipped > 0 {
		uc.AddFlash(view.Flash{
			Kind:    "warning",
			Message: fmt.Sprintf("%d selected row(s) could not be loaded and are not shown.", skipped),
		})
	}
	verb := "Edit"
	if mode == "copy" {
		verb = "Copy"
	}
	p := h.newLoggedPage(r, uc, fmt.Sprintf("%s · %s %d rows", sc.Table, verb, len(body.Rows)))
	p.Breadcrumb = h.buildBreadcrumb(uc, sc)
	p.Tabs = h.tableTabs(r.Context(), uc, sc, "browse", conn)
	p.Body = body
	h.render(w, r, "table_bulk_edit", p)
}

// TableBulkApply writes the multi-row form (POST .../rows/apply). Mode comes
// from a hidden field set when the form was RENDERED, not from the button that
// submitted it: the user already chose Edit or Copy in the browse grid, and a
// form that could switch between updating and duplicating on submit is one
// mis-click from doubling a table.
//
// All-or-nothing: every statement runs in one transaction, so a failure halfway
// through rolls back rather than leaving half the selection written.
func (h *Handlers) TableBulkApply(w http.ResponseWriter, r *http.Request) {
	uc, sc, ok := h.mutationScope(w, r)
	if !ok {
		return
	}
	mode := r.PostFormValue("mode")
	if mode != "edit" && mode != "copy" {
		h.renderError(w, r, http.StatusBadRequest, "Unknown bulk action.", "")
		return
	}
	count, err := strconv.Atoi(r.PostFormValue("bulk_count"))
	if err != nil || count <= 0 || count > maxBulkFormRows {
		h.renderError(w, r, http.StatusBadRequest, "Invalid row count.", "")
		return
	}
	// Token validation stays BEFORE the dial, as on every other row-mutation
	// path: a bad row key must fail without opening a connection.
	tokens := make([][]rowKeyEntry, count)
	if mode == "edit" {
		for i := range count {
			entries, err := decodeRowKey(r.PostFormValue(fmt.Sprintf("r%d_where", i)))
			if err != nil {
				h.renderError(w, r, http.StatusBadRequest, "Invalid row reference.", "")
				return
			}
			tokens[i] = entries
		}
	}
	conn, cols, ok := h.mutationConn(w, r, uc, sc)
	if !ok {
		return
	}
	byName := colSet(cols)

	// Observed, so each statement reaches the audit trail (SQL text only) and
	// a rollback leaves its own marker.
	tx, err := conn.BeginObserved(r.Context())
	if err != nil {
		h.dbError(w, r, err, "")
		return
	}
	defer tx.Rollback()
	var affected int64
	unchanged := 0
	countKnown := true
	for i := range count {
		prefix := fmt.Sprintf("r%d_", i)
		names, values := readRowValues(r.PostForm, prefix, cols, mode == "copy")
		if len(names) == 0 {
			unchanged++ // nothing dirty in this row's fieldset
			continue
		}
		sb := newSQLBuilder(conn.Dialect())
		if mode == "copy" {
			buildInsertInto(sb, conn.QualifiedName(sc.tableRef()), names, values)
		} else {
			buildUpdateInto(sb, conn.QualifiedName(sc.tableRef()), names, values)
			sb.raw(" WHERE ")
			if err := buildWhereInto(sb, byName, tokens[i]); err != nil {
				h.renderError(w, r, http.StatusBadRequest, err.Error(), "")
				return
			}
		}
		res, err := tx.Exec(r.Context(), sb.String(), sb.args...)
		if err != nil {
			h.dbError(w, r, err, sb.String()) // the deferred Rollback undoes the earlier rows
			return
		}
		if n, err := res.RowsAffected(); err == nil {
			affected += n
		} else {
			// The statement ran; only its count is unavailable. Without this,
			// affected stays low and the flash reports a wrong number.
			countKnown = false
		}
	}
	if err := tx.Commit(); err != nil {
		h.dbError(w, r, err, "")
		return
	}
	h.afterMutation(w, r, uc, sc, bulkApplyFlash(mode, affected, unchanged, count, countKnown))
}

// bulkApplyFlash decides TableBulkApply's outcome message. Pure, so the
// countless-driver arm is testable without a driver that cannot count. The
// unchanged==count arm needs no countKnown guard: it is only reached when
// every row was skipped before any statement ran.
func bulkApplyFlash(mode string, affected int64, unchanged, count int, countKnown bool) view.Flash {
	flash := view.Flash{Kind: "success"}
	switch {
	case mode == "copy" && !countKnown:
		flash.Message = "The selected row(s) were inserted as copies — this driver does not report how many rows were affected."
	case mode == "copy":
		flash.Message = fmt.Sprintf("%d row(s) inserted as copies.", affected)
	case unchanged == count:
		flash.Kind = "info"
		flash.Message = "No changes to save — every row was left untouched."
	case !countKnown:
		// An honest countless success, never "0 row(s) updated." — and the
		// still-true no-changes note is not suppressed by the unknown count.
		flash.Message = "The edited row(s) were updated — this driver does not report how many rows were affected."
		if unchanged > 0 {
			flash.Message += fmt.Sprintf(" %d row(s) had no changes.", unchanged)
		}
	default:
		flash.Message = fmt.Sprintf("%d row(s) updated.", affected)
		if unchanged > 0 {
			flash.Message += fmt.Sprintf(" %d row(s) had no changes.", unchanged)
		}
	}
	return flash
}
