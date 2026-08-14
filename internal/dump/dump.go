// Package dump builds and writes TableX's database exports.
//
// It holds the whole dump engine: the per-schema planner, the cross-schema
// dependency graph with its cycle resolution and drop-first teardown, and the
// SQL/CSV/JSON writers. None of it imports net/http — it used to live inside
// the HTTP handler package purely because that is where the export route is,
// which put ~1,800 lines of planning and writing behind a request handler.
//
// The handler now does only what a handler does: parse the form, resolve the
// scope, open the export connection, and hand this package a plan to write.
package dump

import (
	"context"

	"github.com/tablexdev/tablex/internal/driver"
	"github.com/tablexdev/tablex/internal/model"
)

// SchemaGroup is the (non-view) tables of one schema to export. Schema is ""
// for schema-less engines (MySQL/SQLite).
type SchemaGroup struct {
	Schema string
	Tables []driver.TableRef
}

// scopeOf narrows a table reference to the database/schema scope the
// introspection and dump calls take.
func scopeOf(t driver.TableRef) driver.Scope {
	return driver.Scope{Database: t.Database, Schema: t.Schema}
}

// NewPlan wraps an already-collected DumpPlan as a section plan. The
// database-global object section is built this way — the objects come straight
// from the dialect, with no per-table preflight.
func NewPlan(objects driver.DumpPlan) *Plan { return &Plan{objects: objects} }

// insertableColumns returns the columns that can be written back on restore or
// import — every non-generated column, in column order. It is the SINGLE source
// of the "non-generated" filter shared by the SQL dump (INSERT list + the
// identity-always OVERRIDING walk) and the CSV plan (binary-column mask +
// header): keeping exactly one filter guarantees the streamed SELECT list, the
// binaryCols index mask and the CSV header stay aligned 1:1, so a generated
// column sitting between two binary ones can never shift the indexes. Generated
// columns are excluded because no engine accepts them in an INSERT (and
// importCSV refuses a generated header).
func insertableColumns(cols []model.Column) []model.Column {
	out := make([]model.Column, 0, len(cols))
	for _, c := range cols {
		if c.IsGenerated {
			continue
		}
		out = append(out, c)
	}
	return out
}

// quotedInsertableCols returns the dialect-quoted names of the insertable
// (non-generated) columns, in column order — the INSERT/SELECT list both the SQL
// and CSV exporters build. Callers apply their own extras (the SQL path also
// tracks identity-always columns for an OVERRIDING clause) over the same
// insertableColumns filter.
func quotedInsertableCols(d driver.Dialect, cols []model.Column) []string {
	ins := insertableColumns(cols)
	quoted := make([]string, 0, len(ins))
	for _, c := range ins {
		quoted = append(quoted, d.QuoteIdent(c.Name))
	}
	return quoted
}

// CommentSafe re-exports driver.CommentSafe so the dump writers (and export.go,
// which reaches it as dump.CommentSafe) keep their existing spelling. The one
// implementation lives in internal/driver — the package the dialects also
// depend on — so a dialect that builds its own comment line shares it instead of
// carrying a twin. See driver.CommentSafe for the rationale.
func CommentSafe(s string) string { return driver.CommentSafe(s) }

// Options are the user's POSTed dump choices.
type Options struct {
	Structure bool
	Data      bool
	DropFirst bool
	// Rows restricts the data phase to specific rows of ONE table (the browse
	// grid's "with selected" export). Nil for an ordinary whole-table dump.
	Rows *RowFilter
	// Range bounds the data phase to a slice of the table's rows, for sampling
	// something too big to export whole. Nil for an unbounded dump.
	Range *RowRange
}

// RowRange is a LIMIT/OFFSET over a table's rows.
//
// A caveat worth stating rather than hiding: SQL gives an unordered SELECT no
// defined row order, so an OFFSET is only meaningful relative to whatever order
// the engine happened to use for the same query moments earlier. "First N rows"
// is dependable; "rows 1000-2000, twice" is not. Adding an ORDER BY to make it
// so would put a sort on every export of every large table, which is a steep
// price for a sampling aid — so the export form says this instead.
type RowRange struct {
	Limit  int
	Offset int64
}

// clauseFor renders the dialect's LIMIT/OFFSET for one table, or "" when there
// is no range to apply. It takes the same shape as RowFilter.clauseFor so the
// two compose in the one place a data SELECT is built.
func (rr *RowRange) clauseFor(d driver.Dialect) string {
	if rr == nil || rr.Limit <= 0 {
		return ""
	}
	return " " + d.LimitClause(rr.Limit, rr.Offset)
}

// RowFilter restricts a dump's data phase to specific rows of one table: a
// parameterized WHERE body (no leading "WHERE") plus the values to bind.
//
// It names its target table on purpose. A dump walks a table LIST, and a filter
// built from one grid's row keys names key columns that a sibling table need not
// even have — so "apply it to whatever table comes next" is either an error or,
// far worse, a silent match on rows the user never selected. clauseFor is the
// single place that decision is made, and its answer for a non-target table is
// "no data", never "all data".
type RowFilter struct {
	Target driver.TableRef
	Where  string
	Args   []any
}

// clauseFor returns the WHERE suffix and bound args to append to one table's
// data SELECT, and whether that table may contribute data at all. A nil filter
// passes everything through unchanged, so the unfiltered path is untouched.
func (f *RowFilter) clauseFor(t driver.TableRef) (where string, args []any, allowed bool) {
	if f == nil || f.Where == "" {
		return "", nil, true
	}
	if f.Target.Database != t.Database || f.Target.Schema != t.Schema || f.Target.Table != t.Table {
		return "", nil, false
	}
	return " WHERE " + f.Where, f.Args, true
}

// tableDump is one table's preflighted dump state.
type tableDump struct {
	scope      driver.TableRef
	qualified  string
	create     string // restore-oriented DDL (empty when structure is off)
	insertCols string // quoted, comma-joined column list (generated columns excluded)
	selectSQL  string // explicit SELECT matching insertCols (empty = no data to dump)
	overriding bool   // PG GENERATED ALWAYS AS IDENTITY: INSERT ... OVERRIDING SYSTEM VALUE
	// countSQL is set only for a zero-insertable-column table (zero columns, or
	// every column generated): its rows carry no writable value, so the dump emits
	// that many all-defaults INSERTs (L10) instead of the normal INSERT … VALUES.
	countSQL string
	// args are the values bound by selectSQL/countSQL — non-nil only under a
	// row filter, whose row-identity values are parameters, never literals.
	args []any
	// excluded marks a table a row filter does not target: it contributes NO
	// data, and says so in the dump rather than appearing to be empty.
	excluded bool
	// parents holds the linked INHERITS parents the create was rendered with
	// (nil for a standalone/plain table) so the cycle resolver can re-render
	// the same shape with deferred clauses stripped.
	parents []string
}

// Plan holds everything introspected up front: all structure DDL is
// small strings, so collecting it before the download headers go out turns an
// introspection failure into a rendered error instead of a silently
// incomplete download. Only row data streams afterwards.
type Plan struct {
	objects driver.DumpPlan
	tables  []tableDump
}

// Section is one schema's preflighted dump plan within a database section
// (schema is "" for schema-less engines).
type Section struct {
	Schema string
	Plan   *Plan
}

// bulkColumnsOrNil prefetches every table's columns in one schema-wide query
// when the engine supports it (driver.BulkIntrospector). A nil map — engine
// unsupported (SQLite) or query failed — makes callers fall back to the
// per-table Columns call, so the bulk path is purely an optimization: any
// real introspection problem still surfaces through the per-table error.
func bulkColumnsOrNil(ctx context.Context, conn *driver.Connection, scope driver.Scope) map[string][]model.Column {
	m, ok, err := conn.BulkColumns(ctx, scope)
	if !ok || err != nil {
		return nil
	}
	return m
}

// PlanEmpty reports whether a DumpPlan carries nothing to emit — the
// global-object section is only added when a dialect actually produced
// globals, so engines without a GlobalDumper keep byte-identical output.
func PlanEmpty(p driver.DumpPlan) bool {
	return len(p.Collations) == 0 && len(p.Types) == 0 && len(p.Routines) == 0 &&
		len(p.Sequences) == 0 && len(p.Views) == 0 && len(p.PostData) == 0 &&
		len(p.Warnings) == 0
}

// allIn reports whether every value is present in set.
func allIn(vals []string, set map[string]bool) bool {
	for _, v := range vals {
		if !set[v] {
			return false
		}
	}
	return true
}
