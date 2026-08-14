package handlers

import (
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/tablexdev/tablex/internal/driver"
	"github.com/tablexdev/tablex/internal/dump"
	"github.com/tablexdev/tablex/internal/model"
	"github.com/tablexdev/tablex/internal/view"
)

type exportBody struct {
	Scope   reqScope
	Level   string // db | table | server
	PostURL string
	// ServerNote is the engine's server-scope help sentence, precomputed from
	// the dialect's ServerDumpProfile so the template renders neutral data
	// instead of branching on an engine name.
	ServerNote string
	// SelectedRows are the browse grid's checked row-identity tokens for a
	// "with selected" export; empty for an ordinary whole-table/database export.
	SelectedRows []string
	// Objects are the database's tables, offered as checkboxes so a db-scope
	// export can be narrowed to a subset. Empty at table and server scope.
	Objects []exportObject
}

// exportObject is one selectable table on the db-scope export form.
type exportObject struct {
	Schema string
	Table  string
	Token  string
}

// objectToken encodes a (schema, table) pair into one checkbox value.
//
// It is length-prefixed rather than joined with a separator because a SQL
// identifier may legally contain any character, '.' and ':' included — the same
// ambiguity the CSV writer avoids by emitting separate "# schema:"/"# table:"
// comment lines. "6:publicorders" has exactly one reading. Two parallel
// checkbox arrays would not work at all: an unchecked box submits nothing, so
// the two arrays would silently misalign.
func objectToken(schema, table string) string {
	return strconv.Itoa(len(schema)) + ":" + schema + table
}

func parseObjectToken(tok string) (schema, table string, ok bool) {
	n, rest, found := strings.Cut(tok, ":")
	if !found {
		return "", "", false
	}
	l, err := strconv.Atoi(n)
	if err != nil || l < 0 || l > len(rest) {
		return "", "", false
	}
	return rest[:l], rest[l:], true
}

// filterGroupsBySelection narrows a db-scope export to the tables the form
// checked. An EMPTY selection means everything — that is the pre-existing
// behaviour and the shape of every other export — so this only ever removes
// tables when the user actually chose some.
//
// Selected names are matched against the introspected groups rather than
// trusted: an unknown name is dropped, so a stale form cannot name a table into
// existence, and nothing reaches the quoting layer that introspection did not
// just return.
func filterGroupsBySelection(groups []dump.SchemaGroup, tokens []string) []dump.SchemaGroup {
	if len(tokens) == 0 {
		return groups
	}
	want := make(map[string]bool, len(tokens))
	for _, tok := range tokens {
		if schema, table, ok := parseObjectToken(tok); ok {
			want[objectToken(schema, table)] = true
		}
	}
	out := make([]dump.SchemaGroup, 0, len(groups))
	for _, g := range groups {
		kept := make([]driver.TableRef, 0, len(g.Tables))
		for _, t := range g.Tables {
			if want[objectToken(t.Schema, t.Table)] {
				kept = append(kept, t)
			}
		}
		if len(kept) > 0 {
			out = append(out, dump.SchemaGroup{Schema: g.Schema, Tables: kept})
		}
	}
	return out
}

// exportSchemaGroups returns the schema→tables groups to export for a database.
// For a schema-having engine (PostgreSQL) an empty rawSchema expands to EVERY
// non-system schema — so a "whole database" or server dump does not silently omit
// tables/views/routines in non-public schemas (the H1 data-loss bug) — while a
// specific rawSchema restricts to that one. Schema-less engines always return a
// single schema-less group, so their behavior is unchanged.
func (h *Handlers) exportSchemaGroups(ctx context.Context, conn *driver.Connection, db, rawSchema string) ([]dump.SchemaGroup, error) {
	var schemas []string
	switch {
	case !conn.Capabilities().HasSchemas:
		schemas = []string{""}
	case rawSchema != "":
		schemas = []string{rawSchema}
	default:
		list, err := conn.ListSchemas(ctx, db)
		if err != nil {
			return nil, err
		}
		for _, s := range list {
			if !s.IsSystem { // skip pg_catalog / pg_toast / information_schema
				schemas = append(schemas, s.Name)
			}
		}
	}
	groups := make([]dump.SchemaGroup, 0, len(schemas))
	for _, schema := range schemas {
		list, err := h.tableNames(ctx, conn, driver.Scope{Database: db, Schema: schema})
		if err != nil {
			return nil, err
		}
		g := dump.SchemaGroup{Schema: schema}
		for _, t := range list {
			if t.IsView() {
				continue
			}
			g.Tables = append(g.Tables, driver.TableRef{Database: db, Schema: schema, Table: t.Name})
		}
		groups = append(groups, g)
	}
	return groups, nil
}

// rowSelectionFilter turns the browse grid's selected row keys into a dump row
// filter: one parameterized WHERE over the target table, with every identity
// value BOUND. Returns nil when no rows were submitted, so an ordinary export is
// untouched.
//
// The filter names its target table, and the dump refuses to apply it to any
// other — see dump.RowFilter. That matters here because the tokens are opaque to
// the caller: they are validated against THIS table's live introspection, and a
// key naming a column the table no longer has is dropped rather than trusted.
func (h *Handlers) rowSelectionFilter(ctx context.Context, conn *driver.Connection, sc reqScope, tokens []string) (*dump.RowFilter, int, error) {
	if len(tokens) == 0 {
		return nil, 0, nil
	}
	if len(tokens) > maxSelectedRows {
		return nil, 0, fmt.Errorf("%d rows selected; at most %d can be exported as a selection — export the whole table instead", len(tokens), maxSelectedRows)
	}
	cols, err := conn.Columns(ctx, sc.tableRef())
	if err != nil {
		return nil, 0, err
	}
	sb := newSQLBuilder(conn.Dialect())
	used, skipped, err := buildRowSetWhere(sb, colSet(cols), tokens)
	if err != nil {
		return nil, 0, err
	}
	if used == 0 {
		// Every key was undecodable or named a column the table no longer has.
		// Falling through with no filter would export the WHOLE table — the one
		// outcome a "with selected" export must never produce.
		return nil, skipped, fmt.Errorf("none of the %d selected row(s) could be resolved against this table", len(tokens))
	}
	return &dump.RowFilter{Target: sc.tableRef(), Where: sb.String(), Args: sb.args}, skipped, nil
}

// parseRowRange reads the export form's row limit/offset. Nil unless a positive
// limit was given: an offset on its own has no meaning (there is nothing to
// count from without a bound), and a zero or negative limit is "no limit"
// rather than "no rows" — the latter would turn a fat-fingered field into a
// silently empty dump.
func parseRowRange(form url.Values) *dump.RowRange {
	limit, err := strconv.Atoi(strings.TrimSpace(form.Get("row_limit")))
	if err != nil || limit <= 0 {
		return nil
	}
	offset, err := strconv.ParseInt(strings.TrimSpace(form.Get("row_offset")), 10, 64)
	if err != nil || offset < 0 {
		offset = 0
	}
	return &dump.RowRange{Limit: limit, Offset: offset}
}

// isDataFormat reports whether an export format streams table ROWS rather than
// planning structure — CSV, JSON and XML. It is the single list the foreign-table
// gate and any future row-streaming decision share, because the fallback for an
// unrecognized format is the SQL path: a format missing from here is silently
// treated as SQL, which is the wrong answer in exactly the cases that matter.
func isDataFormat(format string) bool {
	switch format {
	case "csv", "json", "xml":
		return true
	}
	return false
}

// ServerExport / DBExport / TableExport: GET renders the form, POST streams the
// download. Server scope dumps every (non-system) database.
func (h *Handlers) ServerExport(w http.ResponseWriter, r *http.Request) { h.export(w, r, "server") }
func (h *Handlers) DBExport(w http.ResponseWriter, r *http.Request)     { h.export(w, r, "db") }
func (h *Handlers) TableExport(w http.ResponseWriter, r *http.Request)  { h.export(w, r, "table") }

func (h *Handlers) export(w http.ResponseWriter, r *http.Request, level string) {
	uc, sc, conn, ok := h.requireConn(w, r)
	if !ok {
		return
	}

	if r.Method == http.MethodPost {
		// An export opens a PRIVATE connection pool per database it touches
		// (ExportConnFor), deliberately outside PoolBudget. Reserve an in-flight
		// slot so parallel exports cannot exhaust the database's max_connections.
		// Held for the whole stream, not just the dial.
		release, ok := h.acquireDBOp(w, r)
		if !ok {
			return
		}
		defer release()
		h.streamExport(w, r, uc, conn, sc, level)
		return
	}

	h.renderExportForm(w, r, uc, sc, conn, level, nil)
}

// renderExportForm renders the export options page. selected carries the browse
// grid's checked row keys for a "with selected" export — they ride the form as
// hidden inputs so the real download POST (which needs the user's format and
// contents choices) sees the same selection the grid made.
func (h *Handlers) renderExportForm(w http.ResponseWriter, r *http.Request, uc *UserContext, sc reqScope, conn *driver.Connection, level string, selected []string) {
	postURL, title, tabs := h.levelChrome(r.Context(), uc, sc, level, "export", "Export", conn)
	p := h.newLoggedPage(r, uc, title)
	p.Breadcrumb = h.buildBreadcrumb(uc, sc)
	p.Tabs = tabs
	body := exportBody{Scope: sc, Level: level, PostURL: postURL, SelectedRows: selected}
	if level == "server" {
		if f, ok := uc.Dialect().(driver.ServerDumpFramer); ok {
			body.ServerNote = f.ServerDumpProfile().FormNote
		}
	}
	if level == "db" {
		// Offered as a convenience, so a listing failure must not cost the user
		// the export form itself: on error the checkbox list is simply absent
		// and the export covers everything, exactly as before.
		if groups, err := h.exportSchemaGroups(r.Context(), conn, sc.DB, h.resolveScope(r).Schema); err == nil {
			for _, g := range groups {
				for _, t := range g.Tables {
					body.Objects = append(body.Objects, exportObject{
						Schema: g.Schema, Table: t.Table, Token: objectToken(g.Schema, t.Table),
					})
				}
			}
		}
	}
	p.Body = body
	h.render(w, r, "export", p)
}

// streamExport writes the chosen format directly to the response without
// buffering the whole dump, satisfying the "large exports stream" requirement.
func (h *Handlers) streamExport(w http.ResponseWriter, r *http.Request, uc *UserContext, conn *driver.Connection, sc reqScope, level string) {
	if !h.parseFormOr400(w, r) {
		return
	}
	ctx := r.Context()
	format := r.PostFormValue("format")
	withStructure := r.PostForm["structure"] != nil
	withData := r.PostForm["data"] != nil
	dropFirst := r.PostForm["drop"] != nil
	if !withStructure && !withData {
		withStructure, withData = true, true
	}

	// Server scope dumps every database and is SQL-only (a multi-database CSV/JSON
	// has no single coherent shape).
	if level == "server" {
		h.streamServerExport(w, r, uc, withStructure, withData, dropFirst)
		return
	}

	// Resolve the schema→tables groups to export. A DB-scope export uses the RAW
	// requested schema (not the withSchemaDefault "public"), so an unset schema on
	// PostgreSQL dumps EVERY non-system schema rather than only public.
	var groups []dump.SchemaGroup
	// target is the resolved relation at table scope — nil for db/server scope. A
	// selected VIEW/matview must dump as CREATE VIEW, not a physical CREATE TABLE
	// snapshot (V1); the SQL path branches on target.IsView(). CSV/JSON keep
	// exporting a view's rows unchanged (they never consult target).
	var target *model.Table
	if level == "table" {
		// Resolve the path-supplied relation before streaming (QualifiedName quotes
		// the name but does not verify it) so a bad name is a clean error, not a
		// corrupt mid-stream download, and so the SQL path can branch on its Type.
		tbl, found, err := h.lookupTable(ctx, conn, sc)
		if err != nil {
			h.dbError(w, r, err, "")
			return
		}
		// A FOREIGN table is deliberately absent from the relation
		// listings (no browsing/data-format export — its rows live on the remote
		// server), so lookupTable cannot find it. Resolve it here ONLY when the
		// EFFECTIVE format is SQL — an omitted/unrecognized format falls through
		// to the SQL branch below, so the gate is "not a data format", not
		// format=="sql" — and tag it with the explicit TableForeign
		// discriminator that routes to structure-only planning (provably no
		// data pass). The row-streaming formats keep their historical 404.
		//
		// EVERY new data format must be added to isDataFormat, or a foreign
		// table exported in it would be resolved as structure-only and then
		// row-streamed from the REMOTE server.
		if !found && !isDataFormat(format) {
			isForeign, ferr := conn.IsForeignTable(ctx, sc.scope(), sc.Table)
			if ferr != nil {
				h.dbError(w, r, ferr, "")
				return
			}
			if isForeign {
				tbl = model.Table{Schema: sc.Schema, Name: sc.Table, Type: model.TableForeign}
				found = true
			}
		}
		if !found {
			h.renderError(w, r, http.StatusNotFound, "Table not found.", "")
			return
		}
		target = &tbl
		groups = []dump.SchemaGroup{{Schema: sc.Schema, Tables: []driver.TableRef{sc.tableRef()}}}
	} else {
		var err error
		groups, err = h.exportSchemaGroups(ctx, conn, sc.DB, h.resolveScope(r).Schema)
		if err != nil {
			h.dbError(w, r, err, "")
			return
		}
		// Per-object selection. Nothing checked means everything, so an ordinary
		// whole-database export is untouched.
		if sel := r.PostForm["objects[]"]; len(sel) > 0 {
			groups = filterGroupsBySelection(groups, sel)
			if len(groups) == 0 {
				h.renderError(w, r, http.StatusBadRequest,
					"None of the selected tables exist in this database — nothing to export.", "")
				return
			}
		}
	}
	var tables []driver.TableRef
	for _, g := range groups {
		tables = append(tables, g.Tables...)
	}

	// "With selected" export: restrict the data phase to the rows the browse grid
	// checked. Table scope only — a selection is made in one grid, so there is no
	// coherent meaning for it at database or server scope, and silently ignoring
	// it there would export everything under a "selected rows" label.
	var rowFilter *dump.RowFilter
	if level == "table" {
		var err error
		rowFilter, _, err = h.rowSelectionFilter(ctx, conn, sc, r.PostForm["rows[]"])
		if err != nil {
			h.renderError(w, r, http.StatusBadRequest, "Export failed: "+err.Error(), "")
			return
		}
	}

	// Row range: sample a slice of the table instead of all of it. Table scope
	// only — "the first 100 rows of every table" is not a coherent database
	// export.
	var rowRange *dump.RowRange
	if level == "table" {
		rowRange = parseRowRange(r.PostForm)
	}

	base := sc.Table
	if level == "db" {
		base = sc.DB
	}
	// All formats stream rows over a dedicated transient connection: dump
	// session state (MySQL's UTC time_zone) never touches the shared pools,
	// and a long-running download cannot starve the session's pool.
	econn, err := uc.ExportConnFor(ctx, sc.DB)
	if err != nil {
		h.connError(w, r, uc, err)
		return
	}
	defer econn.Close()

	gz := wantsGzip(r)
	out, finish, abort := exportSink(w, gz)
	// finish (which writes the gzip trailer) only on the path that ran to
	// completion; a panic or an early error return takes abort instead. The
	// flag is read inside the closure — a `defer finish(done)` would capture
	// the initial false at the defer statement.
	done := false
	defer func() {
		if done {
			finish()
		} else {
			abort()
		}
	}()
	switch format {
	case "csv":
		// Preflight: resolve each table's non-generated column list and explicit
		// SELECT before the download commits (the first body write below). A
		// column-introspection failure — or, for a single-table export, the
		// all-generated degenerate case — is then a clean rendered error, not a
		// corrupt, already-committed download. (Multi-table exports skip an
		// all-generated table with an explicit comment instead.)
		csvPlan, err := dump.BuildCSVPlan(ctx, econn, tables, rowFilter, rowRange)
		if err != nil {
			h.renderError(w, r, http.StatusInternalServerError, "Export failed: "+err.Error(), "")
			return
		}
		h.setDownload(w, base+".csv", "text/csv", gz)
		if err := dump.WriteCSV(ctx, out, econn, csvPlan); err != nil {
			// The download is already committed, so the error can only be
			// appended. Note the importer strips LEADING '#' comments only (a
			// data row may legitimately begin with '#', so trailing comments
			// cannot be stripped safely) — re-importing a failed export
			// therefore errors on this line, which is the correct outcome: the
			// file is incomplete and must not import silently.
			fmt.Fprintf(out, "\n# export error: %v\n", dump.CommentSafe(err.Error()))
		}
	case "json":
		h.setDownload(w, base+".json", "application/json", gz)
		// Schema-having engines nest tables under their schema so same-named tables
		// in different schemas cannot collide (identifiers may contain '.', so a
		// "schema.table" concat would be ambiguous); schema-less engines stay flat.
		dump.WriteJSON(ctx, out, econn, groups, conn.Capabilities().HasSchemas, rowFilter, rowRange)
	case "xml":
		h.setDownload(w, base+".xml", "application/xml", gz)
		// Same schema nesting as JSON, for the same reason: an identifier may
		// contain '.', so a "schema.table" name would be ambiguous.
		dump.WriteXML(ctx, out, econn, groups, conn.Capabilities().HasSchemas, rowFilter, rowRange)
	default: // sql
		o := dump.Options{Structure: withStructure, Data: withData, DropFirst: dropFirst, Rows: rowFilter, Range: rowRange}
		// Preflight: every piece of structure DDL is collected before the download
		// headers go out (per schema section), so an introspection failure is a
		// rendered error, not a silently incomplete download. Only row data streams.
		sections := make([]dump.Section, 0, len(groups)+1)
		// Database-GLOBAL objects (non-schema-owned — casts and
		// foreign-data classes plug in here) ride a schema-less leading section:
		// only database/server-scope exports are self-contained, so table scope
		// skips them (its external deps are diagnostics, not emissions).
		if level != "table" {
			gplan, err := econn.DumpGlobalObjects(ctx, o.Structure)
			if err != nil {
				h.renderError(w, r, http.StatusInternalServerError, "Export failed during structure introspection: "+err.Error(), "")
				return
			}
			if !dump.PlanEmpty(gplan) {
				sections = append(sections, dump.Section{Schema: "", Plan: dump.NewPlan(gplan)})
			}
		}
		for _, g := range groups {
			plan, err := dump.BuildPlan(ctx, econn, driver.TableRef{Database: sc.DB, Schema: g.Schema}, g.Tables, level, o, target)
			if err != nil {
				h.renderError(w, r, http.StatusInternalServerError, "Export failed during structure introspection: "+err.Error(), "")
				return
			}
			sections = append(sections, dump.Section{Schema: g.Schema, Plan: plan})
		}
		// The unified planner — cross-schema/cross-phase topological
		// ordering with cycle resolution; a genuinely unrestorable cycle is a
		// PREFLIGHT failure (rendered error), never a broken download.
		dbp, err := dump.ResolveDB(ctx, econn, sections, o)
		if err != nil {
			h.renderError(w, r, http.StatusInternalServerError, "Export failed during structure planning: "+err.Error(), "")
			return
		}
		h.setDownload(w, base+".sql", "application/sql", gz)
		fmt.Fprintf(out, "-- TableX SQL export\n-- Engine: %s\n\n", uc.Engine)
		dump.WritePreamble(out, uc.Dialect())
		dump.WriteDB(ctx, out, econn, dbp, o)
		dump.WritePostamble(out, uc.Dialect())
	}
	done = true
}

// streamServerExport dumps every non-system database as one SQL script. All
// per-engine framing lives behind driver.ServerDumpFramer: section headers
// (MySQL's executable CREATE DATABASE/USE, PostgreSQL's \connect markers),
// preamble scope (global vs per-section — PostgreSQL session SETs do not
// survive \connect), addressability guards (the PG newline-in-name skip,
// SQLite's main-only rule) and the dump-header help text. This handler loops
// over databases and delegates; it never branches on an engine name.
func (h *Handlers) streamServerExport(w http.ResponseWriter, r *http.Request, uc *UserContext, structure, data, dropFirst bool) {
	ctx := r.Context()
	o := dump.Options{Structure: structure, Data: data, DropFirst: dropFirst}
	d := uc.Dialect()
	framer, _ := d.(driver.ServerDumpFramer)
	var profile driver.ServerDumpProfile
	if framer != nil {
		profile = framer.ServerDumpProfile()
	}
	// The FULL listing (not ListDatabaseNames): the dump needs each database's
	// default collation for its section header, and a server dump is heavyweight
	// anyway — one aggregate listing query is noise.
	dbs, err := uc.ServerConn().ListDatabases(ctx)
	if err != nil {
		h.dbError(w, r, err, "")
		return
	}
	// A server dump names no database in its route, so the allowlist has to be
	// applied to its CONTENTS or it would hand over in one file exactly what the
	// rest of the UI declines to show. See allowedDatabases.
	dbs = h.allowedDatabases(dbs)

	type dbPlan struct {
		name      string
		collation string // introspected default collation (for the section header)
		resolved  *dump.DBPlan
		skipErr   string
	}
	preflight := func(name string) dbPlan {
		if framer != nil {
			if reason := framer.UnaddressableDatabase(name); reason != "" {
				return dbPlan{name: name, skipErr: reason}
			}
		}
		econn, err := uc.ExportConnFor(ctx, name)
		if err != nil {
			// A failed dial may echo the DSN; redact before it lands in the dump.
			return dbPlan{name: name, skipErr: uc.redactErr(err)}
		}
		defer econn.Close()
		// Enumerate every non-system schema (PostgreSQL) so a server dump does not
		// silently omit non-public schemas; schema-less engines return one group.
		groups, err := h.exportSchemaGroups(ctx, econn, name, "")
		if err != nil {
			return dbPlan{name: name, skipErr: "list tables failed: " + err.Error()}
		}
		var sections []dump.Section
		// Database-global objects — once per database (globals live per
		// database, so a server dump spanning databases runs the collector for
		// each section).
		gplan, err := econn.DumpGlobalObjects(ctx, o.Structure)
		if err != nil {
			return dbPlan{name: name, skipErr: "structure introspection failed: " + err.Error()}
		}
		if !dump.PlanEmpty(gplan) {
			sections = append(sections, dump.Section{Schema: "", Plan: dump.NewPlan(gplan)})
		}
		for _, g := range groups {
			plan, err := dump.BuildPlan(ctx, econn, driver.TableRef{Database: name, Schema: g.Schema}, g.Tables, "db", o, nil)
			if err != nil {
				return dbPlan{name: name, skipErr: "structure introspection failed: " + err.Error()}
			}
			sections = append(sections, dump.Section{Schema: g.Schema, Plan: plan})
		}
		// The unified planner runs per database section — the server-scope
		// path previously looped complete per-schema sections, hiding every
		// cross-schema dependency from the ordering.
		resolved, err := dump.ResolveDB(ctx, econn, sections, o)
		if err != nil {
			return dbPlan{name: name, skipErr: "structure planning failed: " + err.Error()}
		}
		return dbPlan{name: name, resolved: resolved}
	}

	var plans []dbPlan
	for _, db := range dbs {
		// db.IsSystem already flags every engine-internal database: MySQL's
		// information_schema/mysql/performance_schema/sys (mysqlSystemDBs), and
		// PostgreSQL templates never appear (ListDatabaseNames filters
		// datistemplate=false). SQLite flags none; its framer skips ATTACH-ed
		// databases via UnaddressableDatabase.
		if db.IsSystem {
			continue
		}
		p := preflight(db.Name)
		p.collation = db.Collation
		plans = append(plans, p)
	}

	gz := wantsGzip(r)
	h.setDownload(w, "server.sql", "application/sql", gz)
	out, finish, abort := exportSink(w, gz)
	// Same completion discipline as the table/DB export above: the trailer
	// only on the path that ran to the end.
	done := false
	defer func() {
		if done {
			finish()
		} else {
			abort()
		}
	}()
	fmt.Fprintf(out, "-- TableX SQL export (server scope)\n-- Engine: %s\n", uc.Engine)
	if framer != nil {
		framer.WriteServerDumpHeader(out)
	}
	fmt.Fprintln(out)
	if !profile.PerSectionPreamble {
		dump.WritePreamble(out, d)
	}

	for _, p := range plans {
		fmt.Fprintf(out, "\n-- ===========================\n-- Database: %s\n-- ===========================\n", dump.CommentSafe(p.name))
		if p.skipErr != "" {
			fmt.Fprintf(out, "-- skipped database %s: %s\n", dump.CommentSafe(p.name), dump.CommentSafe(p.skipErr))
			continue
		}
		if framer != nil {
			framer.WriteDatabaseSectionHeader(out, p.name, p.collation)
		}
		if profile.PerSectionPreamble {
			dump.WritePreamble(out, d)
		}
		// One transient connection per database, closed before the next opens
		// (holding every per-DB pool at once would defeat the pool budget). The
		// helper scopes the close in a defer so a panic inside a section write
		// (recovered by the middleware) cannot leak the pool.
		func() {
			econn, err := uc.ExportConnFor(ctx, p.name)
			if err != nil {
				fmt.Fprintf(out, "-- skipped database %s: %s\n", dump.CommentSafe(p.name), dump.CommentSafe(uc.redactErr(err)))
				return
			}
			defer econn.Close()
			dump.WriteDB(ctx, out, econn, p.resolved, o)
		}()
	}
	if !profile.PerSectionPreamble {
		dump.WritePostamble(out, d)
	}
	done = true
}

// exportWriteTimeout bounds how long a single export write may stall before the
// connection is dropped (see newDeadlineWriter). It shares the view package's
// per-write bound so every response write path uses the one constant.
const exportWriteTimeout = view.WriteTimeout

// deadlineWriter extends the response write deadline on every write so a
// streaming export is bounded per chunk without a fixed overall WriteTimeout
// cutting off a large but progressing dump. SetWriteDeadline is best-effort: if
// the platform/writer doesn't support it the writer degrades to a plain pass-through.
type deadlineWriter struct {
	w   io.Writer
	rc  *http.ResponseController
	per time.Duration
}

func newDeadlineWriter(w http.ResponseWriter, per time.Duration) *deadlineWriter {
	return &deadlineWriter{w: w, rc: http.NewResponseController(w), per: per}
}

func (d *deadlineWriter) Write(p []byte) (int, error) {
	_ = d.rc.SetWriteDeadline(time.Now().Add(d.per))
	return d.w.Write(p)
}

// clear removes the rolling deadline once the export finishes, so a stale
// deadline cannot linger on the keep-alive connection and cut off an
// unrelated later response on it.
func (d *deadlineWriter) clear() {
	_ = d.rc.SetWriteDeadline(time.Time{})
}

// wantsGzip reports whether the export form asked for a COMPRESSED FILE. This is
// unrelated to the transport gzip middleware, which negotiates Accept-Encoding
// and is undone by the browser before the file is saved: only this produces a
// .gz on disk.
func wantsGzip(r *http.Request) bool { return r.PostFormValue("compression") == "gzip" }

// exportSink builds the writer a dump streams into: the per-write deadline
// writer (there is no global WriteTimeout — exports stream — so a stalled client
// must not hold the connection open indefinitely, while a slow-but-progressing
// dump keeps extending its deadline), optionally wrapped in a gzip encoder.
//
// Exactly one of the returned pair must run before the handler returns, and
// which one is the whole point. finish closes the gzip stream: a gzip file
// without its trailer is a truncated file that most tools refuse outright, so
// it belongs on the path that ran to completion — and ONLY there. abort clears
// the deadline WITHOUT writing the trailer, for a dump that did not finish (a
// panic unwinding the caller's defer): sealing that stream would present a
// truncated backup as a complete one, and this is the form-selected .gz file
// the transport middleware's own abort path cannot reach (setDownload labels
// it application/gzip, deliberately absent from the transport allowlist).
//
// A pair rather than finish(ok bool) on purpose: `defer finish(ok)` evaluates
// ok at the defer STATEMENT, capturing the initial false — every successful
// compressed export would then ship trailer-less. A pair has no argument to
// capture and cannot be got wrong.
func exportSink(w http.ResponseWriter, compress bool) (out io.Writer, finish, abort func()) {
	dw := newDeadlineWriter(w, exportWriteTimeout)
	if !compress {
		return dw, dw.clear, dw.clear
	}
	zw := gzip.NewWriter(dw)
	finish = func() {
		_ = zw.Close()
		dw.clear()
	}
	return zw, finish, dw.clear
}

func (h *Handlers) setDownload(w http.ResponseWriter, filename, contentType string, compressed bool) {
	if compressed {
		// A gzip FILE, not a gzip transfer encoding — so no Content-Encoding
		// header, and application/gzip is deliberately absent from the transport
		// middleware's compressible allowlist, which is what stops the response
		// being compressed a second time.
		filename += ".gz"
		contentType = "application/gzip"
	}
	// Only the two pure-UTF-8 text formats carry a charset. A SQL dump does not:
	// MySQL object bodies are emitted byte-exact under their original
	// character_set_client, so the file is mixed-encoding by design (exactly like
	// mysqldump's output) and a utf-8 label would invite re-encoding. Byte-exact
	// restore requires re-importing the dump as a FILE UPLOAD — a textarea paste
	// is re-encoded by the browser. A gzip file is binary and carries none either.
	switch contentType {
	case "text/csv", "application/json", "application/xml":
		contentType += "; charset=utf-8"
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", "attachment; filename=\""+safeFilename(filename)+"\"")
	w.Header().Set("Cache-Control", "no-store")
}

func safeFilename(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r == '.' || r == '-' || r == '_' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	return b.String()
}
