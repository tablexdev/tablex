package handlers

import (
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

// tableRow decorates a model.Table with the action links the structure grid
// needs, so the template stays declarative.
type tableRow struct {
	model.Table
	BrowseURL    string
	StructureURL string
	SearchURL    string
	InsertURL    string
	DropURL      string
}

type schemaRow struct {
	model.Schema
	URL string
}

type dbStructureBody struct {
	Scope       reqScope
	ShowSchemas bool
	Schemas     []schemaRow
	Tables      []tableRow
	TotalRows   int64
	TotalSize   int64
	HasSize     bool
	Caps        driver.Capabilities
	CreateURL   string
}

// DBStructure renders a database's Structure tab (GET /db/{db}). For PostgreSQL
// with no schema selected it lists schemas; otherwise it lists tables/views.
func (h *Handlers) DBStructure(w http.ResponseWriter, r *http.Request) {
	uc, ok := h.requireUser(w, r)
	if !ok {
		return
	}
	sc := h.resolveScope(r)
	p := h.newLoggedPage(r, uc, "Database: "+sc.DB)
	p.Breadcrumb = h.buildBreadcrumb(uc, sc)
	p.Tabs = h.dbTabs(uc, sc, "structure")

	body := dbStructureBody{Scope: sc, Caps: uc.Capabilities()}

	conn, err := uc.ConnFor(r.Context(), sc.DB)
	if err != nil {
		h.connError(w, r, uc, err)
		return
	}

	if uc.Capabilities().HasSchemas && sc.Schema == "" {
		schemas, err := conn.ListSchemas(r.Context(), sc.DB)
		if err != nil {
			h.dbError(w, r, err, "")
			return
		}
		body.ShowSchemas = true
		for _, s := range schemas {
			body.Schemas = append(body.Schemas, schemaRow{Schema: s, URL: urlDB(sc.DB, s.Name, "structure")})
		}
		p.Body = body
		h.render(w, r, "db_structure", p)
		return
	}

	tables, err := conn.ListTables(r.Context(), sc.scope())
	if err != nil {
		h.dbError(w, r, err, "")
		return
	}
	for _, t := range tables {
		if t.IsSequence() {
			continue // MariaDB sequences are not browsable data tables
		}
		body.Tables = append(body.Tables, tableRow{
			Table:        t,
			BrowseURL:    urlTable(sc.DB, sc.Schema, t.Name, "browse"),
			StructureURL: urlTable(sc.DB, sc.Schema, t.Name, "structure"),
			SearchURL:    urlTable(sc.DB, sc.Schema, t.Name, "search"),
			InsertURL:    urlTable(sc.DB, sc.Schema, t.Name, "insert"),
			DropURL:      urlTable(sc.DB, sc.Schema, t.Name, "operations"),
		})
		if t.Rows > 0 {
			body.TotalRows += t.Rows
		}
		if t.Size > 0 {
			body.TotalSize += t.Size
			body.HasSize = true
		}
	}
	// The Create-table link requires a SchemaEditor (all three engines have
	// one; a future dialect without it simply shows no link) and DDL permission.
	// Leaving the URL empty is what the template already reads as "no link",
	// including in the empty-database hint, which then points at the SQL console
	// instead — and, under a policy that also withholds the console, says nothing
	// misleading either way.
	if _, ok := conn.Dialect().(driver.SchemaEditor); ok && h.allowance().DDL {
		body.CreateURL = urlDB(sc.DB, sc.Schema, "create-table")
	}
	p.Body = body
	h.render(w, r, "db_structure", p)
}

// --- Create table -----------------------------------------------------------------

type createTableBody struct {
	Scope       reqScope
	PostURL     string
	ColumnTypes []string
	RowIndexes  []int // the fixed batch of blank column rows (no-JS fallback)
	// ValueListTypes are the types taking a value list rather than a length
	// (MySQL ENUM/SET). Empty on an engine with none, which hides the control.
	ValueListTypes []string
}

// createTableMaxRows bounds the indexed-field scan on POST (the form starts
// with createTableFormRows blank rows; the Alpine add-row enhancement can
// append up to this many).
const (
	createTableFormRows = 8
	createTableMaxRows  = 50
)

// DBCreateTable renders (GET) and runs (POST) the create-table form. It
// mirrors DBOperations' dispatch shape: validate-first, build via the
// SchemaEditor, exec via ExecScript, redirect with a flash.
func (h *Handlers) DBCreateTable(w http.ResponseWriter, r *http.Request) {
	uc, ok := h.requireUser(w, r)
	if !ok {
		return
	}
	sc := h.resolveScope(r).withSchemaDefault(uc.Capabilities())
	conn, err := uc.ConnFor(r.Context(), sc.DB)
	if err != nil {
		h.connError(w, r, uc, err)
		return
	}
	editor, ok := conn.Dialect().(driver.SchemaEditor)
	if !ok {
		h.renderError(w, r, http.StatusBadRequest, "This engine does not support structure editing.", "")
		return
	}
	if found, err := h.databaseExists(r.Context(), uc, sc.DB); err != nil {
		h.dbError(w, r, err, "")
		return
	} else if !found {
		h.renderError(w, r, http.StatusNotFound, "Database not found.", "")
		return
	}

	if r.Method == http.MethodPost {
		if !h.parseFormOr400(w, r) {
			return
		}
		name := strings.TrimSpace(r.PostFormValue("table_name"))
		if !driver.ValidNewIdentifier(conn.Capabilities(), name) {
			h.renderError(w, r, http.StatusBadRequest, "Invalid table name.", "")
			return
		}
		exists, err := h.tableExists(r.Context(), conn, reqScope{DB: sc.DB, Schema: sc.Schema, Table: name})
		if err != nil {
			// Fail closed — the most consequential of tableExists' callers:
			// this guard used to read a failed lookup as "no duplicate" and
			// let CREATE TABLE proceed against catalog state it never saw.
			h.Log.Warn("create-table duplicate guard failed", "err", redactConnError(err), "reqid", RequestID(r.Context()))
			h.renderError(w, r, http.StatusInternalServerError, "Could not verify whether that table already exists.", "")
			return
		}
		if exists {
			h.renderError(w, r, http.StatusBadRequest, "A table with that name already exists.", "")
			return
		}
		cols, pk, err := parseCreateColumns(conn.Dialect(), editor, r)
		if err != nil {
			h.renderError(w, r, http.StatusBadRequest, err.Error(), "")
			return
		}
		ref := driver.TableRef{Database: sc.DB, Schema: sc.Schema, Table: name}
		stmts, err := editor.CreateTableSQL(ref, cols, pk)
		if err != nil {
			h.renderError(w, r, http.StatusBadRequest, err.Error(), "")
			return
		}
		if err := conn.ExecScript(r.Context(), stmts, conn.Capabilities().SupportsTransactionalDDL); err != nil {
			h.dbError(w, r, err, strings.Join(stmts, ";\n"))
			return
		}
		h.redirectTo(w, r, urlTable(sc.DB, sc.Schema, name, "structure"),
			view.Flash{Kind: "success", Message: fmt.Sprintf("Table %q created.", name)})
		return
	}

	body := createTableBody{
		Scope:       sc,
		PostURL:     urlDB(sc.DB, sc.Schema, "create-table"),
		ColumnTypes: editor.ColumnTypes(),
		RowIndexes:  make([]int, createTableFormRows),
	}
	if typer, ok := conn.Dialect().(driver.ValueListTyper); ok {
		body.ValueListTypes = typer.ValueListTypes()
	}
	for i := range body.RowIndexes {
		body.RowIndexes[i] = i
	}
	p := h.newLoggedPage(r, uc, sc.DB+" · Create table")
	p.Breadcrumb = h.buildBreadcrumb(uc, sc)
	p.Tabs = h.dbTabs(uc, sc, "structure")
	p.Body = body
	h.render(w, r, "db_create_table", p)
}

// parseCreateColumns loops the indexed repeatable fields (col_name_0,
// col_type_0, …) into ColumnSpecs through the same inner helpers the
// single-column structure path uses (assembleColumnType, buildDefault). Rows
// whose trimmed name is empty are skipped BEFORE any validation — the no-JS
// form always submits its blank rows — and every surviving column name passes
// driver.ValidNewIdentifier (the inner helpers validate type/default only).
// PK checkbox selections ride the surviving rows; the dialect builder
// re-validates pk membership and duplicates.
func parseCreateColumns(d driver.Dialect, editor driver.SchemaEditor, r *http.Request) (cols []driver.ColumnSpec, pk []string, err error) {
	for i := range createTableMaxRows {
		sfx := "_" + strconv.Itoa(i)
		name := strings.TrimSpace(r.PostFormValue("col_name" + sfx))
		if name == "" {
			continue // blank row from the fixed batch
		}
		if !driver.ValidNewIdentifier(d.Capabilities(), name) {
			return nil, nil, fmt.Errorf("invalid column name %q", name)
		}
		base := strings.ToLower(strings.TrimSpace(r.PostFormValue("col_type" + sfx)))
		// Same type assembly as the add-column path, per row: an ordinary type
		// takes col_length, one of the engine's list-valued types (MySQL
		// ENUM/SET) takes col_values instead. columnType reads the row's own
		// suffixed fields, so it is handed a one-row view of the form.
		typ, err := columnType(d, editor, url.Values{
			"col_length": {r.PostFormValue("col_length" + sfx)},
			"col_values": {r.PostFormValue("col_values" + sfx)},
		}, r.PostFormValue("col_type"+sfx), nil)
		if err != nil {
			return nil, nil, fmt.Errorf("column %q: %w", name, err)
		}
		def, err := buildDefault(d, r.PostFormValue("default_mode"+sfx), r.PostFormValue("default_value"+sfx), base)
		if err != nil {
			return nil, nil, fmt.Errorf("column %q: %w", name, err)
		}
		isPK := r.PostFormValue("col_pk"+sfx) != ""
		cols = append(cols, driver.ColumnSpec{
			Name: name,
			Type: typ,
			// A PRIMARY KEY column must be NOT NULL. MySQL/PostgreSQL force this
			// implicitly, but SQLite permits NULLs in a non-INTEGER PK declared
			// without NOT NULL — so gate it here rather than emit a nullable PK.
			Nullable: !isPK && r.PostFormValue("col_nullable"+sfx) != "",
			Default:  def,
			Comment:  strings.TrimSpace(r.PostFormValue("col_comment" + sfx)),
		})
		if isPK {
			pk = append(pk, name)
		}
	}
	if len(cols) == 0 {
		return nil, nil, errors.New("define at least one column")
	}
	return cols, pk, nil
}
