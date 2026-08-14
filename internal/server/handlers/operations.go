package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/tablexdev/tablex/internal/audit"
	"github.com/tablexdev/tablex/internal/driver"
	"github.com/tablexdev/tablex/internal/model"
	"github.com/tablexdev/tablex/internal/view"
)

type tableOpsBody struct {
	Scope     reqScope
	PostURL   string
	BrowseURL string
	IsView    bool // views: no truncate/empty; rename/drop route to view DDL

	// Maintenance is whatever the engine offers (nil for an engine with no
	// TableMaintainer); Report holds the last run's output, which on MySQL is
	// the whole point — CHECK and REPAIR answer with a status table.
	Maintenance []driver.TableMaintenanceOp
	Report      *driver.ResultSet
	ReportOp    string
}

type dbOpsBody struct {
	Scope   reqScope
	PostURL string
	// EngineManagesDB is the CAPABILITY (this engine has CREATE/DROP DATABASE);
	// CanManageDB is capability AND policy (DDL allowed). The two are split so
	// the template can tell "SQLite has no such statement" (the single-file
	// message) from "this TableX forbids DDL" (a neutral policy message) —
	// under allow_ddl=false, folding them made a PostgreSQL/MySQL operator
	// read the SQLite-only wording. table_operations.html already does this.
	EngineManagesDB  bool
	CanManageDB      bool             // engine supports CREATE/DROP DATABASE AND DDL is allowed
	CanManageSchemas bool             // engine has schemas (PostgreSQL)
	Schemas          []model.Schema   // non-system schemas of this DB (drop select)
	Collations       []collationGroup // create-DB collation options, grouped by charset
}

// collationGroup is one charset's collations for the create-database select's
// optgroups.
type collationGroup struct {
	Charset    string
	Collations []driver.Collation
}

// collationOptions returns the server's collations grouped for the
// create-database select's optgroups. A listing failure returns nil: the
// selector is simply hidden (creation still works with the server default and
// the POST path re-validates independently). Shared by the DB-operations and
// server-databases pages.
func (h *Handlers) collationOptions(ctx context.Context, uc *UserContext) []collationGroup {
	list, err := uc.ServerConn().ListCollations(ctx)
	if err != nil {
		return nil
	}
	return groupCollations(list)
}

// groupCollations groups the flat introspected collation list by charset,
// preserving the introspection order (already charset-then-name sorted).
func groupCollations(list []driver.Collation) []collationGroup {
	var out []collationGroup
	for _, c := range list {
		if n := len(out); n == 0 || out[n-1].Charset != c.Charset {
			out = append(out, collationGroup{Charset: c.Charset})
		}
		out[len(out)-1].Collations = append(out[len(out)-1].Collations, c)
	}
	return out
}

// lookupTable finds a table or view by name via introspection, returning the
// matched model.Table so the caller can branch on its Type (a view must not get
// a DROP TABLE). The error is kept distinct from "not found" so a destructive
// operation can surface an introspection failure instead of a misleading 404.
func (h *Handlers) lookupTable(ctx context.Context, conn *driver.Connection, sc reqScope) (model.Table, bool, error) {
	tables, err := h.tableNames(ctx, conn, sc.scope())
	if err != nil {
		return model.Table{}, false, err
	}
	for _, t := range tables {
		if t.Name == sc.Table {
			return t, true, nil
		}
	}
	return model.Table{}, false, nil
}

// tableExists validates that a table/view is present via introspection before a
// destructive operation builds SQL referencing it. found and err are distinct
// — lookupTable's own contract — because the callers fail in OPPOSITE
// directions when the two are conflated: the create-table duplicate guard
// would read a failed lookup as "no duplicate" and proceed against catalog
// state it never saw, while the rest would report a misleading 404.
func (h *Handlers) tableExists(ctx context.Context, conn *driver.Connection, sc reqScope) (bool, error) {
	_, found, err := h.lookupTable(ctx, conn, sc)
	return found, err
}

// requireDataTable is the shared table-route guard against MariaDB SEQUENCE
// objects: sequences are listed as tables by introspection, but browsing,
// editing, restructuring or importing into one through the data-table routes
// would corrupt its single state row. Every table-scoped route except export
// calls this after resolving its connection (export stays allowed — the dump
// is restore-valid and carries sequence state). It reuses the
// request-memoized listing via lookupTable, so the identity query runs at
// most once per request. A missing table or a listing error passes — the
// handler then surfaces its own not-found/introspection handling. When ok is
// false a rejection page was already written and the caller must return.
func (h *Handlers) requireDataTable(w http.ResponseWriter, r *http.Request, conn *driver.Connection, sc reqScope) bool {
	if sc.Table == "" {
		return true
	}
	tbl, found, err := h.lookupTable(r.Context(), conn, sc)
	if err != nil || !found {
		return true
	}
	if tbl.IsSequence() {
		h.renderError(w, r, http.StatusBadRequest,
			fmt.Sprintf("%q is a sequence, not a data table. Sequences carry generator state and can be exported, but not browsed or edited.", sc.Table), "")
		return false
	}
	return true
}

// requireWritableTable guards the mutating table routes (insert, edit, delete
// and the table-scoped import) against objects TableX does not write in place:
// VIEWS — TableX does not support inserting/editing/deleting rows through a view
// (an app-level read-only-view policy; the SQL console is the
// documented escape hatch, and table-scope EXPORT stays allowed and emits real
// view DDL) — and MariaDB SEQUENCE objects (single-state generators). Unlike
// requireDataTable, which deliberately PASSES views/missing/error through so the
// browse-adjacent handlers surface their own errors, this write guard FAILS
// CLOSED: a lookup error logs the redacted cause and renders 500 (dbError would
// render 400 and bare renderError would not log), a missing table renders 404,
// and a view or sequence renders 400 with the policy message — a write must never
// proceed on an unverified target. Hiding the tabs/links alone is insufficient:
// the routes stay registered, so the enforcement lives here. When ok is false a
// response was already written and the caller must return.
func (h *Handlers) requireWritableTable(w http.ResponseWriter, r *http.Request, conn *driver.Connection, sc reqScope) bool {
	if sc.Table == "" {
		return true
	}
	tbl, found, err := h.lookupTable(r.Context(), conn, sc)
	if err != nil {
		h.Log.Warn("table write-guard lookup failed", "err", redactConnError(err), "reqid", RequestID(r.Context()))
		h.renderError(w, r, http.StatusInternalServerError, "Could not verify the table before writing to it.", "")
		return false
	}
	if !found {
		h.renderError(w, r, http.StatusNotFound, fmt.Sprintf("%q was not found.", sc.Table), "")
		return false
	}
	if tbl.IsView() {
		h.renderError(w, r, http.StatusBadRequest,
			fmt.Sprintf("%q is a view. TableX does not insert, edit or delete rows through a view — use the SQL console to run statements against the underlying tables.", sc.Table), "")
		return false
	}
	if tbl.IsSequence() {
		h.renderError(w, r, http.StatusBadRequest,
			fmt.Sprintf("%q is a sequence, not a data table. Sequences carry generator state and can be exported, but not browsed or edited.", sc.Table), "")
		return false
	}
	return true
}

// objectKind maps a model.TableType to the driver Object* kind used by
// DropObjectSQL / RenameObjectSQL.
func objectKind(t model.TableType) string {
	switch t {
	case model.TableView:
		return driver.ObjectView
	case model.TableMatView:
		return driver.ObjectMatView
	default:
		return driver.ObjectTable
	}
}

// databaseExists validates that a database is present via introspection before a
// destructive operation builds SQL referencing it (DROP DATABASE uses the
// path-supplied name, which QuoteIdent quotes but does not verify).
//
// found and err are distinct, exactly as tableExists keeps them: swallowing a
// listing error and returning false rendered the same "Database not found."
// 404 for a genuinely absent database and for a failed listing, with the cause
// neither logged nor shown — a caller must be able to tell the two apart.
func (h *Handlers) databaseExists(ctx context.Context, uc *UserContext, name string) (bool, error) {
	dbs, err := h.databaseNames(ctx, uc)
	if err != nil {
		return false, err
	}
	for _, db := range dbs {
		if db.Name == name {
			return true, nil
		}
	}
	return false, nil
}

// TableOperations renders and runs table maintenance (rename/truncate/drop).
func (h *Handlers) TableOperations(w http.ResponseWriter, r *http.Request) {
	uc, sc, conn, ok := h.requireConn(w, r)
	if !ok {
		return
	}
	if !h.requireDataTable(w, r, conn, sc) {
		return
	}

	if r.Method == http.MethodPost {
		h.runTableOp(w, r, uc, conn, sc)
		return
	}

	h.renderTableOps(w, r, uc, conn, sc, nil, "")
}

// renderTableOps draws the operations page. report/reportOp carry the output of
// a maintenance run that has just happened (both zero on a plain GET).
func (h *Handlers) renderTableOps(w http.ResponseWriter, r *http.Request, uc *UserContext, conn *driver.Connection, sc reqScope, report *driver.ResultSet, reportOp string) {
	tbl, found, err := h.lookupTable(r.Context(), conn, sc)
	if err != nil {
		// Fail closed, like requireWritableTable: with the error discarded, a
		// view read as IsView=false through the zero-value Table and this
		// page offered Truncate and Drop-as-table for it — destructive
		// controls on the strength of a failed lookup.
		h.Log.Warn("table operations lookup failed", "err", redactConnError(err), "reqid", RequestID(r.Context()))
		h.renderError(w, r, http.StatusInternalServerError, "Could not verify the table before offering operations on it.", "")
		return
	}
	if !found {
		// The companion arm of lookupTable's own contract: a missing object
		// gets its 404 rather than an operations page over nothing. Safe for
		// the re-render after maintenance — rename and drop redirect away and
		// never come back through here under the old name.
		h.renderError(w, r, http.StatusNotFound, fmt.Sprintf("%q was not found.", sc.Table), "")
		return
	}
	body := tableOpsBody{
		Scope:     sc,
		PostURL:   urlTable(sc.DB, sc.Schema, sc.Table, "operations"),
		BrowseURL: urlTable(sc.DB, sc.Schema, sc.Table, "browse"),
		IsView:    tbl.IsView(),
		Report:    report,
		ReportOp:  reportOp,
	}
	// A view has no storage of its own, so none of these apply to one.
	if !body.IsView {
		body.Maintenance = conn.TableMaintenanceOps()
	}
	p := h.newLoggedPage(r, uc, sc.Table+" · Operations")
	p.Breadcrumb = h.buildBreadcrumb(uc, sc)
	p.Tabs = h.tableTabs(r.Context(), uc, sc, "operations", conn)
	p.Body = body
	h.render(w, r, "table_operations", p)
}

func (h *Handlers) runTableOp(w http.ResponseWriter, r *http.Request, uc *UserContext, conn *driver.Connection, sc reqScope) {
	if !h.parseFormOr400(w, r) {
		return
	}
	tbl, found, err := h.lookupTable(r.Context(), conn, sc)
	if err != nil {
		h.dbError(w, r, err, "")
		return
	}
	if !found {
		h.renderError(w, r, http.StatusNotFound, "Table not found.", "")
		return
	}
	editor, ok := conn.Dialect().(driver.SchemaEditor)
	if !ok {
		h.renderError(w, r, http.StatusBadRequest, "This engine does not support table operations.", "")
		return
	}
	isView := tbl.IsView()
	kind := objectKind(tbl.Type)
	noun := "Table"
	if isView {
		noun = "View"
	}
	ref := sc.tableRef()
	caps := conn.Capabilities()
	action := r.PostFormValue("action")

	// Build the statement(s) for the requested op, rejecting invalid combinations
	// (truncate on a view) in the handler — the endpoint is reachable directly, so
	// the template gating is not the authority.
	switch action {
	case "rename":
		newName := strings.TrimSpace(r.PostFormValue("new_name"))
		if !driver.ValidNewIdentifier(caps, newName) {
			h.renderError(w, r, http.StatusBadRequest, "Invalid new "+strings.ToLower(noun)+" name.", "")
			return
		}
		stmts, err := editor.RenameObjectSQL(ref, newName, kind)
		if err != nil {
			h.renderError(w, r, http.StatusBadRequest, err.Error(), "")
			return
		}
		if err := conn.ExecScript(r.Context(), stmts, caps.SupportsTransactionalDDL); err != nil {
			h.dbError(w, r, err, strings.Join(stmts, ";\n"))
			return
		}
		dest := urlTable(sc.DB, sc.Schema, newName, "browse")
		h.redirectToNav(w, r, dest, view.Flash{Kind: "success", Message: fmt.Sprintf("%s renamed to %q.", noun, newName)})

	case "truncate":
		if isView {
			h.renderError(w, r, http.StatusBadRequest, "A view cannot be emptied.", "")
			return
		}
		if !h.requireConfirm(w, r, uc, sc, fmt.Sprintf("Empty %s %q? Every row is deleted.", strings.ToLower(noun), sc.Table),
			urlTable(sc.DB, sc.Schema, sc.Table, "operations"), "Empty") {
			return
		}
		qualified := conn.QualifiedName(ref)
		stmt := "TRUNCATE TABLE " + qualified
		if !caps.SupportsTruncate {
			stmt = "DELETE FROM " + qualified
		}
		if _, err := conn.Exec(r.Context(), stmt); err != nil {
			h.dbError(w, r, err, stmt)
			return
		}
		h.afterMutation(w, r, uc, sc, view.Flash{Kind: "success", Message: "Table emptied."})

	case "drop":
		if !h.requireConfirm(w, r, uc, sc, fmt.Sprintf("Drop %s %q?", strings.ToLower(noun), sc.Table),
			urlTable(sc.DB, sc.Schema, sc.Table, "operations"), "Drop") {
			return
		}
		stmts, err := editor.DropObjectSQL(ref, kind)
		if err != nil {
			h.renderError(w, r, http.StatusBadRequest, err.Error(), "")
			return
		}
		if err := conn.ExecScript(r.Context(), stmts, caps.SupportsTransactionalDDL); err != nil {
			h.dbError(w, r, err, strings.Join(stmts, ";\n"))
			return
		}
		dest := urlDB(sc.DB, sc.Schema, "structure")
		h.redirectToNav(w, r, dest, view.Flash{Kind: "success", Message: fmt.Sprintf("%s %q dropped.", noun, sc.Table)})

	case "maintain":
		h.runMaintenance(w, r, uc, conn, sc, isView, r.PostFormValue("op"))

	default:
		h.renderError(w, r, http.StatusBadRequest, "Unknown operation.", "")
	}
}

// runMaintenance runs one engine maintenance command and re-renders the page
// with whatever it reported. Unlike the other operations it does not redirect:
// MySQL's CHECK and REPAIR answer with a status table that IS the result, and a
// redirect would throw it away.
func (h *Handlers) runMaintenance(w http.ResponseWriter, r *http.Request, uc *UserContext, conn *driver.Connection, sc reqScope, isView bool, op string) {
	if isView {
		h.renderError(w, r, http.StatusBadRequest, "A view has no storage to maintain.", "")
		return
	}
	// Only a name this engine actually offers. The form is not the authority —
	// this endpoint is reachable directly — and the dialect rejects an unknown
	// op as well, so neither layer alone has to be trusted.
	ops := conn.TableMaintenanceOps()
	label := ""
	for _, o := range ops {
		if o.Name == op {
			label = o.Label
		}
	}
	if label == "" {
		h.renderError(w, r, http.StatusBadRequest, "This engine does not offer that maintenance operation.", "")
		return
	}
	set, err := conn.RunTableMaintenance(r.Context(), sc.tableRef(), op)
	if err != nil {
		h.dbError(w, r, err, "")
		return
	}
	uc.AddFlash(view.Flash{Kind: "success", Message: label + " finished."})
	h.renderTableOps(w, r, uc, conn, sc, set, label)
}

// dropDatabase drops the named database, then closes its cached per-session pool
// (a dangling *Connection plus a leaked PoolBudget slot otherwise). PostgreSQL
// cannot drop the database its own session is connected to — WITH (FORCE) only
// terminates OTHER sessions — so when the target is the session's login database
// the drop runs on a transient maintenance connection (the dialect names the
// candidates via driver.MaintenanceDatabaseLister), and the session is rebound
// to that maintenance database so it survives (matching MySQL, which can drop
// its own current database). If no maintenance database opens, the drop is
// refused before any state changes.
func (h *Handlers) dropDatabase(ctx context.Context, uc *UserContext, dm driver.DatabaseManager, target string) error {
	stmt := dm.DropDatabaseSQL(target)
	server := uc.ServerConn()

	// An engine with CanDropConnectedDatabase (MySQL/MariaDB) can drop any
	// database from any connection, and every engine can drop a database its
	// session is NOT connected to. In both cases run on the existing server
	// connection.
	if uc.Capabilities().CanDropConnectedDatabase || server.Info().Database != target {
		if _, err := server.Exec(ctx, stmt); err != nil {
			return &stagedError{Stage: "drop", Executed: true, Err: err}
		}
		uc.ClosePool(target)
		return nil
	}

	// PostgreSQL dropping its own login database: run on a maintenance connection
	// bound elsewhere, opened BEFORE the DROP so a failure leaves all state intact.
	//
	// Every return below is staged, because the caller renders the error and
	// cannot otherwise tell "the DROP was refused" from "the DROP was never
	// issued" — and this first one is a failed DIAL, whose message is the one
	// kind that can echo the DSN.
	maint, mdb, err := uc.openMaintenanceConn(ctx, target)
	if err != nil {
		return &stagedError{Stage: "maintenance-connect", Executed: false,
			Err: fmt.Errorf("cannot drop the database this session is connected to; log in through a different database to drop it (%w)", err)}
	}
	if _, err := maint.Exec(ctx, stmt); err != nil {
		maint.Close()
		return &stagedError{Stage: "drop", Executed: true, Err: err}
	}
	uc.ClosePool(target)
	// Adopt the maintenance connection as the new server connection so
	// ServerConn()/ConnFor("") keep working (the old pool pointed at the dropped
	// database). rebindServerConn closes the old server pool (and closes maint if
	// the session ended meanwhile).
	if err := uc.rebindServerConn(maint, mdb); err != nil {
		// The database IS gone at this point: the statement ran and committed.
		return &stagedError{Stage: "rebind", Executed: true, Err: err}
	}
	return nil
}

// createDatabase validates and creates a new database (name from the db_name
// form field) on the server connection, then redirects to its structure page.
// Shared by the DB-Operations page and the server Databases list. The caller has
// already parsed the form.
func (h *Handlers) createDatabase(w http.ResponseWriter, r *http.Request, uc *UserContext) {
	name := strings.TrimSpace(r.PostFormValue("db_name"))
	if !driver.ValidNewIdentifier(uc.Capabilities(), name) {
		h.renderError(w, r, http.StatusBadRequest, "Invalid database name.", "")
		return
	}
	// The allowlist, checked here rather than in the middleware, for the same
	// reason as /nav/children: the name comes from the BODY, and the middleware
	// reads the path. This handler is reachable from POST /server (whose path
	// names no database at all) as well as from a database's Operations page,
	// so without this an allowlist could be side-stepped by creating a database
	// outside it — a DDL write, not just a listing leak.
	//
	// Ahead of the engine-capability check on purpose: policy first, so the
	// refusal does not depend on which engine happens to be connected.
	if !h.Cfg.Restrict.DatabaseAllowed(name) {
		h.RenderRestricted(w, r, "This TableX is limited to a fixed set of databases, and "+name+" is not one of them.")
		return
	}
	dm, isMgr := uc.Dialect().(driver.DatabaseManager)
	if !uc.Capabilities().CanManageDatabases || !isMgr {
		h.renderError(w, r, http.StatusBadRequest, "This engine cannot create databases.", "")
		return
	}
	// Optional default collation. The builder emits it as a BARE identifier
	// (quoting is invalid in that position), so it is accepted only when it
	// exact-matches the server's introspected collation list — fail-closed:
	// engines without collation support, a failed listing, or an unknown value
	// all reject.
	collation := strings.TrimSpace(r.PostFormValue("db_collation"))
	if collation != "" {
		if !uc.Capabilities().SupportsCharset {
			h.renderError(w, r, http.StatusBadRequest, "This engine does not support a database collation.", "")
			return
		}
		known, err := uc.ServerConn().ListCollations(r.Context())
		if err != nil {
			h.dbError(w, r, err, "")
			return
		}
		valid := false
		for _, c := range known {
			if c.Name == collation {
				valid = true
				break
			}
		}
		if !valid {
			h.renderError(w, r, http.StatusBadRequest, "Unknown collation.", "")
			return
		}
	}
	stmt := dm.CreateDatabaseSQL(name, collation)
	if _, err := uc.ServerConn().Exec(r.Context(), stmt); err != nil {
		h.dbError(w, r, err, stmt)
		return
	}
	h.redirectToNav(w, r, urlDB(name, "", "structure"), view.Flash{Kind: "success", Message: fmt.Sprintf("Database %q created.", name)})
}

// createSchema validates and creates a schema inside the scoped database
// (PostgreSQL). Schemas are per-database objects, so the DDL runs on the
// database-bound connection, not the server connection.
func (h *Handlers) createSchema(w http.ResponseWriter, r *http.Request, uc *UserContext, sc reqScope) {
	sm, isMgr := uc.Dialect().(driver.SchemaManager)
	if !uc.Capabilities().HasSchemas || !isMgr {
		h.renderError(w, r, http.StatusBadRequest, "This engine does not have schemas.", "")
		return
	}
	name := strings.TrimSpace(r.PostFormValue("schema_name"))
	if !driver.ValidNewIdentifier(uc.Capabilities(), name) {
		h.renderError(w, r, http.StatusBadRequest, "Invalid schema name.", "")
		return
	}
	conn, err := uc.ConnFor(r.Context(), sc.DB)
	if err != nil {
		h.connError(w, r, uc, err)
		return
	}
	schemas, err := conn.ListSchemas(r.Context(), sc.DB)
	if err != nil {
		h.dbError(w, r, err, "")
		return
	}
	for _, s := range schemas {
		if s.Name == name {
			h.renderError(w, r, http.StatusBadRequest, "A schema with that name already exists.", "")
			return
		}
	}
	stmt := sm.CreateSchemaSQL(name)
	if _, err := conn.Exec(r.Context(), stmt); err != nil {
		h.dbError(w, r, err, stmt)
		return
	}
	h.redirectToNav(w, r, urlDB(sc.DB, name, "structure"),
		view.Flash{Kind: "success", Message: fmt.Sprintf("Schema %q created.", name)})
}

// dropSchema validates and drops a schema (CASCADE — every object in it) after
// matching it against introspection; system schemas are refused.
func (h *Handlers) dropSchema(w http.ResponseWriter, r *http.Request, uc *UserContext, sc reqScope) {
	sm, isMgr := uc.Dialect().(driver.SchemaManager)
	if !uc.Capabilities().HasSchemas || !isMgr {
		h.renderError(w, r, http.StatusBadRequest, "This engine does not have schemas.", "")
		return
	}
	name := r.PostFormValue("schema_name")
	conn, err := uc.ConnFor(r.Context(), sc.DB)
	if err != nil {
		h.connError(w, r, uc, err)
		return
	}
	schemas, err := conn.ListSchemas(r.Context(), sc.DB)
	if err != nil {
		h.dbError(w, r, err, "")
		return
	}
	found := false
	for _, s := range schemas {
		if s.Name == name {
			if s.IsSystem {
				h.renderError(w, r, http.StatusBadRequest, "System schemas cannot be dropped.", "")
				return
			}
			found = true
			break
		}
	}
	if !found {
		h.renderError(w, r, http.StatusNotFound, "Schema not found.", "")
		return
	}
	if !h.requireConfirm(w, r, uc, sc, fmt.Sprintf("Drop schema %q and everything in it?", name),
		urlDB(sc.DB, sc.Schema, "operations"), "Drop schema") {
		return
	}
	stmt := sm.DropSchemaSQL(name)
	if _, err := conn.Exec(r.Context(), stmt); err != nil {
		h.dbError(w, r, err, stmt)
		return
	}
	h.redirectToNav(w, r, urlDB(sc.DB, "", "structure"),
		view.Flash{Kind: "success", Message: fmt.Sprintf("Schema %q dropped.", name)})
}

// DBOperations renders and runs database maintenance (create/drop database).
func (h *Handlers) DBOperations(w http.ResponseWriter, r *http.Request) {
	uc, ok := h.requireUser(w, r)
	if !ok {
		return
	}
	sc := h.resolveScope(r)
	canManage := uc.Capabilities().CanManageDatabases

	if r.Method == http.MethodPost {
		if !h.parseFormOr400(w, r) {
			return
		}
		dm, isMgr := uc.Dialect().(driver.DatabaseManager)
		switch r.PostFormValue("action") {
		case "create_db":
			h.createDatabase(w, r, uc)
			return
		case "create_schema":
			h.createSchema(w, r, uc, sc)
			return
		case "drop_schema":
			h.dropSchema(w, r, uc, sc)
			return
		case "drop_db":
			if !canManage || !isMgr {
				h.renderError(w, r, http.StatusBadRequest, "This engine cannot drop databases.", "")
				return
			}
			if found, err := h.databaseExists(r.Context(), uc, sc.DB); err != nil {
				h.dbError(w, r, err, "")
				return
			} else if !found {
				h.renderError(w, r, http.StatusNotFound, "Database not found.", "")
				return
			}
			if !h.requireConfirm(w, r, uc, sc, fmt.Sprintf("Drop database %q and everything in it?", sc.DB),
				urlDB(sc.DB, sc.Schema, "operations"), "Drop database") {
				return
			}
			if err := h.dropDatabase(r.Context(), uc, dm, sc.DB); err != nil {
				h.dbErrorStaged(w, r, uc, err, dm.DropDatabaseSQL(sc.DB))
				return
			}
			h.redirectToNav(w, r, urlServer(""), view.Flash{Kind: "success", Message: fmt.Sprintf("Database %q dropped.", sc.DB)})
			return
		default:
			h.renderError(w, r, http.StatusBadRequest, "Unknown operation.", "")
			return
		}
	}

	body := dbOpsBody{
		Scope:           sc,
		PostURL:         urlDB(sc.DB, sc.Schema, "operations"),
		EngineManagesDB: canManage,
		CanManageDB:     canManage && h.allowance().DDL,
	}
	if canManage && uc.Capabilities().SupportsCharset {
		body.Collations = h.collationOptions(r.Context(), uc)
	}
	if _, isSM := uc.Dialect().(driver.SchemaManager); isSM && uc.Capabilities().HasSchemas {
		body.CanManageSchemas = h.allowance().DDL
		if conn, err := uc.ConnFor(r.Context(), sc.DB); err == nil {
			if schemas, err := conn.ListSchemas(r.Context(), sc.DB); err == nil {
				for _, s := range schemas {
					if !s.IsSystem {
						body.Schemas = append(body.Schemas, s)
					}
				}
			}
		}
	}
	p := h.newLoggedPage(r, uc, sc.DB+" · Operations")
	p.Breadcrumb = h.buildBreadcrumb(uc, sc)
	p.Tabs = h.dbTabs(uc, sc, "operations")
	p.Body = body
	h.render(w, r, "db_operations", p)
}

// redirectToNav is redirectTo plus an HX-Trigger asking the client to refresh
// the sidebar tree — for a structural change (create/drop a database,
// create/drop/rename a table or
// table) that otherwise only swaps #page_content and leaves the tree stale. The
// htmx redirect here is 204 + HX-Location (not a 303 hop), so the trigger header
// reaches htmx's event processing.
func (h *Handlers) redirectToNav(w http.ResponseWriter, r *http.Request, url string, flash view.Flash) {
	if view.IsHTMX(r) {
		w.Header().Set("HX-Trigger", "tx-nav-refresh")
	}
	h.redirectTo(w, r, url, flash)
}

// redirectFailed is redirectTo for a mutation the ENGINE failed (a failed
// ALTER, a failed kill, a failed DCL) — as opposed to a request TableX itself
// refused. It files the audit outcome as error before the redirect, because
// redirectTo's default filing is invalid: OutcomeForStatus deliberately keeps
// the two apart, and an engine fault misfiled as a malformed request hides it
// from an operator filtering the trail for failed mutations.
func (h *Handlers) redirectFailed(w http.ResponseWriter, r *http.Request, url, msg string) {
	audit.FromContext(r.Context()).SetOutcomeIfUnset(audit.OutcomeError, msg)
	h.redirectTo(w, r, url, view.Flash{Kind: "error", Message: msg})
}

// redirectTo navigates after a mutation, htmx-aware (HX-Location keeps the SPA
// feel and updates the address bar) or a plain 303.
func (h *Handlers) redirectTo(w http.ResponseWriter, r *http.Request, url string, flash view.Flash) {
	uc, _, _ := h.currentUser(r)
	if uc != nil {
		uc.AddFlash(flash)
	}
	if flash.Kind == "error" {
		// A mutation that failed but answers with a redirect (303, or 204 on
		// htmx) would otherwise be filed outcome=ok by OutcomeForStatus. The
		// default here is invalid — the refused-request shape; a caller whose
		// failure came from the ENGINE goes through redirectFailed, whose
		// pre-set error outcome wins (IfUnset).
		audit.FromContext(r.Context()).SetOutcomeIfUnset(audit.OutcomeInvalid, flash.Message)
	}
	if view.IsHTMX(r) {
		// The header value is JSON, so build it with the JSON encoder (%q emits a
		// Go string literal, whose escaping is not JSON's).
		loc, _ := json.Marshal(struct {
			Path   string `json:"path"`
			Target string `json:"target"`
		}{Path: url, Target: "#page_content"})
		w.Header().Set("HX-Location", string(loc))
		w.WriteHeader(http.StatusNoContent)
		return
	}
	http.Redirect(w, r, url, http.StatusSeeOther)
}
