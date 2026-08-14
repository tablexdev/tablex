package handlers

import (
	"net/http"
	"strconv"

	"github.com/tablexdev/tablex/internal/driver"
	"github.com/tablexdev/tablex/internal/model"
	"github.com/tablexdev/tablex/internal/view"
)

// The *Row types pair a listed object with its rendered position and the URL of
// its lazy definition panel. Index is what the drop form posts back: together
// with the name it identifies the object (see programs.go), so it has to be the
// position in THIS list, which is why the rows are built rather than ranged over
// in the template.

type routineRow struct {
	model.Routine
	Index   int
	DefURL  string
	EditURL string
	PrivURL string // per-routine privileges page; empty when the engine has none
}

type triggerRow struct {
	model.Trigger
	Index   int
	DefURL  string
	EditURL string
}

type eventRow struct {
	model.Event
	Index   int
	DefURL  string
	EditURL string
}

// programAdmin is the administration state the three list pages share. Both
// flags are per object kind — SQLite has triggers but no routines and no events
// — so the controls appear only where the engine really supports them.
//
// Two flags, not one, because restricted mode splits these two actions apart.
// Dropping a stored program is ordinary DDL. WRITING one is not: the body a
// CREATE wraps is unconstrained SQL running on the server, which is the reach
// allow_console governs, and saveProgram refuses it under allow_console = false
// (see the console check it carries in programs.go). One flag would either hide
// a drop that still works or offer an editor the server will refuse.
type programAdmin struct {
	// CanManage gates the drop control: engine support AND allow_ddl.
	CanManage bool
	// CanEdit gates the editor's entry points — the "New …" buttons and the
	// per-row edit links: engine support AND allow_ddl AND allow_console.
	CanEdit bool
	PostURL string
	// NewURL opens the editor's "new object" skeleton. Routines get two: the
	// procedure and function skeletons share no syntax.
	NewURL          string
	NewProcedureURL string
}

type routinesBody struct {
	Scope    reqScope
	Routines []routineRow
	// Empty is the empty-state tier: a SUCCESSFUL zero-result query. Error is
	// the section-error tier: a connection or listing failure. They used to
	// share Empty, leaving wording as the only signal separating a failure
	// from an empty database.
	Empty string
	Error string
	// CanGrant: the engine has routine-scope grants, so each row links to its
	// privileges page. It is INDEPENDENT of CanManage — an account may be able
	// to see and grant on a routine it cannot drop — which is why the action
	// column is gated on either, not on CanManage alone.
	CanGrant bool
	programAdmin
}

// ShowActions reports whether the routines list needs its action column.
//
// Value receiver, deliberately: Page.Body holds this as a non-addressable
// interface value, and a pointer-receiver method is not in a value's method
// set — html/template would fail the lookup at render time, turning the page
// into a 500. The same goes for every other method a template calls on a body.
func (b routinesBody) ShowActions() bool { return b.CanManage || b.CanGrant }

type triggersBody struct {
	Scope    reqScope
	Triggers []triggerRow
	// Empty / Error: see routinesBody — zero-result vs failure, typed apart.
	Empty string
	Error string
	programAdmin
}

type eventsBody struct {
	Scope  reqScope
	Events []eventRow
	// Empty / Error: see routinesBody — zero-result vs failure, typed apart.
	Empty string
	Error string
	programAdmin
}

type dbUsersBody struct {
	Scope      reqScope
	Users      []model.User
	Privileges []model.Privilege
	IsTable    bool
	Empty      string // genuine "nothing to show" note
	Error      string // introspection failure (distinct from Empty, shown even when accounts list)

	// Grant/revoke form support (zero values when the engine has no
	// PrivilegeManager — SQLite — so the controls auto-hide).
	CanManage        bool     // dialect implements driver.PrivilegeManager
	HasHost          bool     // grantee <select> values carry user@host (MySQL)
	HasPublicGrantee bool     // offer PostgreSQL's PUBLIC pseudo-role
	Privs            []string // dialect grant allowlist for this scope
	PostURL          string

	// Routine scope: set on the per-routine privileges page. RoutineName is
	// what the heading and the empty state say; IsTable stays false there, so
	// the column-scope controls and the table wording never appear.
	RoutineName string

	// Column-scope grants (table pages on a driver.ColumnPrivileger engine).
	// ColumnPrivs is the subset of Privs that accepts a column list, and its
	// emptiness is what hides the control; TableColumns is the picker's
	// options, so a grant can only ever name a column the table really has.
	ColumnPrivs  []string
	TableColumns []string
}

// ShowColumnScope reports whether the grants table needs its Column column.
// It is true when the engine can create column grants OR when any listed grant
// already has one — the second half matters because a grant made outside
// TableX must not render as if it covered the whole table.
// (Value receiver — see routinesBody.ShowActions.)
func (b dbUsersBody) ShowColumnScope() bool {
	if len(b.ColumnPrivs) > 0 {
		return true
	}
	for _, p := range b.Privileges {
		if p.Column != "" {
			return true
		}
	}
	return false
}

// fillPrivilegeManage populates the grant/revoke form fields when the engine
// supports privilege management. The privilege checkbox set comes from the
// dialect's GrantablePrivileges — the single source of truth shared with grant
// validation.
func (b *dbUsersBody) fillPrivilegeManage(conn *driver.Connection, postURL string, allow view.Allowance) {
	if !conn.CanManagePrivileges() {
		return
	}
	caps := conn.Capabilities()
	// The engine's answer AND this deployment's: the template gates the whole
	// grant/revoke form on CanManage, so both reasons to withhold it converge
	// here rather than being checked again in the markup.
	b.CanManage = allow.DDL
	b.HasHost = caps.AccountHasHost
	b.HasPublicGrantee = !caps.AccountHasHost
	b.Privs = conn.GrantablePrivileges(b.IsTable)
	b.PostURL = postURL
	if b.IsTable {
		b.ColumnPrivs = conn.ColumnGrantablePrivileges()
	}
}

// listMeta runs a per-connection list function and returns the (items, empty,
// errMsg) triple the metadata-tab handlers share. The three outcomes are
// TYPED, not merely worded: a connection failure or a list error comes back in
// errMsg — the section-error tier, rendered as an error banner — and empty is
// reserved for a successful zero-result query, the empty-state tier. The two
// used to share one string, which left wording as the only signal separating
// a failure from a genuinely empty database.
// (A free generic function, not a method — Go methods can't take type params.)
//
// It takes the caller's ALREADY-RESOLVED (conn, connErr) rather than dialing
// itself: ConnFor caches pools only on success, so a listMeta-internal dial after
// a caller's own failed one (as TableTriggers does for its data-table guard)
// would repeat the ~15-second connect on a broken backend. Every caller now
// resolves ConnFor exactly once per request.
func listMeta[T any](uc *UserContext, emptyMsg string, conn *driver.Connection, connErr error,
	list func(conn *driver.Connection) ([]T, error)) (items []T, empty, errMsg string) {
	if connErr != nil {
		// Section-tier vocabulary, deliberately distinct from connError's
		// terminal literal, which must stay unique to connError.
		return nil, "", "Database unreachable: " + uc.redactErr(connErr)
	}
	got, err := list(conn)
	if err != nil {
		return nil, "", err.Error()
	}
	if len(got) == 0 {
		return nil, emptyMsg, ""
	}
	return got, "", ""
}

// metaTab carries the result of the shared database-level metadata-tab
// preamble: user, scope, the request's one dial, and listMeta's typed triple.
type metaTab[T any] struct {
	uc    *UserContext
	sc    reqScope
	conn  *driver.Connection // nil when the dial failed (err carries why)
	items []T
	empty string
	err   string
}

// newMetaTab runs the preamble DBRoutines/DBTriggers/DBEvents shared verbatim:
// resolve the user and scope, dial once, and run the listing through listMeta.
// nil means the login redirect was already written and the caller must return.
// (A free generic function — Go methods can't take type params.)
func newMetaTab[T any](h *Handlers, w http.ResponseWriter, r *http.Request, emptyMsg string,
	list func(conn *driver.Connection, sc reqScope) ([]T, error)) *metaTab[T] {
	uc, ok := h.requireUser(w, r)
	if !ok {
		return nil
	}
	sc := h.resolveScope(r).withSchemaDefault(uc.Capabilities())
	conn, connErr := uc.ConnFor(r.Context(), sc.DB)
	items, empty, errMsg := listMeta(uc, emptyMsg, conn, connErr,
		func(conn *driver.Connection) ([]T, error) { return list(conn, sc) })
	return &metaTab[T]{uc: uc, sc: sc, conn: conn, items: items, empty: empty, err: errMsg}
}

// DBRoutines lists stored procedures/functions (GET /db/{db}/routines).
func (h *Handlers) DBRoutines(w http.ResponseWriter, r *http.Request) {
	m := newMetaTab(h, w, r, "No routines in this database.",
		func(conn *driver.Connection, sc reqScope) ([]model.Routine, error) {
			return conn.ListRoutines(r.Context(), sc.scope())
		})
	if m == nil {
		return
	}
	uc, sc, conn := m.uc, m.sc, m.conn
	body := routinesBody{Scope: sc, Empty: m.empty, Error: m.err}
	body.CanGrant = conn != nil && len(conn.RoutineGrantablePrivileges()) > 0 && h.allowance().DDL
	for i, rt := range m.items {
		row := routineRow{
			Routine: rt,
			Index:   i,
			DefURL:  urlDefinition(sc.DB, sc.Schema, "", "routine", rt.Name, i),
			EditURL: urlProgramEditor(sc, "routine", rt.Name, i, ""),
		}
		if body.CanGrant {
			row.PrivURL = urlRoutinePrivileges(sc, rt.Name, i)
		}
		body.Routines = append(body.Routines, row)
	}
	if conn != nil {
		body.programAdmin = programAdmin{
			CanManage:       conn.CanManageRoutines() && h.allowance().DDL,
			CanEdit:         conn.CanManageRoutines() && h.allowance().DDL && h.allowance().Console,
			PostURL:         urlDB(sc.DB, sc.Schema, "routines"),
			NewURL:          urlProgramEditor(sc, "routine", "", 0, ""),
			NewProcedureURL: urlProgramEditor(sc, "routine", "", 0, "procedure"),
		}
	}
	h.renderDBTab(w, r, uc, sc, "routines", sc.DB+" · Routines", "db_routines", body)
}

// DBTriggers lists triggers in the database (GET /db/{db}/triggers).
func (h *Handlers) DBTriggers(w http.ResponseWriter, r *http.Request) {
	m := newMetaTab(h, w, r, "No triggers in this database.",
		func(conn *driver.Connection, sc reqScope) ([]model.Trigger, error) {
			return conn.ListTriggers(r.Context(), sc.scope())
		})
	if m == nil {
		return
	}
	uc, sc, conn := m.uc, m.sc, m.conn
	body := triggersBody{Scope: sc, Empty: m.empty, Error: m.err}
	body.Triggers = triggerRows(sc, "", m.items)
	if conn != nil {
		body.programAdmin = programAdmin{
			CanManage: conn.CanManageTriggers() && h.allowance().DDL,
			CanEdit:   conn.CanManageTriggers() && h.allowance().DDL && h.allowance().Console,
			PostURL:   urlDB(sc.DB, sc.Schema, "triggers"),
			NewURL:    urlProgramEditor(sc, "trigger", "", 0, ""),
		}
	}
	h.renderDBTab(w, r, uc, sc, "triggers", sc.DB+" · Triggers", "db_triggers", body)
}

// DBEvents lists scheduled events (GET /db/{db}/events).
func (h *Handlers) DBEvents(w http.ResponseWriter, r *http.Request) {
	m := newMetaTab(h, w, r, "No events in this database.",
		func(conn *driver.Connection, sc reqScope) ([]model.Event, error) {
			return conn.ListEvents(r.Context(), sc.scope())
		})
	if m == nil {
		return
	}
	uc, sc, conn := m.uc, m.sc, m.conn
	body := eventsBody{Scope: sc, Empty: m.empty, Error: m.err}
	for i, e := range m.items {
		body.Events = append(body.Events, eventRow{
			Event:   e,
			Index:   i,
			DefURL:  urlDefinition(sc.DB, sc.Schema, "", "event", e.Name, i),
			EditURL: urlProgramEditor(sc, "event", e.Name, i, ""),
		})
	}
	if conn != nil {
		body.programAdmin = programAdmin{
			CanManage: conn.CanManageEvents() && h.allowance().DDL,
			CanEdit:   conn.CanManageEvents() && h.allowance().DDL && h.allowance().Console,
			PostURL:   urlDB(sc.DB, sc.Schema, "events"),
			NewURL:    urlProgramEditor(sc, "event", "", 0, ""),
		}
	}
	h.renderDBTab(w, r, uc, sc, "events", sc.DB+" · Events", "db_events", body)
}

// DBPrivileges lists the server's accounts and the database's direct grants
// (GET /db/{db}/privileges); with a PrivilegeManager engine it also renders the
// grant/revoke controls (POST handled by DBPrivilegesManage in access.go).
func (h *Handlers) DBPrivileges(w http.ResponseWriter, r *http.Request) {
	uc, ok := h.requireUser(w, r)
	if !ok {
		return
	}
	sc := h.resolveScope(r).withSchemaDefault(uc.Capabilities())
	body := dbUsersBody{Scope: sc}
	// Introspection failures go to body.Error (shown as an error banner even when
	// accounts do list), NOT body.Empty — a grants-query error must not look like
	// "no grants exist".
	addErr := func(msg string) {
		if body.Error != "" {
			body.Error += "; "
		}
		body.Error += msg
	}
	if users, err := uc.ServerConn().ListUsers(r.Context()); err == nil {
		body.Users = users
	} else {
		addErr("accounts unavailable: " + err.Error())
	}
	// Database-scoped grants (engine permitting; SQLite has none).
	if conn, err := uc.ConnFor(r.Context(), sc.DB); err != nil {
		addErr("database unreachable: " + uc.redactErr(err))
	} else {
		if privs, err := conn.Privileges(r.Context(), driver.TableRef{Database: sc.DB, Schema: sc.Schema}); err == nil {
			body.Privileges = privs
		} else {
			addErr("grants unavailable: " + err.Error())
		}
		body.fillPrivilegeManage(conn, urlDB(sc.DB, sc.Schema, "privileges"), h.allowance())
	}
	if len(body.Users) == 0 && len(body.Privileges) == 0 && body.Error == "" {
		body.Empty = "No accounts or grants visible."
	}
	h.renderDBTab(w, r, uc, sc, "privileges", sc.DB+" · Privileges", "db_privileges", body)
}

// TablePrivileges lists the grants on a single table (GET .../privileges);
// with a PrivilegeManager engine it also renders the grant/revoke controls
// (POST handled by TablePrivilegesManage in access.go).
func (h *Handlers) TablePrivileges(w http.ResponseWriter, r *http.Request) {
	uc, ok := h.requireUser(w, r)
	if !ok {
		return
	}
	sc := h.resolveScope(r).withSchemaDefault(uc.Capabilities())
	body := dbUsersBody{Scope: sc, IsTable: true}
	// Resolve the connection once and reuse it for the guard, the grants query
	// and the tab-view check (nil on failure — tableTabs then degrades open).
	conn, connErr := uc.ConnFor(r.Context(), sc.DB)
	if connErr != nil {
		// The section-error tier, not Empty: a failure must never wear
		// empty-state clothes ("no grants visible") on a page that never
		// managed to look.
		body.Error = "Database unreachable: " + uc.redactErr(connErr)
	} else if !h.requireDataTable(w, r, conn, sc) {
		return
	} else {
		if privs, err := conn.Privileges(r.Context(), sc.tableRef()); err == nil {
			body.Privileges = privs
		} else {
			body.Error = "Grants unavailable: " + err.Error()
		}
		body.fillPrivilegeManage(conn, urlTable(sc.DB, sc.Schema, sc.Table, "privileges"), h.allowance())
		if body.CanManage {
			// The shared template's grant form needs grantee options; the DB-level
			// page loads them anyway, this page only when the form renders.
			if users, err := uc.ServerConn().ListUsers(r.Context()); err == nil {
				body.Users = users
			} else {
				// Surface the failure rather than rendering a grant form with an
				// empty grantee list (which would look like "no accounts exist").
				body.Error = "Cannot load accounts for the grant form: " + err.Error()
			}
			// The column picker's options, on an engine that has column grants.
			// Every option here is a name the grant handler will re-verify.
			if len(body.ColumnPrivs) > 0 {
				if cols, err := conn.Columns(r.Context(), sc.tableRef()); err == nil {
					for _, c := range cols {
						body.TableColumns = append(body.TableColumns, c.Name)
					}
				} else if body.Error == "" {
					body.Error = "Cannot load columns for the grant form: " + err.Error()
				}
			}
		}
	}
	if len(body.Privileges) == 0 && body.Empty == "" && body.Error == "" {
		body.Empty = "No table-level grants are visible (or this engine has no privilege system)."
	}
	h.renderTableTab(w, r, uc, sc, conn, "privileges", sc.Table+" · Privileges", "db_privileges", body)
}

// RoutinePrivileges lists the grants on one stored routine
// (GET /db/{db}/routines/privileges?name=…&i=…), with the grant/revoke controls
// on an engine that has routine grants (POST handled by
// RoutinePrivilegesManage in access.go).
//
// It shares dbUsersBody and the db_privileges template with the database- and
// table-scope pages: same grants table, same grantee <select>, same revoke
// button — only the object and the allowlist differ.
func (h *Handlers) RoutinePrivileges(w http.ResponseWriter, r *http.Request) {
	uc, ok := h.requireUser(w, r)
	if !ok {
		return
	}
	sc := h.resolveScope(r).withSchemaDefault(uc.Capabilities())
	conn, routine, ok := h.resolveRoutineForPrivileges(w, r, uc, sc)
	if !ok {
		return
	}
	body := dbUsersBody{Scope: sc, RoutineName: routine.Name}
	if privs, err := conn.RoutinePrivileges(r.Context(), sc.scope(), routine); err == nil {
		body.Privileges = privs
	} else {
		body.Error = "Grants unavailable: " + err.Error()
	}
	body.CanManage = h.allowance().DDL
	caps := uc.Capabilities()
	body.HasHost = caps.AccountHasHost
	body.HasPublicGrantee = !caps.AccountHasHost
	body.Privs = conn.RoutineGrantablePrivileges()
	body.PostURL = urlRoutinePrivileges(sc, routine.Name, routineIndexOf(r))
	if users, err := uc.ServerConn().ListUsers(r.Context()); err == nil {
		body.Users = users
	} else if body.Error == "" {
		body.Error = "Cannot load accounts for the grant form: " + err.Error()
	}
	if len(body.Privileges) == 0 && body.Error == "" {
		body.Empty = "No grants on this routine."
	}
	h.renderDBTab(w, r, uc, sc, "routines", routine.Name+" · Privileges", "db_privileges", body)
}

// routineIndexOf reads the list position from the request, defaulting to 0 —
// the value is only ever used to re-address the same routine, and
// resolveRoutine re-checks the name against it.
func routineIndexOf(r *http.Request) int {
	i, err := strconv.Atoi(r.URL.Query().Get("i"))
	if err != nil || i < 0 {
		return 0
	}
	return i
}

// resolveRoutineForPrivileges resolves the addressed routine and confirms the
// engine has routine grants at all. Errors are already written when ok is false.
func (h *Handlers) resolveRoutineForPrivileges(w http.ResponseWriter, r *http.Request, uc *UserContext, sc reqScope) (*driver.Connection, model.Routine, bool) {
	conn, err := uc.ConnFor(r.Context(), sc.DB)
	if err != nil {
		h.connError(w, r, uc, err)
		return nil, model.Routine{}, false
	}
	if len(conn.RoutineGrantablePrivileges()) == 0 {
		h.renderError(w, r, http.StatusBadRequest, "This engine does not support routine privileges.", "")
		return nil, model.Routine{}, false
	}
	// The name and position ride the URL on both methods — the POST forms
	// target the page's own URL, query string included — with a form field
	// accepted as a fallback so a caller that posts them instead still works.
	name := r.URL.Query().Get("name")
	if name == "" {
		name = r.PostFormValue("name")
	}
	if name == "" {
		h.renderError(w, r, http.StatusBadRequest, "No routine named.", "")
		return nil, model.Routine{}, false
	}
	idx := routineIndexOf(r)
	// The routine that reaches the builder is the one INTROSPECTION returned —
	// carrying the identity arguments PostgreSQL needs to tell overloads apart,
	// which the request could not have supplied trustworthily.
	routine, err := h.resolveRoutine(r, conn, sc, name, idx)
	if err != nil {
		h.renderError(w, r, http.StatusNotFound, err.Error(), "")
		return nil, model.Routine{}, false
	}
	return conn, routine, true
}

// TableTriggers lists triggers, filtered to the current table (GET .../triggers).
func (h *Handlers) TableTriggers(w http.ResponseWriter, r *http.Request) {
	uc, ok := h.requireUser(w, r)
	if !ok {
		return
	}
	sc := h.resolveScope(r).withSchemaDefault(uc.Capabilities())
	// One dial, reused for the sequence guard, the trigger list and the tab-view
	// check. A failed dial skips the guard (as before) and surfaces via listMeta.
	conn, connErr := uc.ConnFor(r.Context(), sc.DB)
	if connErr == nil && !h.requireDataTable(w, r, conn, sc) {
		return
	}
	body := triggersBody{Scope: sc}
	triggers, empty, errMsg := listMeta(uc, "No triggers on this table.", conn, connErr,
		func(conn *driver.Connection) ([]model.Trigger, error) {
			ts, err := conn.ListTriggers(r.Context(), sc.scope())
			if err != nil {
				return nil, err
			}
			// Shared with the definition fragment, which must index into the
			// same filtered slice this page rendered.
			return filterTriggers(ts, sc.Table), nil
		})
	body.Empty, body.Error = empty, errMsg
	// sc.Table rides into every URL so the fragment reapplies this same filter.
	body.Triggers = triggerRows(sc, sc.Table, triggers)
	if conn != nil {
		body.programAdmin = programAdmin{
			CanManage: conn.CanManageTriggers() && h.allowance().DDL,
			CanEdit:   conn.CanManageTriggers() && h.allowance().DDL && h.allowance().Console,
			PostURL:   urlTable(sc.DB, sc.Schema, sc.Table, "triggers"),
			NewURL:    urlProgramEditor(sc, "trigger", "", 0, ""),
		}
	}
	h.renderTableTab(w, r, uc, sc, conn, "triggers", sc.Table+" · Triggers", "db_triggers", body)
}

// triggerRows attaches each trigger's definition-panel URL. table is the filter
// the caller applied (empty at database level), and is echoed into the URLs so
// the fragment handler indexes into an identically filtered list.
func triggerRows(sc reqScope, table string, ts []model.Trigger) []triggerRow {
	out := make([]triggerRow, 0, len(ts))
	for i, t := range ts {
		out = append(out, triggerRow{
			Trigger: t,
			Index:   i,
			DefURL:  urlDefinition(sc.DB, sc.Schema, table, "trigger", t.Name, i),
			EditURL: urlProgramEditor(sc, "trigger", t.Name, i, ""),
		})
	}
	return out
}

// renderDBTab is a small helper that wires the db-level chrome for a metadata
// list page.
func (h *Handlers) renderDBTab(w http.ResponseWriter, r *http.Request, uc *UserContext, sc reqScope, active, title, page string, body any) {
	p := h.newLoggedPage(r, uc, title)
	p.Breadcrumb = h.buildBreadcrumb(uc, sc)
	p.Tabs = h.dbTabs(uc, sc, active)
	p.Body = body
	h.render(w, r, page, p)
}

// renderTableTab is renderDBTab's table-level sibling: the same chrome with
// tableTabs, which additionally takes the connection (nil degrades the
// tab-view check open).
func (h *Handlers) renderTableTab(w http.ResponseWriter, r *http.Request, uc *UserContext, sc reqScope, conn *driver.Connection, active, title, page string, body any) {
	p := h.newLoggedPage(r, uc, title)
	p.Breadcrumb = h.buildBreadcrumb(uc, sc)
	p.Tabs = h.tableTabs(r.Context(), uc, sc, active, conn)
	p.Body = body
	h.render(w, r, page, p)
}
