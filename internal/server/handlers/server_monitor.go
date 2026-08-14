package handlers

import (
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/tablexdev/tablex/internal/driver"
	"github.com/tablexdev/tablex/internal/model"
	"github.com/tablexdev/tablex/internal/view"
)

type varsBody struct {
	Title     string
	Variables []model.Variable
	Empty     string
	// Error carries an introspection FAILURE, kept distinct from Empty. A
	// privilege denial rendered into Empty read as a neutral "no data"
	// empty-state; architecture.md §8 requires a failure to land typed, since
	// wording must never be the only thing separating a failure from an empty
	// result. The sibling empty-states in metadata.go already gate on
	// `&& Error == ""`; this brings the monitor pages into line.
	Error string
}

// processesBody carries the engine's own process columns verbatim. The kill
// controls ride alongside rather than being folded into the grid: IDIndex says
// which cell of each row is the session identifier, and it is -1 whenever the
// engine cannot terminate sessions or its listing does not carry the column the
// dialect named — in which case the page renders exactly as it did before.
type processesBody struct {
	Set   *driver.ResultSet
	Empty string
	Error string // introspection failure, distinct from an empty list (see varsBody.Error)

	CanKill bool
	IDIndex int    // column index of the session identifier; -1 when there is none
	PostURL string // POST /server/processes
}

// KillID returns the session identifier of one process row — the cell the
// dialect's ProcessIDColumn named — or "" when this row cannot be addressed.
// The template asks per row rather than indexing itself, so a short or NULL
// row renders without a button instead of failing the whole page.
func (b processesBody) KillID(row []driver.Value) string {
	if !b.CanKill || b.IDIndex < 0 || b.IDIndex >= len(row) || row[b.IDIndex].Null {
		return ""
	}
	return row[b.IDIndex].Str
}

// resultColumnIndex finds a column by name, case-insensitively (MySQL reports
// "Id", PostgreSQL "pid", and neither guarantees the case its dialect declared),
// or -1.
func resultColumnIndex(rs *driver.ResultSet, name string) int {
	for i, c := range rs.Columns {
		if strings.EqualFold(c.Name, name) {
			return i
		}
	}
	return -1
}

type usersBody struct {
	Users []model.User
	Empty string
	Error string // account-listing failure, distinct from "no accounts" (see varsBody.Error)

	// Account-management form support (zero values when the engine has no
	// UserManager — SQLite — so the controls auto-hide).
	CanManage         bool   // dialect implements driver.UserManager
	HasHost           bool   // accounts carry a host part (MySQL) — show the host field
	HasRoleAttributes bool   // PostgreSQL role attributes — show the checkboxes
	PostURL           string // POST /server/users
	SelfName          string // logged-in account (row actions for it are limited)
	SelfHost          string

	// Role membership (engines whose Capabilities report SupportsRoles — which
	// is version-gated on MySQL/MariaDB, so the same engine may answer
	// differently per server).
	CanManageRoles bool
	Memberships    []model.RoleMembership
	RolesError     string // membership read failed — distinct from "no memberships"
}

// Account renders "name@host" for a host-qualified engine and the bare name
// otherwise — the value shape the grantee/member selects submit and
// driver.SplitAccount decodes.
// (Value receiver — see routinesBody.ShowActions.)
func (b usersBody) Account(name, host string) string {
	if b.HasHost {
		return name + "@" + host
	}
	return name
}

// monitorVars renders a server status or variables key/value page. The reads
// go through the Connection passthroughs so they run under read_stmt_timeout
// like every other generated read — against the bare pool a wedged status
// query held its connection until the client disconnected.
func (h *Handlers) monitorVars(w http.ResponseWriter, r *http.Request, active, title string, pick func(*driver.Connection) ([]model.Variable, error), empty string) {
	uc, ok := h.requireUser(w, r)
	if !ok {
		return
	}
	body := varsBody{Title: title, Empty: empty}
	if conn := uc.ServerConn(); conn.CanMonitor() {
		if vars, err := pick(conn); err == nil {
			body.Variables = vars
		} else {
			// A privilege denial is a FAILURE, not an empty result — it must
			// land typed, or wording is the only thing separating the two.
			body.Error = err.Error()
		}
	}
	p := h.newLoggedPage(r, uc, title)
	p.Breadcrumb = h.buildBreadcrumb(uc, reqScope{})
	p.Tabs = h.serverTabsCaps(uc, active)
	p.Body = body
	h.render(w, r, "server_variables", p)
}

// ServerStatus shows runtime status counters (GET /server/status).
func (h *Handlers) ServerStatus(w http.ResponseWriter, r *http.Request) {
	h.monitorVars(w, r, "status", "Server status",
		func(conn *driver.Connection) ([]model.Variable, error) { return conn.Status(r.Context()) },
		"This engine does not expose server status counters.")
}

// ServerVariables shows configuration variables (GET /server/variables).
func (h *Handlers) ServerVariables(w http.ResponseWriter, r *http.Request) {
	h.monitorVars(w, r, "variables", "Server variables",
		func(conn *driver.Connection) ([]model.Variable, error) { return conn.Variables(r.Context()) },
		"This engine does not expose configuration variables.")
}

// ServerProcesses shows active processes/connections (GET /server/processes).
func (h *Handlers) ServerProcesses(w http.ResponseWriter, r *http.Request) {
	uc, ok := h.requireUser(w, r)
	if !ok {
		return
	}
	body := processesBody{Empty: "This engine does not expose a process list."}
	if conn := uc.ServerConn(); conn.CanMonitor() {
		if rs, err := conn.Processes(r.Context()); err == nil && rs != nil {
			body.Set = h.narrowProcessList(rs)
			body.Empty = ""
		} else if err != nil {
			body.Error = err.Error() // a failure, typed — not a neutral empty list
		}
	}
	if idCol := uc.ServerConn().ProcessIDColumn(); idCol != "" && body.Set != nil {
		body.IDIndex = resultColumnIndex(body.Set, idCol)
		// No id column, no kill button: the alternative — letting the operator
		// type a number — would be a control with nothing verifying it names a
		// session this listing actually reported.
		body.CanKill = body.IDIndex >= 0 && h.allowance().DDL
		body.PostURL = urlServer("processes")
	}
	p := h.newLoggedPage(r, uc, "Processes")
	p.Breadcrumb = h.buildBreadcrumb(uc, reqScope{})
	p.Tabs = h.serverTabsCaps(uc, "processes")
	p.Body = body
	h.render(w, r, "server_processes", p)
}

// ServerProcessesManage handles POST /server/processes — terminating a session.
//
// Validate-first, like every other administrative action here: the identifier
// must parse as an integer (which is also what keeps it out of the statement's
// syntax — see driver.ProcessManager), and it must appear in a FRESH read of
// the process list. Whether the account may actually kill that session is the
// engine's decision; TableX only refuses to name one nobody reported.
func (h *Handlers) ServerProcessesManage(w http.ResponseWriter, r *http.Request) {
	uc, ok := h.requireUser(w, r)
	if !ok {
		return
	}
	if !h.parseFormOr400(w, r) {
		return
	}
	conn := uc.ServerConn()
	idCol := conn.ProcessIDColumn()
	if idCol == "" {
		h.renderError(w, r, http.StatusBadRequest, "This engine cannot terminate sessions.", "")
		return
	}
	if r.PostFormValue("action") != "kill" {
		h.renderError(w, r, http.StatusBadRequest, "Unknown operation.", "")
		return
	}
	id, err := strconv.ParseInt(strings.TrimSpace(r.PostFormValue("pid")), 10, 64)
	if err != nil {
		h.renderError(w, r, http.StatusBadRequest, "Invalid process id.", "")
		return
	}
	if !conn.CanMonitor() {
		h.renderError(w, r, http.StatusBadRequest, "This engine does not expose a process list.", "")
		return
	}
	rs, err := conn.Processes(r.Context())
	if err != nil {
		// Distinct from "no such process": failing to read the list is not
		// evidence the session is absent.
		h.renderError(w, r, http.StatusInternalServerError, "Cannot verify the process list: "+err.Error(), "")
		return
	}
	// Narrowed with the SAME filter the page uses, so a session the operator
	// cannot see is one they cannot terminate either.
	if rs = h.narrowProcessList(rs); rs == nil || !processListed(rs, idCol, id) {
		h.renderError(w, r, http.StatusNotFound, "That process is not in the current list.", "")
		return
	}
	backURL := urlServer("processes")
	if !h.requireConfirm(w, r, uc, reqScope{}, fmt.Sprintf("Terminate session %d? Any transaction it holds is rolled back.", id), backURL, "Terminate") {
		return
	}
	if err := conn.KillProcess(r.Context(), id); err != nil {
		h.Log.Warn("kill process failed", "err", redactConnError(err), "reqid", RequestID(r.Context()))
		h.redirectFailed(w, r, backURL, "Could not terminate that session: "+redactConnError(err))
		return
	}
	h.redirectTo(w, r, backURL, view.Flash{Kind: "success",
		Message: fmt.Sprintf("Session %d terminated.", id)})
}

// processListed reports whether id appears in the process list's identifier
// column. The comparison is numeric, not textual, so a server that pads or
// formats the value differently than the form echoed still matches.
// narrowProcessList applies restrict.database_allowlist to a process listing.
//
// ONE filter, applied once to the SHARED list, because both endpoints read that
// list: the page renders it, and the kill path re-reads it to validate its
// target. Filtering only the render would leave the listing cosmetic and the
// kill path unchanged — a session on a non-allowlisted database would still be
// terminable by pid.
//
// Handler-side rather than SQL-side, deliberately. driver.Monitor.Processes
// takes no allowlist, so a real WHERE would mean changing that interface and
// every implementation, and it would grow postgres/introspect.go, which sits
// exactly on its size pin. The accepted cost: driver.ScanResult applies the
// 1,000-row read cap BEFORE this runs, so under an allowlist the visible count
// can fall well below 1,000 while the "result was truncated" banner still fires
// — the hidden rows consumed the budget. Inherent to filtering outside the
// query; the banner counts the rows actually shown, so it stays honest.
//
// Not a PostgreSQL-only finding: MySQL's SHOW FULL PROCESSLIST discloses the
// same thing, so the engine's own column name is what identifies the database —
// PostgreSQL's datname, MySQL/MariaDB's db. SQLite implements Monitor but has no
// process list to narrow.
//
// Entirely inert with no allowlist configured. That gate is explicit rather than
// left to DatabaseAllowed (which permits everything on an empty list), because
// the NULL rule below is a SEPARATE decision that does not consult it: applied
// unconditionally it would hide background workers and every no-USE MySQL
// connection from stock deployments — a regression in the default.
//
// FOUR sites treat driver.Value.Str as the EXACT stored value and act on it, so
// none may run over a cell capCell could have truncated to a prefix (a prefix
// would silently match a different value):
//   - rowKeyFor (table.go) builds the invertible Edit/Delete WHERE token — it
//     now refuses a truncated key component (Value.Truncated), the fail-safe the
//     other three do not need;
//   - narrowProcessList here enforces the allowlist with DatabaseAllowed against
//     an exact slices.Contains — a shortened prod_secret would match prod;
//   - processListed authorises the kill target by parsing row[i].Str as the PID;
//   - KillID renders that same identifier into the form.
//
// These stay safe because the columns they read — datname/db (≤64 chars) and
// pid/Id (an integer) — are far under MaxCellBytes, and the one long column
// (query/info) is blanked or display-only, never a decision input. Show All's
// byte budget (browsesort.go) is whole-ROW for the same reason: a retained cell
// must stay byte-exact so this invariant needs no per-consumer guard.
func (h *Handlers) narrowProcessList(rs *driver.ResultSet) *driver.ResultSet {
	if rs == nil || len(h.Cfg.Restrict.Databases) == 0 {
		return rs
	}
	dbIdx := resultColumnIndex(rs, "datname") // PostgreSQL
	if dbIdx < 0 {
		dbIdx = resultColumnIndex(rs, "db") // MySQL / MariaDB
	}
	// The query text is its OWN disclosure, and the row filter does not cover it:
	// the db column names the connection's DEFAULT database, not what the
	// statement references. A thread attributed to an allowlisted database
	// running "SELECT * FROM otherdb.customers" passes every row test and would
	// render in full — MySQL's Info column is the whole statement, and the
	// template's truncate is display trimming, not redaction. So it is blanked on
	// every row, trading diagnostic value for confinement: the trade the
	// allowlist exists to make.
	qIdx := resultColumnIndex(rs, "query") // PostgreSQL
	if qIdx < 0 {
		qIdx = resultColumnIndex(rs, "info") // MySQL / MariaDB
	}
	out := &driver.ResultSet{Columns: rs.Columns, Truncated: rs.Truncated}
	for _, row := range rs.Rows {
		// Attribute or refuse. A row TableX cannot place in an allowlisted
		// database is exactly what the allowlist is refusing — including one with
		// no database column to place it by at all. NULL means a background
		// worker on PostgreSQL and, on MySQL, every connection that has not
		// issued a USE plus the replication and event-scheduler threads: under an
		// allowlist those become invisible, and therefore unkillable, too.
		if dbIdx < 0 || dbIdx >= len(row) || row[dbIdx].Null ||
			!h.Cfg.Restrict.DatabaseAllowed(row[dbIdx].Str) {
			continue
		}
		if qIdx >= 0 && qIdx < len(row) && !row[qIdx].Null {
			row = slices.Clone(row) // never mutate the caller's rows
			row[qIdx].Str = "(hidden)"
			row[qIdx].Bytes = nil
		}
		out.Rows = append(out.Rows, row)
	}
	return out
}

func processListed(rs *driver.ResultSet, idCol string, id int64) bool {
	i := resultColumnIndex(rs, idCol)
	if i < 0 {
		return false
	}
	for _, row := range rs.Rows {
		if i >= len(row) || row[i].Null {
			continue
		}
		if got, err := strconv.ParseInt(strings.TrimSpace(row[i].Str), 10, 64); err == nil && got == id {
			return true
		}
	}
	return false
}

// ServerUsers lists database accounts/roles (GET /server/users).
func (h *Handlers) ServerUsers(w http.ResponseWriter, r *http.Request) {
	uc, ok := h.requireUser(w, r)
	if !ok {
		return
	}
	body := usersBody{}
	if !uc.Capabilities().HasUsers {
		body.Empty = "This engine has no user accounts."
	} else if users, err := uc.ServerConn().ListUsers(r.Context()); err != nil {
		// A listing failure (a low-privilege login, a privilege denial) is
		// typed, not a neutral "no accounts". The create form still renders:
		// create authority is the server's call, not the listing's.
		body.Error = err.Error()
	} else {
		body.Users = users
	}
	conn := uc.ServerConn()
	if conn.CanManageUsers() {
		caps := uc.Capabilities()
		body.CanManage = h.allowance().DDL
		body.HasHost = caps.AccountHasHost
		body.HasRoleAttributes = caps.SupportsRoleAttributes
		body.PostURL = urlServer("users")
		body.SelfName, body.SelfHost = currentAccount(conn)
	}
	// Role membership. The read needs privileges on the server's own catalog
	// (mysql.role_edges / mysql.roles_mapping), so a low-privilege login can
	// list accounts and still fail here — which is an ERROR banner, not an
	// empty section: "no memberships" and "you may not see them" are different
	// facts about who can do what.
	if conn.CanManageRoles() {
		body.CanManageRoles = h.allowance().DDL
		if memberships, err := conn.RoleMemberships(r.Context()); err == nil {
			body.Memberships = memberships
		} else {
			body.RolesError = "Role memberships unavailable: " + err.Error()
		}
	}
	p := h.newLoggedPage(r, uc, "User accounts")
	p.Breadcrumb = h.buildBreadcrumb(uc, reqScope{})
	p.Tabs = h.serverTabsCaps(uc, "users")
	p.Body = body
	h.render(w, r, "server_users", p)
}
