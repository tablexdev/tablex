// Account & privilege administration: the POST actions behind the server Users
// page (create/drop account, set password, role attributes) and the database/
// table Privileges pages (GRANT/REVOKE). The read views stay in
// server_monitor.go / metadata.go.
//
// Every action follows validate-first: account names go through the
// engine-shaped validators below (NOT driver.ValidNewIdentifier, which is
// scoped to object names), existing accounts/objects are matched exactly
// against fresh introspection, grant privileges are validated against the
// dialect allowlist inside GrantSQL, and revoke privileges against the freshly
// re-introspected grants plus driver.ValidPrivilegeKeyword. DCL statements run
// under the logged-in user's own database privileges — the engine enforces
// authority; TableX adds no escalation.
//
// Passwords are read from the form and emitted only inside the dialect
// builders via QuoteString. A failed statement that carried a password is
// reported to the browser as a fixed generic message (the engine error can
// echo the statement, and exact-match redaction must not be the only line of
// defence) and logged via redactConnError with both the raw and QuoteString'd
// password as needles.

package handlers

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/tablexdev/tablex/internal/driver"
	"github.com/tablexdev/tablex/internal/model"
	"github.com/tablexdev/tablex/internal/view"
)

// --- account validators ----------------------------------------------------------

// validAccountChars applies ValidNewIdentifier's reject set (empty or
// space-padded, plus driver.HasUnsafeIdentifierRune's shared character set)
// without its object-name length cap — account-name length limits are
// engine-specific and live in validAccountName.
func validAccountChars(s string) bool {
	return s != "" && strings.TrimSpace(s) == s && !driver.HasUnsafeIdentifierRune(s)
}

// validAccountName applies the engine's account-name rule, selected by
// capability shape. Host-qualified engines (MySQL/MariaDB share one dialect)
// get a 128-rune sanity bound — MariaDB 10.6+ allows 128; MySQL's stricter 32
// surfaces as a clean server error. Role-based engines cap at 63 bytes
// (PostgreSQL NAMEDATALEN-1): validate-first matters there because the server
// silently truncates longer identifiers, which would create the role under an
// unexpected name.
func validAccountName(caps driver.Capabilities, name string) bool {
	if !validAccountChars(name) {
		return false
	}
	if caps.AccountHasHost {
		return utf8.RuneCountInString(name) <= 128
	}
	return len(name) <= 63
}

// validHostPattern accepts a MySQL account host: letters, digits and . - _ % :
// / (wildcards, IPv4/IPv6, CIDR masks), at most 255 bytes (the mysql.user.Host
// column width; MariaDB's tighter pre-10.6 limit surfaces as a server error).
func validHostPattern(s string) bool {
	if s == "" || len(s) > 255 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.' || r == '-' || r == '_' || r == '%' || r == ':' || r == '/':
		default:
			return false
		}
	}
	return true
}

// accountsEqual compares two accounts: exact (case-sensitive) name equality
// plus — on host-qualified engines — case-insensitive host equality (MySQL
// host names are not case-sensitive). No wildcard expansion: 'a'@'%' and
// 'a'@'localhost' are distinct accounts.
func accountsEqual(caps driver.Capabilities, aName, aHost, bName, bHost string) bool {
	if aName != bName {
		return false
	}
	if !caps.AccountHasHost {
		return true
	}
	return strings.EqualFold(aHost, bHost)
}

// currentAccount returns the logged-in account as the server reported it:
// MySQL's Info().User is the full CURRENT_USER() "user@host" string, split on
// the last @; role-based engines report the bare role name (which may legally
// contain @, so it is never split).
func currentAccount(conn *driver.Connection) (name, host string) {
	if conn.Capabilities().AccountHasHost {
		return driver.SplitAccount(conn.Info().User)
	}
	return strings.TrimSpace(conn.Info().User), ""
}

// findAccount returns the listed account matching name(+host), if any.
func findAccount(caps driver.Capabilities, users []model.User, name, host string) (model.User, bool) {
	for _, u := range users {
		if accountsEqual(caps, u.Name, u.Host, name, host) {
			return u, true
		}
	}
	return model.User{}, false
}

// isPublicGrantee reports whether the grantee is PostgreSQL's PUBLIC
// pseudo-role: the only valid grantee outside pg_roles (aclexplode grantee OID
// 0) and a fully grant/revoke-able target — REVOKE … FROM PUBLIC is the
// canonical way to drop default database access. Gated to role-based engines;
// on MySQL "PUBLIC" is an ordinary user name and must pass the existence check.
func isPublicGrantee(caps driver.Capabilities, grantee string) bool {
	return grantee == "PUBLIC" && !caps.AccountHasHost
}

// --- shared action plumbing ------------------------------------------------------

// blankPasswordRefusal is the 400 both password-carrying branches return for a
// blank submission. Engine-accurate on purpose: the two engines diverge, and
// neither outcome is what an operator pressing Set with an empty box meant.
// The password inputs also carry `required` as a convenience; this server-side
// check is the gate.
const blankPasswordRefusal = "A password is required: a blank one would allow empty-password logins on MySQL/MariaDB and would remove password authentication on PostgreSQL."

// accessExecFailed reports a failed account/privilege statement. The browser
// never sees the statement; when the statement carried a password the message
// is a fixed generic string (never err.Error(), which can echo the SQL), and
// the log line is redacted with the raw password and its QuoteString form —
// MySQL's QuoteString escapes the bytes, so the raw needle alone would miss
// the quoted representation.
func (h *Handlers) accessExecFailed(w http.ResponseWriter, r *http.Request, conn *driver.Connection, err error, backURL, password string) {
	secrets := []string{}
	if password != "" {
		secrets = append(secrets, password, conn.Dialect().QuoteString(password))
	}
	h.Log.Warn("access-control statement failed", "err", redactConnError(err, secrets...), "reqid", RequestID(r.Context()))
	msg := "The statement failed: " + redactConnError(err, secrets...)
	if password != "" {
		msg = "The statement failed. Check the server log for details."
	}
	h.redirectFailed(w, r, backURL, msg)
}

// --- server-level account administration ------------------------------------------

// ServerUsersManage handles POST /server/users: create_user, drop_user,
// set_password and (role engines) alter_attrs, dispatched on the action field
// like DBOperations. The account admin runs on the server connection.
func (h *Handlers) ServerUsersManage(w http.ResponseWriter, r *http.Request) {
	uc, ok := h.requireUser(w, r)
	if !ok {
		return
	}
	if !h.parseFormOr400(w, r) {
		return
	}
	conn := uc.ServerConn()
	if !conn.CanManageUsers() {
		h.renderError(w, r, http.StatusBadRequest, "This engine does not support account management.", "")
		return
	}
	caps := uc.Capabilities()
	backURL := urlServer("users")

	name := strings.TrimSpace(r.PostFormValue("user_name"))
	// The host is NOT defaulted here: for drop/set_password/alter_attrs it comes
	// from the introspected row (which may legitimately be '' — distinct from
	// '%' on MySQL), and coercing it would target the wrong account. Only
	// create_user applies the blank→'%' "any host" default, in its own branch.
	host := strings.TrimSpace(r.PostFormValue("user_host"))
	password := r.PostFormValue("password") // never trimmed, logged or rendered

	switch r.PostFormValue("action") {
	case "create_user":
		if caps.AccountHasHost && host == "" {
			host = "%" // normalize BEFORE validation so validate-first sees the effective host
		}
		if !validAccountName(caps, name) {
			h.renderError(w, r, http.StatusBadRequest, "Invalid account name.", "")
			return
		}
		if caps.AccountHasHost && !validHostPattern(host) {
			h.renderError(w, r, http.StatusBadRequest, "Invalid host pattern.", "")
			return
		}
		if users, err := conn.ListUsers(r.Context()); err == nil {
			if _, exists := findAccount(caps, users, name, host); exists {
				h.renderError(w, r, http.StatusBadRequest, "That account already exists.", "")
				return
			}
		}
		// Validate-first, like every branch here: a blank password would come
		// out engine-divergent and silently dangerous — MySQL/MariaDB create
		// the account with an EMPTY password it can log in with, PostgreSQL
		// with PASSWORD NULL. The driver's UserSpec deliberately stays
		// permissive ("possibly blank"); this handler is the policy layer.
		if password == "" {
			h.renderError(w, r, http.StatusBadRequest, blankPasswordRefusal, "")
			return
		}
		spec := driver.UserSpec{Name: name, Host: host, Password: password, SetPassword: true}
		if caps.SupportsRoleAttributes {
			spec.CanLogin = r.PostFormValue("attr_login") != ""
			spec.Super = r.PostFormValue("attr_super") != ""
			spec.CreateDB = r.PostFormValue("attr_createdb") != ""
			spec.CreateRole = r.PostFormValue("attr_createrole") != ""
		}
		if err := conn.CreateUser(r.Context(), spec); err != nil {
			h.accessExecFailed(w, r, conn, err, backURL, password)
			return
		}
		h.redirectTo(w, r, backURL, view.Flash{Kind: "success", Message: fmt.Sprintf("Account %q created.", name)})

	case "drop_user":
		if !h.requireExistingAccount(w, r, conn, caps, name, host) {
			return
		}
		if selfName, selfHost := currentAccount(conn); accountsEqual(caps, name, host, selfName, selfHost) {
			h.renderError(w, r, http.StatusBadRequest, "Refusing to drop the account you are logged in as.", "")
			return
		}
		if !h.requireConfirm(w, r, uc, reqScope{}, fmt.Sprintf("Drop account %q?", name), backURL, "Drop account") {
			return
		}
		if err := conn.DropUser(r.Context(), name, host); err != nil {
			h.accessExecFailed(w, r, conn, err, backURL, "")
			return
		}
		h.redirectTo(w, r, backURL, view.Flash{Kind: "success", Message: fmt.Sprintf("Account %q dropped.", name)})

	case "set_password":
		if !h.requireExistingAccount(w, r, conn, caps, name, host) {
			return
		}
		// Same policy as create_user: a blank submission was silently flashed
		// as "Password updated" while doing something engine-divergent (empty
		// password on MySQL/MariaDB, PASSWORD NULL on PostgreSQL).
		if password == "" {
			h.renderError(w, r, http.StatusBadRequest, blankPasswordRefusal, "")
			return
		}
		spec := driver.UserSpec{Name: name, Host: host, Password: password, SetPassword: true}
		if err := conn.AlterUser(r.Context(), spec); err != nil {
			h.accessExecFailed(w, r, conn, err, backURL, password)
			return
		}
		h.redirectTo(w, r, backURL, view.Flash{Kind: "success", Message: fmt.Sprintf("Password updated for %q.", name)})

	case "alter_attrs":
		if !caps.SupportsRoleAttributes {
			h.renderError(w, r, http.StatusBadRequest, "This engine has no role attributes.", "")
			return
		}
		if !h.requireExistingAccount(w, r, conn, caps, name, host) {
			return
		}
		spec := driver.UserSpec{
			Name:       name,
			CanLogin:   r.PostFormValue("attr_login") != "",
			Super:      r.PostFormValue("attr_super") != "",
			CreateDB:   r.PostFormValue("attr_createdb") != "",
			CreateRole: r.PostFormValue("attr_createrole") != "",
		}
		if err := conn.AlterUser(r.Context(), spec); err != nil {
			h.accessExecFailed(w, r, conn, err, backURL, "")
			return
		}
		flash := view.Flash{Kind: "success", Message: fmt.Sprintf("Attributes updated for %q.", name)}
		if selfName, selfHost := currentAccount(conn); accountsEqual(caps, name, host, selfName, selfHost) {
			flash = view.Flash{Kind: "warning", Message: fmt.Sprintf("Attributes updated for %q — this is your own account; a removed LOGIN or SUPERUSER takes effect on your next login.", name)}
		}
		h.redirectTo(w, r, backURL, flash)

	case "grant_role", "revoke_role":
		h.manageRoleMembership(w, r, uc, conn, caps, backURL)

	default:
		h.renderError(w, r, http.StatusBadRequest, "Unknown operation.", "")
	}
}

// manageRoleMembership runs one GRANT/REVOKE of a role to an account. Both ends
// are decoded from the account <select> shape and matched against a fresh
// account listing — the same validate-first rule the grant paths use, and the
// reason a role name never reaches a builder unless the server just reported
// it. Which accounts may act as a role is left to the ENGINE: PostgreSQL lets
// any role be granted to any other, MySQL 8 treats roles as ordinary accounts,
// and only MariaDB has a distinct kind — whose "not a role" error is clearer
// than anything a re-implementation of its rule here could say.
func (h *Handlers) manageRoleMembership(w http.ResponseWriter, r *http.Request, uc *UserContext, conn *driver.Connection, caps driver.Capabilities, backURL string) {
	if !conn.CanManageRoles() {
		h.renderError(w, r, http.StatusBadRequest, "This server does not support role membership.", "")
		return
	}
	var g driver.RoleGrant
	if caps.AccountHasHost {
		g.Role, g.RoleHost = driver.SplitAccount(r.PostFormValue("role"))
		g.Member, g.MemberHost = driver.SplitAccount(r.PostFormValue("member"))
	} else {
		g.Role = strings.TrimSpace(r.PostFormValue("role"))
		g.Member = strings.TrimSpace(r.PostFormValue("member"))
	}
	g.AdminOption = r.PostFormValue("admin_option") != ""

	users, err := conn.ListUsers(r.Context())
	if err != nil {
		h.renderError(w, r, http.StatusBadRequest, "Cannot verify the accounts: "+err.Error(), "")
		return
	}
	if _, ok := findAccount(caps, users, g.Role, g.RoleHost); !ok {
		h.renderError(w, r, http.StatusBadRequest, "Unknown role.", "")
		return
	}
	if _, ok := findAccount(caps, users, g.Member, g.MemberHost); !ok {
		h.renderError(w, r, http.StatusBadRequest, "Unknown member account.", "")
		return
	}
	// A role granted to itself is a cycle the server would reject anyway, but
	// the message it gives varies by engine and version; refuse it here so the
	// answer is the same everywhere.
	if accountsEqual(caps, g.Role, g.RoleHost, g.Member, g.MemberHost) {
		h.renderError(w, r, http.StatusBadRequest, "An account cannot be granted to itself.", "")
		return
	}

	if r.PostFormValue("action") == "grant_role" {
		if err := conn.GrantRole(r.Context(), g); err != nil {
			h.accessExecFailed(w, r, conn, err, backURL, "")
			return
		}
		h.redirectTo(w, r, backURL, view.Flash{Kind: "success",
			Message: fmt.Sprintf("Granted role %q to %q.", g.Role, g.Member)})
		return
	}
	if !h.requireConfirm(w, r, uc, reqScope{}, fmt.Sprintf("Revoke role %q from %q?", g.Role, g.Member), backURL, "Revoke role") {
		return
	}
	if err := conn.RevokeRole(r.Context(), g); err != nil {
		h.accessExecFailed(w, r, conn, err, backURL, "")
		return
	}
	flash := view.Flash{Kind: "success", Message: fmt.Sprintf("Revoked role %q from %q.", g.Role, g.Member)}
	if selfName, selfHost := currentAccount(conn); accountsEqual(caps, g.Member, g.MemberHost, selfName, selfHost) {
		flash = view.Flash{Kind: "warning",
			Message: fmt.Sprintf("Revoked role %q from %q — that is your own account.", g.Role, g.Member)}
	}
	h.redirectTo(w, r, backURL, flash)
}

// requireExistingAccount validates that the drop/alter target matches a listed
// account exactly (existing objects are validated against introspection, never
// against the form). When the account listing itself fails — a low-privilege
// login — there are no verified targets, so the action is refused.
func (h *Handlers) requireExistingAccount(w http.ResponseWriter, r *http.Request, conn *driver.Connection, caps driver.Capabilities, name, host string) bool {
	users, err := conn.ListUsers(r.Context())
	if err != nil {
		h.renderError(w, r, http.StatusBadRequest, "Cannot verify the target account: "+err.Error(), "")
		return false
	}
	if _, ok := findAccount(caps, users, name, host); !ok {
		h.renderError(w, r, http.StatusNotFound, "Unknown account.", "")
		return false
	}
	return true
}

// --- database / table privilege management ----------------------------------------

// DBPrivilegesManage handles POST /db/{db}/privileges (database-scope
// grant/revoke).
func (h *Handlers) DBPrivilegesManage(w http.ResponseWriter, r *http.Request) {
	h.managePrivileges(w, r, false)
}

// TablePrivilegesManage handles POST /db/{db}/table/{table}/privileges
// (table-scope grant/revoke).
func (h *Handlers) TablePrivilegesManage(w http.ResponseWriter, r *http.Request) {
	h.managePrivileges(w, r, true)
}

// resolveGrantee decodes and verifies the posted grantee — shared, byte-for-
// byte, by the object-scope and routine-scope manage handlers. The <select>
// value carries "user@host" on host-qualified engines (decoded with the
// last-@ split); role names are never split — they may legally contain @. A
// non-PUBLIC grantee must match a live account. ok=false means a response was
// already written and the caller must return.
func (h *Handlers) resolveGrantee(w http.ResponseWriter, r *http.Request, uc *UserContext, caps driver.Capabilities) (grantee, host string, ok bool) {
	if caps.AccountHasHost {
		grantee, host = driver.SplitAccount(r.PostFormValue("grantee"))
	} else {
		grantee = strings.TrimSpace(r.PostFormValue("grantee"))
	}
	if !isPublicGrantee(caps, grantee) {
		users, err := uc.ServerConn().ListUsers(r.Context())
		if err != nil {
			h.renderError(w, r, http.StatusBadRequest, "Cannot verify the grantee: "+err.Error(), "")
			return "", "", false
		}
		if _, found := findAccount(caps, users, grantee, host); !found {
			h.renderError(w, r, http.StatusBadRequest, "Unknown grantee.", "")
			return "", "", false
		}
	}
	return grantee, host, true
}

// managePrivileges validates and runs one grant or revoke. Grants run on the
// database connection; privilege keywords are validated inside GrantSQL
// against the dialect allowlist (grant) or — for revoke — against the freshly
// re-introspected grants for the grantee and object, with
// driver.ValidPrivilegeKeyword as the secondary shape gate, so an
// already-present grant of a version-specific keyword (PostgreSQL 17 MAINTAIN)
// stays revokable without ever trusting a raw form value.
func (h *Handlers) managePrivileges(w http.ResponseWriter, r *http.Request, isTable bool) {
	uc, ok := h.requireUser(w, r)
	if !ok {
		return
	}
	if !h.parseFormOr400(w, r) {
		return
	}
	// The schema rides the POST URL's ?schema= (resolveScope reads the query
	// only), so the forms post to urlDB/urlTable-built targets.
	sc := h.resolveScope(r).withSchemaDefault(uc.Capabilities())
	conn, err := uc.ConnFor(r.Context(), sc.DB)
	if err != nil {
		h.connError(w, r, uc, err)
		return
	}
	if !conn.CanManagePrivileges() {
		h.renderError(w, r, http.StatusBadRequest, "This engine does not support privilege management.", "")
		return
	}
	caps := uc.Capabilities()

	var backURL string
	if isTable {
		if !h.requireDataTable(w, r, conn, sc) {
			return
		}
		exists, err := h.tableExists(r.Context(), conn, sc)
		if err != nil {
			// An introspection failure is not "not found": a misleading 404
			// here would tell the operator the table is gone while the truth
			// is that nothing could be read at all.
			h.Log.Warn("table privileges lookup failed", "err", redactConnError(err), "reqid", RequestID(r.Context()))
			h.renderError(w, r, http.StatusInternalServerError, "Could not verify the table before changing its grants.", "")
			return
		}
		if !exists {
			h.renderError(w, r, http.StatusNotFound, "Table not found.", "")
			return
		}
		backURL = urlTable(sc.DB, sc.Schema, sc.Table, "privileges")
	} else {
		if found, err := h.databaseExists(r.Context(), uc, sc.DB); err != nil {
			h.dbError(w, r, err, "")
			return
		} else if !found {
			h.renderError(w, r, http.StatusNotFound, "Database not found.", "")
			return
		}
		backURL = urlDB(sc.DB, sc.Schema, "privileges")
	}

	grantee, host, ok := h.resolveGrantee(w, r, uc, caps)
	if !ok {
		return
	}

	spec := driver.GrantSpec{Database: sc.DB, Schema: sc.Schema, Grantee: grantee, Host: host}
	ref := driver.TableRef{Database: sc.DB, Schema: sc.Schema}
	if isTable {
		spec.Table = sc.Table
		ref.Table = sc.Table
	}

	switch r.PostFormValue("action") {
	case "grant":
		spec.Privileges = r.PostForm["privs"]
		spec.WithGrant = r.PostFormValue("with_grant") != ""
		if len(spec.Privileges) == 0 {
			h.renderError(w, r, http.StatusBadRequest, "Select at least one privilege.", "")
			return
		}
		// Primary gate: every submitted privilege must be in the dialect's
		// offerable allowlist — the same list that rendered the checkboxes.
		// (GrantSQL re-checks defensively before emitting.)
		allowed := conn.GrantablePrivileges(isTable)
		for _, p := range spec.Privileges {
			if !slices.Contains(allowed, strings.ToUpper(strings.TrimSpace(p))) {
				h.renderError(w, r, http.StatusBadRequest, "Invalid privilege.", "")
				return
			}
		}
		if cols, ok := h.resolveGrantColumns(w, r, conn, ref, isTable, spec.Privileges); ok {
			spec.Columns = cols
		} else {
			return
		}
		if err := conn.Grant(r.Context(), spec); err != nil {
			h.accessExecFailed(w, r, conn, err, backURL, "")
			return
		}
		h.redirectTo(w, r, backURL, view.Flash{Kind: "success",
			Message: fmt.Sprintf("Granted %s%s to %q.", strings.Join(spec.Privileges, ", "),
				columnNote(spec.Columns), grantee)})

	case "revoke":
		priv := strings.ToUpper(strings.TrimSpace(r.PostFormValue("priv")))
		// The column is part of the grant's identity, not a modifier of it: a
		// blank column means the object-wide grant, and the two are separately
		// revokable. It is carried into the presence check rather than trusted,
		// so a revoke can only name a (grantee, privilege, column) triple the
		// catalog actually holds.
		column := r.PostFormValue("column")
		// Primary gate: the privilege must be present in a fresh introspection of
		// the displayed grants (never trust the form's copy)...
		patterns, present, err := h.grantPresent(r.Context(), conn, caps, ref, grantee, host, priv, column)
		if err != nil {
			// An introspection failure is distinct from "grant absent" — don't tell
			// the operator the grant is gone when we simply couldn't read it.
			h.renderError(w, r, http.StatusInternalServerError, "Cannot verify current grants: "+err.Error(), "")
			return
		}
		if !present {
			h.renderError(w, r, http.StatusBadRequest, "That grant is not present.", "")
			return
		}
		// ...secondary shape gate before the keyword is emitted verbatim.
		if !driver.ValidPrivilegeKeyword(priv) {
			h.renderError(w, r, http.StatusBadRequest, "Invalid privilege.", "")
			return
		}
		spec.Privileges = []string{priv}
		if column != "" {
			// Safe to emit: the presence check matched it byte-for-byte against
			// an introspected grant row, so this IS the catalog's own spelling.
			spec.Columns = []string{column}
		}
		// MySQL database scope: revoke each grant row by its stored pattern
		// (raw for externally-created grants), not by re-escaping the name.
		spec.DatabasePatterns = patterns
		if !h.requireConfirm(w, r, uc, sc, fmt.Sprintf("Revoke %s%s from %q?", priv, columnNote(spec.Columns), grantee), backURL, "Revoke") {
			return
		}
		if err := conn.Revoke(r.Context(), spec); err != nil {
			h.accessExecFailed(w, r, conn, err, backURL, "")
			return
		}
		flash := view.Flash{Kind: "success", Message: fmt.Sprintf("Revoked %s%s from %q.", priv, columnNote(spec.Columns), grantee)}
		if selfName, selfHost := currentAccount(conn); accountsEqual(caps, grantee, host, selfName, selfHost) {
			flash = view.Flash{Kind: "warning", Message: fmt.Sprintf("Revoked %s%s from %q — that is your own account.", priv, columnNote(spec.Columns), grantee)}
		}
		h.redirectTo(w, r, backURL, flash)

	default:
		h.renderError(w, r, http.StatusBadRequest, "Unknown operation.", "")
	}
}

// grantPresent re-introspects the grants on ref and reports whether the
// grantee holds priv there — scoped to column, with "" meaning the object-wide
// grant — along with the distinct stored grant pattern(s) holding it
// (model.Privilege.StoredObject — MySQL database scope only, nil elsewhere) so
// the revoke targets each grant row exactly as stored. Privilege rows carry the
// grantee in User/Host (PostgreSQL PUBLIC rows have User "PUBLIC").
//
// The column comparison is exact, not case-folded like the privilege keyword:
// keywords are a fixed vocabulary the engines echo in their own case, while a
// column name is an identifier that PostgreSQL treats case-sensitively, so
// folding it here could match a DIFFERENT column's grant.
func (h *Handlers) grantPresent(ctx context.Context, conn *driver.Connection, caps driver.Capabilities, ref driver.TableRef, grantee, host, priv, column string) (patterns []string, present bool, err error) {
	current, err := conn.Privileges(ctx, ref)
	if err != nil {
		return nil, false, err
	}
	for _, p := range current {
		if accountsEqual(caps, p.User, p.Host, grantee, host) && strings.EqualFold(p.Privilege, priv) && p.Column == column {
			present = true
			if p.StoredObject != "" && !slices.Contains(patterns, p.StoredObject) {
				patterns = append(patterns, p.StoredObject)
			}
		}
	}
	return patterns, present, nil
}

// --- routine-scope grants ----------------------------------------------------------

// RoutinePrivilegesManage handles POST /db/{db}/routines/privileges — grant and
// revoke EXECUTE (and MySQL's ALTER ROUTINE) on one stored routine.
//
// It mirrors managePrivileges exactly where it can: same grantee decoding, same
// existence check, same "grant is validated against the allowlist, revoke
// against a fresh introspection" split. What it cannot share is the object —
// a routine is addressed by name AND position (and, on PostgreSQL, by the
// identity arguments only introspection can supply), so resolution goes through
// the stored-program addressing rule instead of a TableRef.
func (h *Handlers) RoutinePrivilegesManage(w http.ResponseWriter, r *http.Request) {
	uc, ok := h.requireUser(w, r)
	if !ok {
		return
	}
	if !h.parseFormOr400(w, r) {
		return
	}
	sc := h.resolveScope(r).withSchemaDefault(uc.Capabilities())
	conn, routine, ok := h.resolveRoutineForPrivileges(w, r, uc, sc)
	if !ok {
		return
	}
	caps := uc.Capabilities()
	backURL := urlRoutinePrivileges(sc, routine.Name, routineIndexOf(r))

	grantee, host, ok := h.resolveGrantee(w, r, uc, caps)
	if !ok {
		return
	}

	g := driver.RoutineGrant{Scope: sc.scope(), Routine: routine, Grantee: grantee, Host: host}
	switch r.PostFormValue("action") {
	case "grant":
		g.Privileges = r.PostForm["privs"]
		g.WithGrant = r.PostFormValue("with_grant") != ""
		if len(g.Privileges) == 0 {
			h.renderError(w, r, http.StatusBadRequest, "Select at least one privilege.", "")
			return
		}
		allowed := conn.RoutineGrantablePrivileges()
		for _, p := range g.Privileges {
			if !slices.Contains(allowed, strings.ToUpper(strings.TrimSpace(p))) {
				h.renderError(w, r, http.StatusBadRequest, "Invalid privilege.", "")
				return
			}
		}
		if err := conn.GrantRoutine(r.Context(), g); err != nil {
			h.accessExecFailed(w, r, conn, err, backURL, "")
			return
		}
		h.redirectTo(w, r, backURL, view.Flash{Kind: "success",
			Message: fmt.Sprintf("Granted %s on %q to %q.", strings.Join(g.Privileges, ", "), routine.Name, grantee)})

	case "revoke":
		priv := strings.ToUpper(strings.TrimSpace(r.PostFormValue("priv")))
		present, err := h.routineGrantPresent(r.Context(), conn, caps, sc, routine, grantee, host, priv)
		if err != nil {
			h.renderError(w, r, http.StatusInternalServerError, "Cannot verify current grants: "+err.Error(), "")
			return
		}
		if !present {
			h.renderError(w, r, http.StatusBadRequest, "That grant is not present.", "")
			return
		}
		if !driver.ValidPrivilegeKeyword(priv) {
			h.renderError(w, r, http.StatusBadRequest, "Invalid privilege.", "")
			return
		}
		g.Privileges = []string{priv}
		if !h.requireConfirm(w, r, uc, sc, fmt.Sprintf("Revoke %s on %q from %q?", priv, routine.Name, grantee), backURL, "Revoke") {
			return
		}
		if err := conn.RevokeRoutine(r.Context(), g); err != nil {
			h.accessExecFailed(w, r, conn, err, backURL, "")
			return
		}
		flash := view.Flash{Kind: "success", Message: fmt.Sprintf("Revoked %s on %q from %q.", priv, routine.Name, grantee)}
		if selfName, selfHost := currentAccount(conn); accountsEqual(caps, grantee, host, selfName, selfHost) {
			flash = view.Flash{Kind: "warning",
				Message: fmt.Sprintf("Revoked %s on %q from %q — that is your own account.", priv, routine.Name, grantee)}
		}
		h.redirectTo(w, r, backURL, flash)

	default:
		h.renderError(w, r, http.StatusBadRequest, "Unknown operation.", "")
	}
}

// routineGrantPresent is grantPresent for a routine: it re-reads the grants and
// reports whether the grantee holds priv there. No stored-pattern companion —
// a routine target is literal on both engines, so there is nothing to match
// verbatim the way a MySQL database pattern must be.
func (h *Handlers) routineGrantPresent(ctx context.Context, conn *driver.Connection, caps driver.Capabilities,
	sc reqScope, routine model.Routine, grantee, host, priv string) (bool, error) {
	current, err := conn.RoutinePrivileges(ctx, sc.scope(), routine)
	if err != nil {
		return false, err
	}
	for _, p := range current {
		if accountsEqual(caps, p.User, p.Host, grantee, host) && strings.EqualFold(p.Privilege, priv) {
			return true, nil
		}
	}
	return false, nil
}

// --- column-scope grants ----------------------------------------------------------

// resolveGrantColumns reads the grant form's optional column list and returns
// the columns to scope the grant to (nil for an object-wide grant). ok is false
// when it has already written the error response.
//
// The asymmetry to keep in mind: every other list in this file may be filtered
// down safely, but silently dropping columns here does the opposite of
// narrowing — an empty list means "the whole table". So a name that does not
// match introspection is refused outright rather than skipped, and the engine
// must be one that can express column scope at all.
func (h *Handlers) resolveGrantColumns(w http.ResponseWriter, r *http.Request, conn *driver.Connection, ref driver.TableRef, isTable bool, privs []string) (cols []string, ok bool) {
	want := r.PostForm["columns"]
	if !anyNonBlank(want) {
		return nil, true
	}
	if !isTable {
		h.renderError(w, r, http.StatusBadRequest, "Column grants apply to a table, not a database.", "")
		return nil, false
	}
	columnPrivs := conn.ColumnGrantablePrivileges()
	if len(columnPrivs) == 0 {
		h.renderError(w, r, http.StatusBadRequest, "This engine does not support column-scope grants.", "")
		return nil, false
	}
	for _, p := range privs {
		if !slices.Contains(columnPrivs, strings.ToUpper(strings.TrimSpace(p))) {
			h.renderError(w, r, http.StatusBadRequest,
				"Only "+strings.Join(columnPrivs, ", ")+" accept a column list.", "")
			return nil, false
		}
	}
	existing, err := conn.Columns(r.Context(), ref)
	if err != nil {
		// Not "unknown column": we could not read the table at all, and telling
		// the operator their column does not exist would be a lie.
		h.renderError(w, r, http.StatusInternalServerError, "Cannot verify the columns: "+err.Error(), "")
		return nil, false
	}
	resolved, err := resolveColumnNames(existing, want)
	if err != nil {
		h.renderError(w, r, http.StatusBadRequest, err.Error(), "")
		return nil, false
	}
	return resolved, true
}

// anyNonBlank reports whether ss holds at least one non-blank entry.
func anyNonBlank(ss []string) bool {
	for _, s := range ss {
		if strings.TrimSpace(s) != "" {
			return true
		}
	}
	return false
}

// resolveColumnNames matches each submitted name against the introspected
// columns and returns the CATALOG's spelling, in introspected order, with
// duplicates collapsed. An unmatched name is an error, never a skip.
//
// Returning the introspected string rather than the form's is what lets the
// dialect quote it: it is then an identifier the catalog vouches for, which is
// the rule the whole codebase applies before any name reaches QuoteIdent.
func resolveColumnNames(existing []model.Column, want []string) ([]string, error) {
	wanted := make(map[string]bool, len(want))
	for _, w := range want {
		if w = strings.TrimSpace(w); w != "" {
			wanted[w] = true
		}
	}
	if len(wanted) == 0 {
		// One representation of "object-wide", so no caller has to distinguish
		// a nil list from an empty one.
		return nil, nil
	}
	out := make([]string, 0, len(wanted))
	for _, c := range existing {
		if wanted[c.Name] {
			out = append(out, c.Name)
			delete(wanted, c.Name)
		}
	}
	if len(wanted) > 0 {
		// Report in submission order so the message is deterministic.
		for _, w := range want {
			if wanted[strings.TrimSpace(w)] {
				return nil, fmt.Errorf("unknown column %q", strings.TrimSpace(w))
			}
		}
	}
	return out, nil
}

// columnNote renders the " on column(s) …" fragment of a grant/revoke flash.
// Empty for an object-wide grant, so the common message is unchanged.
func columnNote(cols []string) string {
	if len(cols) == 0 {
		return ""
	}
	if len(cols) == 1 {
		return " on column " + cols[0]
	}
	return " on columns " + strings.Join(cols, ", ")
}
