package driver

import (
	"context"
	"database/sql"

	"github.com/tablexdev/tablex/internal/model"
)

// This file holds the write-side administration capabilities — accounts,
// privileges, roles and server sessions (DCL and session control). They are
// the contract mirror of the connection layer's connection_dcl.go, split out
// of driver.go so each file stays a single role.

// UserSpec describes a database account to create or alter. Password is the
// plaintext the operator typed: builders emit it only through QuoteString and
// callers must never log, flash or render it (or any SQL embedding it).
type UserSpec struct {
	Name        string
	Host        string // MySQL account host part ('user'@'host'); ignored by role engines
	Password    string
	SetPassword bool // distinguishes "set this password (possibly blank)" from "leave unchanged"
	CanLogin    bool // PostgreSQL LOGIN attribute; MySQL accounts always log in
	Super       bool // PostgreSQL SUPERUSER
	CreateDB    bool // PostgreSQL CREATEDB
	CreateRole  bool // PostgreSQL CREATEROLE
}

// GrantSpec describes one GRANT or REVOKE. Privileges must be pre-validated by
// the caller (grant: membership in GrantablePrivileges; revoke: membership in
// the freshly introspected grants) — the builders re-check defensively but the
// handler is the authority. Grantee "PUBLIC" is PostgreSQL's pseudo-role and is
// emitted as the bare keyword, never as a quoted identifier.
type GrantSpec struct {
	Privileges []string
	Database   string
	Schema     string // PostgreSQL table scope; ignored elsewhere
	Table      string // "" → database scope
	Grantee    string
	Host       string // MySQL grantee host part
	WithGrant  bool
	// Columns restricts the grant to specific columns of Table
	// (GRANT SELECT (a, b) ON t). Empty — the default — is an object-wide
	// grant. Names must have been matched against live introspection by the
	// caller; the builders only quote them.
	//
	// Dropping this list does not fail safe, it WIDENS: "SELECT on two columns"
	// silently becomes "SELECT on every column". So a dialect that cannot
	// express column scope must not receive it — Connection.Grant/Revoke refuse
	// a non-empty Columns unless the dialect is a ColumnPrivileger, and the
	// builders re-check.
	Columns []string
	// DatabasePatterns carries the stored grant pattern(s) exactly as
	// introspected (model.Privilege.StoredObject) for a MySQL database-scope
	// REVOKE: pre-escaped as stored, used verbatim, one REVOKE per pattern.
	// Empty (the default, and always for GRANT and other engines) falls back
	// to escaping Database.
	DatabasePatterns []string
}

// UserManager is an optional, write-only Dialect capability for account
// administration (the read side stays on the mandatory ListUsers). Builders
// quote account parts internally — MySQL as string literals, PostgreSQL as
// identifiers — and return complete statements for Connection.ExecScript.
// Engines without an account system (SQLite) do not implement it and the UI
// hides the controls.
type UserManager interface {
	CreateUserSQL(u UserSpec) ([]string, error)
	AlterUserSQL(u UserSpec) ([]string, error) // set password and/or role attributes
	DropUserSQL(name, host string) ([]string, error)
}

// PrivilegeManager is an optional, write-only Dialect capability for
// GRANT/REVOKE (the read side stays on Privileger). GrantablePrivileges is the
// single source of truth for both the grant form's checkbox set and grant
// validation. RevokeSQL deliberately accepts keywords outside that set — an
// already-present grant of a version-specific privilege (e.g. PostgreSQL 17's
// MAINTAIN) must stay revokable — but every keyword still passes
// ValidPrivilegeKeyword before it is emitted.
type PrivilegeManager interface {
	GrantablePrivileges(table bool) []string // curated allowlist: table or database scope
	GrantSQL(g GrantSpec) ([]string, error)
	RevokeSQL(g GrantSpec) ([]string, error)
}

// ProcessManager is an optional capability: terminate a server session listed
// by Monitor.Processes. Engines with no session table (SQLite) omit it and the
// process page stays read-only.
//
// The process list is an opaque *ResultSet — each engine's own columns — so the
// dialect also names the column holding the identifier. That pairing is the
// whole interface: without it a caller would have to guess which column of
// SHOW FULL PROCESSLIST or pg_stat_activity is the one to kill.
type ProcessManager interface {
	// ProcessIDColumn is the Processes() column whose value KillProcessSQL
	// takes ("Id" on MySQL, "pid" on PostgreSQL).
	ProcessIDColumn() string
	// KillProcessSQL terminates the session with this identifier.
	//
	// The id is an int64, not a string, and that is a deliberate part of the
	// contract rather than a convenience: neither engine accepts a placeholder
	// where the identifier goes (MySQL's KILL takes no parameters at all), so
	// the value is formatted into the statement — and an integer parsed by the
	// caller cannot carry anything else. Do not widen this to a string.
	KillProcessSQL(id int64) string
}

// RoutineGrant describes one GRANT/REVOKE on a stored routine. Routine is the
// object as INTROSPECTION returned it, not as a request named it: PostgreSQL
// needs its ArgSignature to address one of several overloads, and both engines
// need its Type to pick the FUNCTION or PROCEDURE keyword.
type RoutineGrant struct {
	Scope      Scope
	Routine    model.Routine
	Privileges []string
	Grantee    string
	Host       string // MySQL grantee host part
	WithGrant  bool
}

// RoutinePrivileger is an optional capability for routine-scope grants
// (GRANT EXECUTE ON FUNCTION …). Read and write on one interface, for the
// reason the other two privilege capabilities share: an unlistable grant is an
// unrevokable one.
//
// A routine is not a relation, so this deliberately does NOT reuse Privileger's
// TableRef: PostgreSQL addresses a routine by schema, name AND identity
// arguments, which no TableRef has a place for, and silently dropping them
// would target whichever overload the catalog happened to return first.
type RoutinePrivileger interface {
	// RoutineGrantablePrivileges is the curated allowlist for routine scope —
	// EXECUTE everywhere, plus MySQL's ALTER ROUTINE.
	RoutineGrantablePrivileges() []string
	RoutinePrivileges(ctx context.Context, db *sql.DB, s Scope, r model.Routine) ([]model.Privilege, error)
	GrantRoutineSQL(g RoutineGrant) ([]string, error)
	RevokeRoutineSQL(g RoutineGrant) ([]string, error)
}

// RoleGrant describes one GRANT/REVOKE of a role to an account. Both ends must
// have been matched against the live account listing by the caller; the
// builders only quote them.
type RoleGrant struct {
	Role       string
	RoleHost   string // MySQL 8 role account host; ignored by MariaDB and PostgreSQL
	Member     string
	MemberHost string // MySQL/MariaDB grantee host
	// AdminOption lets the member grant the role onward. Ignored by REVOKE,
	// which removes the membership entirely.
	AdminOption bool
}

// RoleManager is an optional Dialect capability for role membership — the
// grants that hand one account another's privileges wholesale. Read and write
// live on one interface because, as with column grants, a membership that
// cannot be listed cannot be revoked.
//
// It is paired with Capabilities.SupportsRoles, which is VERSION-GATED on
// MySQL/MariaDB (roles arrived in MySQL 8.0 and MariaDB 10.0.5) and must fail
// CLOSED on an unknown version: the catalog table simply does not exist on an
// older server, so guessing "supported" turns the page into an error instead of
// a hidden section. That is the opposite of SupportsColumnRename, which fails
// open because only one old flavor lacks the statement.
//
// The two engine families disagree about what a role IS, and the interface
// deliberately does not paper over it: a MySQL 8 role is an ordinary account
// ('r'@'%'), a MariaDB role is a distinct kind of row with no host, and every
// PostgreSQL role can be granted to any other. Each dialect addresses its own
// catalog; handlers only move model.RoleMembership around.
type RoleManager interface {
	RoleMemberships(ctx context.Context, db *sql.DB) ([]model.RoleMembership, error)
	GrantRoleSQL(g RoleGrant) ([]string, error)
	RevokeRoleSQL(g RoleGrant) ([]string, error)
}

// ColumnPrivileger is an optional capability extending PrivilegeManager to
// column-scope grants (GRANT SELECT (a, b) ON t TO u). It embeds
// PrivilegeManager because column scope is a refinement of table scope, never
// an alternative to it: the same GrantSQL/RevokeSQL builders emit both, keyed
// on GrantSpec.Columns.
//
// The read side needs no separate interface — Privileger returns column grants
// as ordinary model.Privilege rows carrying a Column, so an engine's grant
// listing and its revoke path stay one code path. Both halves must ship
// together: a grant nobody can list is a grant nobody can revoke.
type ColumnPrivileger interface {
	PrivilegeManager
	// ColumnGrantablePrivileges is the subset of the table-scope allowlist that
	// accepts a column list — SQL restricts it to the privileges that read or
	// write column values (SELECT/INSERT/UPDATE/REFERENCES), and "GRANT DELETE
	// (col)" is a syntax error rather than a narrower DELETE. It is the single
	// source of truth for the form's column control and for grant validation,
	// exactly as GrantablePrivileges is for the keyword set.
	ColumnGrantablePrivileges() []string
}
