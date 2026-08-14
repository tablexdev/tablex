package driver

// Connection's DCL passthroughs: account, process, privilege and role
// administration. Everything here funnels through dclScript /
// dclScriptRedacted so each statement is observed by the audit trail — and,
// for the password-embedding paths, redacted before it is recorded. Split
// from connection.go by role (the file-size ratchet keeps it that way).

import (
	"context"

	"github.com/tablexdev/tablex/internal/model"
)

// dclScript builds statements via build and executes them. DCL statements are
// grouped transactionally only where DDL/DCL is transactional (PostgreSQL);
// MySQL account statements auto-commit individually either way.
func (c *Connection) dclScript(ctx context.Context, build func() ([]string, error)) error {
	return c.dclScriptRedacted(ctx, nil, build)
}

// dclScriptRedacted is dclScript for statements that EMBED a secret: redact
// rides every statement's audit event so the observer strips the secret from
// the recorded SQL and error before either is written (StatementEvent.Redact).
// The password-carrying DCL is the one generated-SQL shape that would
// otherwise put a replayable credential into the trail, contradicting the
// "nothing in the trail can be replayed to gain access" guarantee
// (docs/security.md) — dclScript has no access to the UserSpec, so the
// needles are built where the spec is still in hand.
func (c *Connection) dclScriptRedacted(ctx context.Context, redact []string, build func() ([]string, error)) error {
	stmts, err := build()
	if err != nil {
		return err
	}
	return c.execScript(ctx, stmts, c.Capabilities().SupportsTransactionalDDL, redact)
}

// redactSecrets builds the audit-redaction needles for a statement embedding a
// password: the raw value AND its QuoteString form — the DCL builders embed
// the quoted form (whose escaping can differ from the raw bytes on MySQL),
// while an engine error may echo either. A blank password contributes nothing:
// an empty needle would blank-redact the whole statement.
func redactSecrets(d Dialect, password string) []string {
	if password == "" {
		return nil
	}
	return []string{password, d.QuoteString(password)}
}

// CreateUser creates a database account/role.
func (c *Connection) CreateUser(ctx context.Context, u UserSpec) error {
	m, ok := c.dialect.(UserManager)
	if !ok {
		return ErrUnsupported
	}
	return c.dclScriptRedacted(ctx, redactSecrets(c.dialect, u.Password), func() ([]string, error) { return m.CreateUserSQL(u) })
}

// AlterUser sets an account's password and/or role attributes.
func (c *Connection) AlterUser(ctx context.Context, u UserSpec) error {
	m, ok := c.dialect.(UserManager)
	if !ok {
		return ErrUnsupported
	}
	return c.dclScriptRedacted(ctx, redactSecrets(c.dialect, u.Password), func() ([]string, error) { return m.AlterUserSQL(u) })
}

// DropUser removes a database account/role.
func (c *Connection) DropUser(ctx context.Context, name, host string) error {
	m, ok := c.dialect.(UserManager)
	if !ok {
		return ErrUnsupported
	}
	return c.dclScript(ctx, func() ([]string, error) { return m.DropUserSQL(name, host) })
}

// --- Process administration (ProcessManager) -------------------------------------

// ProcessIDColumn returns the Processes() column holding the killable session
// identifier, or "" when the engine cannot terminate sessions.
func (c *Connection) ProcessIDColumn() string {
	if m, ok := c.dialect.(ProcessManager); ok {
		return m.ProcessIDColumn()
	}
	return ""
}

// KillProcess terminates a server session. The caller must have matched id
// against a fresh process list first — the engine decides whether the account
// is ALLOWED to kill it, but TableX still refuses to name a session nobody
// reported.
func (c *Connection) KillProcess(ctx context.Context, id int64) error {
	m, ok := c.dialect.(ProcessManager)
	if !ok {
		return ErrUnsupported
	}
	return c.dclScript(ctx, func() ([]string, error) { return []string{m.KillProcessSQL(id)}, nil })
}

// --- Routine-scope grants (RoutinePrivileger) ------------------------------------

// RoutineGrantablePrivileges returns the routine-scope allowlist, or nil when
// the engine has no routine grants — the signal the UI uses to hide the tab.
func (c *Connection) RoutineGrantablePrivileges() []string {
	if m, ok := c.dialect.(RoutinePrivileger); ok {
		return m.RoutineGrantablePrivileges()
	}
	return nil
}

// RoutinePrivileges lists the grants on one routine, or nil when unsupported.
func (c *Connection) RoutinePrivileges(ctx context.Context, s Scope, r model.Routine) ([]model.Privilege, error) {
	m, ok := c.dialect.(RoutinePrivileger)
	if !ok {
		return nil, nil
	}
	ctx, cancel := c.readCtx(ctx)
	defer cancel()
	return m.RoutinePrivileges(ctx, c.db, s, r)
}

// GrantRoutine runs a GRANT on a routine.
func (c *Connection) GrantRoutine(ctx context.Context, g RoutineGrant) error {
	m, ok := c.dialect.(RoutinePrivileger)
	if !ok {
		return ErrUnsupported
	}
	return c.dclScript(ctx, func() ([]string, error) { return m.GrantRoutineSQL(g) })
}

// RevokeRoutine runs a REVOKE on a routine.
func (c *Connection) RevokeRoutine(ctx context.Context, g RoutineGrant) error {
	m, ok := c.dialect.(RoutinePrivileger)
	if !ok {
		return ErrUnsupported
	}
	return c.dclScript(ctx, func() ([]string, error) { return m.RevokeRoutineSQL(g) })
}

// --- Role membership (RoleManager) ---------------------------------------------
//
// The capability is BOTH an interface assertion and a version flag: the mysql
// dialect implements RoleManager on every server, but roles do not exist before
// MySQL 8.0 / MariaDB 10.0.5, so Capabilities().SupportsRoles is the answer
// that accounts for the connected server. Every wrapper here checks both, which
// is what keeps a pre-8.0 connection from querying a table that is not there.

// CanManageRoles reports whether role membership can be read and edited here.
func (c *Connection) CanManageRoles() bool {
	_, ok := c.dialect.(RoleManager)
	return ok && c.dialect.Capabilities().SupportsRoles
}

// RoleMemberships lists the role→account edges, or nil when unsupported (not an
// error: the section simply does not render).
func (c *Connection) RoleMemberships(ctx context.Context) ([]model.RoleMembership, error) {
	if !c.CanManageRoles() {
		return nil, nil
	}
	m := c.dialect.(RoleManager)
	ctx, cancel := c.readCtx(ctx)
	defer cancel()
	return m.RoleMemberships(ctx, c.db)
}

// GrantRole runs GRANT <role> TO <account>.
func (c *Connection) GrantRole(ctx context.Context, g RoleGrant) error {
	if !c.CanManageRoles() {
		return ErrUnsupported
	}
	m := c.dialect.(RoleManager)
	return c.dclScript(ctx, func() ([]string, error) { return m.GrantRoleSQL(g) })
}

// RevokeRole runs REVOKE <role> FROM <account>.
func (c *Connection) RevokeRole(ctx context.Context, g RoleGrant) error {
	if !c.CanManageRoles() {
		return ErrUnsupported
	}
	m := c.dialect.(RoleManager)
	return c.dclScript(ctx, func() ([]string, error) { return m.RevokeRoleSQL(g) })
}

// ColumnGrantablePrivileges returns the privileges that accept a column list on
// this engine, or nil when column-scope grants are unsupported. A nil result is
// the signal the UI uses to hide the column control entirely.
func (c *Connection) ColumnGrantablePrivileges() []string {
	if m, ok := c.dialect.(ColumnPrivileger); ok {
		return m.ColumnGrantablePrivileges()
	}
	return nil
}

// checkColumnScope refuses a column-scoped spec the engine cannot express.
// Ignoring GrantSpec.Columns would not degrade the statement, it would BROADEN
// it — an operator asking for SELECT on one column would get SELECT on the
// whole table and be told it succeeded.
func (c *Connection) checkColumnScope(g GrantSpec) error {
	if len(g.Columns) == 0 {
		return nil
	}
	if _, ok := c.dialect.(ColumnPrivileger); !ok {
		return ErrUnsupported
	}
	return nil
}

// Grant runs a GRANT built from g.
func (c *Connection) Grant(ctx context.Context, g GrantSpec) error {
	m, ok := c.dialect.(PrivilegeManager)
	if !ok {
		return ErrUnsupported
	}
	if err := c.checkColumnScope(g); err != nil {
		return err
	}
	return c.dclScript(ctx, func() ([]string, error) { return m.GrantSQL(g) })
}

// Revoke runs a REVOKE built from g.
func (c *Connection) Revoke(ctx context.Context, g GrantSpec) error {
	m, ok := c.dialect.(PrivilegeManager)
	if !ok {
		return ErrUnsupported
	}
	if err := c.checkColumnScope(g); err != nil {
		return err
	}
	return c.dclScript(ctx, func() ([]string, error) { return m.RevokeSQL(g) })
}
