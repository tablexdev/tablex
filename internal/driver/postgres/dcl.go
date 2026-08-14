// UserManager / PrivilegeManager / RoleManager: role and privilege DDL
// (CREATE/ALTER/DROP ROLE, GRANT, REVOKE, role membership). PostgreSQL has no
// per-host user component, so the engine-neutral host argument is ignored
// throughout.

package postgres

import (
	"context"
	"database/sql"
	"errors"
	"slices"
	"strings"

	"github.com/tablexdev/tablex/internal/driver"
	"github.com/tablexdev/tablex/internal/model"
)

// roleRef renders a GRANT/REVOKE grantee: PUBLIC is the pseudo-role keyword
// (quoting it would target a role literally named PUBLIC, which cannot exist);
// everything else is a quoted identifier.
func (d dialect) roleRef(name string) string {
	if name == "PUBLIC" {
		return "PUBLIC"
	}
	return d.QuoteIdent(name)
}

// roleAttrs renders the role-attribute keywords from the spec's desired state.
// Both polarities are always emitted so ALTER ROLE applies exactly the form's
// checkbox state.
func roleAttrs(u driver.UserSpec) []string {
	pick := func(on bool, yes, no string) string {
		if on {
			return yes
		}
		return no
	}
	return []string{
		pick(u.CanLogin, "LOGIN", "NOLOGIN"),
		pick(u.Super, "SUPERUSER", "NOSUPERUSER"),
		pick(u.CreateDB, "CREATEDB", "NOCREATEDB"),
		pick(u.CreateRole, "CREATEROLE", "NOCREATEROLE"),
	}
}

// passwordOpt renders the PASSWORD option. A blank password becomes PASSWORD
// NULL (no password login) rather than the empty-string password.
func (d dialect) passwordOpt(pw string) string {
	if pw == "" {
		return "PASSWORD NULL"
	}
	return "PASSWORD " + d.QuoteString(pw)
}

func (d dialect) CreateUserSQL(u driver.UserSpec) ([]string, error) {
	opts := roleAttrs(u)
	if u.SetPassword {
		opts = append(opts, d.passwordOpt(u.Password))
	}
	return []string{"CREATE ROLE " + d.QuoteIdent(u.Name) + " WITH " + strings.Join(opts, " ")}, nil
}

// AlterUserSQL emits a password-only ALTER when SetPassword is set (so a
// password reset can never silently flip role attributes), and the full
// attribute state otherwise.
func (d dialect) AlterUserSQL(u driver.UserSpec) ([]string, error) {
	if u.SetPassword {
		return []string{"ALTER ROLE " + d.QuoteIdent(u.Name) + " WITH " + d.passwordOpt(u.Password)}, nil
	}
	return []string{"ALTER ROLE " + d.QuoteIdent(u.Name) + " WITH " + strings.Join(roleAttrs(u), " ")}, nil
}

// DropUserSQL drops a role. When the role still owns objects PostgreSQL fails
// with a dependency error (REASSIGN OWNED / DROP OWNED are out of scope for
// v1); the operator resolves ownership via the SQL console first.
func (d dialect) DropUserSQL(name, _ string) ([]string, error) {
	return []string{"DROP ROLE " + d.QuoteIdent(name)}, nil
}

// --- RoutinePrivileger (routine-scope grants) ------------------------------------

// pgRoutinePrivs: EXECUTE is the only privilege a PostgreSQL routine has.
var pgRoutinePrivs = []string{"EXECUTE"}

func (dialect) RoutineGrantablePrivileges() []string {
	return append([]string(nil), pgRoutinePrivs...)
}

// RoutinePrivileges reads pg_proc.proacl through aclexplode. The identity
// arguments are part of the WHERE clause, not decoration: overloads share a
// proname, and matching on the name alone would report one overload's grants as
// another's — and then revoke from the wrong one.
//
// acldefault('f', …) renders the built-in default (EXECUTE to PUBLIC) for a
// NULL acl, exactly as the relation branch does, so a routine nobody has
// touched does not read as "no access".
func (dialect) RoutinePrivileges(ctx context.Context, db *sql.DB, s driver.Scope, r model.Routine) ([]model.Privilege, error) {
	schema := schemaOfScope(s)
	rows, err := db.QueryContext(ctx, `
		SELECT COALESCE(rl.rolname, 'PUBLIC'), a.privilege_type, a.is_grantable
		FROM pg_catalog.pg_proc p
		JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
		CROSS JOIN LATERAL aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a
		LEFT JOIN pg_catalog.pg_roles rl ON rl.oid = a.grantee
		WHERE n.nspname = $1 AND p.proname = $2
		  AND pg_catalog.pg_get_function_identity_arguments(p.oid) = $3
		ORDER BY 1, 2`, schema, r.Name, r.ArgSignature)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	object := schema + "." + r.Name
	var out []model.Privilege
	for rows.Next() {
		p := model.Privilege{Object: object}
		if err := rows.Scan(&p.User, &p.Privilege, &p.Grantable); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// routineTarget renders the ON clause. The identity-argument list rides along
// verbatim — it is server-generated catalog text with its own quoting already
// applied, and a type list is not something this dialect could quote — which is
// the same contract DropRoutineSQL documents.
func (d dialect) routineTarget(g driver.RoutineGrant) string {
	return driver.RoutineKeyword(g.Routine) + " " +
		d.QuoteIdent(schemaOfScope(g.Scope)) + "." + d.QuoteIdent(g.Routine.Name) +
		"(" + g.Routine.ArgSignature + ")"
}

func (d dialect) GrantRoutineSQL(g driver.RoutineGrant) ([]string, error) {
	privs, err := driver.NormalizePrivileges(g.Privileges, func(p string) bool {
		return slices.Contains(pgRoutinePrivs, p)
	})
	if err != nil {
		return nil, err
	}
	if g.Grantee == "PUBLIC" && g.WithGrant {
		return nil, errors.New("PostgreSQL does not allow WITH GRANT OPTION for PUBLIC")
	}
	stmt := "GRANT " + strings.Join(privs, ", ") + " ON " + d.routineTarget(g) +
		" TO " + d.roleRef(g.Grantee)
	if g.WithGrant {
		stmt += " WITH GRANT OPTION"
	}
	return []string{stmt}, nil
}

func (d dialect) RevokeRoutineSQL(g driver.RoutineGrant) ([]string, error) {
	privs, err := driver.NormalizePrivileges(g.Privileges, driver.ValidPrivilegeKeyword)
	if err != nil {
		return nil, err
	}
	return []string{"REVOKE " + strings.Join(privs, ", ") + " ON " + d.routineTarget(g) +
		" FROM " + d.roleRef(g.Grantee)}, nil
}

// --- RoleManager (role membership) ---------------------------------------------
//
// PostgreSQL draws no line between "user" and "role": every role can be granted
// to any other, so the grantable-role list is simply every account. There is no
// host component, so RoleGrant's two host fields are ignored throughout.

// RoleMemberships reads pg_auth_members — the direct memberships, which is what
// a REVOKE can remove. (pg_has_role() would fold in transitive membership and
// report edges that do not exist.)
func (dialect) RoleMemberships(ctx context.Context, db *sql.DB) ([]model.RoleMembership, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT r.rolname, m.rolname, am.admin_option
		FROM pg_catalog.pg_auth_members am
		JOIN pg_catalog.pg_roles r ON r.oid = am.roleid
		JOIN pg_catalog.pg_roles m ON m.oid = am.member
		ORDER BY 1, 2`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.RoleMembership
	for rows.Next() {
		var m model.RoleMembership
		if err := rows.Scan(&m.Role, &m.Member, &m.AdminOption); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// checkRoleGrant rejects the shapes PostgreSQL has no statement for. PUBLIC is
// the notable one: it is a valid grantee for object privileges (and roleRef
// emits it as the bare keyword there), but it is not a role, so it can neither
// be granted to nor granted away — quoting it here would target a role that
// cannot exist.
func checkRoleGrant(g driver.RoleGrant) error {
	if g.Role == "" || g.Member == "" {
		return errors.New("a role grant needs both a role and a member")
	}
	if g.Role == "PUBLIC" || g.Member == "PUBLIC" {
		return errors.New("PUBLIC is not a role and cannot take part in a role membership")
	}
	return nil
}

func (d dialect) GrantRoleSQL(g driver.RoleGrant) ([]string, error) {
	if err := checkRoleGrant(g); err != nil {
		return nil, err
	}
	stmt := "GRANT " + d.QuoteIdent(g.Role) + " TO " + d.QuoteIdent(g.Member)
	if g.AdminOption {
		stmt += " WITH ADMIN OPTION"
	}
	return []string{stmt}, nil
}

func (d dialect) RevokeRoleSQL(g driver.RoleGrant) ([]string, error) {
	if err := checkRoleGrant(g); err != nil {
		return nil, err
	}
	return []string{"REVOKE " + d.QuoteIdent(g.Role) + " FROM " + d.QuoteIdent(g.Member)}, nil
}

// pgTablePrivs / pgDBPrivs are the grant allowlists, curated from the
// PostgreSQL GRANT syntax documentation. Version-specific
// table privileges (e.g. PG 17 MAINTAIN) are deliberately absent: they stay
// revokable through the introspection-driven revoke path without being offered
// on every server version.
var (
	pgTablePrivs = []string{
		"SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES",
		"TRIGGER", "ALL",
	}
	pgDBPrivs = []string{"CONNECT", "CREATE", "TEMPORARY"}
	// pgColumnPrivs is the subset that accepts a column list. PostgreSQL also
	// accepts ALL (col) — expanding to exactly these four — but offering it
	// would put a keyword in the form that the grant listing then never shows
	// back (the ACL stores the four), so the curated set stays explicit.
	pgColumnPrivs = []string{"SELECT", "INSERT", "UPDATE", "REFERENCES"}
)

func (dialect) GrantablePrivileges(table bool) []string {
	if table {
		return append([]string(nil), pgTablePrivs...)
	}
	return append([]string(nil), pgDBPrivs...)
}

func (dialect) ColumnGrantablePrivileges() []string {
	return append([]string(nil), pgColumnPrivs...)
}

// grantTarget renders the ON clause object: DATABASE db or TABLE schema.table.
func (d dialect) grantTarget(g driver.GrantSpec) string {
	if g.Table != "" {
		return "TABLE " + d.QuoteIdent(schemaOrPublic(g.Schema)) + "." + d.QuoteIdent(g.Table)
	}
	return "DATABASE " + d.QuoteIdent(g.Database)
}

func (d dialect) GrantSQL(g driver.GrantSpec) ([]string, error) {
	allowed := d.GrantablePrivileges(g.Table != "")
	privs, err := driver.NormalizePrivileges(g.Privileges, func(p string) bool { return slices.Contains(allowed, p) })
	if err != nil {
		return nil, err
	}
	if err := driver.CheckColumnScope(g, privs, true, pgColumnPrivs); err != nil {
		return nil, err
	}
	if g.Grantee == "PUBLIC" && g.WithGrant {
		// "Grant options cannot be granted to PUBLIC" — PostgreSQL GRANT reference.
		return nil, errors.New("PostgreSQL does not allow WITH GRANT OPTION for PUBLIC")
	}
	stmt := "GRANT " + driver.PrivilegeList(privs, g.Columns, d.QuoteIdent) + " ON " + d.grantTarget(g) +
		" TO " + d.roleRef(g.Grantee)
	if g.WithGrant {
		stmt += " WITH GRANT OPTION"
	}
	return []string{stmt}, nil
}

// RevokeSQL accepts any privilege keyword shape (the handler validates
// membership against the freshly introspected grants, which keeps
// version-specific keywords like MAINTAIN revokable). Revoking a privilege
// also removes its grant option (PostgreSQL ACL entries are per-privilege).
func (d dialect) RevokeSQL(g driver.GrantSpec) ([]string, error) {
	privs, err := driver.NormalizePrivileges(g.Privileges, driver.ValidPrivilegeKeyword)
	if err != nil {
		return nil, err
	}
	if err := driver.CheckColumnScope(g, privs, false, pgColumnPrivs); err != nil {
		return nil, err
	}
	return []string{"REVOKE " + driver.PrivilegeList(privs, g.Columns, d.QuoteIdent) + " ON " + d.grantTarget(g) +
		" FROM " + d.roleRef(g.Grantee)}, nil
}
