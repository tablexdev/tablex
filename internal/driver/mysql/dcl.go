package mysql

import (
	"context"
	"database/sql"
	"errors"
	"slices"
	"strings"

	"github.com/tablexdev/tablex/internal/driver"
	"github.com/tablexdev/tablex/internal/model"
)

// --- UserManager / PrivilegeManager (DCL) ----------------------------------------

func (d dialect) CreateUserSQL(u driver.UserSpec) ([]string, error) {
	stmt := "CREATE USER " + d.accountRef(u.Name, u.Host)
	if u.SetPassword {
		stmt += " IDENTIFIED BY " + d.QuoteString(u.Password)
	}
	return []string{stmt}, nil
}

// AlterUserSQL supports setting the password; MySQL has no role attributes.
func (d dialect) AlterUserSQL(u driver.UserSpec) ([]string, error) {
	if !u.SetPassword {
		return nil, errors.New("no account changes requested")
	}
	return []string{"ALTER USER " + d.accountRef(u.Name, u.Host) +
		" IDENTIFIED BY " + d.QuoteString(u.Password)}, nil
}

func (d dialect) DropUserSQL(name, host string) ([]string, error) {
	return []string{"DROP USER " + d.accountRef(name, host)}, nil
}

// mysqlTablePrivs are grantable at both database and table scope;
// mysqlDBOnlyPrivs only at database scope. Curated from the MySQL/MariaDB GRANT
// syntax documentation: routine/event/temp-table/lock privileges have no
// table-level form.
var (
	mysqlTablePrivs = []string{
		"SELECT", "INSERT", "UPDATE", "DELETE", "CREATE", "DROP", "ALTER",
		"INDEX", "REFERENCES", "CREATE VIEW", "SHOW VIEW", "TRIGGER",
		"ALL PRIVILEGES",
	}
	mysqlDBOnlyPrivs = []string{
		"CREATE ROUTINE", "ALTER ROUTINE", "EXECUTE", "EVENT",
		"CREATE TEMPORARY TABLES", "LOCK TABLES",
	}
)

func (d dialect) GrantablePrivileges(table bool) []string {
	out := append([]string(nil), mysqlTablePrivs...)
	if !table {
		out = append(out, mysqlDBOnlyPrivs...)
	}
	// DELETE HISTORY (system-versioned tables) is a MariaDB-only privilege
	// (>= 10.3.4), grantable at both database and table scope.
	if d.isMariaDBFlavor() && d.atLeast(10, 3, 4) {
		out = append(out, "DELETE HISTORY")
	}
	return out
}

// grantTarget renders the ON clause object: db.* for database scope, db.table
// for table scope. The database-scope name is LIKE-pattern-escaped (see
// escapeGrantDatabasePattern); the table-scope name and table are literal.
func (d dialect) grantTarget(g driver.GrantSpec) string {
	if g.Table != "" {
		return d.QuoteIdent(g.Database) + "." + d.QuoteIdent(g.Table)
	}
	return d.QuoteIdent(escapeGrantDatabasePattern(g.Database)) + ".*"
}

// mysqlColumnPrivs is the subset of the table allowlist MySQL accepts a column
// list for. The GRANT grammar admits a column list only where a privilege is
// checked per column value; DELETE (col) and the rest are syntax errors, not
// narrower grants.
var mysqlColumnPrivs = []string{"SELECT", "INSERT", "UPDATE", "REFERENCES"}

func (dialect) ColumnGrantablePrivileges() []string {
	return append([]string(nil), mysqlColumnPrivs...)
}

func (d dialect) GrantSQL(g driver.GrantSpec) ([]string, error) {
	allowed := d.GrantablePrivileges(g.Table != "")
	privs, err := driver.NormalizePrivileges(g.Privileges, func(p string) bool { return slices.Contains(allowed, p) })
	if err != nil {
		return nil, err
	}
	if err := driver.CheckColumnScope(g, privs, true, mysqlColumnPrivs); err != nil {
		return nil, err
	}
	stmt := "GRANT " + driver.PrivilegeList(privs, g.Columns, d.QuoteIdent) + " ON " + d.grantTarget(g) +
		" TO " + d.accountRef(g.Grantee, g.Host)
	if g.WithGrant {
		stmt += " WITH GRANT OPTION"
	}
	return []string{stmt}, nil
}

// RevokeSQL accepts any privilege keyword shape (the handler validates
// membership against the freshly introspected grants — version-specific
// keywords outside the grant allowlist must stay revokable). Note MySQL keeps
// GRANT OPTION as a separate level-wide flag: revoking a privilege leaves it in
// place (inert once no privileges remain); grant-option-only revoke is
// deliberately out of scope.
func (d dialect) RevokeSQL(g driver.GrantSpec) ([]string, error) {
	privs, err := driver.NormalizePrivileges(g.Privileges, driver.ValidPrivilegeKeyword)
	if err != nil {
		return nil, err
	}
	if err := driver.CheckColumnScope(g, privs, false, mysqlColumnPrivs); err != nil {
		return nil, err
	}
	joined := driver.PrivilegeList(privs, g.Columns, d.QuoteIdent)
	// MySQL matches REVOKE targets by the exact stored pattern string, so when
	// the introspection supplied the stored pattern(s) — raw for an
	// externally-created grant on a _/%-named database, LIKE-escaped for
	// TableX's own — emit one REVOKE per pattern verbatim; re-escaping here
	// would miss the raw-stored row ("There is no such grant defined").
	if g.Table == "" && len(g.DatabasePatterns) > 0 {
		out := make([]string, 0, len(g.DatabasePatterns))
		for _, pat := range g.DatabasePatterns {
			out = append(out, "REVOKE "+joined+" ON "+d.QuoteIdent(pat)+".*"+
				" FROM "+d.accountRef(g.Grantee, g.Host))
		}
		return out, nil
	}
	return []string{"REVOKE " + joined + " ON " + d.grantTarget(g) +
		" FROM " + d.accountRef(g.Grantee, g.Host)}, nil
}

// --- RoutinePrivileger (routine-scope grants) ------------------------------------

// mysqlRoutinePrivs is the routine-scope allowlist. GRANT OPTION is deliberately
// absent: MySQL stores it in the same Proc_priv set but it is the WITH GRANT
// OPTION flag, surfaced as model.Privilege.Grantable rather than as a privilege
// of its own.
var mysqlRoutinePrivs = []string{"EXECUTE", "ALTER ROUTINE"}

func (dialect) RoutineGrantablePrivileges() []string {
	return append([]string(nil), mysqlRoutinePrivs...)
}

// RoutinePrivileges reads mysql.procs_priv, which is where routine grants live —
// information_schema has no view of them. Proc_priv is a SET column whose
// members are the granted privileges plus, when present, the 'Grant' flag; the
// flag becomes Grantable rather than a privilege row, so the revoke path never
// offers to revoke it as one.
func (d dialect) RoutinePrivileges(ctx context.Context, db *sql.DB, s driver.Scope, r model.Routine) ([]model.Privilege, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT User, Host, Proc_priv
		FROM mysql.procs_priv
		WHERE Db = ? AND Routine_name = ? AND Routine_type = ?
		ORDER BY User, Host`, s.Database, r.Name, driver.RoutineKeyword(r))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	object := s.Database + "." + r.Name
	var out []model.Privilege
	for rows.Next() {
		var user, host, set string
		if err := rows.Scan(&user, &host, &set); err != nil {
			return nil, err
		}
		var privs []string
		grantable := false
		for _, p := range strings.Split(set, ",") {
			p = strings.ToUpper(strings.TrimSpace(p))
			switch p {
			case "":
			case "GRANT":
				grantable = true
			default:
				privs = append(privs, p)
			}
		}
		for _, p := range privs {
			out = append(out, model.Privilege{
				User: user, Host: host, Object: object,
				Privilege: p, Grantable: grantable,
			})
		}
	}
	return out, rows.Err()
}

// routineTarget renders the ON clause. Both name parts are literal here (unlike
// the database-scope table target, which is a LIKE pattern), so neither is
// escaped.
func (d dialect) routineTarget(g driver.RoutineGrant) string {
	return driver.RoutineKeyword(g.Routine) + " " +
		d.QuoteIdent(g.Scope.Database) + "." + d.QuoteIdent(g.Routine.Name)
}

func (d dialect) GrantRoutineSQL(g driver.RoutineGrant) ([]string, error) {
	privs, err := driver.NormalizePrivileges(g.Privileges, func(p string) bool {
		return slices.Contains(mysqlRoutinePrivs, p)
	})
	if err != nil {
		return nil, err
	}
	stmt := "GRANT " + strings.Join(privs, ", ") + " ON " + d.routineTarget(g) +
		" TO " + d.accountRef(g.Grantee, g.Host)
	if g.WithGrant {
		stmt += " WITH GRANT OPTION"
	}
	return []string{stmt}, nil
}

// RevokeRoutineSQL keeps the looser keyword rule the other revoke builders have:
// the handler authorizes it from the introspected grant, not from the allowlist.
func (d dialect) RevokeRoutineSQL(g driver.RoutineGrant) ([]string, error) {
	privs, err := driver.NormalizePrivileges(g.Privileges, driver.ValidPrivilegeKeyword)
	if err != nil {
		return nil, err
	}
	return []string{"REVOKE " + strings.Join(privs, ", ") + " ON " + d.routineTarget(g) +
		" FROM " + d.accountRef(g.Grantee, g.Host)}, nil
}

// --- RoleManager (role membership) ---------------------------------------------
//
// The two flavors disagree on everything here except the idea. MySQL 8 roles
// ARE accounts, addressed as 'role'@'host' and edged in mysql.role_edges;
// MariaDB roles are a distinct kind of mysql.user row with an EMPTY host,
// addressed by bare name and edged in mysql.roles_mapping. One dialect, two
// catalogs, two statement shapes — which is exactly why the host fields on
// model.RoleMembership and driver.RoleGrant are optional rather than assumed.

// supportsRoles gates every role path on the connected server. It fails CLOSED
// on an unknown version (atLeast is false when the version never parsed):
// before MySQL 8.0 / MariaDB 10.0.5 the catalog table does not exist, so a
// wrong "yes" turns the Users page into an error instead of hiding a section.
func (d dialect) supportsRoles() bool {
	if d.isMariaDBFlavor() {
		return d.atLeast(10, 0, 5)
	}
	return d.atLeast(8, 0, 0)
}

func (d dialect) RoleMemberships(ctx context.Context, db *sql.DB) ([]model.RoleMembership, error) {
	query := `
		SELECT FROM_USER, FROM_HOST, TO_USER, TO_HOST, WITH_ADMIN_OPTION
		FROM mysql.role_edges
		ORDER BY FROM_USER, FROM_HOST, TO_USER, TO_HOST`
	if d.isMariaDBFlavor() {
		// A MariaDB role has no host, so the role side is a constant blank
		// rather than a column — keeping the scan shape identical.
		query = `
			SELECT Role, '', User, Host, Admin_option
			FROM mysql.roles_mapping
			ORDER BY Role, User, Host`
	}
	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.RoleMembership
	for rows.Next() {
		var m model.RoleMembership
		var admin string
		if err := rows.Scan(&m.Role, &m.RoleHost, &m.Member, &m.MemberHost, &admin); err != nil {
			return nil, err
		}
		m.AdminOption = strings.EqualFold(admin, "Y")
		out = append(out, m)
	}
	return out, rows.Err()
}

// roleRef renders the role side of a role grant. MySQL 8 needs the full account
// reference because its roles are accounts and 'r'@'%' is a different role from
// 'r'@'localhost'; MariaDB takes the bare name as a string literal (verified
// against 11.4: a quoted name, embedded quote and all, is accepted).
func (d dialect) roleRef(g driver.RoleGrant) string {
	if d.isMariaDBFlavor() {
		return d.QuoteString(g.Role)
	}
	return d.accountRef(g.Role, g.RoleHost)
}

// checkRoleGrant re-checks inside the builder what the handler already checked:
// both ends must be named, and the server must be one that has roles at all.
func (d dialect) checkRoleGrant(g driver.RoleGrant) error {
	if !d.supportsRoles() {
		return errors.New("this server version has no roles")
	}
	if g.Role == "" || g.Member == "" {
		return errors.New("a role grant needs both a role and a member")
	}
	return nil
}

func (d dialect) GrantRoleSQL(g driver.RoleGrant) ([]string, error) {
	if err := d.checkRoleGrant(g); err != nil {
		return nil, err
	}
	stmt := "GRANT " + d.roleRef(g) + " TO " + d.accountRef(g.Member, g.MemberHost)
	if g.AdminOption {
		stmt += " WITH ADMIN OPTION"
	}
	return []string{stmt}, nil
}

func (d dialect) RevokeRoleSQL(g driver.RoleGrant) ([]string, error) {
	if err := d.checkRoleGrant(g); err != nil {
		return nil, err
	}
	return []string{"REVOKE " + d.roleRef(g) + " FROM " + d.accountRef(g.Member, g.MemberHost)}, nil
}
