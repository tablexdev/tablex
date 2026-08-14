// Package model defines TableX's engine-neutral domain types.
//
// These types describe databases, schemas, tables, columns and related
// metadata in a way that does not depend on any particular SQL engine. The
// driver layer (see internal/driver) populates them from engine-specific
// introspection; handlers and templates consume them without ever importing a
// concrete driver. Keeping this package dependency-free (it imports only the
// standard library) is what lets "support all databases" stay a one-interface
// problem rather than a scattered set of engine branches.
package model

import (
	"strconv"
	"time"
)

// Database is a top-level container of tables. Its exact meaning depends on the
// engine: a MySQL "database" (schema in MySQL parlance), a PostgreSQL database,
// or SQLite's main file. For engines with a schema level (PostgreSQL) the
// schemas hang under the database; otherwise tables hang directly under it.
type Database struct {
	Name      string
	Collation string
	// TableCount is the number of relations the database structure page lists
	// — tables and views, excluding the kinds that page skips (MariaDB
	// SEQUENCE objects). Defining it as "what you will see when you click
	// through" is what keeps it comparable across engines: MySQL used to count
	// sequences too, and SQLite used to omit views.
	TableCount int   // -1 when unknown / not yet counted
	Size       int64 // total size in bytes; -1 when unknown
	IsSystem   bool  // information_schema, pg_catalog, mysql, etc.
}

// Schema is the optional level between Database and Table. Only engines whose
// Capabilities report HasSchemas (PostgreSQL) produce these.
type Schema struct {
	Name     string
	Owner    string
	IsSystem bool
}

// TableType distinguishes ordinary tables from views and other relation kinds.
type TableType string

const (
	TableBase     TableType = "table"
	TableView     TableType = "view"
	TableMatView  TableType = "matview"
	TableSystem   TableType = "system"
	TableSequence TableType = "sequence" // MariaDB SEQUENCE object (not a browsable data table)
	// TableForeign is a PostgreSQL FOREIGN TABLE, resolved ONLY by the
	// SQL-export foreign resolver — foreign tables never enter
	// ListTables/ListTableNames (no browsing, no CSV/JSON, no data pass; their
	// rows live on the remote server). The explicit discriminator — not
	// incidental routing — is what provably keeps them out of the data pass.
	TableForeign TableType = "foreign"
)

// Table describes a table or view. Schema is empty for engines without a schema
// level. Numeric stats are best-effort: -1 means "unknown" (e.g. views, or
// engines that do not expose a cheap row estimate).
type Table struct {
	Name      string
	Schema    string
	Type      TableType
	Engine    string // MySQL storage engine (InnoDB, MyISAM, …); empty otherwise
	Rows      int64  // estimated row count; -1 when unknown
	DataSize  int64  // data bytes; -1 when unknown
	IndexSize int64  // index bytes; -1 when unknown
	Size      int64  // total bytes (data+index); -1 when unknown
	Collation string
	Comment   string
	Created   *time.Time
	Updated   *time.Time
}

// IsView reports whether the table is a (materialized) view.
func (t Table) IsView() bool { return t.Type == TableView || t.Type == TableMatView }

// IsSequence reports whether the table is a MariaDB SEQUENCE object. Sequences
// are dumped like tables (SHOW CREATE TABLE + the single state row restores
// nextval() state, matching mariadb-dump), but they are not browsable data
// tables: the UI listings skip them and the table-scoped routes reject them
// (export excepted).
func (t Table) IsSequence() bool { return t.Type == TableSequence }

// Column.Identity values — the engine-neutral spelling of a native identity
// column's mode (PostgreSQL GENERATED { ALWAYS | BY DEFAULT } AS IDENTITY).
const (
	IdentityAlways    = "always"
	IdentityByDefault = "default"
)

// Column describes a single column of a table.
type Column struct {
	Name string
	// Position is the column's 1-based ordinal in the table's column list, and
	// is CONTIGUOUS on every engine. PostgreSQL's catalog attnum is not: it
	// leaves gaps behind a dropped column, which the structure page rendered
	// raw as 1, 2, 4, 5. The dialect renumbers.
	Position        int
	DataType        string // full engine type, e.g. "varchar(255)", "int unsigned", "numeric(10,2)"
	BaseType        string // bare type name, e.g. "varchar", "int", "numeric" (lower-cased)
	Nullable        bool
	Default         *string // nil = no default; *"" = empty string default
	DefaultIsExpr   bool    // Default is an expression/SQL fragment, not a bare literal value
	DefaultIsNull   bool    // Default is the explicit keyword NULL (DEFAULT NULL), never the literal string 'NULL'
	IsPrimaryKey    bool
	IsAutoIncrement bool
	IsGenerated     bool
	GeneratedKind   string // "stored" or "virtual" for generated columns; "" otherwise
	GeneratedExpr   string // generation expression (no surrounding parens) for a generated column; "" if not generated or unknown
	// Identity is a native identity column's mode: IdentityAlways,
	// IdentityByDefault, or "" for an ordinary column. It is a typed field
	// rather than a magic value inside Extra because ENGINE-NEUTRAL code
	// branches on it: a SQL dump must emit OVERRIDING SYSTEM VALUE for an
	// always-identity column, and the column editor must not emit
	// DROP/SET DEFAULT on any identity column.
	Identity string
	// OnUpdate is the column's automatic-update expression, already normalized
	// by the dialect (MySQL "CURRENT_TIMESTAMP" / "CURRENT_TIMESTAMP(3)"); ""
	// when there is none. Typed for the same reason as Identity: the column
	// editor has to preserve it, and it must not do so by running a
	// MySQL-shaped regex over every engine's Extra.
	OnUpdate string
	// Extra is engine free-text shown verbatim in the structure page's Extra
	// cell ("auto_increment", "on update CURRENT_TIMESTAMP", …). Nothing may
	// branch on its contents — that is what the typed fields above are for.
	Extra     string
	Comment   string
	Collation string
	// CollationSchema is the collation's namespace (PostgreSQL) when Collation is
	// a non-default collation the column DDL must emit as COLLATE; "" otherwise.
	CollationSchema string
	Charset         string
}

// ExtraDisplay renders the structure page's "Extra" cell. Identity used to be
// written into Extra by the PostgreSQL dialect, which is why that cell showed
// it; now that Identity is typed, the display is rebuilt here rather than the
// cell silently going blank. The wording is unchanged from what it replaced.
func (c Column) ExtraDisplay() string {
	var identity string
	switch c.Identity {
	case IdentityAlways:
		identity = "identity always"
	case IdentityByDefault:
		identity = "identity"
	}
	switch {
	case identity == "":
		return c.Extra
	case c.Extra == "":
		return identity
	default:
		return c.Extra + " " + identity
	}
}

// IsNumeric reports whether the column holds a numeric type (drives right
// alignment in the browse grid). The PostgreSQL-spelled aliases
// (int2/int4/int8, float4/float8, serial…) are NOT dead: SQLite preserves the
// declared base-type name verbatim via BaseTypeName (sqlite.go), so a
// `CREATE TABLE t(x INT4)` reaches here with BaseType "int4". The near-identical
// integer/float list in the editor's coerceValue is deliberately kept separate,
// not merged — see the note there.
func (c Column) IsNumeric() bool {
	switch c.BaseType {
	case "tinyint", "smallint", "mediumint", "int", "integer", "bigint",
		"decimal", "numeric", "float", "double", "real", "dec", "fixed",
		"int2", "int4", "int8", "serial", "bigserial", "smallserial",
		"float4", "float8", "money", "double precision":
		return true
	}
	return false
}

// IndexColumn is one column participating in an index, in order.
type IndexColumn struct {
	Name       string
	Expr       string // expression index body (when not a plain column)
	Descending bool   // sorted DESC (default is ASC)
	// Prefix is the number of leading characters indexed, for engines with
	// prefix indexes (MySQL's col(10)). Zero means the whole value, which is
	// every key part on every other engine.
	Prefix int
}

// Index describes an index on a table.
type Index struct {
	Name      string
	Columns   []IndexColumn
	Unique    bool
	Primary   bool
	Type      string // BTREE, HASH, GIN, … (engine-dependent)
	Predicate string // partial-index WHERE expression; "" for a full index
}

// ColumnNames returns the index's column names in order.
func (i Index) ColumnNames() []string {
	names := make([]string, 0, len(i.Columns))
	for _, c := range i.Columns {
		if c.Expr != "" {
			names = append(names, c.Expr)
		} else {
			names = append(names, c.Name)
		}
	}
	return names
}

// ColumnDisplay is ColumnNames with each key part's prefix length and sort
// direction, for the structure grid (both are shown there). A prefix is part
// of the key's identity — an index on tag(8) is not an index on tag — so
// rendering the bare name would misreport what the index covers.
func (i Index) ColumnDisplay() []string {
	names := i.ColumnNames()
	for j, c := range i.Columns {
		if c.Prefix > 0 {
			names[j] += "(" + strconv.Itoa(c.Prefix) + ")"
		}
		if c.Descending {
			names[j] += " DESC"
		}
	}
	return names
}

// ForeignKey describes a foreign-key constraint.
type ForeignKey struct {
	Name       string
	Columns    []string
	RefSchema  string
	RefTable   string
	RefColumns []string
	OnUpdate   string
	OnDelete   string

	// Synthetic marks a Name the dialect INVENTED because the engine does not
	// name the constraint (SQLite's PRAGMA foreign_key_list has no name column,
	// so the key is identified only by its ordinal). Such a name exists nowhere
	// in the schema: no statement can reference it, and presenting it like a
	// real constraint name misleads. The UI labels it; nothing may emit it into
	// SQL.
	Synthetic bool
}

// View captures view-specific metadata (definition SQL).
type View struct {
	Name       string
	Definition string
}

// Routine is a stored procedure or function.
type Routine struct {
	Name       string
	Type       string // "PROCEDURE" or "FUNCTION"
	ReturnType string
	Definition string
	Language   string
	Comment    string

	// ArgSignature is the engine's identity argument list ("a integer, b text"),
	// populated only by engines that allow overloading and therefore cannot
	// identify a routine by name alone — PostgreSQL, where DROP FUNCTION f fails
	// with "is not unique" whenever more than one f exists. Empty elsewhere
	// (MySQL routine names are unique within a database), and empty for a
	// zero-argument routine, which is why it renders as an empty pair of
	// parentheses rather than being omitted.
	ArgSignature string
}

// Trigger describes a table trigger.
type Trigger struct {
	Name       string
	Table      string
	Timing     string // BEFORE / AFTER / INSTEAD OF
	Event      string // INSERT / UPDATE / DELETE
	Definition string
}

// Event is a MySQL/MariaDB scheduled event.
type Event struct {
	Name       string
	Type       string // ONE TIME / RECURRING
	Status     string
	ExecuteAt  string
	Interval   string
	Definition string
}

// User describes a database account/role for the privileges screens.
type User struct {
	Name       string
	Host       string // MySQL user host part; empty for role-based engines
	CanLogin   bool
	IsSuper    bool
	Attributes string // e.g. "Superuser, Create DB" (PostgreSQL); free text
}

// RoleMembership is one "role granted to account" edge — GRANT r TO u, the
// membership that makes u inherit r's privileges.
//
// Both ends carry a host part because MySQL 8 roles ARE accounts and are
// addressed as 'role'@'host'. MariaDB roles have no host (they live in
// mysql.user with an empty Host), and PostgreSQL has no host component at all,
// so both leave RoleHost/MemberHost empty and their builders ignore them.
type RoleMembership struct {
	Role       string
	RoleHost   string
	Member     string
	MemberHost string
	// AdminOption: the member may grant this role onward.
	AdminOption bool
}

// Privilege is a single granted privilege row.
type Privilege struct {
	User      string
	Host      string
	Object    string // database/table name when scoped
	Privilege string
	Grantable bool
	// Column names the single column this grant is restricted to, and is empty
	// for an object-wide grant. It is part of the grant's IDENTITY, not a
	// display detail: SELECT on one column and SELECT on the whole table are
	// two different grants that can coexist, and a revoke that dropped the
	// column would remove the wrong one (widening, not narrowing, the account's
	// reach).
	Column string
	// StoredObject is the object pattern exactly as the grant tables store it
	// (MySQL database scope only; empty elsewhere). MySQL matches REVOKE
	// targets by the exact stored pattern string — raw for externally-created
	// grants, LIKE-escaped for TableX's own — so the revoke path must reuse
	// this verbatim instead of re-escaping the database name.
	StoredObject string
}

// Variable is a server status counter or configuration setting (name/value).
type Variable struct {
	Name  string
	Value string
}
