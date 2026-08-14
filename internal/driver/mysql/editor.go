package mysql

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/tablexdev/tablex/internal/driver"
	"github.com/tablexdev/tablex/internal/model"
)

// --- SchemaEditor (DDL) ---------------------------------------------------------

func (dialect) ColumnTypes() []string {
	return []string{
		"INT", "TINYINT", "SMALLINT", "MEDIUMINT", "BIGINT",
		"DECIMAL", "FLOAT", "DOUBLE", "BIT",
		"CHAR", "VARCHAR", "TINYTEXT", "TEXT", "MEDIUMTEXT", "LONGTEXT",
		"DATE", "DATETIME", "TIMESTAMP", "TIME", "YEAR",
		"BINARY", "VARBINARY", "TINYBLOB", "BLOB", "MEDIUMBLOB", "LONGBLOB",
		"ENUM", "SET", "JSON",
	}
}

// ValueListTypes: MySQL's two list-valued types. Spelled as ColumnTypes() does,
// because that is what the form submits and what the handler compares against.
func (dialect) ValueListTypes() []string { return []string{"ENUM", "SET"} }

// setMaxMembers is SET's hard limit; ENUM's (65535) is high enough that the
// server's own error is the better message.
const setMaxMembers = 64

// ValueListType builds ENUM('a','b') / SET('a','b'). Every value goes through
// QuoteString — these are the user's own strings, and no allowlist can exist
// for them — so a value containing a quote, a backslash or a newline is escaped
// rather than closing the literal. Duplicates are rejected here because MySQL's
// own error names only the position, and a duplicate is always a mistake.
func (d dialect) ValueListType(base string, values []string) (string, error) {
	base = strings.ToUpper(strings.TrimSpace(base))
	if base != "ENUM" && base != "SET" {
		return "", fmt.Errorf("%s does not take a value list", base)
	}
	if len(values) == 0 {
		return "", errors.New("an ENUM/SET needs at least one value")
	}
	if base == "SET" && len(values) > setMaxMembers {
		return "", fmt.Errorf("a SET holds at most %d values, got %d", setMaxMembers, len(values))
	}
	seen := make(map[string]bool, len(values))
	quoted := make([]string, 0, len(values))
	for _, v := range values {
		// A NUL has no literal spelling under NO_BACKSLASH_ESCAPES, so
		// QuoteString splices it in with CONCAT(…, CHAR(0), …) — an expression,
		// which is valid where a value goes but NOT where a type's member list
		// does. Refuse it here rather than emit a type definition that cannot
		// parse.
		if strings.ContainsRune(v, 0) {
			return "", errors.New("an ENUM/SET value cannot contain a NUL byte")
		}
		// MySQL compares ENUM/SET members case-insensitively under the usual
		// collations, so "a" and "A" collide as surely as two "a"s.
		k := strings.ToLower(v)
		if seen[k] {
			return "", fmt.Errorf("duplicate value %q", v)
		}
		seen[k] = true
		quoted = append(quoted, d.QuoteString(v))
	}
	return base + "(" + strings.Join(quoted, ",") + ")", nil
}

// Type-category sets for columnDef: each preserved attribute is only valid on
// some types, and MODIFY COLUMN with an attribute the new type cannot carry is
// a hard MySQL syntax error (e.g. INT CHARACTER SET utf8mb4), which previously
// made every cross-category type change fail.
var (
	mysqlUnsignedTypes = map[string]bool{
		"tinyint": true, "smallint": true, "mediumint": true, "int": true,
		"integer": true, "bigint": true, "decimal": true, "numeric": true,
		"float": true, "double": true, "real": true,
	}
	// AUTO_INCREMENT is valid on integer types. Floating-point AUTO_INCREMENT was
	// removed in MySQL 8.4 (ERROR 1063) and is pathological even where still
	// accepted (MariaDB / MySQL <= 8.3), so it is intentionally excluded.
	mysqlAutoIncTypes = map[string]bool{
		"tinyint": true, "smallint": true, "mediumint": true, "int": true,
		"integer": true, "bigint": true,
	}
	mysqlCharsetTypes = map[string]bool{
		"char": true, "varchar": true, "tinytext": true, "text": true,
		"mediumtext": true, "longtext": true, "enum": true, "set": true,
	}
	mysqlOnUpdateTypes = map[string]bool{"timestamp": true, "datetime": true}
)

// columnDef renders a column definition shared by ADD COLUMN and MODIFY COLUMN.
// MODIFY COLUMN restates the whole column, so attributes the handler preserved
// (unsigned/zerofill, charset/collation, ON UPDATE, AUTO_INCREMENT) are emitted
// here to avoid silently dropping them; the ADD path leaves those spec fields
// zero. Each attribute is emitted only when valid for the (possibly new) type
// category, so changing an INT UNSIGNED to VARCHAR drops UNSIGNED instead of
// producing invalid DDL. Clause order follows the MySQL column_definition
// grammar.
func (d dialect) columnDef(c driver.ColumnSpec) string {
	base := driver.BaseTypeName(c.Type)
	var b strings.Builder
	b.WriteString(d.QuoteIdent(c.Name))
	b.WriteByte(' ')
	b.WriteString(c.Type)
	if c.Unsigned && mysqlUnsignedTypes[base] {
		b.WriteString(" UNSIGNED")
	}
	if c.Zerofill && mysqlUnsignedTypes[base] {
		b.WriteString(" ZEROFILL")
	}
	if mysqlCharsetTypes[base] {
		if c.Charset != "" {
			b.WriteString(" CHARACTER SET ")
			b.WriteString(c.Charset)
		}
		if c.Collation != "" {
			b.WriteString(" COLLATE ")
			b.WriteString(c.Collation)
		}
	}
	if c.Nullable {
		b.WriteString(" NULL")
	} else {
		b.WriteString(" NOT NULL")
	}
	if c.Default != nil {
		b.WriteString(" DEFAULT ")
		b.WriteString(defaultClause(*c.Default, c.DefaultExpr))
	}
	if c.OnUpdate != "" && mysqlOnUpdateTypes[base] {
		b.WriteString(" ON UPDATE ")
		b.WriteString(c.OnUpdate)
	}
	if c.AutoIncrement && mysqlAutoIncTypes[base] {
		b.WriteString(" AUTO_INCREMENT")
	}
	if c.Comment != "" {
		b.WriteString(" COMMENT ")
		b.WriteString(d.QuoteString(c.Comment))
	}
	return b.String()
}

// defaultClause renders a DEFAULT value. Literals (and the special NULL /
// CURRENT_TIMESTAMP keywords) are emitted as-is; any other expression default
// must be parenthesized per the MySQL grammar — introspection reports it
// without the wrapping parens.
func defaultClause(def string, isExpr bool) string {
	if !isExpr {
		return def
	}
	up := strings.ToUpper(def)
	if up == "NULL" || strings.HasPrefix(up, "CURRENT_TIMESTAMP") ||
		strings.HasPrefix(up, "NOW(") || strings.HasPrefix(def, "(") {
		return def
	}
	return "(" + def + ")"
}

func (d dialect) AddColumnSQL(t driver.TableRef, c driver.ColumnSpec) ([]string, error) {
	return []string{"ALTER TABLE " + d.QualifyTable(t) + " ADD COLUMN " + d.columnDef(c) + d.placement(c)}, nil
}

// placement renders the FIRST / AFTER clause. It belongs to ADD COLUMN and
// MODIFY COLUMN only — CREATE TABLE gets its order from the column list, and
// columnDef is shared with it — which is why this is not part of columnDef.
// PlacementAfter is an existing column the caller validated against
// introspection.
func (d dialect) placement(c driver.ColumnSpec) string {
	switch c.Placement {
	case driver.PlaceFirst:
		return " FIRST"
	case driver.PlaceAfter:
		return " AFTER " + d.QuoteIdent(c.PlacementAfter)
	}
	return ""
}

// CreateTableSQL emits a single CREATE TABLE with the PRIMARY KEY as a table
// constraint; column comments ride the columnDef inline (MySQL grammar).
func (d dialect) CreateTableSQL(t driver.TableRef, cols []driver.ColumnSpec, pk []string) ([]string, error) {
	if err := driver.ValidateCreateTable(cols, pk); err != nil {
		return nil, err
	}
	defs := make([]string, 0, len(cols))
	for _, c := range cols {
		defs = append(defs, d.columnDef(c))
	}
	return []string{driver.AssembleCreateTable(d.QualifyTable(t), defs, driver.QuoteEach(d, pk))}, nil
}

// ModifyColumnSQL uses MODIFY COLUMN, which keeps the column name — renaming
// goes through RenameColumnSQL, so the handler passes c.Name == old. A trailing
// FIRST/AFTER moves the column; without one, MySQL leaves it where it is.
func (d dialect) ModifyColumnSQL(t driver.TableRef, _ string, c driver.ColumnSpec) ([]string, error) {
	return []string{"ALTER TABLE " + d.QualifyTable(t) + " MODIFY COLUMN " + d.columnDef(c) + d.placement(c)}, nil
}

// RenameColumnSQL uses RENAME COLUMN rather than CHANGE. CHANGE works on every
// MySQL/MariaDB version but restates the entire column definition, so a rename
// spelled that way silently reapplies (and can drop) every attribute the caller
// did not supply. RENAME COLUMN changes the name and nothing else; the versions
// that lack it say so through Capabilities().SupportsColumnRename instead.
func (d dialect) RenameColumnSQL(t driver.TableRef, old, newName string) ([]string, error) {
	return []string{driver.RenameColumnDDL(d, t, old, newName)}, nil
}

func (d dialect) DropColumnSQL(t driver.TableRef, col string) ([]string, error) {
	return []string{driver.DropColumnDDL(d, t, col)}, nil
}

func (d dialect) DropObjectSQL(t driver.TableRef, kind string) ([]string, error) {
	q := d.QualifyTable(t)
	if kind == driver.ObjectView { // MySQL has no materialized views
		return []string{"DROP VIEW " + q}, nil
	}
	return []string{"DROP TABLE " + q}, nil
}

// --- Stored programs -----------------------------------------------------------
//
// No IF EXISTS on any of these, deliberately. The dump path uses it because a
// restore script must be replayable; here the caller has just resolved the
// object from a listing, so "it wasn't there" means the page was stale and the
// user deserves the server's error rather than a success message for a drop that
// did nothing. Routine names are unique within a MySQL database, so the name
// alone identifies one.

func (d dialect) DropRoutineSQL(s driver.Scope, r model.Routine) ([]string, error) {
	kw := "FUNCTION"
	if strings.EqualFold(r.Type, "PROCEDURE") {
		kw = "PROCEDURE"
	}
	return []string{"DROP " + kw + " " + d.qualifyProgram(s, r.Name)}, nil
}

func (d dialect) DropTriggerSQL(s driver.Scope, t model.Trigger) ([]string, error) {
	return []string{"DROP TRIGGER " + d.qualifyProgram(s, t.Name)}, nil
}

func (d dialect) DropEventSQL(s driver.Scope, e model.Event) ([]string, error) {
	return []string{"DROP EVENT " + d.qualifyProgram(s, e.Name)}, nil
}

// qualifyProgram names a stored program as database.name. Programs live in a
// database, not a table, so QualifyTable (which needs a TableRef) does not fit.
func (d dialect) qualifyProgram(s driver.Scope, name string) string {
	return d.QuoteIdent(s.Database) + "." + d.QuoteIdent(name)
}

// --- Table maintenance ----------------------------------------------------------

// mysqlMaintenanceOps is the offered set. Every one of these answers with a
// status table (Table / Op / Msg_type / Msg_text), which the UI renders.
//
// OPTIMIZE and REPAIR rewrite the table and hold it locked for the duration, so
// both ask first. CHECK and ANALYZE are cheap and read-mostly.
var mysqlMaintenanceOps = []driver.TableMaintenanceOp{
	{Name: "check", Label: "Check", Note: "Look for errors in the table"},
	{Name: "analyze", Label: "Analyze", Note: "Recompute key distribution statistics"},
	{Name: "optimize", Label: "Optimize", Note: "Reclaim unused space and defragment",
		Confirm: "Optimize this table? It is rebuilt and locked while that runs, which can take a long time on a large table."},
	{Name: "repair", Label: "Repair", Note: "Attempt to repair a corrupted table (MyISAM/ARCHIVE)",
		Confirm: "Repair this table? It is locked while that runs, and only some storage engines support it."},
}

func (dialect) TableMaintenanceOps() []driver.TableMaintenanceOp {
	return append([]driver.TableMaintenanceOp(nil), mysqlMaintenanceOps...)
}

func (d dialect) TableMaintenanceSQL(t driver.TableRef, op string) (string, error) {
	var kw string
	switch op {
	case "check":
		kw = "CHECK TABLE"
	case "analyze":
		kw = "ANALYZE TABLE"
	case "optimize":
		kw = "OPTIMIZE TABLE"
	case "repair":
		kw = "REPAIR TABLE"
	default:
		return "", fmt.Errorf("mysql: unknown maintenance operation %q", op)
	}
	return kw + " " + d.QualifyTable(t), nil
}

// The editor skeletons. Unqualified names on purpose: the statement runs on a
// connection already bound to the database, and a qualified name in the
// template invites someone to edit the database part rather than the object's.

func (dialect) NewRoutineTemplate(kind driver.ProgramKind) string {
	if kind == driver.ProgramProcedure {
		return `CREATE PROCEDURE procedure_name(IN arg INT)
BEGIN
  -- statements
END`
	}
	return `CREATE FUNCTION function_name(arg INT)
RETURNS INT
DETERMINISTIC
BEGIN
  RETURN arg;
END`
}

func (dialect) NewTriggerTemplate(table string) string {
	if table == "" {
		table = "table_name"
	}
	return `CREATE TRIGGER trigger_name
BEFORE INSERT ON ` + table + `
FOR EACH ROW
BEGIN
  -- statements; refer to the row as NEW.column / OLD.column
END`
}

func (dialect) NewEventTemplate() string {
	return `CREATE EVENT event_name
ON SCHEDULE EVERY 1 DAY
DO
BEGIN
  -- statements
END`
}

// CreateDatabaseSQL creates the database, optionally with a default collation
// (the charset is implied by the collation). The collation is emitted as a BARE
// identifier — backtick-quoting is a syntax error in that position — so the
// caller MUST have validated it against ListCollations first.
func (d dialect) CreateDatabaseSQL(name, collation string) string {
	stmt := "CREATE DATABASE " + d.QuoteIdent(name)
	// collation sits in a bare-identifier position (quoting is a syntax error);
	// the handler validates it against the introspected list, and this guards
	// the same shape as WriteDatabaseSectionHeader for defense-in-depth parity.
	if collation != "" && bareCollationRE.MatchString(collation) {
		stmt += " COLLATE " + collation
	}
	return stmt
}

// ListCollations returns the server's collations with their character sets,
// for the create-database form and its validation allowlist.
func (dialect) ListCollations(ctx context.Context, db *sql.DB) ([]driver.Collation, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT COLLATION_NAME, CHARACTER_SET_NAME, IS_DEFAULT
		FROM information_schema.COLLATIONS
		ORDER BY CHARACTER_SET_NAME, COLLATION_NAME`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []driver.Collation
	for rows.Next() {
		var name, charset, isDefault sql.NullString
		if err := rows.Scan(&name, &charset, &isDefault); err != nil {
			return nil, err
		}
		out = append(out, driver.Collation{
			Name:    name.String,
			Charset: charset.String,
			Default: strings.EqualFold(isDefault.String, "Yes"),
		})
	}
	return out, rows.Err()
}

// DropDatabaseSQL drops the database. MySQL/MariaDB can drop any database from
// any connection (including the currently selected one), so no FORCE clause is
// needed or available.
func (d dialect) DropDatabaseSQL(name string) string {
	return "DROP DATABASE " + d.QuoteIdent(name)
}

func (d dialect) RenameObjectSQL(t driver.TableRef, newName, _ string) ([]string, error) {
	// RENAME TABLE renames both tables and views; ALTER TABLE ... RENAME fails on
	// a view (error 1347), so RENAME TABLE is used uniformly.
	target := d.QualifyTable(driver.TableRef{Database: t.Database, Table: newName})
	return []string{"RENAME TABLE " + d.QualifyTable(t) + " TO " + target}, nil
}

// IndexOptions: MySQL indexes leading prefixes of a value (the reason a
// VARCHAR(1000) can be indexed at all under the key-length limit) and, from
// MySQL 8.0.1, orders a key part descending for real. MariaDB PARSES DESC and
// then ignores it, so it must not claim support — an index that silently is not
// what the user asked for is worse than a refusal. There is no access-method
// choice to offer: the storage engine decides, and USING HASH on InnoDB is an
// error rather than a preference. Partial indexes do not exist here.
func (d dialect) IndexOptions() driver.IndexOptions {
	return driver.IndexOptions{
		SupportsPrefix: true,
		SupportsDesc:   !d.isMariaDBFlavor() && d.atLeast(8, 0, 1),
	}
}

func (d dialect) AddIndexSQL(t driver.TableRef, spec driver.IndexSpec) ([]string, error) {
	kw := "INDEX"
	if spec.Unique {
		kw = "UNIQUE INDEX"
	}
	return []string{"ALTER TABLE " + d.QualifyTable(t) + " ADD " + kw + " " + d.QuoteIdent(spec.Name) +
		" (" + driver.IndexKeyParts(d, spec.Columns) + ")"}, nil
}

func (d dialect) DropIndexSQL(t driver.TableRef, name string) ([]string, error) {
	return []string{"ALTER TABLE " + d.QualifyTable(t) + " DROP INDEX " + d.QuoteIdent(name)}, nil
}

func (d dialect) AddForeignKeySQL(t driver.TableRef, name string, cols []string, refTable string, refCols []string, onUpdate, onDelete string) ([]string, error) {
	return []string{driver.AddForeignKeyDDL(d, t, name, cols, refTable, refCols, onUpdate, onDelete)}, nil
}

func (d dialect) DropForeignKeySQL(t driver.TableRef, name string) ([]string, error) {
	return []string{"ALTER TABLE " + d.QualifyTable(t) + " DROP FOREIGN KEY " + d.QuoteIdent(name)}, nil
}
