// SchemaEditor and friends: the DDL statement builders behind the structure
// pages (columns, tables, indexes, foreign keys, schemas, databases). Every
// identifier reaching these has already been validated against the catalog by
// the handler; they only quote and assemble.

package postgres

import (
	"errors"
	"strings"

	"github.com/tablexdev/tablex/internal/driver"
	"github.com/tablexdev/tablex/internal/model"
)

func (dialect) ColumnTypes() []string {
	return []string{
		"smallint", "integer", "bigint", "numeric", "real", "double precision",
		"smallserial", "serial", "bigserial", "money",
		"varchar", "char", "text",
		"boolean", "uuid", "bytea", "bit", "varbit",
		"date", "time", "timetz", "timestamp", "timestamptz", "interval",
		"json", "jsonb",
	}
}

// columnDef renders the column fragment shared by ADD COLUMN and CREATE TABLE.
// PostgreSQL column comments are separate COMMENT ON COLUMN statements — the
// callers append them. (columnLine, the dump path's renderer, stays separate:
// it takes introspected model.Column values and carries identity/generated
// concerns this editor fragment never sees.)
func (d dialect) AddColumnSQL(t driver.TableRef, c driver.ColumnSpec) ([]string, error) {
	q := d.QualifyTable(t)
	stmts := []string{"ALTER TABLE " + q + " ADD COLUMN " + driver.BasicColumnDef(d, c)}
	if c.Comment != "" {
		stmts = append(stmts, "COMMENT ON COLUMN "+q+"."+d.QuoteIdent(c.Name)+" IS "+d.QuoteString(c.Comment))
	}
	return stmts, nil
}

// CreateTableSQL emits one CREATE TABLE with the PRIMARY KEY as a table
// constraint, followed by COMMENT ON COLUMN statements exactly as AddColumnSQL
// does (comments are not part of the PostgreSQL column grammar).
func (d dialect) CreateTableSQL(t driver.TableRef, cols []driver.ColumnSpec, pk []string) ([]string, error) {
	if err := driver.ValidateCreateTable(cols, pk); err != nil {
		return nil, err
	}
	q := d.QualifyTable(t)
	defs := make([]string, 0, len(cols))
	var comments []string
	for _, c := range cols {
		defs = append(defs, driver.BasicColumnDef(d, c))
		if c.Comment != "" {
			comments = append(comments, "COMMENT ON COLUMN "+q+"."+d.QuoteIdent(c.Name)+" IS "+d.QuoteString(c.Comment))
		}
	}
	stmts := []string{driver.AssembleCreateTable(q, defs, driver.QuoteEach(d, pk))}
	return append(stmts, comments...), nil
}

// ModifyColumnSQL expands a change into ordered ALTER COLUMN steps (rename is
// deferred — the handler passes c.Name == old). The old default is dropped
// before the type change so a stale default expression cannot block the cast,
// then the new default (if any) is set, per the PostgreSQL ALTER TABLE docs.
// Identity columns (c.Identity from the handler's preserved attributes) have
// no separate default: DROP DEFAULT and SET DEFAULT on them are hard errors,
// so both steps are skipped and the identity itself is left untouched.
func (d dialect) ModifyColumnSQL(t driver.TableRef, _ string, c driver.ColumnSpec) ([]string, error) {
	q := d.QualifyTable(t)
	col := d.QuoteIdent(c.Name)
	var stmts []string
	if c.Identity == "" {
		stmts = append(stmts, "ALTER TABLE "+q+" ALTER COLUMN "+col+" DROP DEFAULT")
	}
	// A base-type change needs an explicit USING cast (it covers many conversions;
	// a truly uncastable pair like int->uuid still errors clearly with PostgreSQL's
	// "cannot cast" message). A same-base change (length/precision only) needs no
	// cast: omit USING so PostgreSQL converts natively and, on a shrink that would
	// lose data, errors instead of silently truncating via the explicit cast.
	alterType := "ALTER TABLE " + q + " ALTER COLUMN " + col + " TYPE " + c.Type
	if !c.SameBaseType {
		alterType += " USING " + col + "::" + c.Type
	}
	stmts = append(stmts, alterType)
	if c.Nullable {
		stmts = append(stmts, "ALTER TABLE "+q+" ALTER COLUMN "+col+" DROP NOT NULL")
	} else {
		stmts = append(stmts, "ALTER TABLE "+q+" ALTER COLUMN "+col+" SET NOT NULL")
	}
	if c.Default != nil && c.Identity == "" {
		stmts = append(stmts, "ALTER TABLE "+q+" ALTER COLUMN "+col+" SET DEFAULT "+*c.Default)
	}
	// On the modify path, always set the comment so an emptied field CLEARS the
	// existing comment (IS NULL) rather than silently keeping the old one. The
	// modify form pre-fills the field with the current comment, so an unchanged
	// comment round-trips unchanged.
	if c.Comment != "" {
		stmts = append(stmts, "COMMENT ON COLUMN "+q+"."+col+" IS "+d.QuoteString(c.Comment))
	} else {
		stmts = append(stmts, "COMMENT ON COLUMN "+q+"."+col+" IS NULL")
	}
	return stmts, nil
}

func (d dialect) DropColumnSQL(t driver.TableRef, col string) ([]string, error) {
	return []string{driver.DropColumnDDL(d, t, col)}, nil
}

// RenameColumnSQL is deliberately not folded into ModifyColumnSQL's step list:
// PostgreSQL rewrites every dependent view, index and constraint to follow the
// new name, so a rename is safe on its own in a way a retype is not.
func (d dialect) RenameColumnSQL(t driver.TableRef, old, newName string) ([]string, error) {
	return []string{driver.RenameColumnDDL(d, t, old, newName)}, nil
}

// DDLErrorHint turns PostgreSQL's opaque dependent-object error into actionable
// guidance, so the handler need not sniff engine-specific error text.
func (dialect) DDLErrorHint(err error) (string, bool) {
	if err != nil && strings.Contains(err.Error(), "used by a view or rule") {
		return "Cannot modify this column: a view or rule depends on it (" + err.Error() +
			"). Drop or redefine the dependent view first, then retry.", true
	}
	return "", false
}

func (d dialect) DropObjectSQL(t driver.TableRef, kind string) ([]string, error) {
	q := d.QualifyTable(t)
	switch kind {
	case driver.ObjectView:
		return []string{"DROP VIEW " + q}, nil
	case driver.ObjectMatView:
		return []string{"DROP MATERIALIZED VIEW " + q}, nil
	default:
		return []string{"DROP TABLE " + q}, nil
	}
}

// --- Stored programs -----------------------------------------------------------

// DropRoutineSQL drops a function or procedure.
//
// The argument signature is required, not cosmetic: PostgreSQL allows
// overloading, and DROP FUNCTION f fails with "function name f is not unique"
// the moment a second f exists. r.ArgSignature carries
// pg_get_function_identity_arguments from the listing — server-generated catalog
// text with its own identifier quoting already applied, emitted verbatim because
// it is a type list, not an identifier this dialect could quote. An empty
// signature is a real answer (a zero-argument routine), hence the bare "()".
func (d dialect) DropRoutineSQL(s driver.Scope, r model.Routine) ([]string, error) {
	kw := "FUNCTION"
	if strings.EqualFold(r.Type, "PROCEDURE") {
		kw = "PROCEDURE"
	}
	name := d.QuoteIdent(schemaOfScope(s)) + "." + d.QuoteIdent(r.Name)
	return []string{"DROP " + kw + " " + name + "(" + r.ArgSignature + ")"}, nil
}

// DropTriggerSQL drops a trigger. Unlike MySQL, PostgreSQL names a trigger by
// the table it is attached to — trigger names are unique per table, not per
// schema — so the table is mandatory.
func (d dialect) DropTriggerSQL(s driver.Scope, t model.Trigger) ([]string, error) {
	if t.Table == "" {
		return nil, errors.New("postgres: cannot drop a trigger without knowing its table")
	}
	on := d.QuoteIdent(schemaOfScope(s)) + "." + d.QuoteIdent(t.Table)
	return []string{"DROP TRIGGER " + d.QuoteIdent(t.Name) + " ON " + on}, nil
}

// --- Table maintenance ----------------------------------------------------------

// pgMaintenanceOps is the offered set. None of these report rows; the UI shows
// a plain "done" for them.
//
// VACUUM FULL and REINDEX take an ACCESS EXCLUSIVE lock — the table is
// unreadable for the duration — so both ask first. Plain VACUUM and ANALYZE run
// alongside normal traffic. CLUSTER is deliberately absent: it only works on a
// table that has already been CLUSTERed against an index, so offering it as a
// button would fail on almost every table.
var pgMaintenanceOps = []driver.TableMaintenanceOp{
	{Name: "analyze", Label: "Analyze", Note: "Recompute planner statistics"},
	{Name: "vacuum", Label: "Vacuum", Note: "Reclaim space from dead rows (runs alongside normal traffic)"},
	{Name: "vacuum_analyze", Label: "Vacuum + analyze", Note: "Reclaim space, then recompute statistics"},
	{Name: "vacuum_full", Label: "Vacuum full", Note: "Rewrite the table, returning space to the OS",
		Confirm: "VACUUM FULL rewrites the whole table and holds an ACCESS EXCLUSIVE lock: nothing can read it until this finishes. Continue?"},
	{Name: "reindex", Label: "Reindex", Note: "Rebuild every index on the table",
		Confirm: "REINDEX rebuilds every index on this table and locks it against writes. Continue?"},
}

func (dialect) TableMaintenanceOps() []driver.TableMaintenanceOp {
	return append([]driver.TableMaintenanceOp(nil), pgMaintenanceOps...)
}

func (d dialect) TableMaintenanceSQL(t driver.TableRef, op string) (string, error) {
	q := d.QualifyTable(t)
	switch op {
	case "analyze":
		return "ANALYZE " + q, nil
	case "vacuum":
		return "VACUUM " + q, nil
	case "vacuum_analyze":
		return "VACUUM ANALYZE " + q, nil
	case "vacuum_full":
		return "VACUUM FULL " + q, nil
	case "reindex":
		return "REINDEX TABLE " + q, nil
	}
	return "", errors.New("postgres: unknown maintenance operation " + op)
}

// The editor skeletons. Dollar-quoted bodies, because that is the only form
// that survives an arbitrary body without escaping.

func (dialect) NewRoutineTemplate(kind driver.ProgramKind) string {
	if kind == driver.ProgramProcedure {
		return `CREATE PROCEDURE procedure_name(arg integer)
LANGUAGE plpgsql
AS $$
BEGIN
  -- statements
END;
$$`
	}
	return `CREATE FUNCTION function_name(arg integer)
RETURNS integer
LANGUAGE plpgsql
AS $$
BEGIN
  RETURN arg;
END;
$$`
}

// NewTriggerTemplate points at a separate function on purpose: PostgreSQL
// triggers have no inline body, they EXECUTE a function returning trigger, and
// that function must already exist.
func (dialect) NewTriggerTemplate(table string) string {
	if table == "" {
		table = "table_name"
	}
	return `-- The function must already exist and RETURN trigger; create it on
-- the Routines page first if it does not.
CREATE TRIGGER trigger_name
BEFORE INSERT ON ` + table + `
FOR EACH ROW
EXECUTE FUNCTION function_name()`
}

// CreateDatabaseSQL creates the database. The collation parameter is ignored:
// PostgreSQL database collations (LC_COLLATE/LOCALE) are OS-locale based, not
// the MySQL-style charset collations the form offers, and Capabilities reports
// SupportsCharset=false so the handler never passes one.
func (d dialect) CreateDatabaseSQL(name, _ string) string {
	return "CREATE DATABASE " + d.QuoteIdent(name)
}

// CreateSchemaSQL creates a schema in the CURRENT database — the caller must
// run it on a connection bound to the target database.
func (d dialect) CreateSchemaSQL(name string) string {
	return "CREATE SCHEMA " + d.QuoteIdent(name)
}

// DropSchemaSQL drops the schema and every object in it. CASCADE is deliberate
// (parity with DROP DATABASE, which force-drops): the handler shows an explicit
// "and ALL its objects" confirmation first.
func (d dialect) DropSchemaSQL(name string) string {
	return "DROP SCHEMA " + d.QuoteIdent(name) + " CASCADE"
}

// DropDatabaseSQL drops the database WITH (FORCE) (PostgreSQL 13+), terminating
// any OTHER sessions still connected to it so the drop is not blocked by a stale
// backend. It still cannot drop the database the issuing session is itself
// connected to — the caller runs it on a maintenance connection bound elsewhere.
func (d dialect) DropDatabaseSQL(name string) string {
	return "DROP DATABASE " + d.QuoteIdent(name) + " WITH (FORCE)"
}

// MaintenanceDatabases names the databases a session can bind to in order to
// drop the database it is itself connected to. "postgres" is the conventional
// maintenance database; template1 is the fallback because a managed host often
// blocks postgres — which is precisely why logging in through a user database
// has to work. Every cluster has template1.
//
// The returned slice is fresh on every call: it is handed to a session, which
// must not be able to mutate a value shared by all of them.
func (dialect) MaintenanceDatabases() []string {
	return []string{"postgres", "template1"}
}

func (d dialect) RenameObjectSQL(t driver.TableRef, newName, kind string) ([]string, error) {
	q := d.QualifyTable(t)
	nn := d.QuoteIdent(newName)
	if kind == driver.ObjectMatView {
		// A materialized view is renamed with ALTER MATERIALIZED VIEW (canonical).
		return []string{"ALTER MATERIALIZED VIEW " + q + " RENAME TO " + nn}, nil
	}
	// ALTER TABLE ... RENAME renames both tables and plain views on PostgreSQL.
	return []string{"ALTER TABLE " + q + " RENAME TO " + nn}, nil
}

// pgIndexMethods are the access methods every supported PostgreSQL carries in
// pg_am. Emitted as a keyword after USING, so the handler matches the submitted
// value against this list rather than passing anything through.
var pgIndexMethods = []string{"btree", "hash", "gist", "gin", "spgist", "brin"}

// IndexOptions: PostgreSQL chooses an access method, orders key parts
// descending and takes a WHERE predicate. It has no prefix indexes — the
// equivalent is an expression index, which the editor does not build.
func (dialect) IndexOptions() driver.IndexOptions {
	return driver.IndexOptions{
		Methods:         pgIndexMethods,
		SupportsDesc:    true,
		SupportsPartial: true,
	}
}

func (d dialect) AddIndexSQL(t driver.TableRef, spec driver.IndexSpec) ([]string, error) {
	kw := "CREATE INDEX"
	if spec.Unique {
		kw = "CREATE UNIQUE INDEX"
	}
	stmt := kw + " " + d.QuoteIdent(spec.Name) + " ON " + d.QualifyTable(t)
	// USING precedes the key list; the handler has already matched Method
	// against IndexOptions().Methods, so it is a keyword, not user text.
	if spec.Method != "" {
		stmt += " USING " + spec.Method
	}
	stmt += " (" + driver.IndexKeyParts(d, spec.Columns) + ")"
	if spec.Where != "" {
		stmt += " WHERE " + spec.Where
	}
	return []string{stmt}, nil
}

// DropIndexSQL schema-qualifies the index name: PostgreSQL DROP INDEX is
// schema-scoped (the index lives in the table's schema), not table-scoped.
func (d dialect) DropIndexSQL(t driver.TableRef, name string) ([]string, error) {
	return []string{"DROP INDEX " + d.QuoteIdent(schemaOf(t)) + "." + d.QuoteIdent(name)}, nil
}

func (d dialect) AddForeignKeySQL(t driver.TableRef, name string, cols []string, refTable string, refCols []string, onUpdate, onDelete string) ([]string, error) {
	return []string{driver.AddForeignKeyDDL(d, t, name, cols, refTable, refCols, onUpdate, onDelete)}, nil
}

func (d dialect) DropForeignKeySQL(t driver.TableRef, name string) ([]string, error) {
	return []string{"ALTER TABLE " + d.QualifyTable(t) + " DROP CONSTRAINT " + d.QuoteIdent(name)}, nil
}
