package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/tablexdev/tablex/internal/driver"
	"github.com/tablexdev/tablex/internal/model"
)

// --- Monitor (variables only; SQLite is a single in-process file) ---------------

func (dialect) Status(context.Context, *sql.DB) ([]model.Variable, error) { return nil, nil }

func (dialect) Variables(ctx context.Context, db *sql.DB) ([]model.Variable, error) {
	pragmas := []string{
		"page_size", "page_count", "encoding", "journal_mode", "synchronous",
		"foreign_keys", "busy_timeout", "cache_size", "auto_vacuum",
		"user_version", "application_id", "temp_store",
	}
	var out []model.Variable
	for _, p := range pragmas {
		var val sql.NullString
		// Distinguish the two failure modes instead of dropping both. A PRAGMA
		// this build does not implement returns NO ROW, and omitting it is
		// correct — it genuinely does not exist here. Any other error means the
		// read failed, and silently omitting THAT left the operator unable to
		// tell "this server has no such setting" from "TableX could not read
		// it"; surface it as an explicit value instead.
		switch err := db.QueryRowContext(ctx, "PRAGMA "+p).Scan(&val); {
		case errors.Is(err, sql.ErrNoRows):
			// not implemented by this build — omit
		case err != nil:
			out = append(out, model.Variable{Name: p, Value: "(unavailable: " + err.Error() + ")"})
		default:
			out = append(out, model.Variable{Name: p, Value: val.String})
		}
	}
	return out, nil
}

func (dialect) Processes(context.Context, *sql.DB) (*driver.ResultSet, error) { return nil, nil }

// --- SchemaEditor (DDL) ---------------------------------------------------------

func (dialect) ColumnTypes() []string {
	return []string{"INTEGER", "TEXT", "REAL", "NUMERIC", "BLOB", "BOOLEAN", "DATE", "DATETIME"}
}

// AddColumnSQL enforces the value-only guards SQLite's ALTER TABLE ADD COLUMN
// imposes and that need no DB access (see sqlite.org/lang_altertable.html): the
// default must be a literal constant (no CURRENT_* / expression), and a NOT NULL
// column requires a non-NULL default. Constraints that need introspection (e.g.
// dropping an indexed column) live in the handler.
func (d dialect) AddColumnSQL(t driver.TableRef, c driver.ColumnSpec) ([]string, error) {
	if c.Default != nil {
		u := strings.ToUpper(strings.TrimSpace(*c.Default))
		if strings.HasPrefix(u, "CURRENT_") || strings.HasPrefix(strings.TrimSpace(*c.Default), "(") {
			return nil, errors.New("sqlite: ADD COLUMN default must be a literal constant (no CURRENT_* or expression)")
		}
	}
	if !c.Nullable && (c.Default == nil || strings.EqualFold(strings.TrimSpace(*c.Default), "NULL")) {
		return nil, errors.New("sqlite: cannot add a NOT NULL column without a non-NULL default")
	}
	return []string{"ALTER TABLE " + d.QualifyTable(t) + " ADD COLUMN " + driver.BasicColumnDef(d, c)}, nil
}

// CreateTableSQL reuses columnDef but NOT AddColumnSQL: that method's guards
// (no CURRENT_*/expression defaults, NOT NULL requires a default) are
// ALTER-TABLE-specific — both shapes are legal in a CREATE TABLE column list.
func (d dialect) CreateTableSQL(t driver.TableRef, cols []driver.ColumnSpec, pk []string) ([]string, error) {
	if err := driver.ValidateCreateTable(cols, pk); err != nil {
		return nil, err
	}
	defs := make([]string, 0, len(cols))
	for _, c := range cols {
		defs = append(defs, driver.BasicColumnDef(d, c))
	}
	return []string{driver.AssembleCreateTable(d.QualifyTable(t), defs, driver.QuoteEach(d, pk))}, nil
}

func (d dialect) DropColumnSQL(t driver.TableRef, col string) ([]string, error) {
	return []string{driver.DropColumnDDL(d, t, col)}, nil
}

// RenameColumnSQL is the whole of SQLite's column editing: there is no MODIFY,
// so this dialect implements ColumnRenamer without ColumnModifier. SQLite
// rewrites references to the column in indexes, triggers and views for us.
func (d dialect) RenameColumnSQL(t driver.TableRef, old, newName string) ([]string, error) {
	return []string{driver.RenameColumnDDL(d, t, old, newName)}, nil
}

// EstimateRows returns SQLite's statistics-based row estimate from sqlite_stat1,
// so Browse / Structure need not run an exact COUNT(*) full scan on every render
// for a large table. sqlite_stat1 exists only after ANALYZE; pre-ANALYZE this
// returns -1 and the caller falls back to an exact count.
//
// A table has one stat1 row PER INDEX, and the first token of each is the number
// of rows that index covers — which equals the table's row count only for a full
// index. A PARTIAL index (CREATE INDEX … WHERE …) counts just the matching rows,
// so taking whichever row came first could report 12 for a five-million-row
// table. That is not a cosmetic error: the caller treats a small estimate as
// licence to run the exact COUNT(*) this function exists to avoid, on every
// render.
//
// So: SQLite writes an authoritative row with idx NULL whose stat IS the table's
// row count — prefer it — and otherwise take the LARGEST first token, since no
// index can cover more rows than the table holds and a full index covers exactly
// that. With only partial indexes the answer is still an under-estimate, but the
// closest one available.
func (d dialect) EstimateRows(ctx context.Context, db *sql.DB, t driver.TableRef) (int64, error) {
	prefix := d.schemaPrefix(t.Database)
	var exists int
	err := db.QueryRowContext(ctx, `SELECT 1 FROM `+prefix+`sqlite_master WHERE type='table' AND name='sqlite_stat1'`).Scan(&exists)
	if errors.Is(err, sql.ErrNoRows) {
		return -1, nil // never ANALYZEd
	}
	if err != nil {
		return -1, err
	}
	rows, err := db.QueryContext(ctx,
		`SELECT idx IS NULL, stat FROM `+prefix+`sqlite_stat1 WHERE tbl = ?`, t.Table)
	// The error test comes FIRST, as it does for the query above: a real failure
	// — a closed pool, a cancelled context — must not be reported as the
	// ordinary "no estimate recorded" answer.
	if err != nil {
		return -1, err
	}
	defer rows.Close()
	best := int64(-1)
	for rows.Next() {
		var wholeTable bool
		var stat sql.NullString
		if err := rows.Scan(&wholeTable, &stat); err != nil {
			return -1, err
		}
		if !stat.Valid {
			continue
		}
		fields := strings.Fields(stat.String)
		if len(fields) == 0 {
			continue
		}
		n, perr := strconv.ParseInt(fields[0], 10, 64)
		if perr != nil {
			continue
		}
		if wholeTable {
			// The table's own row, not an index's: authoritative, stop here.
			best = n
			break
		}
		if n > best {
			best = n
		}
	}
	if err := rows.Err(); err != nil {
		return -1, err
	}
	return best, nil
}

func (d dialect) DropObjectSQL(t driver.TableRef, kind string) ([]string, error) {
	q := d.QualifyTable(t)
	if kind == driver.ObjectView { // SQLite has no materialized views
		return []string{"DROP VIEW " + q}, nil
	}
	return []string{"DROP TABLE " + q}, nil
}

func (d dialect) RenameObjectSQL(t driver.TableRef, newName, _ string) ([]string, error) {
	// ALTER TABLE ... RENAME TO renames both tables and views on SQLite (>=3.25).
	return []string{"ALTER TABLE " + d.QualifyTable(t) + " RENAME TO " + d.QuoteIdent(newName)}, nil
}

// DropTriggerSQL implements driver.TriggerManager. Triggers are the only stored
// program SQLite has — there are no routines and no events — which is why the
// three managers are separate interfaces. A trigger is named within its attached
// database, not by its table, so the schema prefix is all the qualification the
// statement needs.
func (d dialect) DropTriggerSQL(s driver.Scope, t model.Trigger) ([]string, error) {
	return []string{"DROP TRIGGER " + d.schemaPrefix(s.Database) + d.QuoteIdent(t.Name)}, nil
}

// --- Table maintenance ----------------------------------------------------------

// TableMaintenanceOps offers ANALYZE only. SQLite's VACUUM rebuilds the WHOLE
// DATABASE FILE and takes no table argument, so it is not a table operation and
// is deliberately not offered from a table's page under a name that would imply
// otherwise.
func (dialect) TableMaintenanceOps() []driver.TableMaintenanceOp {
	return []driver.TableMaintenanceOp{
		{Name: "analyze", Label: "Analyze", Note: "Recompute index statistics for the query planner"},
	}
}

func (d dialect) TableMaintenanceSQL(t driver.TableRef, op string) (string, error) {
	if op != "analyze" {
		return "", fmt.Errorf("sqlite: unknown maintenance operation %q", op)
	}
	return "ANALYZE " + d.QualifyTable(t), nil
}

// NewTriggerTemplate is the editor skeleton. SQLite trigger bodies hold whole
// statements inline and must end with END.
func (dialect) NewTriggerTemplate(table string) string {
	if table == "" {
		table = "table_name"
	}
	return `CREATE TRIGGER trigger_name
BEFORE INSERT ON ` + table + `
FOR EACH ROW
BEGIN
  SELECT RAISE(ABORT, 'message') WHERE NEW.column IS NULL;
END`
}

// IndexOptions: SQLite has ordered key parts and partial indexes (3.8.0+), but
// only one index structure and no prefix indexes.
func (dialect) IndexOptions() driver.IndexOptions {
	return driver.IndexOptions{SupportsDesc: true, SupportsPartial: true}
}

func (d dialect) AddIndexSQL(t driver.TableRef, spec driver.IndexSpec) ([]string, error) {
	kw := "CREATE INDEX"
	if spec.Unique {
		kw = "CREATE UNIQUE INDEX"
	}
	// The index name carries the schema prefix; the table name in CREATE INDEX
	// is never schema-qualified.
	idx := d.schemaPrefix(t.Database) + d.QuoteIdent(spec.Name)
	stmt := kw + " " + idx + " ON " + d.QuoteIdent(t.Table) + " (" + driver.IndexKeyParts(d, spec.Columns) + ")"
	if spec.Where != "" {
		stmt += " WHERE " + spec.Where
	}
	return []string{stmt}, nil
}

func (d dialect) DropIndexSQL(t driver.TableRef, name string) ([]string, error) {
	return []string{"DROP INDEX " + d.schemaPrefix(t.Database) + d.QuoteIdent(name)}, nil
}
