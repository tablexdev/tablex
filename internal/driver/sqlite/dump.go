package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/tablexdev/tablex/internal/driver"
)

// --- Dumper (restore-equivalent dump DDL) ----------------------------------------

// DumpTableCreate returns the table's verbatim CREATE TABLE from sqlite_master.
// Inline foreign keys are fine for restore: the dump preamble disables
// PRAGMA foreign_keys, so creation/insert order does not matter.
func (d dialect) DumpTableCreate(ctx context.Context, db *sql.DB, t driver.TableRef) (string, error) {
	q := fmt.Sprintf(`SELECT sql FROM %ssqlite_master WHERE type='table' AND name = ?`,
		d.schemaPrefix(t.Database))
	var ddl sql.NullString
	if err := db.QueryRowContext(ctx, q, t.Table).Scan(&ddl); err != nil {
		return "", err
	}
	return strings.TrimSpace(ddl.String), nil
}

// DumpDataTables: SQLite has no partitioned tables; every table dumps its own rows.
func (dialect) DumpDataTables(_ context.Context, _ *sql.DB, _ driver.Scope, tables []string) ([]string, error) {
	return tables, nil
}

// DumpView (ViewDumper) dumps a single view for a table-scope SQL export whose
// target is a view: DumpTableCreate reads only type='table' rows, so a view
// errors there. This reads the verbatim CREATE VIEW from sqlite_master and
// keeps the view's INSTEAD OF triggers (their tbl_name is the view — dropping
// them would leave the restored view silently non-updatable; the DROP VIEW on a
// drop-first restore removes them with the view, so they carry no own Drop,
// matching the db-scope path). SQLite has no materialized views, so withData is
// ignored.
func (d dialect) DumpView(ctx context.Context, db *sql.DB, scope driver.Scope, name string, _ bool) (driver.DumpPlan, error) {
	plan := driver.DumpPlan{}
	prefix := d.schemaPrefix(scope.Database)
	var ddl sql.NullString
	switch err := db.QueryRowContext(ctx, fmt.Sprintf(
		`SELECT sql FROM %ssqlite_master WHERE type='view' AND name = ?`, prefix), name).Scan(&ddl); {
	case errors.Is(err, sql.ErrNoRows):
		return plan, nil // not a view (caller classified it; race)
	case err != nil:
		return plan, err
	}
	plan.Views = append(plan.Views, driver.DumpScript{
		Kind:    "view",
		Comment: "View " + name,
		Drop:    "DROP VIEW IF EXISTS " + d.QuoteIdent(name),
		SQL:     strings.TrimSpace(ddl.String),
	})
	trows, err := db.QueryContext(ctx, fmt.Sprintf(
		`SELECT name, COALESCE(sql,'') FROM %ssqlite_master WHERE type='trigger' AND tbl_name = ? ORDER BY rowid`,
		prefix), name)
	if err != nil {
		return plan, err
	}
	defer trows.Close()
	for trows.Next() {
		var tname, tddl string
		if err := trows.Scan(&tname, &tddl); err != nil {
			return plan, err
		}
		if tddl == "" {
			continue
		}
		plan.PostData = append(plan.PostData, driver.DumpScript{
			Kind:    "trigger",
			Comment: "Trigger " + tname,
			SQL:     tddl,
		})
	}
	return plan, trows.Err()
}

// sqliteValueHooks: SQLite has no Inf literal but parses an overflowing
// exponent to ±Inf, so ±Inf round-trips as ±9.0e+999; it cannot store NaN,
// which dumps as NULL.
var sqliteValueHooks = driver.ValueLiteralHooks{
	BinaryLiteral: driver.XHexLiteral,
	NonFinite: func(class string) string {
		switch class {
		case "+inf":
			return "9.0e+999" // overflows to +Inf on parse
		case "-inf":
			return "-9.0e+999"
		}
		return "NULL" // NaN
	},
	// SQLite types each VALUE, not each column: a no-affinity column's INTEGER
	// must dump bare (or typeof() flips to TEXT on restore) and a declared-
	// numeric column's text must dump quoted — decisions the declared type
	// gets wrong in both directions. Paired with the DynamicTyper marker below
	// so the JSON writer makes the same call.
	PreferValueKind: true,
}

// DynamicValueTyping marks SQLite as a per-value-typed engine
// (driver.DynamicTyper) — the JSON writer's half of the PreferValueKind
// decision above.
func (dialect) DynamicValueTyping() {}

// ValueLiteral renders a cell as a SQLite dump literal (see sqliteValueHooks).
func (d dialect) ValueLiteral(col driver.ResultColumn, v driver.Value) string {
	return driver.RenderValueLiteral(d.QuoteString, sqliteValueHooks, col, v)
}

// DumpPreamble disables FK enforcement so creation/insert order does not
// matter; DumpPostamble re-enables it for sessions that outlive the script.
func (dialect) DumpPreamble(w io.Writer) {
	fmt.Fprint(w, "PRAGMA foreign_keys=OFF;\n\n")
}

func (dialect) DumpPostamble(w io.Writer) {
	fmt.Fprint(w, "\nPRAGMA foreign_keys=ON;\n")
}

// DumpObjects emits the sqlite_master rows a table's own row does not carry:
// secondary/UNIQUE indexes and triggers (post-data, filtered to the dumped
// tables — plus, in db scope, triggers whose target is a dumped VIEW: an
// INSTEAD OF trigger's tbl_name is the view, and dropping it would leave the
// restored view silently non-updatable) plus views (database scope only).
// SQLite resolves view references at query time, so creation (rowid) order is
// sufficient. AUTOINCREMENT counters are re-synced from sqlite_sequence so a
// counter ahead of its data survives the round trip.
func (d dialect) DumpObjects(ctx context.Context, db *sql.DB, scope driver.Scope, tables []string, dbScope, structure, _ bool) (driver.DumpPlan, error) {
	plan := driver.DumpPlan{}
	inTables := driver.StringSet(tables)

	q := fmt.Sprintf(`SELECT type, name, tbl_name, COALESCE(sql,'') FROM %ssqlite_master
		WHERE type IN ('index','trigger','view') ORDER BY rowid`, d.schemaPrefix(scope.Database))
	rows, err := db.QueryContext(ctx, q)
	if err != nil {
		return plan, err
	}
	defer rows.Close()
	var indexes []driver.DumpScript
	// Triggers are buffered with their target and filtered after the scan, so
	// keeping a view's triggers needs no assumption about sqlite_master row
	// order between a view and its triggers.
	type trigRow struct {
		tbl    string
		script driver.DumpScript
	}
	var triggers []trigRow
	views := map[string]bool{}
	for rows.Next() {
		var typ, name, tbl, ddl string
		if err := rows.Scan(&typ, &name, &tbl, &ddl); err != nil {
			return plan, err
		}
		if ddl == "" {
			continue // implicit auto-indexes (sqlite_autoindex_*) have no SQL and recreate themselves
		}
		switch typ {
		case "view":
			views[name] = true
			if dbScope && structure {
				plan.Views = append(plan.Views, driver.DumpScript{
					Kind:    "view",
					Comment: "View " + name,
					Drop:    "DROP VIEW IF EXISTS " + d.QuoteIdent(name),
					SQL:     ddl,
				})
			}
		case "index":
			// Index and trigger DDL are structure: a data-only dump discards
			// them (the writer keeps only sequence items in PostData).
			if structure && inTables[tbl] {
				indexes = append(indexes, driver.DumpScript{Kind: "index", Comment: "Index " + name, SQL: ddl})
			}
		case "trigger":
			if structure {
				triggers = append(triggers, trigRow{tbl, driver.DumpScript{Kind: "trigger", Comment: "Trigger " + name, SQL: ddl}})
			}
		}
	}
	if err := rows.Err(); err != nil {
		return plan, err
	}
	plan.PostData = append(plan.PostData, indexes...)
	for _, tr := range triggers {
		// Keep a trigger when its target table is dumped, or — for INSTEAD OF
		// triggers, whose tbl_name is the VIEW — when that view is dumped
		// (db-scope structure dumps carry every view).
		if inTables[tr.tbl] || (dbScope && views[tr.tbl]) {
			plan.PostData = append(plan.PostData, tr.script)
		}
	}

	// AUTOINCREMENT counter sync. sqlite_sequence exists only once some table uses
	// AUTOINCREMENT; a missing table is simply "nothing to sync". Pre-check its
	// existence via sqlite_master so a genuine query error (vs. mere absence) is
	// propagated rather than swallowed — which would silently drop the counter
	// sync. The data inserts set the counter to the max dumped rowid, so only
	// counters ahead of the data strictly need this — emitted for exactness.
	existsQ := fmt.Sprintf(`SELECT 1 FROM %ssqlite_master WHERE type='table' AND name='sqlite_sequence'`, d.schemaPrefix(scope.Database))
	switch err := db.QueryRowContext(ctx, existsQ).Scan(new(int)); {
	case errors.Is(err, sql.ErrNoRows):
		return plan, nil // no AUTOINCREMENT table: nothing to sync
	case err != nil:
		return plan, err
	}
	seqQ := fmt.Sprintf(`SELECT name, seq FROM %ssqlite_sequence ORDER BY name`, d.schemaPrefix(scope.Database))
	srows, err := db.QueryContext(ctx, seqQ)
	if err != nil {
		return plan, err
	}
	defer srows.Close()
	for srows.Next() {
		var name string
		var seq int64
		if err := srows.Scan(&name, &seq); err != nil {
			return plan, err
		}
		if !inTables[name] {
			continue
		}
		plan.PostData = append(plan.PostData,
			driver.DumpScript{Kind: "sequence", Comment: "AUTOINCREMENT counter for " + name,
				SQL: fmt.Sprintf("DELETE FROM sqlite_sequence WHERE name = %s", d.QuoteString(name))},
			driver.DumpScript{Kind: "sequence",
				SQL: fmt.Sprintf("INSERT INTO sqlite_sequence (name, seq) VALUES (%s, %d)", d.QuoteString(name), seq)})
	}
	return plan, srows.Err()
}
