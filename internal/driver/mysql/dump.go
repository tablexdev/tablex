package mysql

import (
	"context"
	"database/sql"
	sqldriver "database/sql/driver"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"

	"github.com/tablexdev/tablex/internal/driver"
)

// --- Dumper (restore-equivalent dump DDL) ----------------------------------------

// DumpTableCreate: SHOW CREATE TABLE is already restore-oriented (it carries
// the AUTO_INCREMENT counter); inline FK constraints restore fine under the
// dump's FOREIGN_KEY_CHECKS=0 preamble.
func (d dialect) DumpTableCreate(ctx context.Context, db *sql.DB, t driver.TableRef) (string, error) {
	return d.CreateSQL(ctx, db, t)
}

// DumpDataTables: MySQL partitions are internal to the table; every listed
// table dumps its own rows.
func (dialect) DumpDataTables(_ context.Context, _ *sql.DB, _ driver.Scope, tables []string) ([]string, error) {
	return tables, nil
}

// DumpView (ViewDumper) dumps a single view for a table-scope SQL export whose
// target is a view — the table path would otherwise route it through the
// table-shaped SHOW CREATE TABLE scan. It mirrors DumpObjects' view emission:
// SHOW CREATE VIEW under a binary-results connection so the definer/charset
// creation context is preserved verbatim. MySQL has no materialized views, so
// withData is ignored.
func (d dialect) DumpView(ctx context.Context, db *sql.DB, scope driver.Scope, name string, _ bool) (driver.DumpPlan, error) {
	plan := driver.DumpPlan{}
	bin, err := openBinaryResults(ctx, db)
	if err != nil {
		return plan, err
	}
	defer bin.Close(ctx)
	qualified := d.QuoteIdent(scope.Database) + "." + d.QuoteIdent(name)
	ddl, oc, err := showCreateContext(ctx, bin.conn, "SHOW CREATE VIEW "+qualified, "create view")
	if err != nil {
		return plan, fmt.Errorf("dump view %s: %w", name, err)
	}
	pre, post := d.creationGuards(oc)
	plan.Views = append(plan.Views, driver.DumpScript{
		Kind:        "view",
		Comment:     "View " + name,
		Drop:        "DROP VIEW IF EXISTS " + d.QuoteIdent(name),
		SQL:         ddl,
		OpaqueFrame: true,
		Pre:         pre,
		Post:        post,
	})
	return plan, nil
}

// mysqlValueHooks: zero dates run as the text PRE-PASS — the driver's
// parseTime maps 0000-00-00[ 00:00:00] to Go's zero time (0001-01-01), so the
// original sentinel is emitted for the dump to round-trip instead of storing
// year 1. MySQL can store neither NaN nor ±Inf, so a non-finite float dumps
// as NULL rather than an invalid bare token.
var mysqlValueHooks = driver.ValueLiteralHooks{
	BinaryLiteral: driver.XHexLiteral,
	TextSpecial: func(col driver.ResultColumn, s string) (string, bool) {
		if zeroDateDBType(col.DBType) {
			switch s {
			case "0001-01-01":
				return "'0000-00-00'", true
			case "0001-01-01 00:00:00":
				return "'0000-00-00 00:00:00'", true
			}
		}
		return "", false
	},
	NonFinite: func(string) string { return "NULL" },
}

// ValueLiteral renders a cell as a MySQL dump literal (see mysqlValueHooks).
func (d dialect) ValueLiteral(col driver.ResultColumn, v driver.Value) string {
	return driver.RenderValueLiteral(d.QuoteString, mysqlValueHooks, col, v)
}

// zeroDateDBType reports the temporal column types that can hold the MySQL
// zero-date sentinel.
func zeroDateDBType(t string) bool {
	switch strings.ToUpper(strings.TrimSpace(t)) {
	case "DATE", "DATETIME", "TIMESTAMP":
		return true
	}
	return false
}

// DumpPreamble pins the session state a restore needs: NO_AUTO_VALUE_ON_ZERO
// protects explicit zero AUTO_INCREMENT values, and a pinned sql_mode
// guarantees the dump body parses regardless of the server default — the
// export session is pinned to this exact mode (ExportConnParams), so data
// literals and SHOW CREATE DDL are rendered under default backslash escaping
// and backtick quoting even when the source server runs NO_BACKSLASH_ESCAPES
// or ANSI_QUOTES. Object bodies are the exception: they are emitted byte-
// exact inside opaque frames and restore under their own recorded creation
// context (per-object @saved_* guards). FK checks off lets cyclic /
// self-referencing schemas restore in any order; time_zone UTC matches the
// UTC TIMESTAMP literals in the data phase.
func (dialect) DumpPreamble(w io.Writer) {
	fmt.Fprint(w, "-- Routines, triggers and events restore under their recorded creation context;\n")
	fmt.Fprint(w, "-- a differing target database collation is disclosed as an import warning\n")
	fmt.Fprint(w, "-- (tablex db-collation markers) and the target database is never altered.\n")
	fmt.Fprint(w, "SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO';\n")
	fmt.Fprint(w, "SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0;\n")
	fmt.Fprint(w, "SET @OLD_TIME_ZONE=@@TIME_ZONE;\nSET TIME_ZONE='+00:00';\n\n")
}

// DumpPostamble restores the preamble's session state for sessions that
// outlive the script.
func (dialect) DumpPostamble(w io.Writer) {
	fmt.Fprint(w, "\nSET TIME_ZONE=@OLD_TIME_ZONE;\nSET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS;\nSET SQL_MODE=@OLD_SQL_MODE;\n")
}

// DumpObjects collects routines, views (dependency-ordered), triggers and
// events as full recreate DDL via SHOW CREATE — information_schema definitions
// are body-only and cannot be replayed. Every definition is fetched on ONE
// dedicated connection pinned to character_set_results=binary (mysqldump's
// approach): without binary retrieval the server converts stored body bytes to
// the client charset, and re-tagging that converted text with the original
// character_set_client guard would corrupt non-ASCII bodies. Each script
// therefore carries its raw body inside an opaque frame (OpaqueFrame), the
// object's creation context as save/set/restore guards (Pre/Post, from the
// sibling columns the SHOW CREATE row already reports), and — for routines,
// triggers and events — a db-collation disclosure marker. Views report only
// the two charset columns, so they get charset guards but never a marker.
func (d dialect) DumpObjects(ctx context.Context, db *sql.DB, scope driver.Scope, tables []string, dbScope, structure, _ bool) (driver.DumpPlan, error) {
	plan := driver.DumpPlan{}
	inTables := driver.StringSet(tables)
	qualify := func(name string) string {
		return d.QuoteIdent(scope.Database) + "." + d.QuoteIdent(name)
	}

	// The binary-results connection is opened lazily — a dump with no objects
	// (or data-only, which skips all of this) never pays for it — and closed
	// with its charset restored on every return path.
	var bin *binaryResults
	fetch := func(query, ddlCol string) (string, objectContext, error) {
		if bin == nil {
			var err error
			if bin, err = openBinaryResults(ctx, db); err != nil {
				return "", objectContext{}, err
			}
		}
		return showCreateContext(ctx, bin.conn, query, ddlCol)
	}
	defer func() {
		if bin != nil {
			bin.Close(ctx)
		}
	}()

	if dbScope && structure {
		routines, err := d.ListRoutines(ctx, db, scope)
		if err != nil {
			return plan, err
		}
		for _, r := range routines {
			kw, col, label := "FUNCTION", "create function", "Function "
			if strings.EqualFold(r.Type, "PROCEDURE") {
				kw, col, label = "PROCEDURE", "create procedure", "Procedure "
			}
			ddl, oc, err := fetch("SHOW CREATE "+kw+" "+qualify(r.Name), col)
			if err != nil {
				return plan, fmt.Errorf("dump %s %s: %w", strings.ToLower(kw), r.Name, err)
			}
			if ddl == "" {
				return plan, fmt.Errorf("mysql: SHOW CREATE %s %s returned no definition (missing SHOW_ROUTINE privilege?)", kw, r.Name)
			}
			pre, post := d.creationGuards(oc)
			plan.Routines = append(plan.Routines, driver.DumpScript{
				Kind:    "routine",
				Comment: label + r.Name,
				Drop:    "DROP " + kw + " IF EXISTS " + d.QuoteIdent(r.Name),
				// mysqldump parity: a routine's drop rides just above its own
				// CREATE, not the reverse teardown block.
				DropInline:     true,
				SQL:            ddl,
				NeedsDelimiter: true,
				OpaqueFrame:    true,
				Pre:            pre,
				Post:           post,
				Markers:        collationMarker("routine", r.Name, oc),
			})
		}

		views, err := d.ListViews(ctx, db, scope)
		if err != nil {
			return plan, err
		}
		names := make([]string, 0, len(views))
		defs := make(map[string]string, len(views))
		for _, v := range views {
			names = append(names, v.Name)
			defs[v.Name] = v.Definition
		}
		// information_schema has no view-dependency data; scan each definition
		// for references to the other view names (conservative: false positives
		// only affect ordering, and TopoOrder tolerates cycles). Precompile one
		// word-boundary matcher per candidate name: the scan is O(n^2), so
		// compiling inside the loop recompiled the same regexp n times.
		wordRE := make(map[string]*regexp.Regexp, len(names))
		for _, w := range names {
			if re, err := regexp.Compile(`(?i)\b` + regexp.QuoteMeta(w) + `\b`); err == nil {
				wordRE[w] = re
			}
		}
		deps := map[string][]string{}
		for _, v := range names {
			for _, w := range names {
				if v != w && viewReferences(defs[v], w, wordRE[w]) {
					deps[v] = append(deps[v], w)
				}
			}
		}
		for _, name := range driver.TopoOrder(names, deps) {
			ddl, oc, err := fetch("SHOW CREATE VIEW "+qualify(name), "create view")
			if err != nil {
				return plan, fmt.Errorf("dump view %s: %w", name, err)
			}
			pre, post := d.creationGuards(oc)
			plan.Views = append(plan.Views, driver.DumpScript{
				Kind:    "view",
				Comment: "View " + name,
				Drop:    "DROP VIEW IF EXISTS " + d.QuoteIdent(name),
				SQL:     ddl,
				// A view body holds no ';', but it is still binary-fetched, so
				// it transits the splitter as an opaque frame like every other
				// object body (NeedsDelimiter alone would route it through the
				// ordinary lexer).
				OpaqueFrame: true,
				Pre:         pre,
				Post:        post,
			})
		}
	}

	// Trigger DDL is structure: a data-only dump discards it (the writer keeps
	// only sequence/refresh items in PostData), so don't introspect it at all.
	if structure {
		triggers, err := d.ListTriggers(ctx, db, scope)
		if err != nil {
			return plan, err
		}
		for _, tr := range triggers {
			if !inTables[tr.Table] {
				continue
			}
			ddl, oc, err := fetch("SHOW CREATE TRIGGER "+qualify(tr.Name), "sql original statement")
			if err != nil {
				return plan, fmt.Errorf("dump trigger %s: %w", tr.Name, err)
			}
			pre, post := d.creationGuards(oc)
			plan.PostData = append(plan.PostData, driver.DumpScript{
				Kind:           "trigger",
				Comment:        "Trigger " + tr.Name,
				Drop:           "DROP TRIGGER IF EXISTS " + d.QuoteIdent(tr.Name),
				SQL:            ddl,
				NeedsDelimiter: true,
				OpaqueFrame:    true,
				Pre:            pre,
				Post:           post,
				Markers:        collationMarker("trigger", tr.Name, oc),
			})
		}
	}

	if dbScope && structure {
		events, err := d.ListEvents(ctx, db, scope)
		if err != nil {
			return plan, err
		}
		for _, e := range events {
			ddl, oc, err := fetch("SHOW CREATE EVENT "+qualify(e.Name), "create event")
			if err != nil {
				return plan, fmt.Errorf("dump event %s: %w", e.Name, err)
			}
			pre, post := d.creationGuards(oc)
			plan.PostData = append(plan.PostData, driver.DumpScript{
				Kind:    "event",
				Comment: "Event " + e.Name,
				Drop:    "DROP EVENT IF EXISTS " + d.QuoteIdent(e.Name),
				// Events live outside the table graph and the reverse teardown
				// walks pre-data only, so their drop rides their own CREATE.
				DropInline:     true,
				SQL:            ddl,
				NeedsDelimiter: true,
				OpaqueFrame:    true,
				Pre:            pre,
				Post:           post,
				Markers:        collationMarker("event", e.Name, oc),
			})
		}
	}
	return plan, nil
}

// objectContext is the creation-context sibling columns a SHOW CREATE row
// carries alongside the object's DDL. Routines/triggers/events report
// sql_mode, the two charset columns and Database Collation; events add
// time_zone; views report only the charset pair. NullString keeps "column
// absent" distinct from "empty value" — an empty sql_mode is a real mode that
// must still be pinned.
type objectContext struct {
	sqlMode     sql.NullString
	csClient    sql.NullString
	collConn    sql.NullString
	timeZone    sql.NullString
	dbCollation sql.NullString
}

// creationGuards renders the mysqldump-style save/set/restore statement pairs
// for an object's creation context. Save variables use the object-local
// @saved_* names — NEVER the preamble's @OLD_* names, which the postamble
// restores last and a per-object guard must not clobber. The set values come
// from the server's own SHOW CREATE row; QuoteString runs under the export
// session's pinned default mode.
func (d dialect) creationGuards(oc objectContext) (pre, post []string) {
	if v := oc.csClient; v.Valid && v.String != "" {
		pre = append(pre,
			"SET @saved_cs_client = @@character_set_client",
			"SET character_set_client = "+d.QuoteString(v.String))
		post = append(post, "SET character_set_client = @saved_cs_client")
	}
	if v := oc.collConn; v.Valid && v.String != "" {
		pre = append(pre,
			"SET @saved_col_connection = @@collation_connection",
			"SET collation_connection = "+d.QuoteString(v.String))
		post = append(post, "SET collation_connection = @saved_col_connection")
	}
	if v := oc.sqlMode; v.Valid {
		pre = append(pre,
			"SET @saved_sql_mode = @@sql_mode",
			"SET sql_mode = "+d.QuoteString(v.String))
		post = append(post, "SET sql_mode = @saved_sql_mode")
	}
	if v := oc.timeZone; v.Valid && v.String != "" {
		pre = append(pre,
			"SET @saved_time_zone = @@time_zone",
			"SET time_zone = "+d.QuoteString(v.String))
		post = append(post, "SET time_zone = @saved_time_zone")
	}
	slices.Reverse(post) // restore in reverse order of setting
	return pre, post
}

// collationMarker renders the db-collation disclosure marker for one object,
// or nil when the SHOW CREATE row carried no Database Collation.
func collationMarker(kind, name string, oc objectContext) []string {
	if !oc.dbCollation.Valid || oc.dbCollation.String == "" {
		return nil
	}
	return []string{driver.FormatCollationMarker(kind, name, oc.dbCollation.String)}
}

// querier abstracts *sql.DB / *sql.Conn for the SHOW CREATE scanners.
type querier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// binaryResults is one pool connection pinned to character_set_results=binary
// so SHOW CREATE returns object bodies as their raw stored bytes. Close
// restores the variable before the connection re-enters the pool; a failed
// restore discards the connection outright (ErrBadConn) so a binary-results
// session can never be handed to a later pool user.
type binaryResults struct {
	conn  *sql.Conn
	saved sql.NullString
}

func openBinaryResults(ctx context.Context, db *sql.DB) (*binaryResults, error) {
	conn, err := db.Conn(ctx)
	if err != nil {
		return nil, err
	}
	b := &binaryResults{conn: conn}
	if err := conn.QueryRowContext(ctx, "SELECT @@character_set_results").Scan(&b.saved); err != nil {
		conn.Close()
		return nil, err
	}
	if _, err := conn.ExecContext(ctx, "SET character_set_results = binary"); err != nil {
		conn.Close()
		return nil, err
	}
	return b, nil
}

func (b *binaryResults) Close(ctx context.Context) {
	// character_set_results may legitimately be NULL ("no conversion").
	restore := "SET character_set_results = NULL"
	if b.saved.Valid {
		// Charset names are [a-z0-9_]; quote-doubling is mode-independent.
		restore = "SET character_set_results = '" + strings.ReplaceAll(b.saved.String, "'", "''") + "'"
	}
	if _, err := b.conn.ExecContext(ctx, restore); err != nil {
		_ = b.conn.Raw(func(any) error { return sqldriver.ErrBadConn })
	}
	_ = b.conn.Close()
}

// showCreateContext runs a SHOW CREATE statement on q (the binary-results
// connection) and returns the DDL column named ddlCol (lower-cased exact
// match) plus the creation-context sibling columns the row carries.
func showCreateContext(ctx context.Context, q querier, query, ddlCol string) (string, objectContext, error) {
	rows, err := q.QueryContext(ctx, query)
	if err != nil {
		return "", objectContext{}, err
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return "", objectContext{}, err
	}
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return "", objectContext{}, err
		}
		return "", objectContext{}, sql.ErrNoRows
	}
	holders := make([]any, len(cols))
	for i := range holders {
		holders[i] = new(sql.NullString)
	}
	if err := rows.Scan(holders...); err != nil {
		return "", objectContext{}, err
	}
	var ddl string
	var oc objectContext
	for i, name := range cols {
		v := *holders[i].(*sql.NullString)
		switch strings.ToLower(name) {
		case ddlCol:
			ddl = v.String
		case "sql_mode":
			oc.sqlMode = v
		case "character_set_client":
			oc.csClient = v
		case "collation_connection":
			oc.collConn = v
		case "time_zone":
			oc.timeZone = v
		case "database collation":
			oc.dbCollation = v
		}
	}
	return ddl, oc, nil
}

// viewReferences reports whether a view definition appears to reference name
// (backtick-quoted, or as a bare word matched by the precompiled wordRE). Used
// only for dump ordering, so a false positive is harmless. wordRE may be nil
// (its name failed to compile), in which case only the quoted form is checked.
func viewReferences(def, name string, wordRE *regexp.Regexp) bool {
	if strings.Contains(def, "`"+name+"`") {
		return true
	}
	return wordRE != nil && wordRE.MatchString(def)
}

// showCreateColumnMatch runs a SHOW CREATE statement and returns the first
// column of its single result row whose name satisfies match. Used by
// CreateSQL, which matches the "Create Table"/"Create View" column by its
// "Create" prefix; DumpObjects uses showCreateContext instead (exact column
// plus the creation-context siblings).
func showCreateColumnMatch(ctx context.Context, db *sql.DB, query string, match func(col string) bool) (string, error) {
	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return "", err
	}
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return "", err
		}
		return "", sql.ErrNoRows
	}
	holders := make([]any, len(cols))
	for i := range holders {
		holders[i] = new(sql.NullString)
	}
	if err := rows.Scan(holders...); err != nil {
		return "", err
	}
	for i, name := range cols {
		if match(name) {
			return holders[i].(*sql.NullString).String, nil
		}
	}
	return "", fmt.Errorf("mysql: no matching column in SHOW CREATE result for %q", query)
}
