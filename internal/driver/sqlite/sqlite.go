// Package sqlite implements the TableX Dialect for SQLite using the pure-Go
// modernc.org/sqlite driver (no CGo). Introspection uses sqlite_master plus the
// PRAGMA family (table_info, index_list, foreign_key_list).
package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"

	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver

	"github.com/tablexdev/tablex/internal/driver"
	"github.com/tablexdev/tablex/internal/model"
)

type dialect struct{}

func init() { driver.Register(dialect{}) }

func (dialect) Name() string          { return "sqlite" }
func (dialect) DisplayName() string   { return "SQLite" }
func (dialect) DefaultPort() int      { return 0 }
func (dialect) SQLDriverName() string { return "sqlite" }

func (dialect) Capabilities() driver.Capabilities {
	return driver.Capabilities{
		HasSchemas:               false,
		HasUsers:                 false,
		HasForeignKeys:           true,
		HasStoredRoutines:        false,
		HasTriggers:              true,
		HasEvents:                false,
		HasViews:                 true,
		SupportsExplain:          true,
		SupportsTransactionalDDL: true,
		SupportsCharset:          false,
		SupportsColumnModify:     false, // SQLite ALTER TABLE cannot change a column
		SupportsColumnRename:     true,  // ... but it has renamed one since 3.25 (modernc.org/sqlite is far newer)
		SupportsForeignKeyDDL:    false, // SQLite cannot add/drop FKs via ALTER TABLE
		CanManageDatabases:       false, // one file == one database
		CanDropConnectedDatabase: false, // irrelevant — CanManageDatabases is already false
		ExecReportsChangedRows:   false, // RowsAffected counts matched rows
		SupportsTruncate:         false, // no TRUNCATE; DELETE FROM empties a table
		RestrictedDropColumn:     true,  // cannot drop a PK/indexed/outgoing-FK column
		DatabasesShareConnection: true,  // one file per connection; ATTACH names are session-scoped
		IsNetworkEngine:          false, // a local file, not a host:port — so no ad-hoc login and no credentials
		IdentifierMaxBytes:       0,     // SQLite imposes no fixed identifier length
	}
}

// RebindDatabase: a SQLite "database" is the file the connection opened (plus
// session-scoped ATTACH names) — a logical database name never maps to a DSN
// parameter, so dial params pass through unchanged.
func (dialect) RebindDatabase(p driver.ConnParams, _ string) driver.ConnParams { return p }

// ValidateFilePath rejects the in-memory spellings for a PREDEFINED server.
// They cannot work behind the connection pool: every pooled connection would
// open its own private empty database, and imports/exports deliberately open
// separate transient connections (OpenPinned / ExportConnFor) that could never
// see the same data. DSN-level support stays — BuildDSN still handles
// :memory: for direct driver use, which is how the tests use it.
func (dialect) ValidateFilePath(path string) error {
	lower := strings.ToLower(strings.TrimSpace(path))
	if lower == ":memory:" || strings.HasPrefix(lower, "file::memory:") || strings.Contains(lower, "mode=memory") {
		return errors.New("in-memory sqlite databases are not supported for predefined servers (each pooled connection would see its own empty database); use a file path")
	}
	return nil
}

// ServerDumpProfile: a server dump covers only "main" (see
// UnaddressableDatabase), with a single global preamble and no section
// headers.
func (dialect) ServerDumpProfile() driver.ServerDumpProfile {
	return driver.ServerDumpProfile{
		FormNote: "ATTACH-ed databases are session-scoped and not included; export them individually at database scope.",
	}
}

func (dialect) WriteServerDumpHeader(w io.Writer) {
	fmt.Fprint(w, "-- ATTACH-ed databases are session-scoped; this dump covers \"main\".\n")
}

func (dialect) WriteDatabaseSectionHeader(io.Writer, string, string) {}

// UnaddressableDatabase: only "main" is dumpable — an ATTACH-ed database is
// session-scoped and would not exist for the restoring session.
func (dialect) UnaddressableDatabase(name string) string {
	if name != "main" {
		return "ATTACH-ed databases are session-scoped and not part of a server dump; export it at database scope instead"
	}
	return ""
}

// sqliteRoutineRe matches the trigger-creating statements whose BEGIN...END
// bodies hold complete inner statements (see LexerProfile.RoutineBodyRe).
// Matched after leading comments are stripped.
var sqliteRoutineRe = regexp.MustCompile(`(?is)^CREATE\s+(TEMP(ORARY)?\s+)?TRIGGER\b`)

// LexerProfile supplies the SQLite script grammar to the statement splitter:
// '$' is an identifier character (never a dollar quote), strings are
// backslash-literal, and CREATE TRIGGER bodies need BEGIN…END tracking.
func (dialect) LexerProfile() driver.LexerProfile {
	return driver.LexerProfile{
		DollarInWords: true,
		// SQLite accepts [name] as a quoted identifier (the MS Access
		// convention it kept for compatibility), and '[' has no other meaning
		// there — no array subscripts. Without this a `;` inside a
		// bracket-quoted name split the statement.
		BracketIdentifiers: true,
		RoutineBodyRe:      sqliteRoutineRe,
		// modernc bundles SQLite >= 3.35, where INSERT/UPDATE/DELETE (and REPLACE,
		// an INSERT-family alias) support RETURNING. UPDATE/DELETE table aliases
		// require AS, so a bare `returning` alias cannot precede the clause. No
		// MERGE in SQLite.
		Returning: driver.ReturningCaps{Insert: true, Update: true, Delete: true, Replace: true},
	}
}

func (dialect) BuildDSN(p driver.ConnParams) (string, error) {
	path := p.FilePath
	if path == "" {
		path = p.Database
	}
	if path == "" {
		return "", errors.New("sqlite: a database file path is required")
	}
	// In-memory databases have no backing file and are not a creation vector.
	memory := path == ":memory:" || strings.HasPrefix(path, "file::memory:")
	if memory {
		// A '#' would start a URI fragment and silently swallow the pragmas
		// appended below. A '?' stays legal here — file::memory:?cache=shared
		// is the documented shared-cache form.
		if strings.Contains(path, "#") {
			return "", errors.New("sqlite: database file path must not contain '#'")
		}
	} else {
		// Defense in depth: the path is operator-configured (SQLite is
		// predefined-only), but reject URI/query control so a stray '?' or '#'
		// cannot smuggle driver parameters or be truncated against the query
		// string we append below.
		if strings.ContainsAny(path, "?#") {
			return "", errors.New("sqlite: database file path must not contain '?' or '#'")
		}
		// Never silently create a missing database file. A missing file is a
		// configuration error, not an invitation to create one — this closes the
		// anonymous file-creation vector. Operators must point a predefined
		// server at an existing database file.
		if _, err := os.Stat(path); err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return "", errors.New("sqlite: database file not found")
			}
			return "", fmt.Errorf("sqlite: cannot access database file: %w", err)
		}
	}
	// Defense in depth for runtime-supplied params: config load already refuses
	// an enabled time-conversion option (driver.ParamsValidator, asked in
	// Config.Validate), but BuildDSN is also reached directly, so it re-checks.
	if err := validateTimeConversionParams(p.Params); err != nil {
		return "", err
	}
	q := url.Values{}
	q.Add("_pragma", "busy_timeout(5000)")
	q.Add("_pragma", "foreign_keys(1)")
	if !memory && !hasJournalModePragma(p.Params) {
		// WAL lets readers proceed while a writer holds the database. Under the
		// default rollback journal a writer blocks every reader, so a concurrent
		// browse and import on the one file surface "database is locked" even
		// though busy_timeout(5000) is waiting for them — TableX serves many
		// requests against a single SQLite file, which is exactly the workload
		// WAL exists for.
		//
		// Unlike the two pragmas above, journal_mode is PERSISTED in the database
		// header and creates -wal/-shm sidecar files. It is a standard,
		// universally supported mode (SQLite 3.7+), reversible, and silently
		// declined by SQLite where WAL cannot work (a network filesystem,
		// read-only media) — the old mode simply stays in force. An operator who
		// wants a different mode sets `_pragma = "journal_mode(DELETE)"` in the
		// server's params, which suppresses this default (hasJournalModePragma):
		// modernc SORTS the _pragma list before executing it (busy_timeout first,
		// then case-insensitive lexicographic — NOT DSN order), so among repeated
		// journal_mode values the lexicographically-largest wins, and "wal" is the
		// largest standard mode. Emitting both would therefore let the default
		// override the operator's choice, so the default is dropped instead.
		// In-memory databases have no journal.
		q.Add("_pragma", "journal_mode(WAL)")
	}
	for k, v := range p.Params {
		q.Add(k, v)
	}
	// A query-bearing memory path already has a '?'; a second one would fold
	// the pragmas into the last existing parameter's value.
	sep := "?"
	if strings.Contains(path, "?") {
		sep = "&"
	}
	return path + sep + q.Encode(), nil
}

// hasJournalModePragma reports whether the operator's server params already set
// a journal mode, in which case BuildDSN must not add its WAL default. modernc
// does not apply repeated _pragma values in DSN order: it SORTS the list and
// executes in that order, so among several journal_mode values the
// lexicographically-largest wins. "wal" is the largest standard mode, so an
// emitted default would override every operator choice — dropping it is what
// lets the operator's value be the only one and therefore take effect.
// (TestSQLitePragmaOrderIsSorted pins the ordering this relies on.)
func hasJournalModePragma(params map[string]string) bool {
	for k, v := range params {
		if strings.EqualFold(k, "_pragma") && strings.Contains(strings.ToLower(v), "journal_mode") {
			return true
		}
	}
	return false
}

// timeConversionParams are the modernc DSN options that make the driver report
// a time.Time scan type — and return one — for a column stored as TEXT or
// INTEGER instead of the stored bytes. TableX assumes those storage classes
// round-trip verbatim in three places: formatValue keeps the string form,
// formatTime narrows a clock-bearing value to its DECLARED type (result.go), and
// the dump engine emits what it scanned. An enabled conversion silently
// corrupts all three, which is why they are refused rather than merely
// documented.
var timeConversionParams = []string{"_texttotime", "_inttotime"}

// validateTimeConversionParams refuses an ENABLED _texttotime/_inttotime — the
// shared core of the ParamsValidator capability (asked at config load) and
// BuildDSN's defense-in-depth check (runtime-supplied params). The driver reads
// each with strconv.ParseBool and only when the value is non-empty (modernc
// sqlite.go), so an absent, empty, or false value is inert and must still start.
// modernc matches these keys case-sensitively through url.Values.Get, so this
// does too: a differently-cased key is an unknown parameter the driver ignores,
// not a live conversion, and refusing it would reject a harmless config.
func validateTimeConversionParams(params map[string]string) error {
	for _, key := range timeConversionParams {
		v, ok := params[key]
		if !ok || v == "" {
			continue
		}
		on, err := strconv.ParseBool(v)
		if err != nil {
			// A non-boolean value is rejected by the driver itself at connect
			// with a precise message; leave that to it rather than duplicating
			// its grammar here. Only an unambiguously enabled value is our
			// concern.
			continue
		}
		if on {
			return fmt.Errorf("sqlite: the %q parameter is not supported — it makes the driver return a time value for a text- or integer-stored column, which TableX's browse, export and row-edit paths would silently narrow or misencode; remove it or set it to false", key)
		}
	}
	return nil
}

// ValidateParams implements driver.ParamsValidator: it refuses an enabled
// time-conversion option before the pool is ever opened.
func (dialect) ValidateParams(params map[string]string) error {
	return validateTimeConversionParams(params)
}

func (dialect) QuoteIdent(name string) string { return driver.QuoteAnsiIdent(name) }

func (dialect) QuoteString(s string) string { return driver.QuoteAnsiString(s) }

func (dialect) Placeholder(int) string { return "?" }

// StorageDDL types TableX's own metadata tables (driver.StorageHost). SQLite's
// type names are affinities rather than constraints, so TEXT and INTEGER cover
// everything; INTEGER is the one that matters, since it is also the affinity a
// Unix-microsecond instant must land in to compare and sort numerically.
func (dialect) StorageDDL() driver.StorageDDL {
	return driver.StorageDDL{ID: "TEXT", Text: "TEXT", Int64: "INTEGER"}
}

func (dialect) LimitClause(limit int, offset int64) string {
	return driver.DefaultLimitClause(limit, offset)
}

func (dialect) InsertDefaultRowSQL(qualified string) string {
	return "INSERT INTO " + qualified + " DEFAULT VALUES"
}

func (d dialect) QualifyTable(t driver.TableRef) string {
	if t.Database != "" && t.Database != "main" {
		return d.QuoteIdent(t.Database) + "." + d.QuoteIdent(t.Table)
	}
	return d.QuoteIdent(t.Table)
}

func (dialect) ExplainSQL(query string, analyze bool) (string, bool) {
	// SQLite has no ANALYZE-style timed explain; report it unsupported rather
	// than silently returning the plain query plan (matches the MySQL dialect).
	if analyze {
		return "", false
	}
	return "EXPLAIN QUERY PLAN " + query, true
}

func (dialect) ServerInfo(ctx context.Context, db *sql.DB) (driver.ServerInfo, error) {
	var version string
	if err := db.QueryRowContext(ctx, "SELECT sqlite_version()").Scan(&version); err != nil {
		return driver.ServerInfo{}, err
	}
	// Report the database's actual text encoding rather than assuming UTF-8.
	charset := "UTF-8"
	var enc sql.NullString
	if err := db.QueryRowContext(ctx, "PRAGMA encoding").Scan(&enc); err == nil && enc.Valid && enc.String != "" {
		charset = enc.String
	}
	return driver.ServerInfo{
		Engine:   "sqlite",
		Flavor:   "SQLite",
		Version:  version,
		Charset:  charset,
		Database: "main",
	}, nil
}

// schemaPrefix returns the quoted "db." prefix for a PRAGMA / sqlite_master
// reference, or "" for the default main database.
func (d dialect) schemaPrefix(database string) string {
	if database == "" || database == "main" {
		return ""
	}
	return d.QuoteIdent(database) + "."
}

func (d dialect) ListDatabases(ctx context.Context, db *sql.DB) ([]model.Database, error) {
	rows, err := db.QueryContext(ctx, "PRAGMA database_list")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Database
	for rows.Next() {
		var seq int
		var name, file sql.NullString
		if err := rows.Scan(&seq, &name, &file); err != nil {
			return nil, err
		}
		out = append(out, model.Database{Name: name.String, TableCount: -1, Size: -1})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// Fill table counts (cheap for local SQLite files). The predicate is the one
	// ListTables uses, so the number equals the number of rows the database
	// structure page shows — it used to omit views and undercount every
	// database that had one.
	for i := range out {
		var n int
		q := fmt.Sprintf("SELECT COUNT(*) FROM %ssqlite_master WHERE type IN ('table','view') AND name NOT LIKE 'sqlite_%%'",
			d.schemaPrefix(out[i].Name))
		if err := db.QueryRowContext(ctx, q).Scan(&n); err == nil {
			out[i].TableCount = n
		}
	}
	return out, nil
}

func (dialect) ListSchemas(context.Context, *sql.DB, string) ([]model.Schema, error) {
	return nil, nil
}

func (d dialect) ListTables(ctx context.Context, db *sql.DB, scope driver.Scope) ([]model.Table, error) {
	q := fmt.Sprintf(`SELECT name, type FROM %ssqlite_master
		WHERE type IN ('table','view') AND name NOT LIKE 'sqlite_%%' ORDER BY name`,
		d.schemaPrefix(scope.Database))
	rows, err := db.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Table
	for rows.Next() {
		var name, typ string
		if err := rows.Scan(&name, &typ); err != nil {
			return nil, err
		}
		t := model.Table{Name: name, Schema: "", Rows: -1, Size: -1, DataSize: -1, IndexSize: -1}
		if typ == "view" {
			t.Type = model.TableView
		} else {
			t.Type = model.TableBase
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (d dialect) Columns(ctx context.Context, db *sql.DB, t driver.TableRef) ([]model.Column, error) {
	// table_xinfo (vs table_info) adds the `hidden` flag, which distinguishes
	// generated columns (2 = VIRTUAL, 3 = STORED) from ordinary ones (0) and
	// internal/hidden columns (1).
	q := fmt.Sprintf("PRAGMA %stable_xinfo(%s)", d.schemaPrefix(t.Database), d.QuoteIdent(t.Table))
	rows, err := db.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Column
	pkCount := 0
	hasGenerated := false
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk, hidden int
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk, &hidden); err != nil {
			return nil, err
		}
		if hidden == 1 {
			continue // internal/hidden column (e.g. a virtual-table shadow column)
		}
		c := model.Column{
			Name: name,
			// Derive the position from the count of columns kept so far, not cid+1:
			// a filtered hidden column (e.g. a virtual-table shadow) would otherwise
			// leave a gap in the displayed sequence (1, 2, 4).
			Position:     len(out) + 1,
			DataType:     ctype,
			BaseType:     driver.BaseTypeName(ctype),
			Nullable:     notnull == 0,
			IsPrimaryKey: pk > 0,
			// PRAGMA table_xinfo hidden: 2 = VIRTUAL, 3 = STORED generated column.
			IsGenerated:   hidden == 2 || hidden == 3,
			GeneratedKind: generatedKind(hidden),
		}
		if dflt.Valid {
			v := dflt.String
			c.Default = &v
			// PRAGMA table_xinfo reports dflt_value as verbatim SQL (literals come
			// with their quotes, expressions as written), never a bare value.
			c.DefaultIsExpr = true
		}
		if pk > 0 {
			pkCount++
		}
		if c.IsGenerated {
			hasGenerated = true
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// A lone INTEGER PRIMARY KEY is SQLite's auto-incrementing rowid alias —
	// unless the table is WITHOUT ROWID (an ordinary primary key) or the column is
	// declared "INTEGER PRIMARY KEY DESC", a documented quirk that is NOT a rowid
	// alias and does not auto-increment. Both need the CREATE TABLE text, which
	// PRAGMA table_xinfo does not expose, so fetch it once and parse for both.
	// The CREATE TABLE text is needed for the rowid-alias detection (a lone
	// INTEGER PRIMARY KEY) and for generated-column expressions (PRAGMA
	// table_xinfo exposes neither), so fetch it once when either applies. A failed
	// lookup returns "" and both consumers degrade gracefully (ordinary rowid
	// table; generated columns keep their marker without a formula).
	if pkCount == 1 || hasGenerated {
		ddl := d.tableDDL(ctx, db, t)
		if pkCount == 1 && !ddlIsWithoutRowid(ddl) && !ddlHasInlinePKDesc(ddl) {
			for i := range out {
				if out[i].IsPrimaryKey && strings.EqualFold(out[i].BaseType, "integer") {
					out[i].IsAutoIncrement = true
				}
			}
		}
		if hasGenerated {
			exprs := parseGeneratedExprs(ddl)
			for i := range out {
				if out[i].IsGenerated {
					if e, ok := exprs[out[i].Name]; ok {
						out[i].GeneratedExpr = e
					}
				}
			}
		}
	}
	return out, nil
}

// generatedKind maps PRAGMA table_xinfo's hidden flag to the neutral
// generated-column kind (2 = VIRTUAL, 3 = STORED; anything else is not a
// generated column).
func generatedKind(hidden int) string {
	switch hidden {
	case 2:
		return "virtual"
	case 3:
		return "stored"
	}
	return ""
}

// tableDDL returns the CREATE TABLE text from sqlite_master, or "" when the
// lookup fails (e.g. a virtual table or transient error). Callers treat "" as
// "ordinary rowid table" to preserve the historical default.
func (d dialect) tableDDL(ctx context.Context, db *sql.DB, t driver.TableRef) string {
	q := fmt.Sprintf("SELECT sql FROM %ssqlite_master WHERE type='table' AND name = ?", d.schemaPrefix(t.Database))
	var ddl sql.NullString
	if err := db.QueryRowContext(ctx, q, t.Table).Scan(&ddl); err != nil || !ddl.Valid {
		return ""
	}
	return ddl.String
}
