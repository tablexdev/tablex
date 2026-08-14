// Package driver is TableX's database abstraction layer.
//
// Everything that genuinely differs between SQL engines lives behind the
// Dialect interface: DSN building, identifier quoting, placeholder syntax,
// metadata introspection and a handful of capability flags. The generic query
// path (open pool, run query, scan rows, paginate) is implemented once on top
// of database/sql in this package, so handlers never import a concrete engine
// package. Adding a new engine means implementing Dialect and registering it —
// nothing else in the application changes.
//
// See docs/database-drivers.md for the design rationale.
package driver

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/tablexdev/tablex/internal/model"
)

// ErrUnsupported is returned by optional Dialect operations that a given engine
// does not provide (e.g. listing events on SQLite). Callers gate on
// Capabilities() before calling, so this is a defensive backstop.
var ErrUnsupported = errors.New("operation not supported by this engine")

// Dialect captures everything that differs between database engines. A single
// value per engine is registered at init time; it is stateless and safe for
// concurrent use (all per-connection state lives in *sql.DB / Connection).
type Dialect interface {
	// Identity.
	Name() string        // canonical id: "mysql", "postgres", "sqlite"
	DisplayName() string // human label: "MySQL / MariaDB", "PostgreSQL", "SQLite"
	DefaultPort() int    // 0 for engines without a network port (SQLite)

	// Connection.
	SQLDriverName() string                 // database/sql driver name: "mysql", "pgx", "sqlite"
	BuildDSN(p ConnParams) (string, error) // engine-specific DSN/connection string

	// SQL syntax.
	QuoteIdent(name string) string // `name` / "name" with correct escaping
	QuoteString(s string) string   // 'literal' with correct escaping (for generated DDL/dumps)
	Placeholder(n int) string      // "?" (n ignored) / "$1"
	// LimitClause renders "LIMIT x OFFSET y" (or the engine equivalent). The
	// offset is int64 end-to-end: browse positions on >2^31-row tables must
	// not truncate through a 32-bit int.
	LimitClause(limit int, offset int64) string
	QualifyTable(t TableRef) string // engine-correct "[db|schema.]table", quoted
	// InsertDefaultRowSQL renders an INSERT that adds one all-defaults row, for a
	// table with NO insertable (non-generated) columns — a zero-column table, or
	// one whose every column is generated (both legal in PostgreSQL). Without it a
	// SQL dump silently loses every such row. PostgreSQL/SQLite use DEFAULT VALUES;
	// MySQL uses the empty () VALUES () form. qualified is already quoted.
	InsertDefaultRowSQL(qualified string) string

	// Connection-scoped helpers.
	ServerInfo(ctx context.Context, db *sql.DB) (ServerInfo, error)

	// Introspection — each takes ctx + *sql.DB and returns neutral model types.
	ListDatabases(ctx context.Context, db *sql.DB) ([]model.Database, error)
	ListSchemas(ctx context.Context, db *sql.DB, database string) ([]model.Schema, error)
	ListTables(ctx context.Context, db *sql.DB, scope Scope) ([]model.Table, error)
	Columns(ctx context.Context, db *sql.DB, t TableRef) ([]model.Column, error)
	Indexes(ctx context.Context, db *sql.DB, t TableRef) ([]model.Index, error)
	ForeignKeys(ctx context.Context, db *sql.DB, t TableRef) ([]model.ForeignKey, error)
	CreateSQL(ctx context.Context, db *sql.DB, t TableRef) (string, error)

	// Extended introspection. Implementations whose Capabilities report the
	// feature absent should return an empty slice (not an error).
	ListViews(ctx context.Context, db *sql.DB, scope Scope) ([]model.View, error)
	ListRoutines(ctx context.Context, db *sql.DB, scope Scope) ([]model.Routine, error)
	ListTriggers(ctx context.Context, db *sql.DB, scope Scope) ([]model.Trigger, error)
	ListEvents(ctx context.Context, db *sql.DB, scope Scope) ([]model.Event, error)
	ListUsers(ctx context.Context, db *sql.DB) ([]model.User, error)

	// ExplainSQL wraps a query for EXPLAIN; ok is false when unsupported.
	ExplainSQL(query string, analyze bool) (sql string, ok bool)

	Capabilities() Capabilities
}

// Privileger is an optional Dialect capability for listing privilege grants
// scoped to a database (ref.Table == "") or a specific table. Engines without an
// access-control system (SQLite) do not implement it, and the handlers degrade
// gracefully.
type Privileger interface {
	Privileges(ctx context.Context, db *sql.DB, ref TableRef) ([]model.Privilege, error)
}

// DatabaseManager is an optional Dialect capability for server-level database
// administration (CREATE / DROP DATABASE). Engines whose Capabilities report
// CanManageDatabases implement it; SQLite (one file per connection) does not.
// The name is quoted with QuoteIdent inside the builder; the handler validates
// it (ValidNewIdentifier for create, introspection match for drop) first.
type DatabaseManager interface {
	// CreateDatabaseSQL creates the database. collation, when non-empty, is a
	// default collation for the new database (MySQL/MariaDB `COLLATE …`; the
	// charset is implied by the collation). It is emitted as a BARE identifier
	// (backtick-quoting is invalid in that position), so the handler MUST have
	// validated it against the server's introspected collation list
	// (CollationLister) — never pass raw user input. Engines whose Capabilities
	// lack SupportsCharset ignore it.
	CreateDatabaseSQL(name, collation string) string
	// DropDatabaseSQL drops the database. PostgreSQL emits WITH (FORCE) (13+) so
	// the drop terminates OTHER sessions still connected to it rather than
	// failing; it cannot drop the database its own session is connected to, so
	// the caller must run it on a connection bound elsewhere.
	DropDatabaseSQL(name string) string
}

// Collation is one server collation and the character set it belongs to, for
// the create-database form (offer) and its validation (allowlist).
type Collation struct {
	Name    string
	Charset string
	Default bool // the charset's default collation
}

// CollationLister is an optional Dialect capability: engines whose CREATE
// DATABASE accepts a collation (Capabilities.SupportsCharset) implement it so
// the create-database form can offer — and the handler validate against — the
// server's real collation list (information_schema.COLLATIONS).
type CollationLister interface {
	ListCollations(ctx context.Context, db *sql.DB) ([]Collation, error)
}

// BulkIntrospector is an optional Dialect capability: one catalog query
// returns the columns (and one the foreign keys) of EVERY table in a scope,
// replacing a per-table N+1 on schema-wide pages (designer) and export
// preflight. Engines whose catalog is inherently per-table (SQLite PRAGMA) omit
// it, and callers fall back to the per-table methods. Implementations MUST be
// built on the same query as the per-table method (a shared scan with an
// optional table filter) so the two paths cannot drift.
type BulkIntrospector interface {
	BulkColumns(ctx context.Context, db *sql.DB, scope Scope) (map[string][]model.Column, error)
	BulkForeignKeys(ctx context.Context, db *sql.DB, scope Scope) (map[string][]model.ForeignKey, error)
}

// FilePathValidator is an optional Dialect capability for a file-backed engine
// (Capabilities.IsNetworkEngine false): reject an operator-configured database
// file path that the engine could technically open but that cannot work as a
// predefined server, at config load rather than at first use. SQLite refuses
// the in-memory spellings — every pooled or transient connection would open its
// own private empty database.
//
// The error is surfaced to the operator verbatim (prefixed with the server's
// position and name), so it must read as a complete explanation on its own.
type FilePathValidator interface {
	ValidateFilePath(path string) error
}

// ParamsValidator is an optional Dialect capability — the params-map
// counterpart of FilePathValidator — for a file-backed engine that accepts
// free-form driver parameters (SQLite's DSN pragmas and modernc's query
// options). It rejects, at config load, a parameter the driver would accept but
// that breaks an invariant the rest of TableX relies on. SQLite refuses the
// text→time and int→time conversions: they make the driver return a time.Time
// for a TEXT- or INTEGER-stored column, and TableX's browse, export and
// row-edit-save paths all assume those storage classes round-trip verbatim
// (formatTime narrows a clock-bearing value to its declared type; the dump
// engine emits the scanned representation).
//
// Only an ENABLED value is refused; the disabled spellings (…=false) are inert
// and must still start. The error is surfaced to the operator verbatim
// (prefixed with the server's position and name, or with "storage.params"), so
// it must read as a complete explanation on its own.
type ParamsValidator interface {
	ValidateParams(params map[string]string) error
}

// MaintenanceDatabaseLister is an optional Dialect capability naming the
// databases a session may connect to in order to run a statement it cannot run
// on its own connection — today, DROP DATABASE against the database the session
// is bound to (Capabilities.CanDropConnectedDatabase false). PostgreSQL returns
// "postgres" then "template1": a managed host often blocks the postgres
// database, which is exactly why user-database logins exist, so template1 is
// the fallback.
//
// The slice is in preference order; the caller tries each in turn and skips the
// database being operated on. Engines that can act on their own connection
// (MySQL) or have no server-level databases at all (SQLite) omit it, and the
// operation is refused with a clear message rather than guessing a name.
//
// Implementations MUST return a fresh slice — the value is shared by every
// session.
type MaintenanceDatabaseLister interface {
	MaintenanceDatabases() []string
}

// SchemaManager is an optional Dialect capability for schema-level management
// inside one database (PostgreSQL). Engines whose Capabilities report
// HasSchemas implement it. Names are quoted with QuoteIdent in the builders;
// the handler validates them first (ValidNewIdentifier for create,
// introspection match for drop). The statements must run on a connection bound
// to the target database — schemas are per-database objects.
type SchemaManager interface {
	CreateSchemaSQL(name string) string
	// DropSchemaSQL drops the schema and every object in it (CASCADE); the
	// handler shows an explicit confirmation before invoking it.
	DropSchemaSQL(name string) string
}

// PoolOpener is an optional Dialect capability: a network engine implements it
// to build its *sql.DB pool through a driver.Connector so ConnParams.DialControl
// can be applied to every connection (the dial-time SSRF guard). Engines without
// a network (SQLite) omit it, and Open falls back to the generic
// sql.Open(SQLDriverName(), BuildDSN()) path.
type PoolOpener interface {
	OpenPool(p ConnParams) (*sql.DB, error)
}

// StorageHost is an optional Dialect capability for engines that can host
// TableX's OWN metadata database — the durable state described in
// internal/storage, as opposed to the databases a user administers. An engine
// that omits it simply cannot be named as the storage backend (config refuses
// it by name at startup); every other capability is unaffected.
//
// It is deliberately the smallest interface in this file. The metadata schema is
// written once, by TableX, in portable SQL — CREATE TABLE IF NOT EXISTS,
// positional placeholders, no engine-specific clauses — so the only thing left
// for a dialect to supply is the SPELLING of a handful of column types.
type StorageHost interface {
	StorageDDL() StorageDDL
}

// StorageDDL names the column types internal/storage's schema needs, in one
// engine's spelling, plus whatever must be appended to a CREATE TABLE.
//
// The vocabulary is three types long on purpose: every field internal/storage
// stores is an identifier, some text, or a 64-bit integer. Most notably there is
// no timestamp — an instant is an Int64 of Unix MICROSECONDS, UTC. A portable
// timestamp type does not exist across these engines (SQLite has no date type at
// all; MySQL and PostgreSQL disagree about whether a column carries a zone, and
// their drivers disagree about what Go type to scan one into), so the schema
// avoids the question rather than papering over it. Comparisons and ordering on
// an integer instant behave identically everywhere.
type StorageDDL struct {
	// ID types a short ASCII identifier — at most 64 characters — that must be
	// usable as a PRIMARY KEY and inside an index. That requirement is why it is
	// not simply Text: MySQL cannot index a TEXT column without a prefix length.
	ID string
	// Text types unbounded UTF-8 text.
	Text string
	// Int64 types a signed 64-bit integer.
	Int64 string
	// TableOptions is appended verbatim to every CREATE TABLE (empty for engines
	// that need nothing). It must begin with a space if non-empty. MySQL pins
	// both the character set — a server defaulting to latin1 would otherwise
	// silently mangle non-ASCII text — and a transactional engine, which the
	// storage layer's atomic updates require.
	TableOptions string
}

// RowEstimator is an optional Dialect capability returning the engine's
// statistics-based row-count estimate for a table (MySQL information_schema
// TABLE_ROWS, PostgreSQL reltuples, SQLite sqlite_stat1). It returns -1 when
// no usable estimate exists (never-analyzed relation, view — SQLite returns
// -1 until ANALYZE has run); callers then fall back to an exact COUNT(*).
type RowEstimator interface {
	EstimateRows(ctx context.Context, db *sql.DB, t TableRef) (int64, error)
}

// NameLister is an optional Dialect capability providing cheap, identity-only
// listings for navigation trees, existence checks and counts. Implementations
// populate only Name/Schema/Type (tables) and Name/IsSystem (databases) and
// must avoid per-object statistics — the full ListDatabases/ListTables queries
// aggregate sizes and row counts, which on MySQL and PostgreSQL touch table
// statistics or stat the relation files for every object. Engines whose full
// listings are already statistics-free (SQLite) omit it and the Connection
// passthrough falls back.
type NameLister interface {
	ListDatabaseNames(ctx context.Context, db *sql.DB) ([]model.Database, error)
	ListTableNames(ctx context.Context, db *sql.DB, scope Scope) ([]model.Table, error)
}

// SearchCaster is an optional Dialect capability returning the SQL expression
// used to LIKE-match a column in the search features. PostgreSQL implements it
// to cast the quoted identifier to text — uuid/json/bool/enum/inet/array
// columns reject a bare LIKE outright there, which silently dropped whole
// tables from database search and failed table search. Engines whose LIKE
// coerces implicitly (MySQL, SQLite) omit it and the identifier is used as-is.
type SearchCaster interface {
	SearchExpr(quotedIdent string) string
}

// Monitor is an optional capability for server-level status, configuration
// variables and the process list. Handlers type-assert a Dialect to Monitor and
// gracefully degrade when an engine does not implement it (e.g. SQLite returns
// empty process lists). All built-in dialects implement it.
type Monitor interface {
	Status(ctx context.Context, db *sql.DB) ([]model.Variable, error)
	Variables(ctx context.Context, db *sql.DB) ([]model.Variable, error)
	Processes(ctx context.Context, db *sql.DB) (*ResultSet, error)
}

// ProgramKind names a STORED PROGRAM — a routine, trigger or event — as opposed
// to the relation kinds (ObjectTable / ObjectView / ObjectMatView) that
// SchemaEditor's DropObjectSQL and RenameObjectSQL take. The two vocabularies
// are deliberately separate: they name different things, are consumed by
// different capabilities, and a single Object* family spanning both would invite
// passing a trigger where a table is meant. "Stored program" is MySQL's own term
// for the group.
//
// It is a closed set the caller maps a listing row onto, so a dialect only ever
// sees a kind for an object it listed in the first place.
type ProgramKind string

const (
	ProgramProcedure ProgramKind = "procedure"
	ProgramFunction  ProgramKind = "function"
	ProgramTrigger   ProgramKind = "trigger"
	ProgramEvent     ProgramKind = "event"
)

// DefinitionViewer is an optional Dialect capability returning the full,
// replayable CREATE statement for ONE named object.
//
// It exists because model.Routine/Trigger/Event.Definition holds whatever the
// engine's catalog cheaply reports alongside the listing, and that is not the
// same artefact on every engine. PostgreSQL's pg_get_functiondef and
// pg_get_triggerdef, and SQLite's sqlite_master.sql, are already complete CREATE
// statements. MySQL's information_schema ROUTINE_DEFINITION/ACTION_STATEMENT is
// the BODY only — no signature, no parameter list, no DEFINER — which is why the
// dump path reads SHOW CREATE instead (see the mysql DumpObjects comment). MySQL
// therefore implements this; engines whose listed Definition is already complete
// omit it and Connection.ObjectDefinition reports "not supported" so the caller
// falls back to the listing, paying no second round-trip.
//
// name must ALREADY have been validated against a listing from this same
// scope — implementations quote it, they do not check that it exists.
type DefinitionViewer interface {
	ObjectDefinition(ctx context.Context, db *sql.DB, scope Scope, kind ProgramKind, name string) (string, error)
}

// ColumnPlacement says where a column sits in the table's column order. Only
// MySQL/MariaDB can express this (FIRST / AFTER col); PostgreSQL and SQLite
// have no reordering statement, so they report SupportsColumnPosition false
// and ignore it. The zero value keeps whatever the engine would do on its own:
// append for ADD COLUMN, leave the column where it is for a MODIFY.
type ColumnPlacement int

const (
	PlaceDefault ColumnPlacement = iota
	PlaceFirst
	PlaceAfter
)

// ColumnSpec describes a column to add or modify. Default is nil for "no
// default"; a non-nil *Default is a pre-validated literal or expression emitted
// verbatim (the handler validates it and, for string types, quotes it via
// QuoteString before populating this). Type is the assembled, already-validated
// engine type (an allowlisted base type plus an optional length/precision).
type ColumnSpec struct {
	Name     string
	Type     string
	Comment  string
	Nullable bool
	Default  *string
	// DefaultExpr marks Default as an expression carried verbatim from
	// introspection (CURRENT_TIMESTAMP, nextval(...), (uuid())), as opposed to a
	// literal the form produced. MySQL wraps non-temporal expression defaults in
	// the parentheses its grammar requires; without this flag an expression
	// default re-applied through the editor would be re-quoted into a string
	// literal ('CURRENT_TIMESTAMP').
	DefaultExpr bool

	// Attributes preserved across a whole-definition MODIFY (MySQL restates the
	// entire column, so anything omitted is dropped). The handler fills these
	// from the existing column before ModifyColumnSQL; the add path leaves them
	// zero. Engines that modify per-attribute (PostgreSQL) ignore them, except
	// Identity, which PostgreSQL needs to avoid DROP/SET DEFAULT on an identity
	// column (a hard error).
	AutoIncrement bool   // MySQL AUTO_INCREMENT
	Unsigned      bool   // MySQL UNSIGNED numeric attribute
	Zerofill      bool   // MySQL ZEROFILL numeric attribute
	OnUpdate      string // MySQL "ON UPDATE <expr>" (validated CURRENT_TIMESTAMP[(n)])
	Collation     string // column collation to preserve (bare identifier)
	Charset       string // MySQL column character set to preserve (bare identifier)
	Identity      string // PostgreSQL identity mode to preserve: "" / "always" / "default"

	// Placement moves the column within the table's column ORDER. Only engines
	// that set Capabilities.SupportsColumnPosition act on it; the others MUST
	// ignore it rather than approximate it — PostgreSQL and SQLite have no way
	// to reorder columns at all, and the only faithful alternative (rebuild the
	// table, copy the data, swap it in) is not something a column edit should
	// do behind the user's back.
	Placement ColumnPlacement
	// PlacementAfter names the EXISTING column that Placement == PlaceAfter
	// refers to. The caller validates it against introspection first, and must
	// reject the column being modified naming itself.
	PlacementAfter string

	// SameBaseType is set on a MODIFY when the new base type matches the existing
	// one (only length/precision/attributes changed). PostgreSQL uses it to omit
	// the "USING col::type" cast: a same-base change needs no cast and, on a
	// shrink that would lose data, errors cleanly instead of silently truncating.
	// Other engines ignore it; the add path leaves it false.
	SameBaseType bool
}

// SchemaEditor is an optional Dialect capability for structure editing (DDL).
// Engines opt in by implementing it; handlers discover it via a type assertion,
// mirroring Monitor. Every identifier in the returned statements is quoted with
// QuoteIdent inside the builder — the handler validates identifiers first (new
// names via ValidNewIdentifier, existing objects by exact match against
// introspection). Builders return one or more statements: a PostgreSQL column
// "modify" expands to several ALTER COLUMN steps; other engines return a single
// statement. Referential actions passed to the FK builders are pre-validated
// keywords emitted verbatim.
// Object kinds for DropObjectSQL / RenameObjectSQL. matview is PostgreSQL-only;
// other engines treat it as a plain view.
const (
	ObjectTable   = "table"
	ObjectView    = "view"
	ObjectMatView = "matview"
)

type SchemaEditor interface {
	ColumnTypes() []string // curated base-type allowlist for the UI + validation
	// CreateTableSQL builds the statements for a NEW table: t names it (the
	// handler validates the name and non-existence first), cols is the full
	// ordered column list, pk the PRIMARY KEY column names (each must appear in
	// cols; empty for no PK). One CREATE TABLE statement — PK inline or as a
	// table constraint — plus any trailing comment statements the engine needs.
	// Implementations reject empty cols and unknown pk entries via
	// ValidateCreateTable.
	CreateTableSQL(t TableRef, cols []ColumnSpec, pk []string) ([]string, error)
	AddColumnSQL(t TableRef, c ColumnSpec) ([]string, error)
	DropColumnSQL(t TableRef, col string) ([]string, error)
	// DropObjectSQL emits the DROP for a table, view or materialized view. kind
	// is one of the Object* constants; matview is PostgreSQL-only (other engines
	// treat it as a view). Routing DROP through the dialect keeps a
	// DROP TABLE-on-a-view (which errors on every engine) from ever being emitted.
	DropObjectSQL(t TableRef, kind string) ([]string, error)
	// RenameObjectSQL renames a table, view or materialized view to newName. kind
	// selects the correct statement where engines differ: a MySQL view cannot be
	// renamed with ALTER TABLE (error 1347) and needs RENAME TABLE; a PostgreSQL
	// materialized view uses ALTER MATERIALIZED VIEW.
	RenameObjectSQL(t TableRef, newName, kind string) ([]string, error)
	AddIndexSQL(t TableRef, spec IndexSpec) ([]string, error)
	DropIndexSQL(t TableRef, name string) ([]string, error)
}

// ColumnModifier is the SchemaEditor half that changes an EXISTING column in
// place. It is separate because SQLite has no such statement at all — ALTER
// TABLE there can add, drop and rename a column but never redefine one — and
// folding it into SchemaEditor forced SQLite to carry a method that only ever
// returned an error, duplicating what Capabilities.SupportsColumnModify already
// says. An engine that sets that flag MUST implement this.
//
// A PostgreSQL "modify" expands to several ordered ALTER COLUMN steps; other
// engines restate the whole column in one statement, which is why the caller
// fills the spec with the attributes the form cannot express first (see
// ColumnSpec).
type ColumnModifier interface {
	ModifyColumnSQL(t TableRef, old string, c ColumnSpec) ([]string, error)
}

// IndexColumn is one key part of an index, in key order.
type IndexColumn struct {
	Name string
	// Desc orders this key part descending. Only set it when
	// IndexOptions().SupportsDesc — MariaDB, for one, PARSES the keyword and
	// then ignores it, which is worse than refusing it.
	Desc bool
	// Prefix indexes only the leading Prefix characters/bytes of the column
	// (MySQL's col(10)). Zero indexes the whole value. Only set it when
	// IndexOptions().SupportsPrefix.
	Prefix int
}

// IndexSpec describes an index to create. It replaced a (name, cols, unique)
// argument list because everything past "unique" is engine-optional, and three
// more positional parameters would have forced every dialect to carry
// arguments it ignores.
//
// The handler validates every part against IndexOptions() before this is
// built, so a dialect can assume it was handed only what it said it supports.
type IndexSpec struct {
	Name    string
	Columns []IndexColumn
	Unique  bool
	// Method is the access method / index type: an entry from
	// IndexOptions().Methods, or "" for the engine default. It is emitted as a
	// keyword, so only an allowlisted value may reach it.
	Method string
	// Where is a partial index's predicate: user-written SQL, split under the
	// dialect's own lexer and required to be ONE statement (docs/security.md).
	Where string
}

// IndexOptions reports which optional parts of an index an engine can express,
// so the UI offers exactly those and the handler refuses the rest. An engine
// with none of them omits IndexOptioner entirely and gets the zero value.
type IndexOptions struct {
	// Methods are the offerable access methods, engine spelling. Empty means
	// the engine has no choice to make (MySQL: the storage engine decides).
	Methods []string
	// SupportsDesc: a descending key part is honoured, not merely parsed.
	SupportsDesc bool
	// SupportsPrefix: a key part may index a leading prefix of the value.
	SupportsPrefix bool
	// SupportsPartial: the index may carry a WHERE predicate.
	SupportsPartial bool
}

// IndexOptioner is the optional capability declaring the above. A dialect that
// implements it must honour what it claims: drivertest checks that each
// claimed option actually changes the statement AddIndexSQL builds, because a
// silently-dropped option is a promise the UI keeps making and the database
// never hears.
type IndexOptioner interface {
	IndexOptions() IndexOptions
}

// ValueListTyper is the optional capability for column types defined by a LIST
// OF VALUES rather than a length or precision — MySQL's ENUM and SET. The
// column editor needs two things from the dialect to offer them: which of its
// ColumnTypes() entries take a value list, and how that list is spelled.
//
// It is the dialect's job because the spelling is engine syntax. PostgreSQL has
// enumerated types but they are user-defined types (CREATE TYPE … AS ENUM), not
// an inline column type, and it has no SET at all; SQLite has neither. Both
// therefore omit this, and the editor's value-list control does not appear.
//
// ValueListType is the ONLY place a user-supplied value reaches a type
// definition, so implementations MUST quote each value through QuoteString.
// The values arrive exactly as typed — they are data, not identifiers, and
// nothing upstream can allowlist them.
type ValueListTyper interface {
	// ValueListTypes returns the base types requiring a value list, spelled as
	// they appear in ColumnTypes().
	ValueListTypes() []string
	// ValueListType assembles the type. base is an allowlisted ColumnTypes()
	// entry; values is the user's list, non-empty, in order. It returns an
	// error for a list this engine cannot accept (a duplicate, or more members
	// than the type allows).
	ValueListType(base string, values []string) (string, error)
}

// ColumnRenamer renames a column WITHOUT restating its definition. It is its
// own capability rather than a field on ColumnSpec because renaming and
// redefining do not travel together:
//
//   - SQLite implements no ColumnModifier at all — it cannot redefine a column
//     — yet it has had ALTER TABLE … RENAME COLUMN since 3.25. Folding rename
//     into the modify path would lock out the one engine whose only column
//     edit IS a rename.
//   - MariaDB below 10.5.2 is the mirror image: it can redefine a column but
//     has no RENAME COLUMN, which is why SupportsColumnRename is decided from
//     the detected server version rather than inferred from
//     SupportsColumnModify.
//
// Keeping it separate also keeps a rename from being a redefinition by
// accident. MySQL's other spelling, CHANGE, restates the whole column, so a
// rename issued that way silently applies every attribute the form could not
// express; RENAME COLUMN touches the name and nothing else.
//
// old is validated by the caller against introspection and newName via
// ValidNewIdentifier; implementations only quote and assemble. An engine that
// sets SupportsColumnRename MUST implement this.
type ColumnRenamer interface {
	RenameColumnSQL(t TableRef, old, newName string) ([]string, error)
}

// RoutineManager administers stored routines, as TriggerManager and EventManager
// do for triggers and events (see ProgramKind). They are three interfaces rather
// than one because engines
// support the three kinds independently — SQLite has triggers but neither
// routines nor events, and only MySQL has events — and folding them together
// would hand SQLite two methods that never do anything but return an error.
// That is precisely the shape ColumnModifier and ForeignKeyEditor were split out
// of SchemaEditor to avoid.
//
// Each takes the LISTED model object rather than a bare name. The caller
// resolves it from introspection first, so the identifier reaching QuoteIdent is
// one the catalog returned; the engine then reads whatever else it needs from
// the same object — PostgreSQL needs a trigger's table to say
// DROP TRIGGER … ON …, and a routine's argument signature to name an overloaded
// function unambiguously.
// The New*Template methods return the skeleton the "new object" editor opens
// with. They are engine SQL — MySQL's BEGIN…END body and PostgreSQL's
// dollar-quoted plpgsql block share no syntax — so the dialect owns them; the
// editor never assembles a statement of its own.
type RoutineManager interface {
	DropRoutineSQL(s Scope, r model.Routine) ([]string, error)
	NewRoutineTemplate(kind ProgramKind) string
}

type TriggerManager interface {
	DropTriggerSQL(s Scope, t model.Trigger) ([]string, error)
	// table is the table the editor was opened from, or "" at database level.
	NewTriggerTemplate(table string) string
}

type EventManager interface {
	DropEventSQL(s Scope, e model.Event) ([]string, error)
	NewEventTemplate() string
}

// programDDLRe matches the head of a stored-program CREATE. It is deliberately
// separate from mysql's own routine-body matcher, which drives the script
// LEXER: coupling them would let a lexing change quietly redefine what the
// editor accepts.
var programDDLRe = regexp.MustCompile(
	`(?is)^\s*CREATE\s+(?:OR\s+REPLACE\s+)?(?:DEFINER\s*=\s*\S+\s+)?(?:AGGREGATE\s+)?(PROCEDURE|FUNCTION|TRIGGER|EVENT)\b`)

// ProgramDDLKind reports the stored-program kind a CREATE statement declares.
// The editor uses it to refuse a statement that is not a CREATE at all, or
// creates a different kind of object than the page it was submitted from — so
// "edit this trigger" cannot quietly run something else.
func ProgramDDLKind(stmt string) (ProgramKind, bool) {
	m := programDDLRe.FindStringSubmatch(stmt)
	if m == nil {
		return "", false
	}
	switch strings.ToUpper(m[1]) {
	case "PROCEDURE":
		return ProgramProcedure, true
	case "FUNCTION":
		return ProgramFunction, true
	case "TRIGGER":
		return ProgramTrigger, true
	case "EVENT":
		return ProgramEvent, true
	}
	return "", false
}

// TableMaintenanceOp is one maintenance command an engine offers for a table.
type TableMaintenanceOp struct {
	Name  string // stable key the form posts back ("optimize")
	Label string // button text ("Optimize")
	Note  string // one line explaining what it does, shown as the button's title
	// Confirm, when non-empty, is the prompt shown before running. Set it for
	// anything that takes a heavy lock or rewrites the table — these operations
	// are not destructive, but running one on a large production table by
	// accident is its own kind of damage.
	Confirm string
}

// TableMaintainer is an optional capability exposing the engine's table
// maintenance commands (MySQL's OPTIMIZE/CHECK/REPAIR/ANALYZE, PostgreSQL's
// VACUUM/ANALYZE/REINDEX, SQLite's ANALYZE).
//
// The offered set is data, not a fixed enum, because the commands have almost
// nothing in common across engines; the handler renders whatever the dialect
// lists and will only run a name from that same list.
//
// Results come back as a ResultSet: MySQL's CHECK and REPAIR report their
// findings as rows, and discarding them would make "check this table" useless.
// Engines whose commands return nothing simply produce no rows.
type TableMaintainer interface {
	TableMaintenanceOps() []TableMaintenanceOp
	TableMaintenanceSQL(t TableRef, op string) (string, error)
}

// ForeignKeyEditor is the SchemaEditor half that adds and drops foreign-key
// constraints, split out for the same reason as ColumnModifier: SQLite cannot
// ALTER a table to add or drop one, so it carried two more error-only stubs.
// An engine that sets Capabilities.SupportsForeignKeyDDL MUST implement this.
//
// The referential actions reaching these builders are pre-validated keywords,
// emitted verbatim.
type ForeignKeyEditor interface {
	AddForeignKeySQL(t TableRef, name string, cols []string, refTable string, refCols []string, onUpdate, onDelete string) ([]string, error)
	DropForeignKeySQL(t TableRef, name string) ([]string, error)
}

// ConnParams are the user-supplied connection inputs collected at login,
// translated by each Dialect into an engine-specific DSN.
type ConnParams struct {
	Host     string
	Socket   string
	Port     int
	User     string
	Password string
	Database string            // optional for MySQL; required for PostgreSQL
	FilePath string            // SQLite database file path
	SSLMode  string            // engine-specific TLS preference (sslmode / tls)
	Params   map[string]string // extra driver params, merged last

	// DialControl, when non-nil, is installed as the net.Dialer.Control hook on
	// every TCP connection opened from these params. It re-validates the
	// *resolved peer IP* of each connection (the SSRF / DNS-rebinding backstop:
	// a rebinding DNS answer cannot slip past the pre-flight resolution because
	// the address actually dialed is re-checked). It is set only for ad-hoc
	// network logins; predefined servers are operator-trusted and carry no
	// dial-time restriction. SQLite ignores it (no network).
	DialControl func(network, address string, c syscall.RawConn) error

	// OnStatement, when non-nil, is notified after each statement this
	// connection runs — the audit trail's statement half. It rides ConnParams
	// rather than being set on a Connection so that every DERIVED dial inherits
	// it for free: the session stamps it once at login and the per-database
	// pools, pinned script connections and export connections all carry it.
	//
	// Which statements reach it is deliberately asymmetric, and the asymmetry is
	// the whole design: see StatementObserver.
	OnStatement StatementObserver

	// Tuning carries the operator's pool and statement-timeout settings down
	// every dial. It rides ConnParams rather than a package-level variable so
	// there is no shared mutable state and a test can dial with its own values:
	// the session's base params are stamped once at login, and every derived
	// dial (per-database pool, pinned script, export connection, maintenance
	// connection) copies them for free. A zero Tuning means "driver defaults".
	Tuning Tuning
}

// Tuning is the operator-settable connection behaviour Open applies. Zero
// fields fall back to the package defaults, so a caller that does not care can
// leave the whole struct zero.
type Tuning struct {
	// MaxOpenConns / MaxIdleConns size a pool. OpenPinned ignores both: a pinned
	// script is one physical session by definition.
	MaxOpenConns int
	MaxIdleConns int
	// ReadStmtTimeout overrides the per-statement budget for generated reads
	// (see the ReadStmtTimeout constant for exactly which statements).
	ReadStmtTimeout time.Duration
}

// Defaults for a zero Tuning. Pool sizing is deliberately modest: PoolCap
// multiplies it, and the product is what has to stay clear of the server's own
// max_connections.
const (
	DefaultMaxOpenConns = 8
	DefaultMaxIdleConns = 4
)

// resolve fills a Tuning's zero fields with the package defaults.
func (t Tuning) resolve() Tuning {
	if t.MaxOpenConns <= 0 {
		t.MaxOpenConns = DefaultMaxOpenConns
	}
	if t.MaxIdleConns <= 0 {
		t.MaxIdleConns = DefaultMaxIdleConns
	}
	if t.MaxIdleConns > t.MaxOpenConns {
		// database/sql would silently clamp idle down to open; do it here so the
		// value a Connection reports back is the one actually in force.
		t.MaxIdleConns = t.MaxOpenConns
	}
	if t.ReadStmtTimeout <= 0 {
		t.ReadStmtTimeout = ReadStmtTimeout
	}
	return t
}

// Capabilities advertises which features an engine supports. The UI reads these
// and never assumes a feature exists, so tabs/links appear only where valid.
type Capabilities struct {
	HasSchemas bool // PostgreSQL: true; MySQL/SQLite: false
	HasUsers   bool // privilege management
	// HasForeignKeys / HasStoredRoutines / HasTriggers / HasEvents / HasViews:
	// the engine has the object kind at all. The four with a Connection listing
	// gate it (ListViews / ListRoutines / ListTriggers / ListEvents return an
	// empty slice without a round-trip when false), so a dialect that lacks the
	// kind does not have to implement a stub that queries for nothing.
	HasForeignKeys           bool
	HasStoredRoutines        bool
	HasTriggers              bool
	HasEvents                bool // MySQL/MariaDB scheduled events
	HasViews                 bool
	SupportsExplain          bool
	SupportsTransactionalDDL bool // DDL rolls back with its transaction. PG/SQLite: true; MySQL: false
	SupportsCharset          bool // CREATE DATABASE ... CHARACTER SET (MySQL)
	SupportsColumnModify     bool // ALTER COLUMN type/null/default (MySQL/PG; not SQLite) — SQLite's ALTER TABLE REACH, which SupportsTransactionalDDL is not about
	SupportsColumnRename     bool // ALTER TABLE ... RENAME COLUMN (all three; MariaDB needs 10.5.2+)
	SupportsColumnPosition   bool // FIRST / AFTER col placement on ADD and MODIFY (MySQL only)
	SupportsForeignKeyDDL    bool // ALTER TABLE add/drop FK (MySQL/PG; not SQLite)
	CanManageDatabases       bool // CREATE/DROP DATABASE (MySQL/PG; not SQLite — one file)
	CanDropConnectedDatabase bool // DROP DATABASE works from a connection bound to that database (MySQL; PG needs a maintenance connection)
	ExecReportsChangedRows   bool // Exec's RowsAffected counts CHANGED rows, not matched (MySQL default protocol; PG/SQLite count matched)
	SupportsTruncate         bool // TRUNCATE TABLE (MySQL/PG; SQLite uses DELETE FROM)
	AccountHasHost           bool // account names carry a host part, 'user'@'host' (MySQL)
	SupportsRoleAttributes   bool // LOGIN/SUPERUSER/CREATEDB/CREATEROLE role attributes (PG)
	// SupportsRoles: role membership (GRANT role TO account) is available, so
	// the Users page renders its memberships section. Version-gated on
	// MySQL/MariaDB and failing CLOSED on an unknown version — the catalog
	// table is absent before MySQL 8.0 / MariaDB 10.0.5, so a wrong "yes" turns
	// the page into an error rather than hiding a section. Promises RoleManager.
	SupportsRoles        bool
	RestrictedDropColumn bool // dropping a PK/indexed/outgoing-FK column is refused (SQLite)
	// IsNetworkEngine: the connection target is a network address (host/port)
	// authenticated with credentials, rather than a local file the process
	// opens. It is the login path's single engine discriminator and carries
	// three consequences:
	//
	//   - Ad-hoc login is offered ONLY for network engines. A file-backed
	//     engine has no credentials, so letting a visitor type its connection
	//     target would be an unauthenticated arbitrary file open (and, for
	//     SQLite historically, create) on the host. File-backed engines are
	//     reachable only through an operator-configured predefined server.
	//   - Credentials are collected at login only for network engines.
	//   - The SSRF host policy (auth.CheckHost / DialControl) applies only to
	//     network engines — there is no host to resolve otherwise.
	//
	// A future engine that is network-attached but should still be barred from
	// ad-hoc login needs its own flag; today the two coincide exactly.
	IsNetworkEngine bool
	// ShowsSSLModeUI: the engine's AD-HOC LOGIN FORM exposes the sslmode
	// selector. Predefined-server config carries SSLMode on every network engine.
	ShowsSSLModeUI bool
	// SSLModeNote explains what THIS engine's sslmode values mean, beside that
	// selector: the vocabulary is shared across engines, the behaviour is not.
	SSLModeNote string
	// DatabasesShareConnection: every logical database is served by the ONE
	// server connection (SQLite: one file; ATTACH-ed names are session-scoped),
	// so ConnFor never opens per-database pools.
	DatabasesShareConnection bool

	// IdentifierMaxBytes / IdentifierMaxChars bound a new or renamed name; a
	// dialect declares at most ONE unit (0 = no limit) and the conformance
	// suite refuses both. PostgreSQL's 63 BYTES is load-bearing (it silently
	// TRUNCATES past it); MySQL/MariaDB's 64 CHARACTERS errs. See validate.go.
	IdentifierMaxBytes int
	IdentifierMaxChars int
}

// ParamsNormalizer is an optional Dialect capability applied by the login
// handler to freshly-built connection params, so engine-specific defaults
// live with the dialect instead of the boundary code. PostgreSQL defaults an
// empty Database to "postgres". This is deliberately a params rewrite, never
// a BuildDSN-internal default: params.Database must stay observably set — it
// flows into the session's base params and the server-connection reuse test.
// Implementations treat p as a value; they may set scalar fields but must
// clone Params before modifying it (the map is shared with the server config).
type ParamsNormalizer interface {
	NormalizeParams(p ConnParams) ConnParams
}

// ExportConnAdjuster is an optional Dialect capability: dialect-owned session
// pinning for a dedicated EXPORT connection's params (MySQL pins time_zone,
// sql_mode and sql_quote_show_create so dumps render restore-parsable).
// Contract: p is a value, and implementations MUST clone Params before
// modifying — the map is shared with ServerConfig.Params and the session's
// base params — and set the pins AFTER copying, so they overwrite any
// same-name key coming from operator config.
type ExportConnAdjuster interface {
	ExportConnParams(p ConnParams) ConnParams
}

// DatabaseRebinder is an optional Dialect capability for engines whose
// logical "database" does not map to a DSN parameter: SQLite's database is
// the file the connection opened (ATTACH names are session-scoped), so
// rebinding is the identity. Engines without the hook get the default
// p.Database = database rebind on the private-connection dial paths
// (PinnedFor / ExportConnFor / server-dump sections).
type DatabaseRebinder interface {
	RebindDatabase(p ConnParams, database string) ConnParams
}

// LoginDatabaseHint is per-engine presentation metadata for the ad-hoc login
// form's database field, carried as data-attributes on the engine <option> so
// the client script reads the dataset instead of naming engines.
type LoginDatabaseHint struct {
	Label       string // field label ("" = the generic "Database")
	Placeholder string
	// Default is the value the form may pre-fill into an EMPTY field (and
	// clear again when switching engines, never touching a user-typed value).
	// The server-side authority for the same default is NormalizeParams.
	Default string
	// Note is a plain-text help sentence under the field ("" = none).
	Note string
}

// LoginFormHinter is an optional Dialect capability supplying LoginDatabaseHint.
type LoginFormHinter interface {
	LoginDatabaseHint() LoginDatabaseHint
}

// DDLErrorHint is an optional Dialect capability that turns a raw DDL error into
// a user-facing hint (e.g. PostgreSQL's "cannot alter type of a column used by a
// view"), so handlers surface guidance without sniffing engine-specific error
// text themselves. ok is false when the error has no engine-specific hint.
type DDLErrorHint interface {
	DDLErrorHint(err error) (hint string, ok bool)
}

// ServerSpecializer is an optional Dialect capability: return a COPY of the
// dialect specialized for one connection's server facts (MySQL derives
// NO_BACKSLASH_ESCAPES from sql_mode plus the flavor/version that gate
// introspection columns and the RETURNING lexer profile; PostgreSQL records the
// major version that gates MERGE … RETURNING).
//
// Contract: the receiver must be treated as a value and the specialized copy
// returned — never mutate the registered singleton, which every session shares.
// Every path that establishes a connection MUST route its dialect through
// Specialize; a path that skips it leaves the registered zero value in play, so
// every version/flavor gate silently fails closed (this is exactly how the SQL
// console once discarded MariaDB's `DELETE … RETURNING` rows).
type ServerSpecializer interface {
	WithServerInfo(info ServerInfo) Dialect
}

// Specialize applies the dialect's optional ServerSpecializer hook, returning d
// unchanged when the engine has no per-connection state. It is the single
// specialization point shared by Open and OpenPinned so the pooled and pinned
// paths cannot drift apart.
func Specialize(d Dialect, info ServerInfo) Dialect {
	if s, ok := d.(ServerSpecializer); ok {
		return s.WithServerInfo(info)
	}
	return d
}

// VersionFloor is implemented by a dialect that knows the oldest server release
// its introspection and DDL rely on. TableX used to perform no version check at
// all, so connecting something older degraded in place — a missing catalog column
// surfaced as an empty listing or a confusing error, at the point of use, with
// nothing pointing at the real cause.
//
// It reports rather than refuses. An operator with an older server may still get
// most of the tool working, and locking them out over a documented feature floor
// would be a worse trade than telling them plainly. The check is per CONNECTION
// because that is the only place the server version is known: a specialized
// dialect has already read it.
type VersionFloor interface {
	// ServerBelowFloor reports the documented floor for the connected flavor, and
	// whether this server is older than it. An implementation that cannot parse
	// the version must answer false: guessing "too old" would cry wolf on every
	// unfamiliar build string.
	ServerBelowFloor() (floor string, below bool)
}

// FloorWarning returns a human-readable advisory when the connected server is
// older than the dialect's documented floor, or "" when it is new enough, the
// version could not be parsed, or the dialect declares no floor.
func FloorWarning(d Dialect, info ServerInfo) string {
	vf, ok := d.(VersionFloor)
	if !ok {
		return ""
	}
	floor, below := vf.ServerBelowFloor()
	if !below {
		return ""
	}
	return fmt.Sprintf("%s %s is older than the %s %s that TableX's introspection "+
		"relies on. Most of the tool will work; some listings and DDL may be "+
		"incomplete or fail.", info.Flavor, info.Version, info.Flavor, floor)
}

// ServerInfo is the engine-neutral summary shown on the home page and used to
// decide MariaDB-vs-MySQL display, schema handling, etc.
type ServerInfo struct {
	Engine    string // dialect Name(): "mysql", "postgres", "sqlite"
	Flavor    string // "MySQL", "MariaDB", "PostgreSQL", "SQLite"
	Version   string // full version string
	User      string // CURRENT_USER as reported by the server
	Charset   string // server/connection default charset
	Collation string // server/connection default collation
	Host      string // connection target host (for display only)
	Port      int
	Database  string // current database, when bound to one
	// SQLMode carries the MySQL/MariaDB @@SESSION.sql_mode at connect time, so a
	// dialect can specialize string escaping for NO_BACKSLASH_ESCAPES via the
	// optional WithServerInfo hook. Empty for engines that do not report it.
	SQLMode string
}
