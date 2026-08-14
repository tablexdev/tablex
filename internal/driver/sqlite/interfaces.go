package sqlite

import "github.com/tablexdev/tablex/internal/driver"

// Compile-time proof of every driver interface this dialect satisfies.
//
// The application discovers optional capabilities by RUNTIME type assertion, so
// a method whose signature drifts away from its interface does not fail the
// build — the assertion simply stops matching and the feature silently
// disappears. These declarations turn that class of mistake back into a compile
// error.
//
// SQLite implements the smallest set of the three built-in engines, which makes
// it the useful reference for how little an engine can provide and still work:
// everything below the required Dialect is opt-in, and every omission named at
// the bottom of this file degrades gracefully rather than erroring.
var (
	// Required of every engine.
	_ driver.Dialect = dialect{}

	// Connection.
	_ driver.DatabaseRebinder  = dialect{} // the database is the open FILE; rebinding is the identity
	_ driver.FilePathValidator = dialect{} // refuses :memory: for a predefined server
	_ driver.ParamsValidator   = dialect{} // refuses the text→time/int→time conversions that break text fidelity
	_ driver.StorageHost       = dialect{} // may host TableX's own metadata database — the zero-setup choice

	// Introspection.
	_ driver.RowEstimator = dialect{} // sqlite_stat1, or -1 until ANALYZE has run
	_ driver.Monitor      = dialect{} // PRAGMA-backed variables; an empty process list

	// DDL. Note the two it does NOT implement, below: ALTER TABLE here can add,
	// drop and rename a column but never redefine one (hence ColumnRenamer
	// without ColumnModifier), and it cannot add or drop a foreign key at all.
	_ driver.SchemaEditor = dialect{}
	// The one column edit SQLite does have (3.25+), which is exactly why rename
	// is its own capability rather than part of ColumnModifier.
	_ driver.ColumnRenamer = dialect{} // SupportsColumnRename
	_ driver.IndexOptioner = dialect{} // DESC key parts and partial indexes
	// The only stored program SQLite has; routines and events do not exist here,
	// which is why the three managers are separate interfaces.
	_ driver.TriggerManager = dialect{}
	// ANALYZE only: SQLite's VACUUM rebuilds the whole database file, so it is
	// not a table operation.
	_ driver.TableMaintainer = dialect{}

	// SQL scripts.
	_ driver.StatementLexer = dialect{}

	// Dump.
	_ driver.Dumper           = dialect{} // the extra sqlite_master rows (indexes, triggers)
	_ driver.DynamicTyper     = dialect{} // per-value storage classes decide bare-vs-quoted dump literals
	_ driver.ServerDumpFramer = dialect{}
	_ driver.ViewDumper       = dialect{}
)

// Deliberately NOT implemented, and why:
//
//	PoolOpener          — no network dial, so no DialControl to install.
//	ServerSpecializer   — no per-connection server facts; the dialect is stateless.
//	ExportConnAdjuster  — no session variables worth pinning for a dump.
//	ParamsNormalizer    — the file path is the whole connection; nothing to default.
//	BulkIntrospector    — the catalog is PRAGMA-based and inherently per-table.
//	NameLister          — the full listings are already statistics-free.
//	SearchCaster        — LIKE coerces implicitly.
//	Privileger          — no access-control system.
//	CollationLister     — no server collation catalog (SupportsCharset is false).
//	CollationProber     — dumps carry no db-collation markers.
//	ColumnModifier      — no ALTER TABLE … MODIFY/ALTER COLUMN (SupportsColumnModify false).
//	ForeignKeyEditor    — no ALTER TABLE … ADD/DROP CONSTRAINT (SupportsForeignKeyDDL false).
//	SchemaManager       — no schema level.
//	DatabaseManager     — a database is a file; creating one is not a statement.
//	UserManager         — no accounts.
//	PrivilegeManager    — no grants.
//	ColumnPrivileger    — no grants to narrow to a column.
//	RoleManager         — no accounts, so nothing to be a member of.
//	RoutinePrivileger   — no routines, and no grants to put on them.
//	ProcessManager      — the process list is empty; there is no session to kill.
//	LoginFormHinter     — the login form's file-path wording is generic.
//	DDLErrorHint        — no error text worth translating.
//	TeardownAuditor     — nothing to probe.
//	StagedTableDumper   — no deferrable table edges are emitted.
//	GlobalDumper        — no database-global object kinds.
//	DataScoper          — no table inheritance.
//	ForeignTableDumper  — no foreign tables.
//	Inheritor           — no table inheritance.
//	RoutineManager      — no stored routines to administer.
//	EventManager        — no scheduled events.
//	MaintenanceDatabaseLister — no server-level databases to fall back to.
//	ValueListTyper      — no ENUM or SET column types, so no member list to type.
//	VersionFloor        — no documented engine floor to warn about: the embedded
//	                      modernc build IS the engine version.
//	DefinitionViewer    — ListTriggers returns sqlite_master.sql, which IS the
//	                      original CREATE statement; there is nothing to re-fetch
//	                      (and no routines or events to view at all).
