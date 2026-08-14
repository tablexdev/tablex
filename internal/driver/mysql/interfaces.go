package mysql

import "github.com/tablexdev/tablex/internal/driver"

// Compile-time proof of every driver interface this dialect satisfies.
//
// The application discovers optional capabilities by RUNTIME type assertion
// (`if m, ok := d.(driver.Monitor); ok`), so a method whose signature drifts
// away from its interface does not fail the build — the assertion simply stops
// matching and the feature silently disappears. These declarations turn that
// class of mistake back into a compile error.
//
// Keep this list in sync when adding or removing a capability: it is also the
// readable answer to "what does MySQL support?" for anyone adding an engine.
var (
	// Required of every engine.
	_ driver.Dialect = dialect{}

	// Connection and session.
	_ driver.PoolOpener         = dialect{} // Connector-based pool so DialControl reaches every dial
	_ driver.ServerSpecializer  = dialect{} // sql_mode + flavor/version, per connection
	_ driver.VersionFloor       = dialect{} // documented engine floor, warned about at connect
	_ driver.ExportConnAdjuster = dialect{} // pins time_zone/sql_mode on the export connection
	_ driver.StorageHost        = dialect{} // may host TableX's own metadata database

	// Introspection.
	_ driver.BulkIntrospector = dialect{} // schema-wide columns/FKs in one query
	_ driver.NameLister       = dialect{} // statistics-free listings for the nav tree
	_ driver.RowEstimator     = dialect{} // information_schema TABLE_ROWS
	_ driver.Monitor          = dialect{} // SHOW STATUS / VARIABLES / PROCESSLIST
	_ driver.Privileger       = dialect{}
	_ driver.CollationLister  = dialect{} // SupportsCharset — the create-database collation list
	_ driver.DefinitionViewer = dialect{} // SHOW CREATE — information_schema bodies lack the signature

	// DDL and administration.
	_ driver.SchemaEditor      = dialect{}
	_ driver.ColumnModifier    = dialect{} // SupportsColumnModify
	_ driver.ColumnRenamer     = dialect{} // SupportsColumnRename — false on MariaDB < 10.5.2
	_ driver.IndexOptioner     = dialect{} // prefix lengths; DESC on MySQL 8.0.1+
	_ driver.ValueListTyper    = dialect{} // ENUM / SET — the only engine of the three with either
	_ driver.ForeignKeyEditor  = dialect{} // SupportsForeignKeyDDL
	_ driver.DatabaseManager   = dialect{}
	_ driver.TableMaintainer   = dialect{} // OPTIMIZE / CHECK / REPAIR / ANALYZE
	_ driver.RoutineManager    = dialect{} // stored programs: routines,
	_ driver.TriggerManager    = dialect{} // triggers and
	_ driver.EventManager      = dialect{} // events — MySQL is the only engine with all three
	_ driver.UserManager       = dialect{}
	_ driver.PrivilegeManager  = dialect{}
	_ driver.ColumnPrivileger  = dialect{} // GRANT SELECT (col) — mysql.columns_priv
	_ driver.RoleManager       = dialect{} // SupportsRoles — MySQL 8.0+ / MariaDB 10.0.5+
	_ driver.RoutinePrivileger = dialect{} // EXECUTE / ALTER ROUTINE — mysql.procs_priv
	_ driver.ProcessManager    = dialect{} // KILL CONNECTION

	// SQL scripts.
	_ driver.StatementLexer  = dialect{} // backslash escapes, `` quoting, RETURNING gating
	_ driver.CollationProber = dialect{} // import-side verification of db-collation markers

	// Dump.
	_ driver.Dumper           = dialect{}
	_ driver.ServerDumpFramer = dialect{} // CREATE DATABASE/USE framing for a server dump
	_ driver.ViewDumper       = dialect{}
)

// Deliberately NOT implemented, and why:
//
//	SchemaManager       — no schema level between database and table.
//	SearchCaster        — LIKE coerces implicitly, so the bare identifier works.
//	FilePathValidator   — a network engine; there is no file path to validate.
//	ParamsValidator     — a network engine; the DSN params are TableX's own and
//	                      carry no operator-supplied fidelity foot-gun to refuse.
//	MaintenanceDatabaseLister — maintenance statements run on the connection's
//	                      own database; no server-level fallback list is needed.
//	ParamsNormalizer    — an empty database is legal; nothing to default.
//	DatabaseRebinder    — the database IS a DSN parameter; the default rebind fits.
//	LoginFormHinter     — the generic database field needs no engine wording.
//	DDLErrorHint        — no error text worth translating beyond the server's own.
//	TeardownAuditor     — drop-first teardown has no cross-object blockers to probe.
//	StagedTableDumper   — cycles are resolved by dumping FKs as post-data ALTERs.
//	GlobalDumper        — no database-global, non-schema-owned object kinds.
//	DataScoper          — no table inheritance, so no FROM ONLY.
//	DynamicTyper        — statically typed: DECIMAL and out-of-int64-range values
//	                      scan as text yet must dump bare for full precision,
//	                      which only the declared column type can decide.
//	ForeignTableDumper  — FEDERATED tables are not modelled.
//	Inheritor           — no table inheritance.
