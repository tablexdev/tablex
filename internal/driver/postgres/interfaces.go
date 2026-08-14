package postgres

import "github.com/tablexdev/tablex/internal/driver"

// Compile-time proof of every driver interface this dialect satisfies.
//
// The application discovers optional capabilities by RUNTIME type assertion, so
// a method whose signature drifts away from its interface does not fail the
// build — the assertion simply stops matching and the feature silently
// disappears. These declarations turn that class of mistake back into a compile
// error, which matters most here: PostgreSQL implements 41 of the 50 optional
// interfaces (a census TestOptionalInterfaceTableIsComplete holds to the
// probe table), and the dump capabilities are reachable only through export.
var (
	// Required of every engine.
	_ driver.Dialect = dialect{}

	// Connection and session.
	_ driver.PoolOpener         = dialect{} // Connector-based pool so DialControl reaches every dial
	_ driver.ServerSpecializer  = dialect{} // records the server major (gates MERGE … RETURNING)
	_ driver.VersionFloor       = dialect{} // documented engine floor, warned about at connect
	_ driver.ParamsNormalizer   = dialect{} // an empty database defaults to "postgres"
	_ driver.ExportConnAdjuster = dialect{}
	_ driver.StorageHost        = dialect{} // may host TableX's own metadata database
	_ driver.LoginFormHinter    = dialect{} // labels the database field, and offers "postgres"
	_ driver.DDLErrorHint       = dialect{} // e.g. "cannot alter type of a column used by a view"

	// Introspection.
	_ driver.BulkIntrospector = dialect{} // schema-wide columns/FKs in one catalog query
	_ driver.NameLister       = dialect{} // statistics-free listings for the nav tree
	_ driver.RowEstimator     = dialect{} // reltuples
	_ driver.Monitor          = dialect{} // pg_stat_activity, pg_settings
	_ driver.Privileger       = dialect{} // aclexplode, including PUBLIC
	_ driver.SearchCaster     = dialect{} // casts to text: uuid/json/inet reject a bare LIKE

	// DDL and administration.
	_ driver.SchemaEditor              = dialect{}
	_ driver.ColumnModifier            = dialect{} // SupportsColumnModify
	_ driver.ColumnRenamer             = dialect{} // SupportsColumnRename
	_ driver.IndexOptioner             = dialect{} // access methods, DESC, partial predicates
	_ driver.ForeignKeyEditor          = dialect{} // SupportsForeignKeyDDL
	_ driver.SchemaManager             = dialect{} // HasSchemas
	_ driver.DatabaseManager           = dialect{}
	_ driver.MaintenanceDatabaseLister = dialect{} // postgres, then template1
	_ driver.TableMaintainer           = dialect{} // VACUUM / ANALYZE / REINDEX
	_ driver.RoutineManager            = dialect{} // DROP needs the identity args (overloading)
	_ driver.TriggerManager            = dialect{} // DROP TRIGGER … ON <table>
	_ driver.UserManager               = dialect{}
	_ driver.PrivilegeManager          = dialect{}
	_ driver.ColumnPrivileger          = dialect{} // GRANT SELECT (col) — pg_attribute.attacl
	_ driver.RoleManager               = dialect{} // pg_auth_members; every role is grantable
	_ driver.RoutinePrivileger         = dialect{} // EXECUTE — pg_proc.proacl, addressed by identity args
	_ driver.ProcessManager            = dialect{} // pg_terminate_backend

	// SQL scripts.
	_ driver.StatementLexer = dialect{} // dollar quotes, E'…', nested block comments

	// Dump. The topological planner reaches these by assertion, so a drifted
	// signature here degrades an export silently rather than failing it.
	_ driver.Dumper             = dialect{}
	_ driver.ServerDumpFramer   = dialect{} // \connect framing for a server dump
	_ driver.ViewDumper         = dialect{}
	_ driver.StagedTableDumper  = dialect{} // cycle resolution: defer DEFAULTs/constraints
	_ driver.GlobalDumper       = dialect{} // casts, FDWs, foreign servers, user mappings
	_ driver.DataScoper         = dialect{} // FROM ONLY for an INHERITS parent
	_ driver.ForeignTableDumper = dialect{}
	_ driver.Inheritor          = dialect{} // INHERITS parents and linked child creates
	_ driver.TeardownAuditor    = dialect{} // warn-only drop-first blocker probe
)

// Deliberately NOT implemented, and why:
//
//	CollationLister  — CREATE DATABASE takes no collation here (SupportsCharset
//	                   is false); LC_COLLATE/ICU locales are not offered.
//	CollationProber  — dumps carry no db-collation markers (that mechanism
//	                   exists for MySQL's per-object collation disclosure).
//	DatabaseRebinder — the database is a DSN parameter; the default rebind fits.
//	EventManager     — no scheduled-event object kind at all.
//	FilePathValidator — a network engine; there is no file path to validate.
//	ParamsValidator  — a network engine; the DSN params are TableX's own and
//	                   carry no operator-supplied fidelity foot-gun to refuse.
//	ValueListTyper   — enumerated types are standalone CREATE TYPE … AS ENUM,
//	                   not an inline column-type value list, and there is no SET.
//	DefinitionViewer — ListRoutines/ListTriggers already return complete CREATE
//	                   statements (pg_get_functiondef / pg_get_triggerdef), so a
//	                   second per-object round-trip would fetch what the caller
//	                   already holds.
//	DynamicTyper     — statically typed: NUMERIC and out-of-int64-range values
//	                   scan as text yet must dump bare for full precision, which
//	                   only the declared column type can decide.
