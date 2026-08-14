package driver

import (
	"context"
	"database/sql"
	"fmt"
	"math"
	"net/netip"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/tablexdev/tablex/internal/model"
)

// Connection is the engine-neutral handle handlers use. It wraps a *sql.DB pool
// plus its Dialect and cached ServerInfo, and exposes high-level operations that
// delegate the engine-specific bits to the Dialect. Handlers never touch a
// concrete driver package or build raw SQL for identifiers.
type Connection struct {
	db      *sql.DB
	dialect Dialect
	info    ServerInfo
	tuning  Tuning // resolved (no zero fields) at Open
	// observe reports mutations to the audit trail; nil when auditing is off, in
	// which case not even a clock is read. Only mutations — see StatementObserver
	// for why the row-returning paths are excluded.
	observe StatementObserver
	// floorWarning is non-empty when the connected server is older than the
	// dialect's documented floor. Computed at Open, where the specialized dialect
	// has just parsed the version; see driver.VersionFloor.
	floorWarning string
}

// FloorWarning returns the advisory for a server older than the documented
// engine floor, or "" when the server is new enough (or the engine declares no
// floor — SQLite is compiled in, so there is no server to be too old).
func (c *Connection) FloorWarning() string { return c.floorWarning }

// Open dials a database using the dialect and params, verifies connectivity,
// loads ServerInfo and returns a ready Connection. Pool limits come from
// p.Tuning (operator config), defaulted so a single browser cannot exhaust the
// server.
func Open(ctx context.Context, d Dialect, p ConnParams) (*Connection, error) {
	db, err := openPool(d, p)
	if err != nil {
		return nil, err
	}
	tuning := p.Tuning.resolve()
	db.SetMaxOpenConns(tuning.MaxOpenConns)
	db.SetMaxIdleConns(tuning.MaxIdleConns)
	db.SetConnMaxIdleTime(5 * time.Minute)
	db.SetConnMaxLifetime(30 * time.Minute)

	pingCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if err := db.PingContext(pingCtx); err != nil {
		db.Close()
		return nil, err
	}
	// ServerInfo shares the ping's 15s budget: the production login passes a
	// deadline-free request context, and a server that connects but wedges on
	// the version/metadata query must not stall login while holding a pooled
	// connection.
	info, err := d.ServerInfo(pingCtx, db)
	if err != nil {
		db.Close()
		return nil, err
	}
	info.Host = p.Host
	info.Port = p.Port
	if info.Database == "" {
		info.Database = p.Database
	}
	// A dialect may specialize itself from the loaded ServerInfo (e.g. MySQL
	// deriving a NO_BACKSLASH_ESCAPES flag from sql_mode so QuoteString escapes
	// correctly). The returned copy becomes this connection's dialect, so every
	// builder sees the per-connection setting with no signature changes.
	d = Specialize(d, info)
	// Computed here, once, because this is the only point where both the
	// specialized dialect (which parsed the version) and the connection exist.
	return &Connection{
		db: db, dialect: d, info: info, tuning: tuning, observe: p.OnStatement,
		floorWarning: FloorWarning(d, info),
	}, nil
}

// openPool builds the *sql.DB pool for a dialect. Network engines implement
// PoolOpener so the dial-time SSRF guard (ConnParams.DialControl) is applied to
// every connection; engines without a network use the generic sql.Open path.
func openPool(d Dialect, p ConnParams) (*sql.DB, error) {
	if o, ok := d.(PoolOpener); ok {
		return o.OpenPool(p)
	}
	dsn, err := d.BuildDSN(p)
	if err != nil {
		return nil, err
	}
	return sql.Open(d.SQLDriverName(), dsn)
}

// DB exposes the underlying pool for advanced operations (transactions, batch
// import). Most code should prefer the higher-level methods.
func (c *Connection) DB() *sql.DB { return c.db }

// Dialect returns the engine dialect (for quoting in DDL builders, etc.).
func (c *Connection) Dialect() Dialect { return c.dialect }

// Engine returns the dialect name ("mysql", "postgres", "sqlite"). MariaDB
// reports "mysql" — unlike Info().Engine, which carries the detected flavor.
func (c *Connection) Engine() string { return c.dialect.Name() }

// Info returns the cached server info.
func (c *Connection) Info() ServerInfo { return c.info }

// Capabilities returns the engine capability flags.
func (c *Connection) Capabilities() Capabilities { return c.dialect.Capabilities() }

// Ping verifies the pool is still alive.
func (c *Connection) Ping(ctx context.Context) error { return c.db.PingContext(ctx) }

// Close shuts the pool down (called on logout / session expiry).
func (c *Connection) Close() error { return c.db.Close() }

// --- Read-statement timeout ----------------------------------------------------

// ReadStmtTimeout is the DEFAULT budget for a single generated read statement
// (introspection, browse, count, estimate, and the three handler-built reads)
// so a few slow reads cannot tie up every pooled connection until the client
// disconnects. It is generous on purpose: the same introspection methods drive
// metadata pages and export planning on large schemas, which must not be
// truncated. Operators override it with Tuning.ReadStmtTimeout.
//
// It is applied ONLY to generated reads. It is deliberately NOT applied to the
// SQL console (Query — the user's own SQL), export Stream, any Pinned path, or
// any generated mutation/DDL (Exec/ExecScript): force-cancelling a write or DDL
// mid-statement is riskier (partial effects, lock churn) than a slow read
// holding a connection, and those are already bounded by the request context.
const ReadStmtTimeout = 60 * time.Second

// WithReadTimeout derives a context bounded by the DEFAULT ReadStmtTimeout, for
// callers with no Connection in hand. Prefer (*Connection).WithReadTimeout,
// which honours the operator's configured budget.
func WithReadTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, ReadStmtTimeout)
}

// WithReadTimeout derives a context bounded by this connection's read budget,
// for a generated read built OUTSIDE the Connection wrappers — the handlers
// (TableSearch, runQBE, fetchRow) that bind args through conn.DB().QueryContext
// and so cannot use Query (which takes no args). The caller must invoke the
// returned cancel once the rows are scanned.
func (c *Connection) WithReadTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, c.tuning.ReadStmtTimeout)
}

// readCtx is the internal shorthand the introspection passthroughs use.
func (c *Connection) readCtx(ctx context.Context) (context.Context, context.CancelFunc) {
	return c.WithReadTimeout(ctx)
}

// Tuning returns the resolved pool and timeout settings in force for this
// connection (no zero fields), for diagnostics and tests.
func (c *Connection) Tuning() Tuning { return c.tuning }

type serverFlavorKey struct{}

// WithServerFlavor carries the connection's already-detected engine flavor
// (e.g. "MariaDB" vs "MySQL", parsed once by ServerInfo at connect) into a
// stateless Dialect introspection call, so the dialect need not re-query
// VERSION() on every call. ServerFlavorFromContext reads it back (empty when
// unset — e.g. a direct dialect call in a test, where the dialect falls back to
// its own probe).
func WithServerFlavor(ctx context.Context, flavor string) context.Context {
	return context.WithValue(ctx, serverFlavorKey{}, flavor)
}

// ServerFlavorFromContext returns the flavor stashed by WithServerFlavor, or "".
func ServerFlavorFromContext(ctx context.Context) string {
	f, _ := ctx.Value(serverFlavorKey{}).(string)
	return f
}

// QuoteEach returns names each quoted via the dialect's QuoteIdent, in order.
// Shared by the dialect DDL builders so the per-name quoting loop isn't
// reimplemented per engine.
func QuoteEach(d Dialect, names []string) []string {
	out := make([]string, len(names))
	for i, n := range names {
		out[i] = d.QuoteIdent(n)
	}
	return out
}

// DefaultLimitClause renders the "LIMIT n OFFSET n" clause every supported
// engine accepts; the dialects delegate here rather than each formatting it.
// The offset is int64 (see Dialect.LimitClause).
func DefaultLimitClause(limit int, offset int64) string {
	return fmt.Sprintf("LIMIT %d OFFSET %d", limit, offset)
}

// QuoteAnsiIdent quotes an identifier with the ANSI double-quote convention
// ("name", embedded quotes doubled), shared byte-for-byte by the PostgreSQL and
// SQLite dialects. QuoteAnsiString quotes a string literal ('lit', embedded
// single quotes doubled) the same way. Keeping one implementation guarantees the
// two engines cannot drift.
func QuoteAnsiIdent(name string) string {
	return `"` + strings.ReplaceAll(name, `"`, `""`) + `"`
}

// QuoteAnsiString quotes a string literal with the ANSI single-quote convention.
func QuoteAnsiString(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

// BasicColumnDef renders the simple column definition shared by the
// PostgreSQL and SQLite DDL builders: quoted name, type, NOT NULL, DEFAULT.
// (MySQL's columnDef carries extra attributes — unsigned/zerofill/charset/
// auto-increment — and stays engine-local.) ColumnSpec.Default is already a
// validated SQL fragment (see the handlers' buildDefault), never raw input.
func BasicColumnDef(d Dialect, c ColumnSpec) string {
	var b strings.Builder
	b.WriteString(d.QuoteIdent(c.Name))
	b.WriteByte(' ')
	b.WriteString(c.Type)
	if !c.Nullable {
		b.WriteString(" NOT NULL")
	}
	if c.Default != nil {
		b.WriteString(" DEFAULT ")
		b.WriteString(*c.Default)
	}
	return b.String()
}

// UnbracketHost returns a bracketed IP literal ("[::1]", "[fe80::1%eth0]") in
// bare form; any other host is returned unchanged. The network dialects call
// this before net.JoinHostPort, which brackets ANY host containing ':' — an
// already-bracketed input would otherwise come out double-bracketed
// ("[[::1]]:5432") and unresolvable. Boundary canonicalization
// (config.CanonicalHost) normally strips brackets before a host reaches a
// dialect; this is defense in depth for direct driver callers.
func UnbracketHost(host string) string {
	if len(host) >= 2 && host[0] == '[' && host[len(host)-1] == ']' {
		if _, err := netip.ParseAddr(host[1 : len(host)-1]); err == nil {
			return host[1 : len(host)-1]
		}
	}
	return host
}

// BaseTypeName extracts the lower-cased bare type name from a SQL column type
// ("DECIMAL(10,2)" → "decimal"). Shared by the dialects' column builders and
// introspection.
func BaseTypeName(typ string) string {
	if i := strings.IndexByte(typ, '('); i >= 0 {
		typ = typ[:i]
	}
	return strings.ToLower(strings.TrimSpace(typ))
}

// AddForeignKeyDDL builds the "ALTER TABLE … ADD CONSTRAINT … FOREIGN KEY …"
// statement shared verbatim by the MySQL and PostgreSQL SchemaEditors. The
// reference target carries both Database and Schema from t; each dialect's
// QualifyTable selects the level it qualifies by (MySQL: Database, PostgreSQL:
// Schema) and ignores the other, so v1's same-database / same-schema target
// assumption holds for both engines without an engine branch here.
func AddForeignKeyDDL(d Dialect, t TableRef, name string, cols []string, refTable string, refCols []string, onUpdate, onDelete string) string {
	ref := TableRef{Database: t.Database, Schema: t.Schema, Table: refTable}
	var b strings.Builder
	b.WriteString("ALTER TABLE ")
	b.WriteString(d.QualifyTable(t))
	b.WriteString(" ADD CONSTRAINT ")
	b.WriteString(d.QuoteIdent(name))
	b.WriteString(" FOREIGN KEY (")
	b.WriteString(strings.Join(QuoteEach(d, cols), ", "))
	b.WriteString(") REFERENCES ")
	b.WriteString(d.QualifyTable(ref))
	b.WriteString(" (")
	b.WriteString(strings.Join(QuoteEach(d, refCols), ", "))
	b.WriteByte(')')
	if onUpdate != "" {
		b.WriteString(" ON UPDATE " + onUpdate)
	}
	if onDelete != "" {
		b.WriteString(" ON DELETE " + onDelete)
	}
	return b.String()
}

// DropColumnDDL builds the "ALTER TABLE … DROP COLUMN …" statement shared
// verbatim by all three SchemaEditors (unlike columnDef / AddIndexSQL, which
// genuinely diverge per engine). Each dialect's QualifyTable selects the level
// it qualifies by.
func DropColumnDDL(d Dialect, t TableRef, col string) string {
	return "ALTER TABLE " + d.QualifyTable(t) + " DROP COLUMN " + d.QuoteIdent(col)
}

// RenameColumnDDL builds the "ALTER TABLE … RENAME COLUMN old TO new"
// statement, which all three engines spell identically (MySQL since 8.0.3,
// MariaDB since 10.5.2, PostgreSQL always, SQLite since 3.25). A dialect whose
// server may predate that support decides so in Capabilities, not here.
func RenameColumnDDL(d Dialect, t TableRef, old, newName string) string {
	return "ALTER TABLE " + d.QualifyTable(t) + " RENAME COLUMN " + d.QuoteIdent(old) + " TO " + d.QuoteIdent(newName)
}

// IndexKeyParts renders an index's key list — "`a`(10), `b` DESC" — shared by
// the three SchemaEditors because the syntax genuinely coincides where the
// options exist at all.
//
// It drops any part the dialect's IndexOptions does not claim, so this is the
// single place enforcing that promise rather than three. The handler refuses an
// unsupported option first, with a message; this is the backstop that keeps a
// caller who skipped that check from emitting SQL the engine cannot parse — or,
// worse, SQL it parses and ignores.
func IndexKeyParts(d Dialect, cols []IndexColumn) string {
	var opts IndexOptions
	if o, ok := d.(IndexOptioner); ok {
		opts = o.IndexOptions()
	}
	parts := make([]string, 0, len(cols))
	for _, c := range cols {
		p := d.QuoteIdent(c.Name)
		if c.Prefix > 0 && opts.SupportsPrefix {
			p += "(" + strconv.Itoa(c.Prefix) + ")"
		}
		if c.Desc && opts.SupportsDesc {
			p += " DESC"
		}
		parts = append(parts, p)
	}
	return strings.Join(parts, ", ")
}

// AssembleCreateTable renders the CREATE TABLE statement every SchemaEditor
// shares: the pre-built column definitions plus, when quotedPK is non-empty, a
// PRIMARY KEY table constraint. qualified and quotedPK arrive already quoted
// (QualifyTable / QuoteEach); what genuinely diverges per engine — the
// columnDef grammar and PostgreSQL's COMMENT ON COLUMN trailer — stays with
// the dialects.
func AssembleCreateTable(qualified string, colDefs, quotedPK []string) string {
	parts := append(make([]string, 0, len(colDefs)+1), colDefs...)
	if len(quotedPK) > 0 {
		parts = append(parts, "PRIMARY KEY ("+strings.Join(quotedPK, ", ")+")")
	}
	return "CREATE TABLE " + qualified + " (\n  " + strings.Join(parts, ",\n  ") + "\n)"
}

// --- Introspection passthrough -------------------------------------------------
//
// Every method here time-bounds its statement with ReadStmtTimeout: they all
// fully materialize their result (a slice or scalar) before returning, so the
// deferred cancel never races a still-open rows iterator.

func (c *Connection) ListDatabases(ctx context.Context) ([]model.Database, error) {
	ctx, cancel := c.readCtx(ctx)
	defer cancel()
	return c.dialect.ListDatabases(ctx, c.db)
}
func (c *Connection) ListSchemas(ctx context.Context, database string) ([]model.Schema, error) {
	ctx, cancel := c.readCtx(ctx)
	defer cancel()
	return c.dialect.ListSchemas(ctx, c.db, database)
}

// ListCollations returns the server's collation list for the create-database
// form and its validation, or nil for engines without collation support.
func (c *Connection) ListCollations(ctx context.Context) ([]Collation, error) {
	l, ok := c.dialect.(CollationLister)
	if !ok {
		return nil, nil
	}
	ctx, cancel := c.readCtx(ctx)
	defer cancel()
	return l.ListCollations(ctx, c.db)
}
func (c *Connection) ListTables(ctx context.Context, scope Scope) ([]model.Table, error) {
	ctx, cancel := c.readCtx(ctx)
	defer cancel()
	return c.dialect.ListTables(ctx, c.db, scope)
}

// ListDatabaseNames is the cheap identity-only database listing (Name/IsSystem
// populated, no sizes or table counts) for navigation and existence checks. It
// falls back to the full listing when the dialect has no NameLister.
func (c *Connection) ListDatabaseNames(ctx context.Context) ([]model.Database, error) {
	ctx, cancel := c.readCtx(ctx)
	defer cancel()
	if n, ok := c.dialect.(NameLister); ok {
		return n.ListDatabaseNames(ctx, c.db)
	}
	return c.dialect.ListDatabases(ctx, c.db)
}

// ListTableNames is the cheap identity-only table listing (Name/Schema/Type
// populated, no statistics) for navigation and existence checks. It falls back
// to the full listing when the dialect has no NameLister.
func (c *Connection) ListTableNames(ctx context.Context, scope Scope) ([]model.Table, error) {
	ctx, cancel := c.readCtx(ctx)
	defer cancel()
	if n, ok := c.dialect.(NameLister); ok {
		return n.ListTableNames(ctx, c.db, scope)
	}
	return c.dialect.ListTables(ctx, c.db, scope)
}
func (c *Connection) Columns(ctx context.Context, t TableRef) ([]model.Column, error) {
	ctx, cancel := c.readCtx(ctx)
	defer cancel()
	// Pass the flavor parsed at connect so a dialect (MySQL/MariaDB) needn't
	// re-detect it with a per-call VERSION() query.
	ctx = WithServerFlavor(ctx, c.info.Flavor)
	return c.dialect.Columns(ctx, c.db, t)
}
func (c *Connection) Indexes(ctx context.Context, t TableRef) ([]model.Index, error) {
	ctx, cancel := c.readCtx(ctx)
	defer cancel()
	return c.dialect.Indexes(ctx, c.db, t)
}
func (c *Connection) ForeignKeys(ctx context.Context, t TableRef) ([]model.ForeignKey, error) {
	ctx, cancel := c.readCtx(ctx)
	defer cancel()
	return c.dialect.ForeignKeys(ctx, c.db, t)
}

// BulkColumns returns every table's columns in one query when the dialect
// supports it (ok=false otherwise — the caller falls back to per-table calls).
func (c *Connection) BulkColumns(ctx context.Context, scope Scope) (map[string][]model.Column, bool, error) {
	b, isBulk := c.dialect.(BulkIntrospector)
	if !isBulk {
		return nil, false, nil
	}
	ctx, cancel := c.readCtx(ctx)
	defer cancel()
	ctx = WithServerFlavor(ctx, c.info.Flavor)
	m, err := b.BulkColumns(ctx, c.db, scope)
	return m, true, err
}

// BulkForeignKeys returns every table's foreign keys in one query when the
// dialect supports it (ok=false otherwise).
func (c *Connection) BulkForeignKeys(ctx context.Context, scope Scope) (map[string][]model.ForeignKey, bool, error) {
	b, isBulk := c.dialect.(BulkIntrospector)
	if !isBulk {
		return nil, false, nil
	}
	ctx, cancel := c.readCtx(ctx)
	defer cancel()
	m, err := b.BulkForeignKeys(ctx, c.db, scope)
	return m, true, err
}
func (c *Connection) CreateSQL(ctx context.Context, t TableRef) (string, error) {
	ctx, cancel := c.readCtx(ctx)
	defer cancel()
	return c.dialect.CreateSQL(ctx, c.db, t)
}

// ListViews is capability-gated HERE rather than in each dialect, as are the
// three extended listings after it. The Dialect contract already says an engine
// without the feature must return an empty slice; enforcing it centrally means a
// new dialect cannot forget, an engine that lacks the object kind pays no round-trip for it, and
// the Capabilities flags are load-bearing rather than decorative.
func (c *Connection) ListViews(ctx context.Context, scope Scope) ([]model.View, error) {
	if !c.dialect.Capabilities().HasViews {
		return nil, nil
	}
	ctx, cancel := c.readCtx(ctx)
	defer cancel()
	return c.dialect.ListViews(ctx, c.db, scope)
}
func (c *Connection) ListRoutines(ctx context.Context, scope Scope) ([]model.Routine, error) {
	if !c.dialect.Capabilities().HasStoredRoutines {
		return nil, nil
	}
	ctx, cancel := c.readCtx(ctx)
	defer cancel()
	return c.dialect.ListRoutines(ctx, c.db, scope)
}
func (c *Connection) ListTriggers(ctx context.Context, scope Scope) ([]model.Trigger, error) {
	if !c.dialect.Capabilities().HasTriggers {
		return nil, nil
	}
	ctx, cancel := c.readCtx(ctx)
	defer cancel()
	return c.dialect.ListTriggers(ctx, c.db, scope)
}
func (c *Connection) ListEvents(ctx context.Context, scope Scope) ([]model.Event, error) {
	if !c.dialect.Capabilities().HasEvents {
		return nil, nil
	}
	ctx, cancel := c.readCtx(ctx)
	defer cancel()
	return c.dialect.ListEvents(ctx, c.db, scope)
}
func (c *Connection) ListUsers(ctx context.Context) ([]model.User, error) {
	ctx, cancel := c.readCtx(ctx)
	defer cancel()
	return c.dialect.ListUsers(ctx, c.db)
}

// Privileges lists grants for a database (ref.Table == "") or a table. Returns
// nil for engines without a privilege system (SQLite).
func (c *Connection) Privileges(ctx context.Context, ref TableRef) ([]model.Privilege, error) {
	p, ok := c.dialect.(Privileger)
	if !ok {
		return nil, nil
	}
	ctx, cancel := c.readCtx(ctx)
	defer cancel()
	return p.Privileges(ctx, c.db, ref)
}

// ObjectDefinition returns the full CREATE statement for one already-listed
// object. ok is false when the engine has no DefinitionViewer, which is not an
// error: it means the listing's own Definition is already the complete
// statement and the caller should use that instead of paying a second query.
func (c *Connection) ObjectDefinition(ctx context.Context, scope Scope, kind ProgramKind, name string) (def string, ok bool, err error) {
	v, ok := c.dialect.(DefinitionViewer)
	if !ok {
		return "", false, nil
	}
	ctx, cancel := c.readCtx(ctx)
	defer cancel()
	def, err = v.ObjectDefinition(ctx, c.db, scope, kind, name)
	return def, true, err
}

// --- Account & privilege administration (UserManager / PrivilegeManager) --------
//
// The write wrappers assert the optional interfaces internally, mirroring
// Privileges, so handlers stay free of dialect assertions. Unlike the read
// side's graceful nil, a write on an engine without the capability returns
// ErrUnsupported — a silent no-op would report success for DCL that never ran.

// CanManageUsers reports whether the engine supports account administration.
func (c *Connection) CanManageUsers() bool {
	_, ok := c.dialect.(UserManager)
	return ok
}

// CanManagePrivileges reports whether the engine supports GRANT/REVOKE.
func (c *Connection) CanManagePrivileges() bool {
	_, ok := c.dialect.(PrivilegeManager)
	return ok
}

// GrantablePrivileges returns the engine's curated privilege allowlist for the
// grant form and grant validation, or nil when unsupported.
func (c *Connection) GrantablePrivileges(table bool) []string {
	if m, ok := c.dialect.(PrivilegeManager); ok {
		return m.GrantablePrivileges(table)
	}
	return nil
}

// --- Stored programs (RoutineManager / TriggerManager / EventManager) ----------
//
// The three kinds are reported and administered separately because engines
// support them separately; see the interface docs. Reads degrade gracefully via
// the List* wrappers above, but a drop on an engine without the capability
// returns ErrUnsupported rather than silently succeeding.

// CanManageRoutines reports whether stored routines can be administered here.
func (c *Connection) CanManageRoutines() bool {
	_, ok := c.dialect.(RoutineManager)
	return ok
}

// CanManageTriggers reports whether triggers can be administered here.
func (c *Connection) CanManageTriggers() bool {
	_, ok := c.dialect.(TriggerManager)
	return ok
}

// CanManageEvents reports whether scheduled events can be administered here.
func (c *Connection) CanManageEvents() bool {
	_, ok := c.dialect.(EventManager)
	return ok
}

// DropRoutine drops a stored procedure or function the caller has already
// resolved from a listing.
func (c *Connection) DropRoutine(ctx context.Context, s Scope, r model.Routine) error {
	m, ok := c.dialect.(RoutineManager)
	if !ok {
		return ErrUnsupported
	}
	return c.dclScript(ctx, func() ([]string, error) { return m.DropRoutineSQL(s, r) })
}

// DropTrigger drops a trigger the caller has already resolved from a listing.
func (c *Connection) DropTrigger(ctx context.Context, s Scope, t model.Trigger) error {
	m, ok := c.dialect.(TriggerManager)
	if !ok {
		return ErrUnsupported
	}
	return c.dclScript(ctx, func() ([]string, error) { return m.DropTriggerSQL(s, t) })
}

// DropEvent drops a scheduled event the caller has already resolved from a
// listing.
func (c *Connection) DropEvent(ctx context.Context, s Scope, e model.Event) error {
	m, ok := c.dialect.(EventManager)
	if !ok {
		return ErrUnsupported
	}
	return c.dclScript(ctx, func() ([]string, error) { return m.DropEventSQL(s, e) })
}

// --- Table maintenance (TableMaintainer) ---------------------------------------

// TableMaintenanceOps lists the maintenance commands this engine offers, or nil
// when it offers none.
func (c *Connection) TableMaintenanceOps() []TableMaintenanceOp {
	m, ok := c.dialect.(TableMaintainer)
	if !ok {
		return nil
	}
	return m.TableMaintenanceOps()
}

// RunTableMaintenance runs one maintenance command and returns whatever the
// engine reported. op must be one of TableMaintenanceOps' names — the dialect
// rejects anything else, so an op cannot be smuggled in through the form.
//
// It runs as a query, not an exec: MySQL's OPTIMIZE/CHECK/REPAIR/ANALYZE all
// answer with a status table that is the entire point of running them, while
// PostgreSQL's VACUUM and REINDEX simply return no rows. No read timeout is
// applied — VACUUM FULL on a large table legitimately takes minutes, and the
// request context already bounds it.
func (c *Connection) RunTableMaintenance(ctx context.Context, t TableRef, op string) (*ResultSet, error) {
	m, ok := c.dialect.(TableMaintainer)
	if !ok {
		return nil, ErrUnsupported
	}
	stmt, err := m.TableMaintenanceSQL(t, op)
	if err != nil {
		return nil, err
	}
	return runQuery(ctx, c.db, stmt, maintenanceRowCap)
}

// maintenanceRowCap bounds a maintenance report. MySQL emits one row per table
// touched plus a row per message; this is far above any real output and only
// exists so a pathological result cannot be buffered without limit.
const maintenanceRowCap = 500

// CreateProgram runs one stored-program CREATE statement. It is a plain Exec
// rather than a script: the statement is sent whole, so a body full of internal
// semicolons (MySQL's BEGIN…END) needs no DELIMITER — that is a client-side
// convention for text scripts, not a wire-protocol one.
func (c *Connection) CreateProgram(ctx context.Context, create string) error {
	_, err := c.Exec(ctx, create)
	return err
}

// ReplaceProgram redefines an existing stored program: drop, then create.
//
// On an engine with transactional DDL the pair runs in one transaction, so a
// rejected CREATE leaves the original untouched. MySQL has no such thing —
// every DDL statement commits itself — so a CREATE that fails after the DROP
// succeeded would destroy the routine outright. There, the object's previous
// definition is replayed to put it back, and the caller is told whether that
// worked: losing a stored procedure to a typo is not an acceptable outcome of
// pressing Save.
//
// restore is the object's current full CREATE statement (what the editor was
// pre-filled with).
func (c *Connection) ReplaceProgram(ctx context.Context, drop []string, create, restore string) error {
	if c.Capabilities().SupportsTransactionalDDL {
		return c.ExecScript(ctx, append(append([]string{}, drop...), create), true)
	}
	if err := c.ExecScript(ctx, drop, false); err != nil {
		return err
	}
	createErr := c.CreateProgram(ctx, create)
	if createErr == nil {
		return nil
	}
	if restore == "" {
		return fmt.Errorf("%w (the original was already dropped and no saved definition was available to restore it)", createErr)
	}
	if restoreErr := c.CreateProgram(ctx, restore); restoreErr != nil {
		return fmt.Errorf("%w — and restoring the previous definition also failed: %v", createErr, restoreErr)
	}
	return fmt.Errorf("%w (the previous definition has been restored)", createErr)
}

// Query runs a row-returning statement and scans up to limit rows. Used by the
// SQL console (the user's own SQL under their own credentials) and by Browse.
func (c *Connection) Query(ctx context.Context, query string, limit int) (*ResultSet, error) {
	return runQuery(ctx, c.db, query, limit)
}

// Stream runs a query and delivers rows one at a time to perRow without
// buffering — used by streaming export of large tables.
func (c *Connection) Stream(ctx context.Context, query string, perRow func([]ResultColumn, []Value) error) error {
	return c.StreamArgs(ctx, query, nil, perRow)
}

// StreamArgs is Stream with bound parameters, for an export restricted to
// specific rows: the row-identity values are BOUND, never concatenated, so a
// "with selected" export keeps the same injection-free guarantee as the edit
// and delete paths it shares its row keys with.
func (c *Connection) StreamArgs(ctx context.Context, query string, args []any, perRow func([]ResultColumn, []Value) error) error {
	rows, err := c.db.QueryContext(ctx, query, args...)
	if err != nil {
		return err
	}
	return StreamResult(rows, perRow)
}

// Exec runs a non-row statement and reports affected rows.
func (c *Connection) Exec(ctx context.Context, query string) (ExecResult, error) {
	if c.observe == nil {
		return runExec(ctx, c.db, query)
	}
	start := time.Now()
	res, err := runExec(ctx, c.db, query)
	c.observe(ctx, StatementEvent{SQL: query, Rows: res.RowsAffected, Duration: time.Since(start), Err: err})
	return res, err
}

// SetStatementObserver installs the audit observer on an already-open
// connection.
//
// It exists for one case: the LOGIN pool is dialled before the identity to record
// is known — it is the connection that reveals it — so its observer cannot ride
// the ConnParams the way every derived dial's does. Call it before the Connection
// is shared with anything; there is no locking, because at that point there is
// nothing to race.
func (c *Connection) SetStatementObserver(fn StatementObserver) { c.observe = fn }

// resultStats extracts the affected-row count from an exec result (ExecResult
// carries nothing else), reporting rather than swallowing the reason it could
// not.
//
// Two things can go wrong, and neither means the statement failed:
//
//   - the driver does not track affected rows and returns an error;
//   - some drivers (modernc.org/sqlite) hand back a NIL driver.Result for input
//     that compiles to no statement — a comment-only script — and
//     database/sql's wrapper then dereferences it inside RowsAffected.
//
// The recover is scoped to that second case ONLY: a runtime error out of this
// one call. Anything else is a genuine bug and is re-panicked, so the process's
// own recover middleware sees it with its stack intact. The previous blanket
// `defer func() { _ = recover() }()` made every panic in reach invisible.
func resultStats(res sql.Result) (out ExecResult, err error) {
	if res == nil {
		return out, nil
	}
	defer func() {
		if p := recover(); p != nil {
			re, ok := p.(runtime.Error)
			if !ok {
				panic(p)
			}
			err = fmt.Errorf("driver returned no result for this statement: %w", re)
		}
	}()
	n, err := res.RowsAffected()
	if err != nil {
		return ExecResult{}, err
	}
	return ExecResult{RowsAffected: n}, nil
}

// ExecScript runs a sequence of non-row statements. When useTx is set it wraps
// them in a single transaction (all-or-nothing, mirroring the importer's BeginTx
// pattern); otherwise it runs them sequentially, stopping at the first error.
// The structure editor relies on this because some builders emit several
// statements (e.g. a PostgreSQL column modify) that must run as one unit on
// engines with transactional DDL — Connection.Exec has no transaction path.
func (c *Connection) ExecScript(ctx context.Context, stmts []string, useTx bool) error {
	return c.execScript(ctx, stmts, useTx, nil)
}

// execScript is ExecScript's implementation; redact rides every statement's
// audit event (StatementEvent.Redact) for the password-embedding DCL paths
// (dclScriptRedacted), and is nil everywhere else.
func (c *Connection) execScript(ctx context.Context, stmts []string, useTx bool, redact []string) error {
	if len(stmts) == 0 {
		return nil
	}
	// Each statement is reported to the audit observer individually, including
	// inside the transaction: what an auditor needs is the statements that ran,
	// and "one script" would tell them nothing about which. A failing statement is
	// reported too, with its error — an attempted DROP is as interesting as a
	// successful one.
	exec := func(run func() (sql.Result, error), stmt string) error {
		if c.observe == nil {
			_, err := run()
			return err
		}
		start := time.Now()
		res, err := run()
		rows := int64(-1)
		if err == nil {
			if stats, serr := resultStats(res); serr == nil {
				rows = stats.RowsAffected
			}
		}
		c.observe(ctx, StatementEvent{SQL: stmt, Rows: rows, Duration: time.Since(start), Err: err, Redact: redact})
		return err
	}
	if useTx {
		tx, err := c.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		// Panic safety AND the audit contract: a transaction that does not
		// commit emits the explicit "ROLLBACK" marker once observed statements
		// exist (the same contract observer.go's Tx documents), so a script
		// whose statement 3 fails does not leave statements 1–2 in the trail
		// reading as applied. A failed Commit rides the marker as its Err —
		// the statements themselves were recorded errorless.
		observed := 0
		var commitErr error
		committed := false
		defer func() {
			if committed {
				return
			}
			_ = tx.Rollback()
			if c.observe != nil && observed > 0 {
				c.observe(ctx, StatementEvent{SQL: "ROLLBACK", Rows: -1, Err: commitErr})
			}
		}()
		for _, s := range stmts {
			err := exec(func() (sql.Result, error) { return tx.ExecContext(ctx, s) }, s)
			observed++
			if err != nil {
				return err
			}
		}
		if commitErr = tx.Commit(); commitErr != nil {
			return commitErr
		}
		committed = true
		return nil
	}
	for _, s := range stmts {
		if err := exec(func() (sql.Result, error) { return c.db.ExecContext(ctx, s) }, s); err != nil {
			return err
		}
	}
	return nil
}

// qualifiedName builds the engine-correct, quoted table reference.
func (c *Connection) qualifiedName(t TableRef) string {
	return c.dialect.QualifyTable(t)
}

// QualifiedName exposes the engine-correct quoted table reference for handlers
// that build display SQL or pass-through queries.
func (c *Connection) QualifiedName(t TableRef) string { return c.qualifiedName(t) }

// SearchExpr returns the expression used to LIKE-match a column (already
// validated against introspection by the caller): the quoted identifier,
// text-cast where the engine requires it for LIKE (PostgreSQL).
func (c *Connection) SearchExpr(col string) string {
	quoted := c.dialect.QuoteIdent(col)
	if sc, ok := c.dialect.(SearchCaster); ok {
		return sc.SearchExpr(quoted)
	}
	return quoted
}

// Browse runs a paginated, optionally sorted SELECT * over a table. Sort columns
// must already exist (validated by the caller against Columns); Browse re-checks
// their shape and quotes them. It never accepts a raw WHERE fragment — filtering
// is done through the parameterized Search path — so there is no string-concat
// injection surface here.
func (c *Connection) Browse(ctx context.Context, t TableRef, page Pagination, sorts []Sort) (*ResultSet, error) {
	var b strings.Builder
	b.WriteString("SELECT * FROM ")
	b.WriteString(c.qualifiedName(t))
	if len(sorts) > 0 {
		b.WriteString(" ORDER BY ")
		for i, s := range sorts {
			if !safeSortColumn(s.Column) {
				return nil, fmt.Errorf("invalid sort column %q", s.Column)
			}
			if i > 0 {
				b.WriteString(", ")
			}
			b.WriteString(c.dialect.QuoteIdent(s.Column))
			if s.Descending {
				b.WriteString(" DESC")
			} else {
				b.WriteString(" ASC")
			}
		}
	}
	if page.Limit > 0 {
		b.WriteString(" ")
		b.WriteString(c.dialect.LimitClause(page.Limit, page.Offset))
	}
	// Browse is a generated read, so it is time-bounded — unlike the bare Query it
	// delegates to, which the SQL console also calls and must NOT bound. The
	// ResultSet is fully scanned (up to page.Limit) before this returns, so the
	// deferred cancel can't truncate it.
	ctx, cancel := c.readCtx(ctx)
	defer cancel()
	// A byte budget (Show all) takes the budgeted scan; it reads the bare pool
	// exactly as Query does, so the console entry point stays unbudgeted. The
	// budget is a scan bound only — the SQL above already carries page.Limit.
	if page.ByteBudget > 0 {
		return runQueryBudget(ctx, c.db, b.String(), page.Limit, page.ByteBudget)
	}
	return c.Query(ctx, b.String(), page.Limit)
}

// CountRows returns the exact row count for a table. Used to drive pagination
// totals.
func (c *Connection) CountRows(ctx context.Context, t TableRef) (int64, error) {
	ctx, cancel := c.readCtx(ctx)
	defer cancel()
	q := "SELECT COUNT(*) FROM " + c.qualifiedName(t)
	var n int64
	if err := c.db.QueryRowContext(ctx, q).Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

// CountRowsBounded counts a relation's rows but stops looking once more than
// max exist, so a relation with no usable statistics estimate — a VIEW above
// all, whose count re-runs the whole underlying query — cannot cost an
// unbounded scan on every Browse and Structure render.
//
// It reports exact=true with the true count when the relation holds at most max
// rows, and exact=false with max when it holds more ("at least this many"). The
// engine work is bounded either way: the derived table stops at max+1 rows.
// max <= 0 degrades to the plain unbounded CountRows.
//
// The SQL —
// SELECT COUNT(*) FROM (SELECT 1 FROM rel LIMIT n) t — is accepted verbatim by
// every supported engine; only the LIMIT spelling varies, and that comes from
// the dialect. The derived table is aliased because MySQL requires it.
func (c *Connection) CountRowsBounded(ctx context.Context, t TableRef, max int64) (n int64, exact bool, err error) {
	if max <= 0 {
		n, err = c.CountRows(ctx, t)
		return n, err == nil, err
	}
	ctx, cancel := c.readCtx(ctx)
	defer cancel()
	// max+1 distinguishes "exactly max" from "more than max". max is an int64
	// from operator config; guard the increment rather than wrap to negative.
	probe := max
	if probe < math.MaxInt64 {
		probe++
	}
	inner := "SELECT 1 FROM " + c.qualifiedName(t) + " " + c.dialect.LimitClause(clampToInt(probe), 0)
	if err := c.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM ("+inner+") tx_bounded_count").Scan(&n); err != nil {
		return 0, false, err
	}
	if n >= probe {
		return max, false, nil
	}
	return n, true, nil
}

// clampToInt narrows an int64 to int without wrapping on a 32-bit build (the
// CI matrix includes GOARCH=386), saturating at the platform maximum.
func clampToInt(v int64) int {
	if v > int64(math.MaxInt) {
		return math.MaxInt
	}
	return int(v)
}

// EstimateRows returns the engine's statistics-based row estimate for a table,
// or -1 when no usable estimate exists (engine keeps none, relation never
// analyzed, view). Callers fall back to CountRows on -1.
func (c *Connection) EstimateRows(ctx context.Context, t TableRef) (int64, error) {
	e, ok := c.dialect.(RowEstimator)
	if !ok {
		return -1, nil
	}
	ctx, cancel := c.readCtx(ctx)
	defer cancel()
	return e.EstimateRows(ctx, c.db, t)
}

// Explain runs EXPLAIN (or EXPLAIN ANALYZE) for a query if the engine supports
// it, returning the plan as a result set.
func (c *Connection) Explain(ctx context.Context, query string, analyze bool) (*ResultSet, error) {
	return runExplain(ctx, c.dialect, c.db, query, analyze)
}

// ExplainSQL returns the exact statement Explain would execute (e.g. SQLite's
// "EXPLAIN QUERY PLAN …"), so the console can label the result with what really
// ran rather than a generic "EXPLAIN …".
func (c *Connection) ExplainSQL(query string, analyze bool) (string, bool) {
	return c.dialect.ExplainSQL(query, analyze)
}
