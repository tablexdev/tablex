# TableX — Database Driver Abstraction

> This is the heart of "support all databases." Companion: [`architecture.md`](./architecture.md).

## 1. Design principle

We do **not** duplicate query execution per engine. The generic path (open pool, run query, scan rows, paginate) is shared once, on top of Go's `database/sql`. Only the parts that genuinely differ between engines live behind a small **`Dialect`** interface:

- DSN building
- identifier quoting & placeholder syntax
- metadata introspection (list databases/schemas/tables/columns/indexes/foreign keys)
- engine capabilities
- a few SQL fragments (LIMIT/OFFSET, `SHOW CREATE`, etc.)

A single `Connection` type wraps `*sql.DB` + a `Dialect` and exposes engine-neutral methods to handlers. Adding a new engine = implement `Dialect` + register it. Nothing else changes.

---

## 2. Core interfaces (target shape — refined during implementation)

```go
package driver

// Dialect captures everything that differs between database engines.
type Dialect interface {
    // Identity
    Name() string         // canonical id: "mysql", "postgres", "sqlite"
    DisplayName() string  // "MySQL / MariaDB", "PostgreSQL", "SQLite"
    DefaultPort() int

    // Connection
    SQLDriverName() string                 // database/sql driver name: "mysql", "pgx", "sqlite"
    BuildDSN(p ConnParams) (string, error) // engine-specific DSN

    // SQL syntax
    QuoteIdent(name string) string         // `name` / "name"
    Placeholder(n int) string              // "?"  /  "$1"
    LimitClause(limit int, offset int64) string // mostly "LIMIT x OFFSET y"; the offset is int64 end-to-end

    // Introspection (each takes ctx + *sql.DB, returns neutral model types)
    ServerInfo(ctx context.Context, db *sql.DB) (ServerInfo, error)
    ListDatabases(ctx context.Context, db *sql.DB) ([]model.Database, error)
    ListSchemas(ctx context.Context, db *sql.DB, database string) ([]model.Schema, error)
    ListTables(ctx context.Context, db *sql.DB, scope Scope) ([]model.Table, error)
    Columns(ctx context.Context, db *sql.DB, t TableRef) ([]model.Column, error)
    Indexes(ctx context.Context, db *sql.DB, t TableRef) ([]model.Index, error)
    ForeignKeys(ctx context.Context, db *sql.DB, t TableRef) ([]model.ForeignKey, error)
    CreateSQL(ctx context.Context, db *sql.DB, t TableRef) (string, error)

    Capabilities() Capabilities
}

type ConnParams struct {
    Host, Socket string
    Port         int
    User, Password string
    Database     string // optional; required for PostgreSQL
    FilePath     string // SQLite database file path
    SSLMode      string // engine-specific TLS preference
    Params       map[string]string // extra driver params, merged last

    // Set once at login and inherited by every DERIVED dial (per-database pool,
    // pinned script connection, export connection), which is why they ride
    // ConnParams rather than a Connection or a package-level variable.
    DialControl func(network, address string, c syscall.RawConn) error // SSRF / DNS-rebinding backstop; ad-hoc network logins only
    OnStatement StatementObserver // the audit trail's statement half
    Tuning      Tuning            // pool sizes and statement timeouts; zero means driver defaults
}

type Capabilities struct {
    HasSchemas      bool // PostgreSQL: true; MySQL/SQLite: false
    HasUsers        bool // privilege management
    HasForeignKeys  bool
    HasStoredRoutines bool
    HasTriggers     bool
    HasEvents       bool // MySQL/MariaDB events
    HasViews        bool
    SupportsExplain bool
    SupportsTransactionalDDL bool // PG: true; MySQL: false; SQLite: true
    DatabasesShareConnection bool // SQLite: true (one file); MySQL/PG: false
    IsNetworkEngine bool // host:port + credentials, not a local file
}
```

(Abridged — see `internal/driver/driver.go` for the full set.)
`IsNetworkEngine` is the login path's only engine discriminator: ad-hoc login is
offered **only** for network engines, credentials are collected only for them,
and the SSRF host policy applies only to them. A file-backed engine has no
credentials, so an ad-hoc login for it would be an unauthenticated arbitrary
file open; it is reachable only through an operator-configured predefined
server.

```go
// Connection is engine-neutral and is what handlers use.
type Connection struct {
    db           *sql.DB
    dialect      Dialect
    info         ServerInfo
    tuning       Tuning            // resolved (no zero fields) at Open
    observe      StatementObserver // audit sink; nil when auditing is off
    floorWarning string            // set at Open when the server is below the engine floor
}

func (c *Connection) ListDatabases(ctx) ([]model.Database, error)
func (c *Connection) ListTables(ctx, scope Scope) ([]model.Table, error)
func (c *Connection) Browse(ctx, t TableRef, page Pagination, sorts []Sort) (*ResultSet, error)
func (c *Connection) Query(ctx, query string, limit int) (*ResultSet, error)   // SQL console
func (c *Connection) Exec(ctx, sql string) (ExecResult, error)
func (c *Connection) Capabilities() Capabilities { return c.dialect.Capabilities() }
```

`ResultSet` is engine-neutral: column metadata + `[][]Value`, scanned generically via `rows.ColumnTypes()` so any engine's result renders in the browse grid.

---

## 3. Registry & registration

```go
// registry.go — every accessor takes the package-level RWMutex, because init()
// registration and a later lookup are not guaranteed to be on the same goroutine.
var (
    mu       sync.RWMutex
    dialects = map[string]Dialect{}
)

// Register panics on a duplicate name: that is a programming error (two packages
// claiming one engine), and failing at startup beats one of them winning silently.
func Register(d Dialect)
func Get(name string) (Dialect, bool)
func RegisteredNames() []string // names only, sorted — config validation, error messages
func All() []Dialect            // every dialect, sorted by Name for stable UI ordering
```

Each engine package registers itself; `cmd/tablex` blank-imports them:

```go
import (
    _ "github.com/tablexdev/tablex/internal/driver/mysql"
    _ "github.com/tablexdev/tablex/internal/driver/postgres"
    _ "github.com/tablexdev/tablex/internal/driver/sqlite"
)
```

Removing/adding an engine is one import line.

---

## 4. Per-engine specifics

### 4.1 MySQL / MariaDB — `go-sql-driver/mysql` v1.10.0
- **DSN:** `user:pass@tcp(host:port)/dbname?parseTime=true&loc=UTC&tls=...`
- **Quoting:** backticks `` `ident` `` (escape internal backticks by doubling).
- **Placeholders:** `?`
- **Schemas:** none — a "database" is the top level. `HasSchemas=false`.
- **Introspection:** `information_schema` (`SCHEMATA`, `TABLES`, `COLUMNS`, `STATISTICS`, `KEY_COLUMN_USAGE`) and `SHOW CREATE TABLE`.
- **MariaDB detection:** version string contains `MariaDB`; surface as display info; behavior largely identical.
- **Multiple DBs per connection:** yes at the SQL level (`USE db`, or a qualified `` `db`.`table` ``) — but `DatabasesShareConnection=**false**`. That flag means "one connection serves every logical database", which is true only for SQLite; TableX opens a pool per database the user visits (§2's `Capabilities` comment and §5's matrix note say the same).
- **Capabilities:** users/privileges ✔, FKs ✔ (InnoDB), routines ✔, triggers ✔, events ✔, views ✔, transactional DDL ✘.

### 4.2 PostgreSQL — `jackc/pgx/v5` v5.10.0 (via `pgx/v5/stdlib`)
- **DSN:** URL form `postgres://user:pass@host:port/dbname?sslmode=prefer&connect_timeout=15`. `connect_timeout=15` is set unconditionally; both it and `sslmode` are rejected as extra `Params` keys, so a same-named key cannot silently override the computed value.
- **Quoting:** double quotes `"ident"` (escape internal quotes by doubling).
- **Placeholders:** `$1, $2, …`
- **Schemas:** **yes** — `HasSchemas=true`. Tree shows Database → Schema → Table. Default schema `public`.
- **One DB per connection:** `DatabasesShareConnection=false`. Switching databases opens a new pool (see connection manager).
- **Introspection:** `pg_catalog` only (`pg_namespace`, `pg_class`, `pg_attribute`, `pg_index`, `pg_constraint`, …); `pg_get_constraintdef`, `pg_get_indexdef` for DDL reconstruction (no native `SHOW CREATE TABLE`). `information_schema` is never read — it appears only in the predicates that exclude it as a system schema — because it cannot express what the dump needs (partition bounds, exclusion constraints, storage/reloptions, identity vs serial).
- **Capabilities:** users/roles ✔, FKs ✔, routines/functions ✔, triggers ✔, events ✘, views/matviews ✔, transactional DDL ✔, EXPLAIN/EXPLAIN ANALYZE ✔.

### 4.3 SQLite — `modernc.org/sqlite` v1.56.0 (pure Go)
- **DSN:** file path plus pragmas (e.g. `file:/path/app.db?_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)`), or `:memory:` (DSN-level only — config validation rejects in-memory paths for predefined servers, since every pooled/transient connection would open its own private empty database).
  - `busy_timeout(5000)` and `foreign_keys(1)` are added **always**. `journal_mode(WAL)` is **conditional**: skipped for an in-memory database, and skipped when the operator's own `_pragma` params already set a journal mode. That condition is not politeness — modernc does **not** apply repeated `_pragma` values in DSN order (neither first nor last): it **sorts** the list (`busy_timeout` first, then case-insensitive lexicographic) and executes in that order, so among several `journal_mode` values the lexicographically-largest wins. `wal` is the largest standard mode, so emitting both the default and the operator's would let the default override the operator's choice — dropping the default is what lets the operator's value be the only one and take effect. WAL also differs from the other two in kind: it is persisted in the database header and creates `-wal`/`-shm` sidecar files.
- **Quoting:** double quotes `"ident"` (also accepts `[ident]` / backticks; we emit double quotes).
- **Placeholders:** `?`
- **Schemas:** none; `main` is the database. Additional files via `ATTACH`. `HasSchemas=false`.
- **Introspection:** `sqlite_master` (or `sqlite_schema`) + `PRAGMA index_list` and `PRAGMA foreign_key_list`; the `sql` column of `sqlite_master` *is* the create statement. Both column pragmas are live and do different jobs: **`table_xinfo`** supplies the column list (its `hidden` flag is what distinguishes a generated column — 2 VIRTUAL, 3 STORED — from an ordinary one), while **`table_info`** still resolves an implicit-PK foreign key's referenced columns, where the `pk` position is all that is needed.
- **Capabilities:** users/privileges ✘ (none), FKs ✔ (when enabled), routines ✘, triggers ✔, events ✘, views ✔, transactional DDL ✔, EXPLAIN ✔ (`EXPLAIN QUERY PLAN`).
  - `SupportsTransactionalDDL` is **true** for SQLite, unconditionally: DDL inside a transaction rolls back with it, which is what the flag is consumed for. The qualifier people reach for belongs to a different question — how much `ALTER TABLE` can express (no column type change, no add/drop FK) — and that is carried by `SupportsColumnModify` / `SupportsForeignKeyDDL`, not by this flag.
- UI must **gracefully hide** unsupported tabs (Users, Routines, Events) when `Capabilities` says so.

### 4.4 Minimum supported engine versions

These are the floors the introspection and round-trip code actually relies on. A server below its engine's floor is **reported at login** — a warning flash plus a log line — rather than left to degrade at the point of use, where a missing catalog column surfaced as an empty listing or a confusing error with nothing pointing at the cause. It warns rather than refuses: most of the tool still works, and locking an operator out over a feature floor would be the worse trade. The check lives on the dialect (`driver.VersionFloor`), because only the specialized dialect has parsed the version.

**This section uses "floor" in two senses, and only one of them is a check.** A
*checked* floor is a `driver.VersionFloor` implementation — a login-time
comparison that produces the warning above. A *feature* floor is the oldest
release whose catalog and DDL surface TableX relies on: a documented
requirement with no code behind it. MySQL and MariaDB have both, and the
numbers are the same ones (`ServerBelowFloor` compares against exactly the
table's 8.0.13 and 10.2.7). SQLite has only the second — it declares no
`VersionFloor`, since the library is compiled into the binary and there is no
operator's server to be too old, so its 3.26+ / 3.31+ rows below are
requirements on a database *file*'s schema, never a login-time check.

| Engine | Minimum | Why |
|---|---|---|
| MySQL | **8.0.13+** | `DEFAULT_GENERATED` marker in `information_schema.COLUMNS.EXTRA` (expression defaults / functional defaults). |
| MariaDB | **10.2.7+** | Quoted-literal `COLUMN_DEFAULT` convention (literals quoted, expressions bare) and `DEFAULT (expr)` expression defaults. |
| PostgreSQL | **13+** | `attgenerated` generated columns (12+) **and** `DROP DATABASE … WITH (FORCE)` (13+), which the Operations "Drop database" action emits so a drop is not blocked by a lingering backend. (Identity columns and declarative partitioning need only 10+, `pg_partition_tree` 12+, but 13 is the effective floor.) |
| SQLite | **3.26+** | `PRAGMA table_xinfo` introspection. **3.31+** is additionally required for any schema that *contains* generated columns (`GENERATED ALWAYS AS`, added in SQLite 3.31.0) — `table_xinfo` only reads them, it does not backport the feature. |

**Verified in CI** against the Docker service containers: **MySQL 8.4 and 8.0**, **MariaDB 11.4 and 10.6**, and **PostgreSQL 13 and 18** — the live round-trip suite runs against both the 13 floor and the current 18 release, so the version-dependent catalog queries (`to_jsonb` column reads, collation/`attstattarget` shapes) are exercised on both; newer-only seed features (column-subset `SET NULL`, UNLOGGED sequences, multirange types, column compression, VIRTUAL generated columns) version-gate themselves. The Operations "Drop database" action emits `DROP DATABASE … WITH (FORCE)` on PostgreSQL (**13+**) so a drop is not blocked by a lingering backend (the drop still runs on a connection bound to a different database, since PostgreSQL cannot drop the database its own session is connected to); the test harness uses the same statement to evict pool connections between round-trips.

The oldest images CI runs are MySQL **8.0**, MariaDB **10.6** and PostgreSQL **13**. Note what that does and does not prove: the PostgreSQL floor (13) is exercised exactly, but the MySQL and MariaDB feature floors (8.0.13, 10.2.7) are *older* than any image in CI, so the code paths between those versions and the tested ones are reasoned about, not run. The login-time check above at least names the floor to an operator who is below it.

This floor is a *feature* floor, not a support-lifecycle statement: the MariaDB 10.2.7 and SQLite 3.26 rows are likewise long-EOL versions, and PostgreSQL 13 itself reached end-of-life on 2025-11-13 — but the PostgreSQL floor is now exercised in CI (the round-trip suite runs against a `postgres:13` service alongside 18), so the 13-compatible code path is verified, not merely asserted. It is the lowest version whose catalog/DDL surface TableX relies on, not a claim that older releases are unsupported by their vendors.

---

## 5. Capability matrix (drives which UI tabs appear)

| Feature | MySQL/MariaDB | PostgreSQL | SQLite |
|---|:---:|:---:|:---:|
| Schemas level | ✘ | ✔ | ✘ |
| Multiple DBs per connection | ✔ | ✘ | ✔ (ATTACH) |
| Users / privileges | ✔ | ✔ (roles) | ✘ |
| Foreign keys | ✔ (InnoDB) | ✔ | ✔ |
| Views | ✔ | ✔ (+matviews) | ✔ |
| Stored routines | ✔ | ✔ (functions) | ✘ |
| Triggers | ✔ | ✔ | ✔ |
| Events | ✔ | ✘ | ✘ |
| Transactional DDL | ✘ | ✔ | ✔ |
| EXPLAIN | ✔ | ✔ (+ANALYZE) | ✔ (QUERY PLAN) |
| Native `SHOW CREATE` | ✔ | ✘ (reconstruct) | ✔ (sqlite_master) |

The UI reads `Capabilities()` and never assumes a feature exists.

Two rows need reading carefully, because their tick does **not** correspond to the
similarly named capability flag:

- **Multiple DBs per connection** records the engine's own ergonomics — MySQL's
  `USE db` and qualified `` `db`.`table` ``, SQLite's `ATTACH`. It is *not*
  `DatabasesShareConnection`, which only SQLite sets: MySQL gets a ✔ here and
  `DatabasesShareConnection=false`, because TableX still opens a pool per database.
- **Transactional DDL** is `SupportsTransactionalDDL`, and SQLite sets it
  unconditionally. What SQLite's `ALTER TABLE` cannot *express* is a separate
  question, carried by `SupportsColumnModify` and `SupportsForeignKeyDDL`.

**Users / privileges are write-capable, not view-only:** on MySQL/MariaDB and
PostgreSQL the server Users page can create/drop accounts and set passwords
(plus PostgreSQL role attributes: LOGIN/SUPERUSER/CREATEDB/CREATEROLE), and the
database/table Privileges pages run GRANT/REVOKE at either scope. The write
side lives behind the optional `UserManager`/`PrivilegeManager` dialect
interfaces (SQLite implements neither, so its UI hides every control), with the
account shape driven by `Capabilities().AccountHasHost` (MySQL `'user'@'host'`)
and `SupportsRoleAttributes` (PostgreSQL). Grant checkboxes come from the
dialect's `GrantablePrivileges` allowlist; revoke is introspection-driven, so a
version-specific privilege (e.g. PostgreSQL 17 `MAINTAIN`) stays revokable
without being offered. PostgreSQL privilege listings read the direct ACLs
(`aclexplode` over `pg_database.datacl` / `pg_class.relacl`), which also
surfaces — and lets you revoke — grants to `PUBLIC`.

---

## 6. Safety rules (enforced in this layer)

1. **All data values are parameterized** — never string-concatenated into SQL — **except in DDL positions that accept no placeholder**, where the value goes through `Dialect.QuoteString` instead: an `ENUM`/`SET` member list, a column's `DEFAULT` literal and `COMMENT`, account parts and passwords in DCL, and a dumped data literal. [`security.md`](./security.md) §4 enumerates them and is the authoritative list.
2. **Identifiers** (table/column/db names) chosen by the user are inserted only via `Dialect.QuoteIdent`, after validating they match the object actually present in introspection. We never trust a raw identifier from the URL/form into SQL unquoted.
3. **The SQL console** intentionally runs arbitrary SQL — that is the product. It runs under the *user's own credentials and privileges*, scoped to their session connection. We add no extra power. **SQL import**, a **stored program's body**, and a **partial index's `WHERE` predicate** are the same bargain in narrower places; `allow_console = false` closes all four.
4. **Context-bound** — every call carries the request `context.Context` for cancellation/timeouts.

Details and the broader threat model: [`security.md`](./security.md).

---

## 7. Adding a new engine (e.g., CockroachDB, SQL Server, ClickHouse)

1. Add a pure-Go `database/sql` driver dependency.
2. Create `internal/driver/<engine>/` implementing `Dialect` (DSN, quoting, placeholders, introspection, capabilities).
3. `driver.Register(engine{})` in the package `init()`, plus an `interfaces.go` asserting every optional interface it satisfies.
4. Blank-import it in `cmd/tablex` — the only edit outside the new package.
5. Add integration tests; the conformance suite already covers it via `driver.All()`.

No handler, template, or model change is required unless the engine introduces a genuinely new concept — in which case extend `Capabilities` and let the UI key off it. This is why the abstraction matters: breadth comes from new dialects, not new branches scattered through the app.

**→ [adding-an-engine.md](./adding-an-engine.md)** is the full contract: the 26
required methods and what each must guarantee, every optional interface and
what it unlocks, the capability⇒interface rules, the script-grammar profile,
and `internal/driver/drivertest` — the reusable conformance suite that enforces
quoting round-trips, placeholder consistency, 64-bit `LIMIT` offsets,
capability/interface coherence and neutral-model population for every
registered dialect.

---

## 8. Known limitations

- **User-defined types, collations, RLS, and object metadata (PostgreSQL).** SQL
  dumps now carry user-defined **enums, domains and composite types** and
  user-defined **collations** (both dependency-ordered, before the objects that
  use them), plus each column's non-default **COLLATE**; **row-level security**
  state (ENABLE/FORCE) and **policies** (with `row_security = off` pinned on the
  export session, so a role *subject* to policies fails visibly instead of
  silently exporting filtered rows); non-default **REPLICA IDENTITY**; per-column
  **storage / compression / statistics** (`SET STORAGE|COMPRESSION|STATISTICS`)
  on tables **and materialized views** (`ALTER MATERIALIZED VIEW … ALTER
  COLUMN`; `SET COMPRESSION` is emitted only on PG14+ servers); a matview's
  **indexes** (+ their comments), on both the database- and single-matview
  export paths; **`INSTEAD OF` view triggers** and **view-column defaults**
  (`ALTER VIEW … SET DEFAULT`); every trigger's non-default **enable state**
  (`ENABLE ALWAYS` / `ENABLE REPLICA` / `DISABLE TRIGGER` — a disabled trigger
  used to restore enabled); on **PostgreSQL 18+** the catalogued **named table
  `NOT NULL` constraints** — names, comments and `NO INHERIT` survive (validated
  local ones inline, `NOT VALID` ones as post-data `ADD CONSTRAINT … NOT VALID`
  so a pre-existing NULL row survives), a purely-inherited copy's own comment
  rides along when its parent link is restored, and a validated child copy under
  a `NOT VALID` parent is re-validated post-data (`VALIDATE CONSTRAINT`); a
  purely-inherited copy on a table dumped *standalone* (table scope /
  cross-schema parent) is **materialized as the child's own named constraint**
  (name and comment survive; a `NOT VALID` copy rides post-data, which
  superseded an earlier bare-clause form); **typed tables** (`CREATE TABLE
  … OF type`, per-column
  `WITH OPTIONS NOT NULL/DEFAULT` deviations and table constraints — previously
  flattened to an ordinary CREATE TABLE that failed the type linkage);
  **user-defined non-SELECT rewrite rules** (`pg_get_ruledef` on tables and
  views, recreated post-data so a `DO ALSO` rule cannot double-apply during the
  row restore, with `ENABLE/DISABLE … RULE` state and `COMMENT ON RULE`);
  relation **storage parameters** (`reloptions` — a table's
  `fillfactor`, a view's `security_invoker` / `security_barrier` /
  `check_option`) and non-default
  **access method** (`USING`); a view/matview's DDL at table scope (`CREATE VIEW`,
  not a physical-table snapshot); UNLOGGED / renamed identity sequences; matview
  *populated* state; and every object **comment** (table, column, view, matview,
  sequence, trigger, index, constraint — including inline PK/UNIQUE/EXCLUDE and
  PG18 named NOT NULL — schema, type, collation). An ICU collation's tailoring
  **`RULES`** (PG16+) ride its `CREATE COLLATION`, since a collation restored
  without them silently compares differently. Not dumped:
  **database-default-provider collations** — PostgreSQL itself rejects `CREATE
  COLLATION … FROM "default"`, so this one is an engine limit, not a gap; the
  collation is skipped with a warning naming it, and must be created in the
  target beforehand — plus index-column / extended (`CREATE STATISTICS`)
  statistics, clustered-index state, tablespaces, ownership/ACLs (see below).
  (Range/multirange, base and shell types ARE dumped, conditionally on
  their support functions' shared library — see the object-surface entry below.) An export must run as a role that can read every
  in-scope RLS table unfiltered (superuser or `BYPASSRLS`; plain ownership
  suffices only without `FORCE ROW LEVEL SECURITY`), and restored policies name
  roles that must already exist in the target.

- **Cross-schema restore ordering (PostgreSQL) — the topology engine.** One
  unified planner serves every SQL export path (single-schema, whole-database
  AND each server-scope database section — the server path previously emitted
  complete per-schema sections that hid every cross-schema dependency). The
  pre-data phase is a genuine **topological sort** over all pre-data kinds,
  seeded by a pg_dump-style object-class priority (collations → types →
  routines → sequences → tables → views) with real catalog edges overriding it:
  cross-schema type-over-type, composite-typed columns, view-over-view, a PG14+
  `BEGIN ATOMIC` routine reading a later table (its body is parsed at creation
  and records enforced `pg_depend` edges — the table is hoisted above it),
  routine default-argument chains, and DB-wide dependency-ordered matview
  REFRESHes. The export session pins an **empty `search_path`** so every
  deparsed definition is fully qualified (shadowed same-named cross-schema
  objects restore correctly). **Dependency cycles are RESOLVED, not warned
  away**: a deferrable edge (a domain's DEFAULT/CHECK, a table column DEFAULT,
  a validated CHECK/EXCLUDE expression) that closes a cycle is cut and re-added
  as deferred DDL (`ALTER DOMAIN … SET DEFAULT` in the pre-data finalizer lane
  with consumers re-ordered after it; column defaults/constraints post-data,
  where row INSERTs name every column explicitly); a routine cycle (mutually
  recursive atomic bodies, cyclic argument defaults) is STAGED — a
  signature-preserving stub with every argument default omitted and an
  unchecked placeholder body, then the original `CREATE OR REPLACE` restores
  body/language/defaults; a cycle nothing resolves fails the export at
  PREFLIGHT with a precise error instead of producing a broken dump.
  **Residuals:** a **schema-scoped** export (a single named schema) is not
  self-contained for cross-schema references (a partition child, FK, view or
  inheritance child whose counterpart lives in another schema is omitted or
  dumped standalone); and a staged routine whose argument DEFAULT relies on
  another staged routine's *defaults* (a bare `f()` call in the default
  expression of a mutually-cyclic pair) restores only when the referenced
  defaults happen to restore first — `pg_dump` cannot restore any default-arg
  cycle at all.

- **Ordinary (INHERITS) inheritance (PostgreSQL).** An inheritance parent's data
  is dumped with `FROM ONLY`, so child rows are no longer duplicated into the
  parent (a former silent data-corruption bug). A child whose parents are **all in
  the same export and same schema** now dumps `CREATE TABLE … INHERITS (parent)`
  with only its **local** columns/constraints re-declared, so the link and column
  provenance (`attislocal`) round-trip; the create loop orders parents before
  children. A **cross-schema** parent, or a **table-scope** export of a child
  alone, dumps the child *standalone* (all columns local, link lost) with a
  warning — the standalone materialization is **complete**: inherited
  validated CHECKs inline, inherited `NOT VALID` CHECKs and cloned FKs
  post-data, PG18 named `NOT NULL` copies with their comments, and (partition
  children) cloned triggers with enable state, attached indexes and a
  **synthesized partition-bound CHECK** from
  `pg_get_partition_constraintdef` (a **HASH** bound embeds the parent's OID
  via `satisfies_hash_partition` and is dropped with a warning — an explicit
  residual). A child's **divergent** inherited-column default now
  re-establishes post-data through the deferred-DDL carrier (`ALTER TABLE ONLY
  child … SET DEFAULT/DROP DEFAULT` — both directions, and partition children
  diverging from their root), a **multi-parent default conflict** (which fails
  `CREATE … INHERITS` before any staged DDL) suppresses the column inline
  across the hierarchy and re-emits each member's own default the same way
  (pg_dump's separate-default-statement strategy; `attislocal`/`attinhcount`
  untouched), and a **divergent inherited-only generated expression**
  re-establishes via PG17+ `SET EXPRESSION` (unreachable below 17). Partition
  children keep their `PARTITION OF` linkage and their child-local objects
  (FKs, NOT VALID checks, triggers, RLS, replica identity, comments,
  child-only indexes) at database/server scope.

- **Replacement sequences + data-state gating (PostgreSQL).** A **scoped
  (table-scope) export** whose emitted tables reference a sequence the dump
  does not emit — an inherited serial default, a default naming a standalone or
  cross-schema sequence (early-bound `'s'::regclass` via its `pg_depend` edge
  OR late-bound `'s'::text` by scanning the deparsed expression), or a
  standalone partition child's **root identity sequence** — materializes a
  deterministic **`tablex_seq_<sha256-prefix>` replacement**: the source's
  COMPLETE definition (`AS type`, START/INCREMENT/MIN/MAX/CACHE/CYCLE,
  persistence, comment), seeded from the source's current value, with every
  referencing default rebound through a quote-aware literal rewriter. Serial
  replacements are standalone `CREATE SEQUENCE` (the single `OWNED BY` owner is
  preserved when emitted, else `OWNED BY NONE` + warning — consumer count never
  forces NONE); an identity replacement rides **inline** as `SEQUENCE NAME`
  inside the child's `GENERATED … AS IDENTITY` (no standalone CREATE/OWNED
  BY/drop), splitting the tree's shared identity stream per child with a
  fidelity warning. Names are collision-checked against the placement schema's
  ENTIRE source `pg_class` namespace (hex prefix lengthened 12→52 on
  collision, then an explicit error). A **data-only** dump instead targets the
  ORIGINAL qualified sequence with `setval` and never references a
  replacement; an unresolvable late-bound reference (unqualified, dynamic,
  dangling) is warned, never guessed. A **structure-only** dump now carries no
  `setval` and no `REFRESH MATERIALIZED VIEW` at all (they are data-state;
  matviews restore `WITH NO DATA`), and an identity sequence whose
  persistence diverges from its table's (PG15+) restores it via `ALTER
  SEQUENCE … SET LOGGED/UNLOGGED`.

- **Drop-first teardown: complete, cycle-aware, and honestly advisory.** A
  drop-first dump now tears down the object classes a reverse walk previously
  left standing — **routines, procedures, window functions and aggregates**
  (identity-qualified, each with the signature form its own command takes:
  plain identity arguments for `DROP FUNCTION`/`DROP PROCEDURE`, the
  direct/`ORDER BY` split and `(*)` for `DROP AGGREGATE`), plus the
  object-surface classes below (casts, operators, operator classes, foreign
  data). Routine drops ride the
  **reverse teardown**, ahead of the types their signatures name — a routine
  using a dumped type would otherwise block that type's `DROP` (MySQL keeps its
  mysqldump-style inline drop, declared per dialect rather than hard-coded).
  - **Cycles the restore deliberately creates are handled, never emitted
    broken.** The topology engine restores cycles through shells and stubs, so the RESTORED
    catalog holds dependency cycles that individually-ordered `DROP`s cannot
    linearize: each fails under RESTRICT while another member still references
    it, and the importer stops at the first error. The teardown therefore
    rebuilds the drop graph over **logical** objects (a shell type and the
    CREATE completing it collapse into one; so do an operator family and the
    ALTER adding its loose members) with **uncut** edges, and runs Tarjan over
    it. A cycle whose members share a list-taking `DROP` class — or whose
    members are all routines, which one `DROP ROUTINE` covers using the **flat
    input signature** — becomes a single multi-object statement. Grouping is
    gated on an explicit capability table (`FUNCTION`/`PROCEDURE`/`AGGREGATE`/
    `ROUTINE`/`TYPE`/`DOMAIN`/`SEQUENCE`/`VIEW`/`OPERATOR`/`TABLE`); a
    list-less class is never rendered as invalid grouped SQL.
  - **What cannot be dropped is RETAINED and warned, not force-dropped.**
    `CASCADE` is never emitted (it would strip objects outside the export's
    knowledge), so a cycle no single command spans — a **base type and its I/O
    functions**, a **range type with a `CANONICAL` function**, a **domain
    default (or table/view default) and the routine it calls** — has its whole
    component's drops omitted with a warning naming the objects. Omitting only
    the `DROP TYPE` would leave a `DROP FUNCTION` that fails and aborts the
    restore. `DROP OPERATOR FAMILY` is likewise never emitted (it drops
    contained, possibly target-only, operator classes even without CASCADE).
    Retention then **propagates along prerequisite edges**: a surviving object
    still holds its own prerequisites, so their drops are omitted too (a
    retained family's loose members, a retained range type's subtype/opclass/
    collation). Retention is warn-only — no member is ever de-linked, because
    `ALTER OPERATOR FAMILY … DROP OPERATOR` addresses a slot rather than the
    occupying member and could remove a target-only one.
  - **Fresh-target safety is preserved.** `DROP FUNCTION/AGGREGATE/CAST/
    OPERATOR … IF EXISTS` no-ops on a fresh target even when its identity names
    a user-defined type that does not exist yet (PostgreSQL propagates
    `missing_ok` into that lookup). The single exception is an operator class
    over a **non-built-in access method**, which raises `undefined_object` even
    under `IF EXISTS`; that one drop is wrapped in an error-tolerant `DO` guard
    (PL/pgSQL, the default language) with the statement quoted as a string
    literal inside a collision-free dollar tag. An internally-owned routine (a
    range type's auto-created constructors) carries no drop at all — it is not
    independently droppable and dies with its owner.
  - **The blocker audit is source-side and advisory.** Once per database it
    probes `pg_depend` NORMAL dependents of every planned drop, resolving each
    to its owner first (an index, rule, constraint, default or trigger dies
    with its relation and blocks nothing when that relation is dropped too),
    and traverses **`pg_inherits`** as well, because partitioning records
    `'P'`/`'S'` dependencies a NORMAL scan alone would miss. Anything left —
    an external view over a dumped table, an out-of-scope index using a dumped
    operator class, an out-of-scope inheritance or partition child — becomes an
    inert `-- WARNING:` naming the exact blocked statement. It never fails an
    export, never suppresses the drop it warns about, and never escalates to
    CASCADE; a failed audit degrades to a note. Blockers that exist only in the
    RESTORE TARGET are unknowable from the source connection, and a fresh
    target no-ops every `DROP … IF EXISTS` regardless — so drop-first into a
    **populated** target stays best-effort: a retained cycle's objects must be
    removed manually before re-restoring over them.

- **Object-surface breadth (PostgreSQL).** The SQL dump now covers, beyond
  enum/domain/composite types and plain functions/procedures:
  - **Range types** (full `pg_range` surface — subtype, non-default subtype
    opclass, collation, `CANONICAL`, `SUBTYPE_DIFF`) via the **type-shell →
    support-function → type-final bootstrap** (a shell `CREATE TYPE q;`, the
    support functions created against the shell, then the completing CREATE);
    on PG14+ the **actual multirange name** is always pinned via
    `MULTIRANGE_TYPE_NAME` (the auto-derived name varies on collision). A
    range's multirange and auto-array are side effects of the FINAL stage —
    consumers (including signatures naming the multirange) wait for it, while
    a support function's signature edge to the range itself targets the shell.
  - **Base types** (complete physical surface: INPUT/OUTPUT/RECEIVE/SEND,
    TYPMOD_IN/OUT, ANALYZE, SUBSCRIPT on 14+, INTERNALLENGTH, PASSEDBYVALUE,
    ALIGNMENT, STORAGE, CATEGORY/PREFERRED, DEFAULT — expression vs
    text-literal branches — ELEMENT, DELIMITER, COLLATABLE) and **shell
    types**; both *conditional*: the I/O functions are LANGUAGE C/internal, so
    the target needs the same shared library/symbols, superuser, and (base
    types) a compatible ABI. Empty enums and zero-attribute composites (valid
    DDL, previously dropped) and domain/composite-attribute **COLLATE** now
    round-trip too.
  - **Aggregates** (full `pg_aggregate` surface: state/moving-state functions
    and types, SSPACE/MSSPACE, FINALFUNC[_EXTRA/_MODIFY], combine/serial/
    deserial, INITCOND/MINITCOND, SORTOP, PARALLEL, and the explicit
    **aggkind** — a HYPOTHETICAL set aggregate restores as one, not as a plain
    ordered-set), plus **window** and **LANGUAGE C/internal** functions
    best-effort with honest prerequisite warnings.
  - **Casts** (database-global; dumpable = above the built-in OID threshold and
    not internally/automatically generated, with PostgreSQL's PG14+ auto
    range→multirange cast excluded by an explicit `pg_range` direction check —
    a user-created multirange→range cast is preserved). Casts are EDGE-LESS
    from their consumers (an expression records only the cast's function/
    types), so the class-priority slot orders them before any view/default
    using them.
  - **Operators, operator families and classes** (schema-scoped; access method
    is part of the identity). Commutator/negator pairs restore via the
    **CREATE-only define-first bootstrap** — only the later pair member names
    the link and PostgreSQL backfills the earlier — never `ALTER OPERATOR SET`
    (PG17+-only); HASHES/MERGES ride the CREATE clauses. Member ownership
    (class-inline vs family-loose `ALTER OPERATOR FAMILY … ADD`) is classified
    by the `pg_depend` ownership edge, never a cross-type heuristic; an
    explicitly-created family gets its own CREATE, an implicit one rides its
    same-named opclass.
  - **Foreign data** (database/server-scope): `CREATE SERVER`, `CREATE USER
    MAPPING` and `CREATE FOREIGN TABLE` (columns with per-column options/
    collations/defaults, inline CHECKs and PG18 named NOT NULLs, INHERITS,
    triggers/rules/comments — a foreign-table trigger's enable state uses
    `ALTER FOREIGN TABLE`), hand-created optionless wrappers, and foreign
    **partition leaves** (`CREATE FOREIGN TABLE … PARTITION OF … SERVER …`).
    A partition tree containing a foreign leaf splits its data source: local
    leaves are read individually (`FROM ONLY`, exactly-once), the foreign
    leaf's remote rows are skipped with a warning. A **table-scope SQL export**
    of a foreign table resolves through a dedicated SQL-only resolver
    (`TableForeign`) — structure only, provably no data pass — while
    CSV/JSON/listings keep their historical 404 (foreign tables never enter
    the UI or data paths). Option security is below.

- **Extension-attached objects (PostgreSQL).** TableX emits no
  `CREATE EXTENSION` (extensions-as-objects are out of scope) and cannot tell
  from the catalog which members an extension's install script would recreate
  (`ALTER EXTENSION … ADD` only *associates* an existing object, never adds it
  to the script). Extension-member **relations** (tables/views/matviews) are
  therefore **kept loose** — dumped like any relation, rows and definitions
  preserved, never excluded — with an inert `-- WARNING:` notice naming each
  one: a restore that *also* runs `CREATE EXTENSION` may conflict with the
  loose DDL and halt the import at that statement (a visible, manually
  reconcilable failure, never silent loss), and the membership link itself is
  not restored. Extension-member **non-relation** objects (types, routines,
  collations, sequences) stay **excluded**: the pre-existing posture, which
  assumes `CREATE EXTENSION` in the target recreates them — note the asymmetry
  that a *manually attached* non-relation object is excluded yet NOT recreated
  by `CREATE EXTENSION` (a documented residual). SQL-format only; CSV/JSON/
  listings/UI never consult extension membership.

- **Foreign-data options are redacted by provenance-keyed allowlist
  (PostgreSQL).** Every foreign-data option surface (wrapper/server/user
  mapping/foreign table/column) is treated as potentially secret. A wrapper is
  "recognized" by **provenance** — extension membership of the same-named
  `postgres_fdw`/`file_fdw` extension with an extension-owned handler — never
  by name (a wrapper merely *named* postgres_fdw is UNKNOWN and fully
  redacted). Only known-non-secret options survive: postgres_fdw `host`/`port`
  (+ `dbname` when it is a plain database-name literal — a DSN-shaped value is
  redacted as defense in depth), postgres_fdw table/column `schema_name`/
  `table_name`/`column_name`, file_fdw `format`/`header`. ALL user-mapping
  options (credentials by design) and everything else are redacted with a
  re-supply warning. Consequences follow the **three-state model**: (a)
  emitted executable; (b) external prerequisite (an extension-owned wrapper —
  `CREATE EXTENSION`, superuser, must run in the target first; dependents stay
  executable); (c) unavailable — an unknown wrapper WITH options, or a
  file_fdw table whose validator-REQUIRED `filename`/`program` was redacted —
  emitted only as an inert commented **template** (through the same
  newline-neutralizing comment channel as every warning) with its dependents
  (triggers/comments/rules) suppressed. An OPTIONLESS custom wrapper has
  nothing to redact and round-trips as executable DDL. No credential or DSN
  ever lands in a dump (docs/security.md).

- **Dumps are not point-in-time consistent.** An export runs on the ordinary
  transient connection pool (up to `pool_max_conns` connections) with **no wrapping
  repeatable-read transaction** — structure preflight, the object passes and the
  row stream can each observe a different catalog/data state under concurrent
  writes or DDL. The guarantee is per-statement consistency only, not a
  snapshot. `pg_dump` opens a serializable snapshot for exactly this reason;
  TableX deliberately does not (it is a browsing/admin tool, not a backup tool).
  Use `pg_dump` / `mysqldump` for point-in-time backups.

- **Ownership and privileges are not dumped (PostgreSQL).** PostgreSQL SQL dumps
  emit no `ALTER … OWNER TO`, `GRANT`/`REVOKE`, or `ALTER DEFAULT PRIVILEGES`:
  every restored object belongs to the *restoring* role with default privileges
  — the `pg_dump --no-owner --no-acl` posture. Use `pg_dump` when ownership/ACL
  fidelity is required. MySQL/MariaDB are the documented opposite: `SHOW CREATE`
  DDL is replayed **verbatim, including the source `DEFINER` clause** on
  routines/views/triggers/events (mysqldump parity — stripping it would silently
  change `SQL SECURITY DEFINER` semantics). Restoring definer-carrying objects
  therefore needs a restoring account that can set the definer — MySQL 8.2+
  `SET_ANY_DEFINER` (with `ALLOW_NONEXISTENT_DEFINER` when the definer account is
  absent), MySQL 8.0–8.1 `SET_USER_ID` (or the deprecated `SUPER`), MariaDB
  10.5.2+ `SET USER`, older MariaDB `SUPER`, or a definer matching the restoring
  account (plus `SYSTEM_USER` on MySQL 8.0.16+ when the definer holds it). This
  is now **live-verified on both engines**: a view, procedure, function,
  trigger and event created under a DISTINCT definer account round-trip with
  that account intact rather than collapsing onto the importing one, and every
  MySQL/MariaDB round-trip fingerprint now includes each stored object's
  `DEFINER` — a dropped definer is a silent privilege change, so it must fail a
  comparison rather than look clean.
