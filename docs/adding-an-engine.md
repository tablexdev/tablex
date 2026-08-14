# Adding a database engine

TableX supports a new SQL engine by adding one package under
`internal/driver/<engine>/` that implements `driver.Dialect` and registers
itself. Nothing outside that package needs to change — no handler, no template,
no model, no config allowlist. This document is the contract that makes that
true, and the conformance suite in `internal/driver/drivertest` is how it is
enforced.

Read [database-drivers.md](./database-drivers.md) first for the design
rationale; this file is the checklist.

---

## 1. The shape of an engine package

```go
package clickhouse

import "github.com/tablexdev/tablex/internal/driver"

type dialect struct{}                        // stateless; one registered value
func init() { driver.Register(dialect{}) }    // runs via the blank import in main
```

Register **exactly one** value per engine name; a duplicate panics at startup.
The registered value is shared by every session, so the dialect must be
immutable and safe for concurrent use. Per-connection state belongs in
`Connection`, or in a copy returned by `WithServerInfo` (see
`ServerSpecializer` below) — never mutated in place on the receiver.

Three files to start, by convention:

| File | Contents |
|---|---|
| `<engine>.go` | the dialect: DSN, quoting, introspection, DDL builders |
| `interfaces.go` | the `var _ driver.X = dialect{}` assertions (see §4) |
| `<engine>_internal_test.go` | package-internal tests for the pure builders |

Three files is the right start for a small engine — everything in one place
while the surface is still forming. Once a file passes **900 lines**, split it
by ROLE, the partition every built-in engine now follows:

| File | Contents |
|---|---|
| `<engine>.go` | identity, connection, syntax (quoting, DSN, LIMIT) |
| `introspect.go` | catalog reads |
| `editor.go` | non-DCL statement builders (DDL, indexes, columns) |
| `dcl.go` | grant/revoke builders (engines with an access-control system) |
| `dump*.go` | the export path, split by catalog object class when it grows |

(SQLite adds `ddlparse.go` — its catalog is `CREATE TABLE` text, so the pure
DDL parser is a role of its own.) A per-file size ratchet
(`internal/driver/filesize_test.go`) holds the split. Its rule is not a single
number but **max(the file's pinned baseline, 900)**: a new file gets 900, and
the files still over that — `connection.go`, `driver.go`, and two of
PostgreSQL's (`introspect.go`, `dump_types.go`) — are pinned at their own size
and cannot grow by a single line. A pin is lowered when a split beats it, never
raised to make a red build green; when the ratchet trips, split by role. Two
pins have already been retired that way, as their splits took the files back
under the ceiling.

Add the blank import to `cmd/tablex` so `init()` runs:

```go
_ "github.com/tablexdev/tablex/internal/driver/clickhouse"
```

That import is the **only** edit outside the new package. Config validation and
the error message naming the valid engines read `driver.RegisteredNames()`. The
login form's engine list reads `driver.All()`, and must: it needs each
dialect's `DisplayName()`, `DefaultPort()` and `Capabilities()`, not just its
name — `IsNetworkEngine` is what keeps a file-backed engine off the form.

---

## 2. The required interface

`driver.Dialect` has 26 methods in six groups. All are mandatory: a dialect
that cannot support one returns an empty result rather than an error, unless
noted.

**Identity (3)** — `Name`, `DisplayName`, `DefaultPort`.
`Name` is a lower-case bare token; it appears in config files and URLs.
`DefaultPort` is `0` for a file-backed engine and 1..65535 for a network one —
the conformance suite checks this against `Capabilities.IsNetworkEngine`.

**Connection (2)** — `SQLDriverName`, `BuildDSN`.
The `database/sql` driver must be pure Go (no CGo) to keep the single-binary
promise. `BuildDSN` must reject anything in `ConnParams.Params` that could
override a security-relevant setting.

**SQL syntax (6)** — `QuoteIdent`, `QuoteString`, `Placeholder`,
`LimitClause`, `QualifyTable`, `InsertDefaultRowSQL`.
These are where an injection bug would live, so the conformance suite is
strictest here:

- `QuoteIdent` must round-trip **exactly**, including a name containing the
  delimiter. Doubling the delimiter is the expected escape.
- `QuoteString` must leave no unescaped quote that could end the literal early.
  It is the only defence everywhere a user's string reaches SQL in a position
  **no placeholder can carry**: an `ENUM`/`SET` member list (see
  `ValueListTyper`), a column's `DEFAULT` literal and `COMMENT`, account parts
  and passwords in DCL, and a dumped data literal. `docs/security.md` §4 is the
  authoritative list. Everywhere else, values are parameterized.
- `Placeholder` must be either one reused form (`?`) or one form per index
  (`$1`, `$2`, …) — never a partial mix, which binds the wrong argument.
- `LimitClause` takes an **int64** offset. Rendering it through an `int`
  truncates on a 32-bit build and silently reshuffles the page.

**Server info (1)** — `ServerInfo`.

**Introspection (7 + 5)** — `ListDatabases`, `ListSchemas`, `ListTables`,
`Columns`, `Indexes`, `ForeignKeys`, `CreateSQL`, plus the extended listings
`ListViews`, `ListRoutines`, `ListTriggers`, `ListEvents`, `ListUsers`.
Four of those five — `ListViews`, `ListRoutines`, `ListTriggers`, `ListEvents`
— are **capability-gated in `Connection`**: when the matching `Has*` flag is
false the passthrough returns an empty slice without calling the dialect, so an
engine without events does not have to implement a stub that queries for
nothing. (`ListUsers` has no gate; `HasUsers` drives the UI.)

**Explain + capabilities (2)** — `ExplainSQL`, `Capabilities`.

### Populating the neutral model

Introspection returns `internal/model` types, and handlers and templates read
only those. Three rules the conformance suite enforces:

- `Column.Position` is the **contiguous** 1-based ordinal, not the catalog's
  slot number. PostgreSQL's `attnum` keeps gaps after a `DROP COLUMN`; the
  dialect renumbers.
- `Column.BaseType` is the bare type name, lower-cased.
- `Column.Extra` is free text shown verbatim. **Nothing may branch on its
  contents.** Semantics that engine-neutral code acts on get a typed field —
  `Identity`, `OnUpdate`, `GeneratedKind`, `DefaultIsExpr`. If your engine has
  a concept none of those cover, add a field; do not encode it in `Extra`.
- `Database.TableCount` is the number of relations the database structure page
  will list, so the number a user sees on the databases page matches the rows
  they get when they click through.

---

## 3. Capabilities

`Capabilities` is what the UI reads to decide whether a tab, button or form
exists. A flag is a promise, and several of them promise an optional interface:

| Flag | ⇒ must implement |
|---|---|
| `SupportsColumnModify` | `ColumnModifier` (and `SchemaEditor`) |
| `SupportsColumnRename` | `ColumnRenamer` |
| `SupportsColumnPosition` | *(no interface — `ColumnSpec.Placement`, see below)* |
| `SupportsForeignKeyDDL` | `ForeignKeyEditor` |
| `CanManageDatabases` | `DatabaseManager` |
| `HasSchemas` | `SchemaManager` |
| `HasUsers` | `UserManager`, `PrivilegeManager`, `Privileger` |
| `SupportsRoles` | `RoleManager` |
| `SupportsCharset` | `CollationLister` |
| `IsNetworkEngine` | `PoolOpener` |

`drivertest` fails the build's tests if a flag is set without its interface —
otherwise the UI renders a control that the handler's type assertion refuses.
`ColumnModifier` and `ForeignKeyEditor` are checked in **both** directions:
implementing the builder while leaving the flag false hides a working feature.
`ColumnRenamer` and `RoleManager` are checked one way only, because their flags
legitimately depend on the *detected server version* — MySQL implements both
builders always but reports `SupportsColumnRename` false on MariaDB below
10.5.2, which has no `RENAME COLUMN`, and `SupportsRoles` false below MySQL 8.0
/ MariaDB 10.0.5. Note the two fail in OPPOSITE directions on an unknown
version, and each is right: rename fails **open** because only one old flavor
lacks the statement, roles fail **closed** because the catalog table the page
reads is simply absent. Do the same for any capability your engine gained in a
particular release: decide it in `Capabilities()` from the version
`WithServerInfo` handed you, and default an **unknown** version to whichever
answer is safe for your engine (fail closed for an introspection query that
would error, open for a feature only an ancient release lacks).

`ColumnPrivileger` has no flag at all — the interface *is* the promise — but
`drivertest` still pins the invariant its callers assume: every keyword
`ColumnGrantablePrivileges()` offers must also be in `GrantablePrivileges(true)`.
The grant handler validates against the table allowlist **first** and the column
set second, so a keyword in only the column set would render a checkbox the
first gate then rejects. It also asserts a column list reaches the emitted
statement, and that database scope refuses one: both failures are silent
widenings, not errors the operator would see.

`SupportsColumnPosition` is the one capability with no interface behind it: it
governs a *field*, `ColumnSpec.Placement` (FIRST / AFTER col), which only MySQL
can express. `drivertest` checks it in both directions, and the negative half is
the important one — an engine that cannot reorder must **ignore** a placement it
is handed, never approximate it. Rebuilding the table to honour "AFTER x" would
be doing something a column edit has no business doing, and the caller, which
only reads the flag, would never find out.

`IsNetworkEngine` deserves its own note. It is the login path's single engine
discriminator, and three things follow from it: ad-hoc login is offered only
for network engines, credentials are collected only for them, and the SSRF host
policy applies only to them. A file-backed engine has no credentials, so an
ad-hoc login for it would be an unauthenticated arbitrary file open — such
engines are reachable only through an operator-configured predefined server.
`PoolOpener` is required for a network engine because it is what routes the
pool through a `driver.Connector`, and that is the only way
`ConnParams.DialControl` — the dial-time SSRF guard — reaches every connection.

---

## 4. The optional interfaces

Everything beyond the required 26 methods is opt-in and discovered by **runtime
type assertion**. That means a method whose signature drifts does not fail the
build; the assertion simply stops matching and the feature silently disappears.

**Every engine package must therefore carry an `interfaces.go`** declaring what
it satisfies:

```go
var (
    _ driver.Dialect      = dialect{}
    _ driver.RowEstimator = dialect{}
    // …
)
```

plus a comment listing what it deliberately does **not** implement, and why.
`TestDialectCapabilitySets` in `internal/driver` catches the other direction —
a capability gained or lost without that list being updated.

| Interface | What it unlocks |
|---|---|
| `ServerSpecializer` | a per-connection copy carrying flavor/version facts. **Every connection path routes through `driver.Specialize`**; an engine that needs version gates must implement this or every gate fails closed |
| `VersionFloor` | the login-time "this server is older than TableX relies on" warning (§4.4 of [database-drivers.md](./database-drivers.md)). It reports, it does not refuse. Only a **specialized** dialect can answer, since only it has parsed the version — so this pairs with `ServerSpecializer`, and an implementation that cannot parse a build string must answer `false` rather than cry wolf |
| `PoolOpener` | Connector-based pool, so the dial-time SSRF guard applies (required for network engines) |
| `ParamsNormalizer` | engine-specific login defaults (PostgreSQL's empty database → `postgres`) |
| `DatabaseRebinder` | for an engine whose "database" is not a DSN parameter (SQLite's file) |
| `FilePathValidator` | reject an unusable operator-configured file path at config load |
| `ParamsValidator` | reject an operator-supplied driver parameter that the engine accepts but that breaks a TableX invariant, at config load (SQLite refuses the `_texttotime` / `_inttotime` conversions, which would make a text/integer column scan as `time.Time` and break text fidelity). Only an *enabled* value is refused; `…=false` still starts |
| `MaintenanceDatabaseLister` | the databases a session can bind to in order to drop the one it is on |
| `LoginFormHinter` | per-engine wording/placeholder for the login form's database field |
| `DDLErrorHint` | turn a raw DDL error into user-facing guidance |
| `BulkIntrospector` | schema-wide columns/FKs in one query (kills the N+1 on the designer and export preflight) |
| `NameLister` | statistics-free listings for the navigation tree |
| `RowEstimator` | a cheap row estimate, so large tables skip an exact `COUNT(*)` |
| `SearchCaster` | a cast expression for `LIKE` on types that reject it |
| `Monitor` | server status, variables and the process list |
| `TableMaintainer` | the Table maintenance card on a table's Operations page. The engine NAMES ITS OWN operation set (`TableMaintenanceOps`) rather than implementing fixed ones — MySQL's OPTIMIZE/CHECK/REPAIR/ANALYZE, PostgreSQL's VACUUM/ANALYZE/REINDEX and SQLite's lone ANALYZE have almost nothing in common — and only a name from that set is ever run. Results come back as a `ResultSet` because MySQL's CHECK and REPAIR report their findings as rows |
| `DefinitionViewer` | the routines/triggers/events definition panel, when the listing's `Definition` is not itself a replayable `CREATE` (MySQL's `information_schema` gives a body without its signature; PostgreSQL's `pg_get_functiondef` is already complete, so it omits this) |
| `RoutineManager` / `TriggerManager` / `EventManager` | the Drop button and the definition editor (create / redefine) on the routines / triggers / events pages. Three interfaces, not one: engines support the three kinds independently (SQLite has only triggers; only MySQL has events). Each takes the **listed model object** for its `Drop*SQL`, so an engine can read whatever else it needs from it — PostgreSQL uses `Trigger.Table` (`DROP TRIGGER … ON …`) and `Routine.ArgSignature` (overloads make the bare name ambiguous). Each also supplies a `New*Template` skeleton for the editor, because a MySQL `BEGIN…END` body and a PostgreSQL dollar-quoted plpgsql block share no syntax — the editor never assembles a statement itself |

> **If your `List*` order is not total, positions are meaningless.** The
> definition panel and the drop both address an object by its position in the
> rendered list plus its name. Sort by every column needed to break ties —
> PostgreSQL orders routines by `proname` **and** identity arguments, and
> triggers by `tgname` **and** table, because neither name is unique on its own.

| Interface | What it unlocks |
|---|---|
| `Privileger` / `UserManager` / `PrivilegeManager` | the privileges UI (read / accounts / grants) |
| `ColumnPrivileger` | column-scope grants (`GRANT SELECT (a, b) ON t`): the column picker on a table's grant form, and the Column column of its grant list. It EMBEDS `PrivilegeManager` — column scope is a refinement of table scope, emitted by the same `GrantSQL`/`RevokeSQL` keyed on `GrantSpec.Columns`. **Ship the read half with it**: `Privileger` must return column grants as rows carrying `model.Privilege.Column`, or the UI shows an account as having no access to a table it can read two columns of, and the grant becomes unrevokable. Note the asymmetry with every other narrowing input in the codebase — an EMPTY column list means the whole object, so a dropped or filtered column WIDENS the grant; that is why `Connection.Grant` refuses a `Columns` the dialect cannot express rather than degrading |
| `ProcessManager` | the Kill button on the server Processes page. The process list is an opaque `*ResultSet` of the engine's own columns, so the dialect also names the one holding the identifier (`ProcessIDColumn`) — without that pairing a caller would have to guess which column of `SHOW FULL PROCESSLIST` or `pg_stat_activity` to act on. `KillProcessSQL` takes an **int64**, deliberately: neither engine accepts a placeholder where the identifier goes, so the value is formatted into the statement and an integer parsed by the caller cannot carry anything else — do not widen it to a string. Terminate the session, not just its statement (`KILL CONNECTION`, `pg_terminate_backend`); the weaker form returns success and leaves the connection alive, which reads as a broken button |
| `RoutinePrivileger` | the per-routine privileges page (`GRANT EXECUTE ON FUNCTION …`), reached from the routines list. Read and write together, as above. It deliberately does NOT reuse `Privileger`'s `TableRef`: a routine is addressed by schema, name AND — on PostgreSQL — identity arguments, which no `TableRef` has a place for. It takes the **listed `model.Routine`** instead, so `ArgSignature` and `Type` come from introspection. Both are load-bearing: neither engine has a bare "ON \<name\>" for routines, and both have a way for a name alone to be ambiguous (PostgreSQL overloads on argument types; MySQL keeps functions and procedures in separate namespaces, so both can hold an `rp_calc`) |
| `RoleManager` | the Role memberships section of the Users page (`GRANT role TO account`), read and write on one interface for the same reason as `ColumnPrivileger`. Paired with `Capabilities.SupportsRoles`, which is version-gated on MySQL/MariaDB and **fails closed** on an unknown version — the catalog table does not exist before MySQL 8.0 / MariaDB 10.0.5. Expect no agreement between engines on what a role even is: a MySQL 8 role IS an account (`'r'@'host'`, `mysql.role_edges`), a MariaDB role is a hostless row of its own kind (`mysql.roles_mapping`), and every PostgreSQL role can be granted to any other (`pg_auth_members`). `RoleGrant`'s host fields exist for the first of those and are ignored by the rest |
| `CollationLister` / `CollationProber` | the create-database collation list; import-side marker verification |
| `SchemaEditor` | the structure editor (create table, add/drop column, indexes, drop/rename) |
| `ColumnModifier` | modifying an existing column in place |
| `ColumnRenamer` | renaming a column, and nothing else about it |
| `ValueListTyper` | column types defined by a value list rather than a length (MySQL `ENUM`/`SET`) |
| `IndexOptioner` | which index options this engine can express: access methods, `DESC` key parts, prefix lengths, partial predicates |
| `ForeignKeyEditor` | adding and dropping foreign-key constraints |
| `SchemaManager` | create/drop schema (engines with a schema level) |
| `DatabaseManager` | create/drop database |
| `StatementLexer` | the engine's script grammar (see §5) |
| `Dumper` | restore-oriented DDL for SQL export — **without it, `DumpTableCreate` hard-fails**; display-oriented `CreateSQL` is not a substitute |
| `DynamicTyper` | marks an engine whose storage class lives on each value (SQLite): the dump writers then trust a cell's runtime kind over the declared column type when deciding bare-numeric vs quoted emission. Pair it with `ValueLiteralHooks.PreferValueKind` in the dialect's own `ValueLiteral` — the two must agree, or the SQL and JSON exports classify the same cell differently |
| `ExportConnAdjuster` | dialect-owned session pinning on the dedicated EXPORT connection (MySQL pins `time_zone`, `sql_mode` and `sql_quote_show_create` so a dump renders restore-parsable). Clone `Params` before touching it — the map is shared with `ServerConfig.Params` and the session's base params — and set the pins **after** copying, so they win over a same-named operator key |
| `ServerDumpFramer` | how a server-scope dump frames each database section |
| `ViewDumper` | dumping a single view at table scope |
| `StagedTableDumper` | deferring DEFAULTs/constraints to break a dependency cycle |
| `GlobalDumper` | database-global, non-schema-owned objects |
| `DataScoper` | `FROM ONLY` where an inheritance parent would duplicate child rows |
| `ForeignTableDumper` | structure-only dump of foreign tables |
| `Inheritor` | ordinary table inheritance links |
| `TeardownAuditor` | warn-only probe for objects a drop-first teardown would block on |
| `StorageHost` | eligibility to host TableX's OWN metadata database (`internal/storage`) — the state the application needs to outlive a process, today the session envelopes that make sessions survive a restart and work behind a load balancer. It is the smallest interface here, and deliberately: the metadata schema is written by TableX in the portable intersection of these engines (`CREATE TABLE IF NOT EXISTS`, positional placeholders, no engine-specific clauses), so all a dialect supplies is the SPELLING of three column types plus whatever must follow a `CREATE TABLE`. Notably absent from that vocabulary is a timestamp: an instant is an `Int64` of Unix **microseconds**, because no portable date type exists across these engines and the two that have one disagree about zones. `ID` is separate from `Text` for one reason — it is a primary key, and MySQL cannot index a `TEXT` column without a prefix length. Put the character set in `TableOptions`, or a server defaulting to latin1 will mangle non-ASCII text, and a transactional engine too (`Replace` is a transaction). An engine that omits this simply cannot be named as the storage backend; config refuses it by name at startup and nothing else about the engine is affected |

---

## 5. Script grammar

The SQL console and the importer split scripts with one grammar-driven lexer.
A dialect supplies its grammar through `StatementLexer` → `LexerProfile`; a
dialect that omits it gets `DefaultLexerProfile` (standard-conforming quoting
with PostgreSQL's extensions).

The profile covers backslash string escapes, `E'…'` strings, dollar quoting,
`#` comments, the `--`-needs-whitespace rule, nested block comments,
`DELIMITER` directives, `$` as an identifier character, `[bracket]`
identifiers, a client-side batch separator (`GO`), procedural `BEGIN…END` body
tracking, and which DML statements support `RETURNING`.

A T-SQL-shaped engine is therefore expressible without touching
`internal/driver`:

```go
func (dialect) LexerProfile() driver.LexerProfile {
    return driver.LexerProfile{
        BracketIdentifiers: true,
        BatchSeparator:     "GO",
        Returning:          driver.ReturningCaps{Insert: true, Update: true, Delete: true},
    }
}
```

If your engine's grammar genuinely needs something the profile cannot express
(Oracle's `q'[…]'` alternative quoting, for instance), add a field to
`LexerProfile` and a case to the scanner — but check first, because the point
of the profile is that this should be rare.

---

## 6. Wiring up the tests

The conformance suite covers everything above that can be checked without a
database, and it runs automatically over `driver.All()`:

```
go test ./internal/driver/ -run TestDialectConformance
```

Because it iterates the registry, **a new engine is covered the moment its
blank import is added** — there is no per-engine test to remember to write.

The connection half needs a live database and asserts the neutral model is
actually populated:

```go
drivertest.RunConnectionSuite(t, conn, driver.Scope{Database: "…", Schema: "…"})
```

SQLite runs it in `internal/driver` on every `go test ./...`; MySQL, MariaDB
and PostgreSQL run it in `internal/server`'s live suite against Docker. Add
your engine to whichever fits, and add a round-trip test (export → drop →
re-import → compare) if it supports SQL dumps.

Live tests **skip silently** without their `TABLEX_TEST_*` environment
variables, so run them with `-v` and confirm `--- PASS`, not `--- SKIP`.

---

## 7. Checklist

- [ ] `internal/driver/<engine>/<engine>.go` implements `driver.Dialect`, registers in `init()`
- [ ] `internal/driver/<engine>/interfaces.go` asserts every optional interface, and documents the omissions
- [ ] `Capabilities()` agrees with the interfaces (see §3)
- [ ] `Column.Position` contiguous; nothing branches on `Column.Extra`
- [ ] blank import added to `cmd/tablex`
- [ ] `go test ./internal/driver/ -run TestDialectConformance` green
- [ ] `RunConnectionSuite` wired to a real database
- [ ] `gofmt -l`, `go vet ./...`, `go test ./...`, `govulncheck ./...` all clean
- [ ] the driver is **pure Go** — `CGO_ENABLED=0 go build ./...` still works
- [ ] the capability matrix in [database-drivers.md](./database-drivers.md) updated
