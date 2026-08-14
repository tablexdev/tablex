# TableX — Design Overview

> What TableX is, what it deliberately leaves out, and how it is tested and
> shipped. The system design lives in [`architecture.md`](./architecture.md),
> engine behavior in [`database-drivers.md`](./database-drivers.md), the design
> system in [`ui-design.md`](./ui-design.md), and the threat model in
> [`security.md`](./security.md).

## What TableX is

A standalone, single-binary web administration tool for MySQL, MariaDB,
PostgreSQL and SQLite. One `Dialect` abstraction serves every engine; the UI
adapts through `Capabilities()` rather than per-engine branches, so tabs and
controls appear only where the connected engine supports them. Assets are
embedded with `go:embed`; there is no PHP, no Node and no runtime dependency.

## Feature map (v1)

**Server level:** Databases list · SQL · Status · Variables · Processes · Users/privileges · Export · Import · (Settings — deferred).
**Database level:** Structure · SQL · Search · Export · Import · Operations · Privileges · Routines · Events · Triggers · Query builder · Designer.
**Table level:** Browse · Structure · SQL · Search · Insert · Export · Import · Privileges · Operations · Triggers.
**Cross-cutting:** navigation tree · breadcrumb · context tabs · flash messages · confirmations · pagination/sort/filter · CodeMirror SQL · query history · theme/dark mode.

> Engine-gated items (Users, Routines, Events) appear only where
> `Capabilities()` allows. SQLite hides most server/user features by design.

## Data browsing and editing

- The browse grid: striped/hover rows, checkbox + Edit/Copy/Delete columns,
  sortable headers with arrows (**multi-column**: each header sorts by itself
  alone, a trailing badge adds it as a further key), sort-by-key from the
  table's indexes, pagination, rows-per-page, "show all" (bounded), filter-rows,
  column visibility, and a **"with selected"** bar offering Edit, Copy, Export
  and Delete.
  - **Bulk Edit/Copy** render one prefixed fieldset per selected row and apply
    in a single transaction; the mode is fixed when the form is rendered, so a
    submit cannot switch between updating and duplicating. Capped at 100 rows —
    the form costs a round trip and a full row form each.
  - **Bulk Export** hands the selection to the export form (a download needs a
    format, which only that form has) and restricts the dump's DATA phase
    through `dump.RowFilter`, whose values are bound. The filter names its
    target table and yields "no data" — never "all data" — for any other; an
    unresolvable selection is refused rather than falling back to a whole-table
    dump.
  - **filter-rows is offered only when the grid holds the whole result** (one
    page, or "show all"). It narrows the rendered rows in the browser and does
    not re-query, so over a *paginated* grid it would report a value that
    exists in the table but not on this page as absent. Server-side filtering
    is Search's job, where the condition is parameterized.
- Insert/edit/copy/delete (single + bulk) use type-aware inputs, safe
  WHERE-clause generation from unique keys, parameterized statements and
  validated identifiers; every mutation is POST + CSRF-protected and
  destructive actions are confirmed server-side. *(In-cell inline grid editing
  is deferred.)*
- The SQL console: CodeMirror 5 editor, multi-statement execution with stacked
  result sets, error display, per-session query history, and one-click
  **Explain** where `Capabilities.SupportsExplain` allows.

## Schema operations

- Create/drop **database/schema**; create/drop/rename **table**,
  truncate/empty (Operations tab).
- **Structure editing:** add/modify/**rename**/drop **columns**, manage
  **indexes** and **foreign keys** from the Structure tab, gated by capability.
  Engine differences live behind the optional `driver.SchemaEditor` interface;
  identifiers are quoted in the builders and validated (new names via
  `ValidNewIdentifier`, existing objects by exact match against introspection)
  in the handler first.
- Transactional DDL where supported (PG/SQLite) via `Connection.ExecScript`.
- **SQLite limitations:** `ADD`/`RENAME`/`DROP COLUMN` and `CREATE`/`DROP
  INDEX` only — column **modify** and **foreign-key** DDL are unsupported by
  the engine, so those controls are hidden
  (`SupportsColumnModify`/`SupportsForeignKeyDDL` = false). Column **rename**
  is its own capability (`SupportsColumnRename` + `driver.ColumnRenamer`)
  precisely because it does not travel with modify: SQLite can rename but not
  redefine, and MariaDB below 10.5.2 the reverse. `AFTER`/`FIRST` positioning
  (`SupportsColumnPosition` + `ColumnSpec.Placement`) is MySQL-only — the other
  two engines have no reordering statement at all, so the control is hidden
  rather than approximated by a table rebuild. **AUTO_INCREMENT** changes
  remain deferred (engine-divergent).

## Export / import

- **Export**: SQL dump (structure/data), CSV, JSON, **XML**; per-table/db/server scope; download streaming; optional **gzip** (a `.gz` FILE — distinct from the transport gzip the middleware negotiates, which the browser undoes before saving); **per-table selection** at database scope; a **row LIMIT/OFFSET** at table scope for sampling (an unordered SELECT has no defined row order, so this is a sampling aid, not pagination — the form says so).
  - **JSON and XML are export-only** (data-exchange formats: all columns, NULL kept distinct from an empty value). XML carries a column's NAME as an attribute, never an element name — an identifier may hold spaces, quotes or a leading digit, none of which an element name allows — and hex-encodes any value XML 1.0 cannot represent (raw bytes, invalid UTF-8, a control character), because `xml.EscapeText` passes control bytes through unchanged and would otherwise produce an unparseable document.
- **Import**: SQL script execution and CSV import with column mapping; progress/result reporting. A gzipped upload is decompressed transparently, detected from its magic bytes rather than its name, and bounded by a separate expanded-size cap against decompression bombs (see [`security.md`](./security.md) §8).
- Export then re-import round-trips a database on each engine (asserted by the
  live round-trip suite in CI); large exports stream without exhausting memory.

## Server administration

- **Users/privileges** (MySQL, PostgreSQL roles); **Search** (db/table);
  **Routines/Functions**, **Triggers**, **Events** (engine-gated);
  **Views/matviews**; server **status/variables/processes**.
  - The **process list is actionable**: a session can be terminated from it
    (POST + CSRF + confirmation), on engines that have one. The identifier is
    parsed as an integer and must appear in a fresh read of the list before any
    statement runs; whether the account may kill that session stays the
    engine's decision.
  - **Routine-scope grants** (EXECUTE, plus MySQL's ALTER ROUTINE) on a
    per-routine privileges page. The routine is addressed by name **and** list
    position, and what reaches the builder is the introspected object —
    PostgreSQL needs its identity arguments to tell overloads apart, MySQL its
    FUNCTION/PROCEDURE kind.
  - **Role membership** (`GRANT role TO account`) on the Users page, engine-
    and version-gated: PostgreSQL always, MySQL 8.0+ / MariaDB 10.0.5+. The
    gate fails closed, because the catalog table is absent below those
    versions.
  - Grants run at database, table and **column** scope. A column grant is a
    distinct grant, listed with its column and revoked on its own; the
    privileges that accept a column list come from the dialect
    (`ColumnPrivileger`), since SQL admits one only for
    SELECT/INSERT/UPDATE/REFERENCES. A submitted column that does not match
    introspection is refused rather than skipped — an empty column list means
    the whole table, so dropping a name would widen the grant instead of
    narrowing it.
- Preferences: rows-per-page (per session) and a dark-mode toggle persisted
  client-side via cookie + localStorage. *(A dedicated Settings page is
  deferred; v1 is English-only with no localization layer.)*

## Optional subsystems

Everything in this section is opt-in and configured by its own block; nothing
here runs, allocates or listens until an operator turns it on.

- **TableX's own metadata database** (`[storage]`, optional; `internal/storage`) — a database TableX keeps its own state in, so that state can outlive a process. Ships with one thing in it: the session envelope, which makes a session's identity durable and shared. That is what lets a login form rendered by one replica be submitted to another; a pre-auth session works fully across replicas, while an authenticated one stays bound to the process holding its pools, because the credential is never persisted. Portable across every engine implementing `driver.StorageHost` — one schema, three column-type spellings, instants as Unix microseconds — with forward-only idempotent migrations. Off by default; nothing changes until an operator names an engine.

- **Audit trail** (`[audit]`, optional; `internal/audit`) — a durable record of who changed what, to which object, from where, and whether it worked, as JSON Lines and/or through the process logger. Distinct from the access log. The `action` half is emitted from **one** middleware so it is complete by construction rather than by remembering to instrument each handler; the `auth` half comes from the login and logout handlers, because a rejected login's status code describes an ordinary page. No password, DSN, CSRF token or session id ever reaches it.

- **Restricted mode** (`[restrict]`, optional) — narrows what a logged-in user may do *below* what their grants allow: `read_only`, `allow_console`, `allow_ddl`, `database_allowlist`. Defence in depth, not a boundary — the database's own privileges remain the real control; what this buys is the case grants cannot express, an operator who must use a privileged account and wants TableX itself to refuse the dangerous half. Enforced by a middleware keyed on the route, inside the auth gate, and never in the templates, so every restriction holds against a request typed by hand. The policy is a per-route table, declared beside each route's registration, and it fails **closed**: a state-changing request that resolves to no entry is treated as needing DDL permission, so a route added without one is refused under `allow_ddl = false` until somebody declares its needs deliberately. The UI then *reflects* that policy — withheld tabs, withheld buttons, narrowed listings, and a standing note saying what is withheld — derived in one place from the same config, so the two cannot disagree. `database_allowlist` narrows the listings as well as the routes, the contents of a server-scope dump included.

- **Metrics** (`[metrics]`, optional; `/metrics`) — the Prometheus text exposition format, written by hand: no client library, no new dependency, a handful of atomics read once per scrape. Access-controlled by a constant-time bearer token and/or an address allowlist, and **enabling it with neither refuses startup** — the numbers describe TableX's internals, and there is no defensible default to guess. Cardinality is bounded by construction (method and status *class*; never path, database or account). Series for a subsystem that is not configured are omitted rather than reported as zero. `/healthz` stays a bare `ok` so a container probe never needs a credential, which is exactly why the metadata-database probe lives here instead.

- **Single sign-on** (`[sso]`, optional) — an OIDC provider as an **extra
  factor** in front of the credential login; the user still supplies their own
  database credentials afterwards, so the audit trail keeps naming the real
  account. See [`security.md`](./security.md).

- **Per-session query budget** (`session_query_budget`, optional) — bounds how many statements **one session** may submit over a window, the dimension a single authenticated user can otherwise saturate alone. It charges the SQL a user *wrote* (console, `EXPLAIN`, SQL import) and not the queries TableX generates for them, whose cost is already bounded per request. A spent budget refuses through the same per-statement channel a SQL error uses, so a script is truncated at the budget rather than silently part-run.

With no `[storage]`, `[audit]`, `[restrict]`, `[metrics]` or `[sso]` block, behaviour is byte-for-byte what it was — each is absent rather than idle: nothing allocated, no goroutine, nothing on the request path.

## Deliberately deferred or decided against

Each entry is a decision with a reason, not drift; if one ships later, this
list is what gets updated.

- **In-cell inline grid editing** — deferred; the row editor covers the need.
- **AUTO_INCREMENT changes** — deferred (engine-divergent).
- **A dedicated Settings page** — deferred; the two shipped preferences
  (rows-per-page, dark mode) live where they are used.
- **Localization** — v1 is English-only; all UI strings live in the templates.
  A message-catalog layer can be reintroduced later if needed.
- **A console drawer and a global keyboard-shortcut system** — deferred. Three
  individual shortcuts do ship: Escape closes the mobile nav drawer, Tab is
  trapped while it is an overlay, and Ctrl/Cmd+Enter runs the query.
- **A density toggle** — not planned. The spacing tokens exist and
  coarse-pointer devices get the looser values automatically
  (`ui-design.md` §7); nothing lets a user choose.
- **Sticky table headers** — **decided against**, not deferred: the result
  tables sit inside Bootstrap's `.table-responsive` overflow container, which
  makes `position: sticky` inert for page scrolling. The reason is recorded
  beside the code in `tablex.css`.

## Testing strategy (summary)

| Layer | Approach |
|---|---|
| Unit | dialect SQL/quoting/DSN/pagination/result scanning — no DB |
| Integration | Docker MySQL + MariaDB + PostgreSQL; SQLite temp file |
| HTTP | `httptest` over handlers with SQLite-backed connection |
| Template | assertions over pages rendered by the real server (headings, header scopes, control names, the live region) — see `internal/server/a11y_test.go`. **Not** golden-file snapshots: there is no `testdata/` and no `.golden` in the repo. A snapshot of a page this dense would fail on every cosmetic edit and be re-blessed unread, which is a test that asserts nothing. |
| CSS | contrast ratios computed from the shipped stylesheet for both themes, plus invariants that no rule carries a raw colour and no class is styled but never rendered (`web/contrast_test.go`, `web/embed_test.go`) |
| Front-end JS | content assertions over the embedded `app.js` + `node --check` in CI. There is no JS runner, on purpose: no Node in the build, no npm in the repo |
| Security | checklist review + targeted tests (CSRF, escaping, headers) |

## Packaging

- `go build` with embedded assets → single binary per `GOOS/GOARCH`.
- Minimal scratch/distroless Docker image.
- Versioned releases from a tag (`.github/workflows/release.yml`): static binaries
  for six OS/arch pairs, a signed `SHA256SUMS`, an SPDX SBOM, and a signed
  multi-arch image on ghcr.io. [`SECURITY.md`](../SECURITY.md) documents how to
  verify them; [`CHANGELOG.md`](../CHANGELOG.md) records what changed.
