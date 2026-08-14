# TableX — Architecture

> Companion docs: [`tech-stack.md`](./tech-stack.md) · [`database-drivers.md`](./database-drivers.md) · [`ui-design.md`](./ui-design.md) · [`security.md`](./security.md)

## 1. Overview

TableX is a single Go binary that serves a server-rendered web UI for administering multiple SQL databases. One process can manage many connections to many servers of different engines (MySQL/MariaDB, PostgreSQL, SQLite), each scoped to a user session.

```
                ┌────────────────────────────────────────────────┐
                │                 tablex (one binary)            │
                │                                                │
  Browser  ───► │  net/http  ─► middleware ─► router ─► handler  │
  (HTML +       │     ▲             │                     │      │
   htmx)        │     │             │                     ▼      │
                │     │        session mgr          driver layer │
                │     │             │              (Dialect +    │
                │  html/template    │               Connection)  │
                │  + embedded       ▼                     │      │
                │  assets      session store              ▼      │
                │  (go:embed)                    database/sql ───┼──► MySQL / MariaDB
                │                                                │──► PostgreSQL
                │                                                │──► SQLite (file)
                └────────────────────────────────────────────────┘
```

Everything (templates, CSS, JS, images) is compiled into the binary via `go:embed`. No external files are needed to run.

---

## 2. Package layout

```
tablex/
├── cmd/
│   └── tablex/
│       └── main.go              # entrypoint: parse flags/config, embed assets, start server, graceful shutdown
├── internal/
│   ├── config/                  # config model: flags + env + TOML; predefined servers
│   ├── server/
│   │   ├── server.go            # http.Server wiring, routes, middleware chain
│   │   ├── middleware.go        # recover, logging, session, body cap, CSRF, SSO gate, auth gate, security headers (§3 has the order)
│   │   ├── compress.go          # gzip response encoding (Accept-Encoding, Vary, ETag variants)
│   │   ├── restrict.go          # restricted mode: the [restrict] policy, enforced on the request
│   │   ├── metrics.go           # /metrics: the Prometheus text exposition, written by hand (no client library)
│   │   ├── router.go            # route table (ServeMux patterns → handlers)
│   │   └── handlers/            # one file per feature area (31 non-test files; the load-bearing ones)
│   │       ├── handlers.go      # the Handlers struct, shared rendering, error vocabulary
│   │       ├── context.go       # UserContext: the session's live Connections, keyed by database
│   │       ├── auth.go          # login / logout
│   │       ├── sso.go           # the OIDC callback half of the SSO gate
│   │       ├── home.go          # server landing page
│   │       ├── server.go        # server-level views (databases list, status, variables, users)
│   │       ├── database.go      # database-level views (structure, sql, search, export, ...)
│   │       ├── table.go         # table-level views (browse, structure, insert, ...)
│   │       ├── structure.go     # column / index / foreign-key editing
│   │       ├── operations.go    # table rename/truncate/drop, create/drop database
│   │       ├── programs.go      # stored routines, triggers, events (list, editor, drop)
│   │       ├── export.go        # export forms + the streaming download
│   │       ├── importer.go      # SQL / CSV import
│   │       ├── sql.go           # SQL console + query execution + results
│   │       ├── nav.go           # nav-tree fragments (htmx)
│   │       └── ...              # access, designer, qbe, search, metadata, listings, chrome, urls, ...
│   ├── session/                 # session manager + store interface (+ in-memory impl)
│   ├── storage/                 # TableX's OWN metadata database (optional): portable schema + migrations, and the durable session store built on it. Never holds a credential — see docs/security.md §2
│   ├── audit/                   # audit trail (optional): who changed what, to which object, from where. JSON Lines + stderr sinks. Distinct from the access log; never holds a replayable secret
│   ├── auth/                    # CSRF tokens, SSRF host guard, login rate limiting, and the whole OIDC provider (oidc.go) behind the [sso] gate — see §8b (credentials are validated by driver.Open in handlers/auth.go)
│   ├── driver/                  # the database abstraction (20 non-test files at this level)
│   │   ├── driver.go            # Dialect interface, Capabilities, the optional interfaces, shared types
│   │   ├── connection.go        # Connection wrapper over *sql.DB + Dialect
│   │   ├── registry.go          # name → Dialect registry
│   │   ├── result.go            # generic row scanning into engine-neutral result sets
│   │   ├── dump.go              # the DumpScript/DumpPlan vocabulary the dump engine plans over
│   │   ├── lexer.go             # LexerProfile: the script grammar a dialect declares
│   │   ├── validate.go          # the pure input validators (identifier, account, privilege, table shape)
│   │   ├── scope.go             # the read-addressing value types (Scope, TableRef, Pagination, Sort)
│   │   ├── admin.go             # account/privilege/role/session administration contracts
│   │   ├── ...                  # comment, connection_dcl, connection_exec, connection_monitor,
│   │   │                        # dumpmemo, grants, group, marker, observer, pinned, seqrewrite
│   │   ├── drivertest/          # the reusable conformance suite, run against every registered dialect
│   │   ├── mysql/               # MySQL/MariaDB dialect
│   │   ├── postgres/            # PostgreSQL dialect
│   │   └── sqlite/              # SQLite dialect
│   ├── dump/                    # the SQL dump engine, extracted from the export handler: dependency-graph planner (Tarjan SCC, cycle cutting, routine staging) + the writers. Imports no net/http — a dump is a plan over a schema, not an HTTP concern
│   ├── sqlscript/               # SQL lexer/splitter/classifier: turns a script into statements without executing anything, driven by the LexerProfile a dialect declares (defined in driver/lexer.go)
│   ├── model/                   # engine-neutral domain types: Server, Database, Schema, Table, Column, Index, ...
│   └── view/                    # template registry, render helpers, template funcs
└── web/
    ├── templates/               # html/template files (embedded)
    │   ├── layout/              # base layout + partials (navbar, sidebar, breadcrumb, tabs, flash)
    │   └── pages/               # per-page templates
    └── static/                  # embedded assets
        ├── css/                 # tablex theme: one hand-authored stylesheet, no preprocessor and no build step
        ├── js/                  # small app JS
        ├── img/                 # icons
        └── vendor/              # bootstrap, htmx, alpine, codemirror
```

**Rule:** all application packages live under `internal/` so the module exposes no accidental public API. `cmd/tablex` is the only `main`.

---

## 3. Request lifecycle

```
request
  → recoverMiddleware        (turn panics into 500s, never crash the process)
  → loggingMiddleware        (structured access log via log/slog; request id, never credentials. Also the
                              only layer that sees the final status and the whole duration, so this is where
                              the audit action event is emitted and the /metrics HTTP counters are observed —
                              one duration serves all three. A /metrics scrape is excluded from the counters)
  → gzip                     (compress compressible types when the client accepts it: pages, fragments,
                              static assets and streamed dumps; TableX runs standalone, so nothing else would)
  → securityHeaders          (CSP, X-Content-Type-Options, frame-ancestors, Referrer-Policy, HSTS-when-TLS)
  → sessionMiddleware        (load/create session from cookie — or, when session_create_max is set and this
                              client is over it, refuse the CREATION with 429 + Retry-After rather than mint
                              another session; see §8)
  → limitBody                (MaxBytesReader: 1 MiB unauthenticated, 32 MiB import, 64 MiB otherwise)
  → importAdmission          (bounds concurrent import UPLOADS on its own semaphore, never the database-op
                              one: it must run BEFORE csrf, which parses the multipart body for a form
                              token, so by the handler the spill has already happened. Authenticated import
                              POSTs only, matched through the policy mux)
  → csrfMiddleware           (verify token on unsafe methods: POST/PUT/PATCH/DELETE; for an unauthenticated
                              protected route redirects to /login BEFORE parsing the body, and reserves the
                              coarse bare-IP login-rate key for /login pre-parse — two-stage with the handler)
  → ssoGate                  (only when [sso] is configured: a request with no verified provider identity
                              goes to the provider, not to the login form. OUTSIDE the auth gate, so it is
                              consulted FIRST — SSO is an extra factor in front of the credential login,
                              never a replacement for it)
  → authGate                 (redirect to /login if route requires auth and session has no live connection)
  → restrict                 (the [restrict] policy, looked up per ROUTE; inside the auth gate so an
                              unauthenticated request still goes to /login rather than being told which
                              routes exist. A request that resolves to no policy entry fails CLOSED —
                              see docs/security.md §9)
  → router                   (ServeMux pattern match)
  → handler                  (resolve active Connection from session, call driver, build view model)
  → view.Render              (html/template → HTML; or htmx fragment)
  → response
```

For htmx requests (`HX-Request: true`), handlers render a **fragment template** (just the content panel) instead of the full layout, so navigation swaps only `#page_content` and feels instant without a SPA.

---

## 4. The object model (handling engine differences)

Different engines expose different hierarchies. TableX normalizes them into one tree with an optional **schema** level:

```
Server
└── Database
    └── (Schema)        ← present only for engines that have schemas
        └── Table / View / ...
```

| Engine | Server | Database | Schema | Table |
|---|---|---|---|---|
| MySQL / MariaDB | the connection target | a "database" (a.k.a. schema in MySQL terms) | **none** | tables in the database |
| PostgreSQL | the connection target | one DB per connection | **yes** (`public`, …) | tables in a schema |
| SQLite | the file/instance | `main` (+ `ATTACH`ed DBs) | **none** | tables in `main` |

The `Dialect.Capabilities()` flag `HasSchemas` drives whether the navigation tree and breadcrumb render a schema level. Handlers and templates are written against the generic `model` types; the dialect decides how to populate them. This is the single most important design decision for "support all databases."

> Key consequence for PostgreSQL: a `*sql.DB` is bound to **one** database. Switching databases means opening a new pooled connection, cached per session (§5).

---

## 5. Connection management

- On login (or selecting a predefined server), TableX opens a `*sql.DB` using the engine's driver and the user-supplied credentials.
- `*sql.DB` is itself a pool; we set sane `SetMaxOpenConns` / `SetConnMaxIdleTime`. Pool sizing and the generated-read statement budget are operator-tunable (`pool_max_conns`, `pool_idle_conns`, `read_stmt_timeout`), carried down every dial on `driver.ConnParams.Tuning` rather than through package state.
- Exports, SQL console scripts and SQL imports each open a **private** connection outside the cached-pool machinery (and so outside `pool_cap`). `max_concurrent_db_ops` bounds how many may run at once; over the cap a request is refused with 503 + `Retry-After` rather than queued.
- A per-session `handlers.UserContext` holds active `Connection`s in a map keyed by **database name** (the session is bound to one `serverID`, so the name alone is unambiguous). PostgreSQL **and MySQL** open an additional pool per database the user visits; only SQLite reuses the single connection for every logical database (`Capabilities().DatabasesShareConnection` — one file, session-scoped `ATTACH` names).
- Credentials live **only in server-side session memory** — never in the cookie, never logged, never written to disk (unless an admin defines a predefined server in config). See [`security.md`](./security.md).
- On logout / session expiry, all pools for that session are closed.

```go
// package driver
type Connection struct {
    db           *sql.DB
    dialect      Dialect
    info         ServerInfo
    tuning       Tuning            // resolved pool sizes and statement budgets
    observe      StatementObserver // audit sink; nil when auditing is off
    floorWarning string            // set at Open when the server is below the engine floor
}
```

`Connection` exposes high-level, engine-neutral methods (`ListDatabases`, `ListTables`, `Columns`, `Browse`, `Exec`, `Query`, …) that delegate dialect-specific bits to the `Dialect`. Handlers never import a concrete driver package.

---

## 6. Configuration

Resolution order (later overrides earlier):

1. Built-in defaults.
2. TOML config file (`--config tablex.toml`), if present — defines listen address, TLS, session settings, and optional **predefined servers**.
3. Environment variables (`TABLEX_*`).
4. Command-line flags.

Two connection modes (both supported):

- **Ad-hoc login** — the login page collects host/port/user/password; nothing is persisted.
- **Predefined servers** — listed in config so users only pick a server and enter credentials (or use config-supplied credentials for trusted deployments).

Five optional subsystems are each one config block, and each is **absent rather
than idle** when unconfigured — no allocation, no goroutine, and nothing on the
request path: `[storage]` (TableX's own metadata database, §2 of
docs/security.md), `[audit]` (the audit trail), `[restrict]` (restricted mode,
which does not even split a path per request when nothing is restricted),
`[metrics]` (`/metrics`, whose counters are not allocated and therefore not
incremented while it is off), and `[sso]` (the single sign-on gate, whose
routes 404 when no provider is configured). A block that is partly filled in,
or that tunes a subsystem it never switches on, **refuses startup** rather than
being silently ignored: a config block that does nothing is worse than a
refusal to start.

---

## 7. Rendering layer

- One parsed `template.Template` set at startup from the embedded FS, with a shared func map (icons, formatting, URL building, number/byte humanization, identifier display).
- **Base layout** composes partials: top navbar/icons, left navigation panel (`#tx_nav`), breadcrumb (`#server-breadcrumb`), tab bar (`#topmenu`), flash messages, and `#page_content`.
- **Page templates** fill `#page_content`. Each page also has a **fragment** entry used for htmx swaps — defined once, in the base layout, and present in every page's template set.
- All dynamic values pass through `html/template` auto-escaping. Any intentional raw HTML is explicit and reviewed.

---

## 8. Concurrency, lifecycle, errors

- The process is a standard concurrent `net/http` server; handlers must be goroutine-safe (no shared mutable globals; per-request state only).
- All DB calls take a `context.Context` derived from the request, so slow queries are cancelled when the client disconnects.
- **Graceful shutdown:** on SIGINT/SIGTERM, stop accepting connections, drain in-flight requests, close all session pools.
- **Error strategy:** handlers return errors to a central error renderer that shows a structured error panel (and the offending SQL where relevant), logs server-side detail, and never leaks stack traces or credentials to the client.
- **The three error tiers.** Every handler failure lands in exactly one of three named tiers, and the choosing rule is *what the rest of the page did*:
  1. **Terminal** — the request produced no usable page: `renderError`/`connError`/`dbError`. The semantic status is real (`503` for a failed dial, `400` for a bad request, `413` over a body cap), but a logged-in **htmx** caller receives it as an error panel swapped into `#page_content` at wire HTTP 200 — htmx refuses to swap non-2xx responses, so a "true" status would leave the user with no feedback. Full-page requests carry the real status. The connection-failure literal `"Connection failed"` belongs to `connError` alone (a repo-wide test holds it to one occurrence).
  2. **Section error** — the page rendered *successfully* with one section unavailable: a section-error field on the body (`structureBody.SectionError`, the metadata bodies' `Error`, `dbUsersBody.Error`), rendered as an error banner in place. Vocabulary: `"Database unreachable: …"` for a failed dial, `"… unavailable: …"` for a failed listing. A failure must land here **typed**, never in `Empty` — wording must never be the only thing separating a failure from an empty database.
  3. **Empty state** — a *successful* zero-result query: `body.Empty`, rendered as the neutral `empty_state` partial. Reserved for success; `listMeta` enforces the split for the metadata tabs.

  These are three deliberate patterns, not one inconsistency: flattening them (e.g. "every failure gets a real 4xx/5xx") breaks htmx navigation or lies about what happened.
- **Mid-stream failure and truncation:** a panic partway through a *compressed* streaming export leaves the gzip stream deliberately unterminated (no trailer is written on the abort path, on the transport encoder and the form-selected `.gz` sink alike), so a decoder reports `io.ErrUnexpectedEOF` instead of presenting a truncated dump as a complete one. Known residual: an **uncompressed** streaming response that fails mid-stream still ends at HTTP 200 with no in-band signal — HTTP offers nothing to revoke a status line already sent, so consumers who need integrity should prefer a compressed export or verify row counts after restore.

---

## 8b. The enterprise layer (all optional, all off by default)

Five subsystems an organization needs and a single-user tool does not. Each is
config-gated and each degrades to the previous behaviour when absent, so the
default deployment is exactly what it was before they existed.

- **`internal/storage` — TableX's own metadata database.** A portable schema with
  migrations, over any engine TableX can already speak (`driver.StorageHost`). It
  exists so state that should outlive a process has somewhere to live: today the
  durable session store, which is what unblocks running more than one replica.
  **It never holds a database credential** — see [`security.md`](./security.md) §2.
  Absent, sessions stay in the in-memory map behind the same `session.Store`
  interface, and nothing else changes.

- **`internal/audit` — the audit trail.** Distinct from the access log, which
  records method/path/status and cannot answer "who dropped that table". The
  trail records identity, source, target object, statement class and text,
  outcome and duration, emitted from the existing choke points rather than
  sprinkled through the handlers. Sinks are JSON Lines and stderr. It never holds
  a replayable secret.

- **Restricted mode (`internal/server/restrict.go`).** `read_only`,
  `allow_console`, `allow_ddl` and `database_allowlist`, enforced **on the
  request** — the middleware refuses the route whatever the UI shows. The UI then
  reflects the same policy through one derivation (`view.Allowance`), so a
  restricted deployment stops *offering* what it will refuse. Both halves matter:
  enforcing without reflecting looks broken, and reflecting without enforcing is
  not a control at all.

- **The SSO gate (`[sso]`, `internal/auth/oidc.go` + `handlers/sso.go`).** An
  OIDC provider in front of the login form, as an extra factor rather than a
  replacement for it: the connection still uses the user's own credentials, so
  per-user audit attribution and the never-store-a-credential guarantee both
  survive. Written against `net/http` and `encoding/json` — no OIDC library —
  which is affordable because the flow is deliberately the small one (code +
  PKCE, no front-channel token). See `docs/security.md` §2 for why skipping the
  ID token's signature is sound for a token fetched over TLS from the token
  endpoint, and unsound anywhere else.

- **`/metrics` and the query budget (`internal/server/metrics.go`).** Prometheus
  text format written by hand — the format is a few `Fprintf` lines over atomics,
  and a client library would have been the fifth dependency. Label cardinality is
  bounded by construction (method × status *class*; never a path, database or
  account). Unconfigured subsystems emit **no series** rather than zeros, so a
  scrape cannot imply a feature is running when it is off. `/metrics` refuses to
  start when enabled with neither a token nor a CIDR allowlist: the mistake is
  otherwise silent, and no default is defensible.

---

## 9. Testing architecture

- **Unit:** dialect SQL builders, identifier quoting, DSN building, result scanning, pagination math — no DB needed.
- **Integration:** spin up MySQL/MariaDB/PostgreSQL via Docker and run the real introspection/CRUD paths; SQLite uses a temp file (no Docker).
- **HTTP:** `httptest` against handlers with a fake/SQLite-backed connection.
- **Template:** content assertions over pages rendered by the real server (headings, header scopes, control names — see `internal/server/a11y_test.go`), deliberately NOT golden-file snapshots: a snapshot of pages this dense would fail on every cosmetic edit and be re-blessed unread.

See the feature map, testing strategy and packaging in [`design.md`](./design.md).
