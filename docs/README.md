# TableX — Documentation

**TableX** is a standalone, single-binary web administration tool for multiple SQL databases — **MySQL, MariaDB, PostgreSQL, and SQLite** — with the classic web database-admin experience, written in Go, MIT-licensed.

> Status: **Implemented.** The full stack (config, drivers, session/auth, server, handlers, templates) is in place and `go build` / `go vet` / `go test` pass. Deliberately deferred items are listed in [design.md](./design.md).

## Read in this order

1. **[tech-stack.md](./tech-stack.md)** — locked technology choices and exact versions (Go, drivers, Bootstrap/htmx/Alpine/CodeMirror), dependency policy.
2. **[architecture.md](./architecture.md)** — system design: single binary, package layout, request lifecycle, the Server→Database→(Schema)→Table object model, connection management.
3. **[database-drivers.md](./database-drivers.md)** — the `Dialect`/`Connection` abstraction that makes "all databases" work; per-engine specifics; capability matrix.
   → **[adding-an-engine.md](./adding-an-engine.md)** is the practical contract for adding a new one: the 26 required methods, every optional interface and what it unlocks, the capability⇒interface rules, and the `drivertest` conformance suite that enforces them.
4. **[ui-design.md](./ui-design.md)** — design system: tokens, page skeleton, template hierarchy, components, htmx/Alpine/CodeMirror usage, modernization rules.
5. **[security.md](./security.md)** — threat model, auth/session/CSRF, credential handling, SQL-injection & XSS prevention, headers, TLS.
6. **[design.md](./design.md)** — the feature map, deliberate deferrals, testing strategy and packaging.

## TL;DR

| Decision | Choice |
|---|---|
| Language / shape | Go 1.26, **single embedded binary**, no PHP/Node at runtime |
| UI | Server-rendered `html/template` + Bootstrap 5 + our own classic theme + htmx + Alpine (no React) |
| Databases | MySQL/MariaDB (`go-sql-driver/mysql`), PostgreSQL (`pgx`), SQLite (`modernc.org/sqlite`) — all pure-Go |
| Abstraction | One `Dialect` interface; breadth = new dialects, not scattered branches |
| License | MIT — all original code |
| Priority | Keep the classic UI; modernize carefully, never degrading it |

## Project

| | |
|---|---|
| Module / repo | `github.com/tablexdev/tablex` · org [github.com/tablexdev](https://github.com/tablexdev) |
| Website | https://tablex.dev |
| Support | info@tablex.dev |
| License | MIT — © 2026 Vishnu. See [`LICENSE`](../LICENSE). |

> Contact/identity convention: the **`info@tablex.dev`** address and **tablex.dev** domain are for tool-facing and general use (app About page, docs, website). The maintainer address `vishnu@codeseasy.com` is for repository/Git use only — commits and annotated tags. (It appears in no shipped artifact: `go.mod` carries no email at all, and the packages are stamped `info@tablex.dev`.)
