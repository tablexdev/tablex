# Contributing to TableX

## What TableX is trying to be

Start at [`docs/README.md`](./docs/README.md) — the documentation index. Four
priorities, in order, resolve most design arguments before they start:

1. **Keep the classic UI**, and modernize carefully. A change that improves
   the design but loses the classic feel is not an improvement here.
2. **One self-contained binary.** Assets are embedded; there is no PHP, no Node,
   no build step, and nothing to install alongside it.
3. **Minimal, clean, secure code.** Few dependencies, all pure Go — no CGo.
4. **MIT.** Every line of TableX is original work. Never copy code, templates,
   styles or assets from another project — regardless of its license. This is
   the whole reason TableX can be MIT-licensed.

## The gates

Every change has to leave these green:

```bash
gofmt -l internal cmd web        # must print nothing
go vet ./...
staticcheck ./...                # config: staticcheck.conf
go test ./...
go build ./...
```

CI additionally runs `-race`, a `GOARCH=386` pass over the whole tree,
`govulncheck`, a Docker build, a cross-compile matrix, `node --check` over
`app.js`, a coverage floor, and live round-trip tests against MySQL, MariaDB and
PostgreSQL. Note what the engine coverage does and does not prove: PostgreSQL's
documented floor (13) is exercised exactly, while MySQL's and MariaDB's oldest
CI images (8.0, 10.6) are both *newer* than their documented feature floors
(8.0.13, 10.2.7), so the code paths between them are reasoned about, not run.

The live tests **skip silently** without their `TABLEX_TEST_*` variables. If you
are touching a driver, run them for real — a skipped test is not a passing one:

```bash
TABLEX_TEST_POSTGRES_HOST=127.0.0.1 TABLEX_TEST_POSTGRES_PORT=5433 \
TABLEX_TEST_POSTGRES_USER=postgres  TABLEX_TEST_POSTGRES_PASSWORD=... \
go test ./internal/server/ -count=1 -v -run Postgres
```

## Conventions that are not negotiable

These are the ones a reviewer will send a change back for:

- **SQL safety.** Values are always parameterized. Identifiers go through
  `Dialect.QuoteIdent` **after** being validated against introspection. Never
  concatenate user input into SQL. The exceptions are the four places the user's
  OWN SQL runs under their own credentials (the SQL console, SQL import, a
  stored program's body, and a partial index's `WHERE` predicate), plus the DDL
  positions that accept no placeholder — a type definition, an expression, a
  `CREATE`/`ALTER` clause. They are enumerated in
  [`docs/security.md`](./docs/security.md) §4; a new one needs the same
  treatment and the same write-up.
- **Engine differences live behind `Dialect`.** Handlers and templates use the
  neutral `internal/model` types and read `Capabilities()`. An `if engine ==
  "mysql"` in a handler is a bug; adding breadth means adding a capability or a
  dialect. See [`docs/adding-an-engine.md`](./docs/adding-an-engine.md).
- **State-changing routes are POST + CSRF-protected**, and destructive ones are
  confirmed **server-side** — the browser dialog is a convenience, not the
  control.
- **Rendering always goes through `html/template`.** Raw HTML needs a reason in a
  comment.
- **Credentials are never logged, flashed, exported or persisted** (except
  admin-defined predefined servers).
- **New dependencies need justifying** and must be pure Go. The bar is high: the
  current list is four modules.

## Tests

A change that fixes a bug should come with the test that would have caught it,
and the useful question is not "does the test pass?" but **"does it fail when I
break the thing it is about?"** Several assertions in this repo's history passed
while the code they guarded was reverted — most memorably three that were vacuous
on SQLite, which has no `CREATE DATABASE`, no process list and one database. So:

- Before asserting that something is **hidden**, assert it is **shown** in the
  permissive case, on the same engine.
- Give a scanning test a **floor** on how much it inspected, so it cannot pass by
  matching nothing.
- Break your own fix and watch the named test go red.

Front-end behaviour has no JS runner (see priority 2). It is covered by content
assertions over the embedded files in `web/embed_test.go` plus real-server
rendering tests in `internal/server`. That is a real limit, stated rather than
papered over.

## Commits and pull requests

- One logical change per commit. A refactor and a behaviour change in the same
  commit cannot be reviewed or reverted separately.
- Say **why** in the message, not just what. The diff already shows what.
- Keep docs in step with the code in the same commit. A doc that claims a control
  the code does not have is treated as a defect — the doc-coherence tests in
  `cmd/tablex/docs_test.go` exist because exactly that kept happening.
- Bug reports and feature requests have [issue templates](./.github/ISSUE_TEMPLATE),
  and pull requests get a short checklist from the
  [PR template](./.github/PULL_REQUEST_TEMPLATE.md) — the gates above, run
  before pushing, are the whole of it.
