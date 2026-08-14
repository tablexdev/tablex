# TableX

**A standalone, single-binary web admin tool for MySQL, MariaDB, PostgreSQL and SQLite — the classic database-admin experience, written in Go, MIT-licensed.**

[![CI](https://github.com/tablexdev/tablex/actions/workflows/ci.yml/badge.svg)](https://github.com/tablexdev/tablex/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/tablexdev/tablex)](https://github.com/tablexdev/tablex/releases/latest)
[![Go Reference](https://pkg.go.dev/badge/github.com/tablexdev/tablex.svg)](https://pkg.go.dev/github.com/tablexdev/tablex)
[![Go 1.26](https://img.shields.io/badge/go-1.26-00ADD8?logo=go&logoColor=white)](https://go.dev/dl/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](./LICENSE)
[![Engines](https://img.shields.io/badge/engines-MySQL%20%7C%20MariaDB%20%7C%20PostgreSQL%20%7C%20SQLite-blue)](./docs/database-drivers.md)

[tablex.dev](https://tablex.dev) · support: info@tablex.dev

TableX compiles to **one self-contained binary** with every asset embedded (`go:embed`) — no PHP, no Node, no runtime dependencies. It speaks to all four engines behind a single `Dialect` abstraction, so the same UI serves every database.

---

## Features

- **Connect** to MySQL/MariaDB, PostgreSQL (with schemas) and SQLite via ad-hoc login or predefined servers.
- **Navigate** a classic tree (database → schema → table) with lazy-loaded, htmx-driven fragments and a fast filter.
- **Browse** data with pagination, sorting, per-row edit/copy/delete and a "with selected" bulk delete.
- **Structure** editing: add/modify/drop columns, add/drop indexes and foreign keys — alongside the native/reconstructed `CREATE` statement.
- **SQL console** with a CodeMirror editor, multi-statement execution, stacked result sets and per-session history.
- **Edit data**: type-aware insert/edit forms and safe, parameterized delete — all POST + CSRF-protected.
- **Schema operations**: create/drop database, create table (multi-column form with primary key), rename/truncate/drop table.
- **Export** (SQL / CSV / JSON / XML, streaming; SQL only at server scope) and **Import** (SQL scripts anywhere, CSV with header→column mapping at table scope).
- **Search** a table by per-column conditions, or a whole database for a term.
- **Server tools**: status, variables, processes, and full account & privilege management (create/drop users, set passwords, PostgreSQL role attributes, GRANT/REVOKE at database and table scope) — shown only where the engine supports them.
- **Modern touches** (opt-in): dark mode, a responsive off-canvas sidebar for small screens, a resizable navigation panel (persisted, no first-paint flash), keyboard-friendly focus — never degrading the classic look.
- **For organizations** (all optional, all off by default): a durable session store so TableX can run behind a load balancer, an audit trail recording who changed what from where, restricted mode (`read_only`, no console, no DDL, a database allowlist) enforced on the request *and* reflected in the UI, a Prometheus `/metrics` endpoint, and **single sign-on as an extra factor** — you pass an OIDC provider, then still supply your own database credentials, so the audit trail keeps naming the real account. See [`docs/security.md`](./docs/security.md).

The UI **adapts to each engine's capabilities**: tabs like Users, Routines and Events appear only where they exist (e.g. they're hidden for SQLite).

---

## Install

**Linux / macOS**

```bash
curl -fsSL https://tablex.dev/install.sh | sh
```

**Windows (PowerShell)**

```powershell
irm https://tablex.dev/install.ps1 | iex
```

**Windows (cmd.exe)**

```bat
curl -fsSLO https://tablex.dev/install.cmd && install.cmd
```

Then run `tablex` and open <http://localhost:8080>. The scripts detect your
OS/architecture and verify every download against the release's `SHA256SUMS`,
and — when the GitHub CLI is installed and logged in — GitHub's
build-provenance attestation over that file, refusing on any mismatch. (They do
not check the cosign signature; that is the manual step below.) If tablex.dev is
unreachable, the same scripts are served from the repository:
`https://raw.githubusercontent.com/tablexdev/tablex/master/install.sh` (and
`.ps1` / `.cmd`). The archives themselves always come from the GitHub release,
never from tablex.dev — but note that `install.cmd` is only a bootstrapper: it
fetches `install.ps1` from `https://tablex.dev/install.ps1` unless you set
`TABLEX_PS1_URL`, so on that path either point it at the raw URL too or just
run the `.ps1` directly.

**Debian/Ubuntu and Fedora/RHEL packages** ship with every
[release](https://github.com/tablexdev/tablex/releases/latest) (`.deb` and
`.rpm`, amd64 + arm64), installing `/usr/bin/tablex` plus a hardened example
systemd unit under `/usr/share/doc/tablex/` — documentation, deliberately not
an enabled service: a database-admin login page should never auto-start from a
package install.

**Docker**

```bash
docker run --rm -p 8080:8080 ghcr.io/tablexdev/tablex
```

**Manual download + verification** — grab an archive for any of the six
OS/arch targets from the [releases page](https://github.com/tablexdev/tablex/releases/latest),
then verify it three independent ways:

```bash
# 1. checksum
sha256sum -c SHA256SUMS --ignore-missing

# 2. cosign signature
cosign verify-blob \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp 'https://github.com/tablexdev/tablex/.github/workflows/release.yml@.*' \
  --signature SHA256SUMS.sig --certificate SHA256SUMS.pem \
  SHA256SUMS

# 3. GitHub build-provenance attestation
gh attestation verify SHA256SUMS \
  --repo tablexdev/tablex \
  --signer-workflow tablexdev/tablex/.github/workflows/release.yml
```

> **Gatekeeper / SmartScreen:** the binaries are open-source builds without
> paid Apple/Microsoft signing certificates, so macOS and Windows may warn on
> first launch. The verification above is the stronger check — it proves a
> download came from this repository's release workflow.

<!-- Package managers (uncomment as each one goes live):
**Homebrew**: `brew install tablexdev/tap/tablex`
**Scoop**: `scoop bucket add tablex https://github.com/tablexdev/scoop-bucket && scoop install tablex`
**winget**: `winget install TableX.TableX`
-->

---

## Quick start

```bash
# Build the single binary (assets embedded)
go build -o tablex ./cmd/tablex     # or: make build (outputs bin/tablex)

# Run (default http://localhost:8080)
./tablex                            # or: ./bin/tablex after `make build`; or: make run
```

Open <http://localhost:8080>, pick an engine and log in:

- **MySQL/MariaDB or PostgreSQL** — host, port, user, password (and database for PostgreSQL).
- **SQLite** — not login-selectable: add a predefined `[[servers]]` entry with `engine = "sqlite"` and `file = "/path/to/app.db"` pointing at an **existing** database file (see [`tablex.example.toml`](./tablex.example.toml)). Missing files are rejected, never created.

> **Minimum engine versions:** MySQL **8.0.13+**, MariaDB **10.2.7+**, PostgreSQL **13+**, SQLite **3.26+** (**3.31+** for any schema using generated columns). CI verifies MySQL 8.4 and 8.0, MariaDB 11.4 and 10.6, and PostgreSQL 13 and 18 — note what that does and does not prove: the PostgreSQL floor (13) is exercised exactly, while the MySQL and MariaDB feature floors are *older* than any image CI runs. A server below its engine's floor is reported at login rather than left to degrade; see [docs/database-drivers.md](./docs/database-drivers.md#44-minimum-supported-engine-versions) for the rationale.

### Docker

```bash
make docker VERSION=dev             # builds a distroless image tagged tablex:dev
docker run --rm -p 8080:8080 tablex:dev
```

The image is `gcr.io/distroless/static-debian13:nonroot` + the static binary, runs as a non-root user, and contains nothing else.

---

## Configuration

Resolution order (later overrides earlier): **defaults → TOML file → `TABLEX_*` env → flags.**

```bash
./tablex --config tablex.toml --listen 127.0.0.1:8080
```

| Flag | Env | Purpose |
|---|---|---|
| `--listen` | `TABLEX_LISTEN` | Listen address (default `:8080`) |
| `--config` | `TABLEX_CONFIG` | Path to a TOML config file |
| `--tls-cert` / `--tls-key` | `TABLEX_TLS_CERT` / `TABLEX_TLS_KEY` | Enable direct HTTPS |
| `--allow-adhoc=true\|false` | `TABLEX_ALLOW_ADHOC` | Permit arbitrary-host login. It takes an explicit value — it is not a bare switch, so `--allow-adhoc` alone is an error |
| — | `TABLEX_COOKIE_NAME` | Session cookie name (default `tablex_session`) |
| — | `TABLEX_SECURE_COOKIES` | Force `Secure` cookies behind a TLS-terminating proxy |
| — | `TABLEX_IDLE_TIMEOUT` | Session idle timeout (Go duration, e.g. `30m`) |
| — | `TABLEX_ABSOLUTE_TIMEOUT` | Session absolute lifetime (Go duration, e.g. `12h`) |
| — | `TABLEX_MAX_EXACT_COUNT` | Row-count ceiling (TOML `max_exact_count`, default `50000`): relations whose statistics estimate more rows show the estimate, and ones with no usable estimate (a view) are counted only this far; both are marked `≈` with a "count exact" link, instead of running `COUNT(*)` on every Browse/Structure render; `0` always counts exactly |
| — | `TABLEX_POOL_CAP` | Process-wide cap on cached per-database connection pools (TOML `pool_cap`, default `32`); `0` removes the cap |
| — | `TABLEX_POOL_MAX_CONNS` / `TABLEX_POOL_IDLE_CONNS` | Size of each pool (TOML `pool_max_conns` / `pool_idle_conns`, default `8` / `4`); `pool_cap × pool_max_conns` bounds outbound connections to one server |
| — | `TABLEX_READ_STMT_TIMEOUT` | Budget for one generated read statement (TOML `read_stmt_timeout`, default `60s`); never applied to the console, exports, imports or writes |
| — | `TABLEX_MAX_CONCURRENT_DB_OPS` | How many exports / console scripts / imports may hold a private DB connection at once (TOML `max_concurrent_db_ops`, default `16`); over the cap a request gets 503 + `Retry-After`; `0` removes the cap |
| `--healthcheck` | — | Probe `GET /healthz` on the configured listen address and exit 0/1 — what the Docker image's `HEALTHCHECK` runs, and usable from any orchestrator |
| `--version` | — | Print version and exit |

This table is a selection. [`tablex.example.toml`](./tablex.example.toml) is the **canonical reference**: every config key with its documentation, and the complete environment-override table at the end of the file — plus session policy, predefined servers, and the SSRF/rate-limit controls.

---

## Security

TableX holds DB credentials and runs SQL on your behalf, so it is built defensively (full details in [`docs/security.md`](./docs/security.md)):

- Credentials live **only in server-side session memory** — never in cookies, logs or disk (except admin-defined predefined servers).
- 256-bit `crypto/rand` session IDs; `HttpOnly` / `SameSite` / `Secure` cookies (with the `__Host-` prefix when served over TLS, or behind a TLS-terminating proxy via `secure_cookies`); ID rotation on login.
- All state-changing routes are **POST + CSRF-protected**; login is rate-limited per IP and per username.
- **No string-built SQL for identifiers/values** — values are always parameterized; identifiers are validated against introspection and quoted per engine. (The SQL console intentionally runs your own SQL under your own credentials.)
- Strict **Content-Security-Policy** — `script-src 'self'` with no `unsafe-eval`/`unsafe-inline` for scripts, achievable because the bundled front-end (Bootstrap, htmx, the Alpine **CSP build**, CodeMirror) needs no eval. (Styles allow `'unsafe-inline'`; see [`docs/security.md`](./docs/security.md).)
- SSRF guard for ad-hoc logins: link-local/cloud-metadata addresses are always refused, with optional allow/deny lists and opt-in blocking of private/loopback ranges (`block_private`).

---

## Development

```bash
make test     # unit + integration tests (SQLite-backed; no Docker required)
make lint     # gofmt check + go vet + staticcheck
make cover    # cross-package coverage
make cross    # release binaries: linux/darwin/windows × amd64/arm64 (6 targets)
```

SQLite (pure-Go, `modernc.org/sqlite`) backs the integration and HTTP tests, so the full stack is exercised without spinning up a database server. On top of that, live MySQL / MariaDB / PostgreSQL round-trip tests (`internal/server/live_roundtrip_test.go`: export → drop → re-import → schema+data equality) run in CI against Docker service containers; locally they skip unless you point `TABLEX_TEST_{MYSQL,MARIADB,POSTGRES}_{HOST,PORT,USER,PASSWORD}` at your own servers.

### Layout

```
cmd/tablex/         entrypoint (config, embed, server, graceful shutdown)
internal/
  config/  session/  auth/  view/  model/
  driver/           Dialect interface + mysql/ postgres/ sqlite/ implementations
  server/           http server, middleware, router, handlers/
  dump/             the SQL dump engine (planner + writers; no net/http)
  sqlscript/        SQL lexer/splitter/classifier for console + import
  storage/          TableX's own metadata database + the durable session store
  audit/            the audit trail (JSONL + stderr sinks)
web/                templates/ + static/ (embedded; vendored Bootstrap/htmx/Alpine/CodeMirror)
docs/               design and operations docs (architecture, drivers, UI, security)
```

Adding a database engine is one new `Dialect` implementation + one import line — no handler or template changes.

---

## License

MIT © 2026 Vishnu. See [`LICENSE`](./LICENSE).

TableX is an original, independent implementation. Its UI takes inspiration from classic web database-admin tools such as phpMyAdmin, but every line of code, template and stylesheet is TableX's own. TableX is not affiliated with or endorsed by any other project.
