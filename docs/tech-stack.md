# TableX — Technology Stack

> Status: **Locked** for v1. Changing anything here is an architecture decision — update this file and every doc that cites these versions together.
> Last verified: **2026-08-05**.

TableX is a standalone, multi-database web administration tool that brings the classic web database-admin experience to MySQL, MariaDB, PostgreSQL, and SQLite behind one abstraction.

The guiding constraints, in priority order:

1. **The classic UI first**, then careful modernization.
2. **Single self-contained binary** — no runtime dependencies, no PHP, no Node at runtime.
3. **Minimal, clean, secure code** — few dependencies, all pure-Go where possible.
4. **MIT licensed** — every line is original work.

---

## 1. Language & runtime

| Item | Choice | Version | Why |
|---|---|---|---|
| Language | **Go** | 1.26.6 (require ≥ 1.26) | Single static binary, `embed.FS` for assets, great stdlib HTTP + `database/sql`, easy cross-compilation. |
| HTTP server | **net/http (stdlib)** | — | Go 1.22+ `ServeMux` supports method + path patterns (`GET /db/{name}`). No external router needed. |
| Templating | **html/template (stdlib)** | — | Context-aware auto-escaping = XSS-safe by default. Fits the server-rendered model. |
| Sessions | **custom, stdlib only** | — | Lean in-memory session manager (`crypto/rand` IDs, pluggable store). No external session lib. |
| Logging | **log/slog (stdlib)** | — | Structured, leveled logging (Go 1.21+). No external logging dep; credentials are never logged (see [`security.md`](./security.md)). |
| Config | **flags + env + TOML file** | — | `flag` + env for ops; optional TOML (`github.com/BurntSushi/toml`) for predefined servers. One small config dep. |

### Why a single binary (not PHP)
The user asked for a "standalone" tool. A Go binary with assets embedded via `go:embed` ships as **one file** that runs on Linux/macOS/Windows with zero install steps. PHP would require a PHP runtime + web server. Go also gives us first-class concurrency for connection pooling.

---

## 2. Database drivers — all pure-Go (no CGo)

Pure-Go drivers are mandatory: they keep the binary CGo-free so we can cross-compile to every platform from one machine and ship a truly standalone artifact.

| Engine | Driver | Version | `database/sql` name | Notes |
|---|---|---|---|---|
| MySQL / MariaDB | `github.com/go-sql-driver/mysql` | v1.10.0 | `mysql` | Same wire protocol covers both; detect MariaDB from version string. |
| PostgreSQL | `github.com/jackc/pgx/v5` (stdlib adapter `pgx/v5/stdlib`) | v5.10.0 | `pgx` | Best-in-class PG driver; pure Go. |
| SQLite | `modernc.org/sqlite` | v1.56.0 | `sqlite` | **Pure-Go** SQLite (transpiled, SQLite 3.53.3), no CGo. Avoids `mattn/go-sqlite3`'s CGo requirement. |

All three plug into Go's `database/sql`, so the generic query/exec path is shared; only dialect-specific behavior is per-driver. See [`database-drivers.md`](./database-drivers.md).

---

## 3. Front-end — vendored, embedded, permissively licensed, no build step

All front-end libraries are permissively licensed (MIT, except htmx which is Zero-Clause BSD — see the table and `THIRD-PARTY-NOTICES` at the repo root), downloaded as prebuilt files, vendored under `web/static/vendor/`, and embedded into the binary. **There is no Node/npm build pipeline at runtime or in CI for v1** — we ship prebuilt assets to keep the build Go-only.

| Library | Version | Purpose | License |
|---|---|---|---|
| **Bootstrap** | 5.3.8 | Layout + component base. | MIT |
| **htmx** | 2.0.10 | Partial-page swaps / AJAX — an app-like feel without a SPA. | Zero-Clause BSD (MIT-compatible) |
| **Alpine.js** | 3.15.12 — **CSP build** (`@alpinejs/csp`) | Small client-side state — eight registered components covering the export form's format-dependent fields, login-form engine switching, the nav select, the row filter, check-all/bulk row actions, the object picker, the SQL console and the create-table row editor. No modals and no dropdowns: destructive confirms are server-rendered interstitials and collapsibles are native `<details>`. The CSP build is mandatory: it avoids `new Function()` so we keep a strict CSP with **no `unsafe-eval`** (see below). | MIT |
| **CodeMirror** | 5.65.21 (single-file) | SQL editor (syntax highlight, line numbers). Single-file distribution; no bundler required. **Bundle the SQL mode only** (`mode/sql/sql.js`) — never `mode/markdown/markdown.js`. | MIT |

### Note on CodeMirror 5 vs 6
**CodeMirror 5** ships as single JS/CSS files and needs **no bundler** — ideal for our no-Node policy. CodeMirror 6 (6.0.2 + `@codemirror/lang-sql` 6.10.0) is more modern but is modular and requires an esbuild/rollup step. **Decision: start with CM5 (single-file, pinned to 5.65.21 — the latest 5.x)**; revisit CM6 only if we later add a small optional asset-build step.

**Security note (CVE-2025-6493):** CM5 ≤ 5.65.20 has a ReDoS in its **Markdown mode** (`mode/markdown/markdown.js`). TableX ships **only the SQL mode**, so this code path is never bundled and the CVE is out of scope; pinning 5.65.21 keeps us on the latest patched 5.x regardless. The long-term remediation (and CM5's own recommendation) is migrating to CM6, which is the eventual upgrade path above.

**Legacy-maintenance note:** CodeMirror 5 is in **legacy maintenance, not end-of-life**. 5.65.21 is the latest 5.x; the GitHub *mirror* (`codemirror/codemirror5`) was archived on 2026-04-16 and development moved upstream to `code.haverbeke.berlin`, and the project itself calls the line "legacy". So expect patches to be **rare, not none** — `web/static/vendor/MANIFEST` records the same status and is the authority on it. No advisory affects the files we ship (`codemirror.min.js`/`.css` + the SQL mode). Accepted for v1; the documented exit is the CM6 migration above, which requires adding a small asset-build step.

### CSP compatibility (front-end ↔ security)
The front-end choices are constrained by our strict Content-Security-Policy goal (`script-src 'self'`, **no `unsafe-eval`/`unsafe-inline`** — see [`security.md`](./security.md)):

- **Alpine.js** — the standard build evaluates `x-*` attribute expressions with `new Function()`, which a strict CSP blocks. We therefore use the **`@alpinejs/csp`** build and register components via `Alpine.data()` (referencing properties/methods by key). No `unsafe-eval` needed.
- **htmx** — core attributes (`hx-get`, `hx-target`, `hx-headers`, …) need no eval. We avoid the `js:` prefix and `hx-on:` features, which would.
- **CodeMirror** — no eval. **Bootstrap** is vendored CSS-only (no Bootstrap JS, no Popper). `style-src` allows `'unsafe-inline'` for Alpine's `x-show` inline `display:none` toggles and the server-rendered `--tx-nav-width` style; finalized in [`security.md`](./security.md).

### No React / no SPA
Per the user's explicit preference: no React or heavy front-end framework. The app is server-rendered HTML; htmx handles the dynamic, partial-update feel.

---

## 4. Custom theme (the classic look)

TableX's look is **our own CSS** layered on Bootstrap — an original stylesheet giving the app its classic two-tone admin appearance. The design tokens (palette, typography, spacing) are documented in [`ui-design.md`](./ui-design.md). We may author our theme in SCSS and pre-compile to a single committed CSS file (compilation is a dev-time convenience, never required to build the binary).

---

## 5. Dependency policy

- **Minimize dependencies.** Prefer the standard library. Every new module must earn its place.
- **Pure Go only** for anything compiled in (no CGo) so cross-compilation stays trivial.
- **Pin exact versions** in `go.mod`; review transitive deps.
- **Vendor + embed** front-end assets; never load third-party JS/CSS from a CDN at runtime (offline-capable, no CDN fetches, better privacy/security).

### Current `go.mod` direct dependencies
```
github.com/go-sql-driver/mysql v1.10.0
github.com/jackc/pgx/v5         v5.10.0
modernc.org/sqlite              v1.56.0
github.com/BurntSushi/toml      v1.6.0      // config files
```

---

## 6. Tooling

| Concern | Tool |
|---|---|
| Build | `go build` (assets embedded via `go:embed`); reproducible builds (`-trimpath`, and the build toolchain pinned by the **`toolchain`** directive in `go.mod` — the `go` directive states the minimum language version, which is a different thing) |
| Cross-compile | `GOOS`/`GOARCH` matrix → per-platform binaries |
| Lint/format | `gofmt`, `go vet`, `staticcheck` — one definition (`make lint`), which the CI `lint` job calls so the local gate and CI cannot drift |
| Vulnerability scan | **`govulncheck`** (golang.org/x/vuln) in CI — fails the build on known-vulnerable stdlib/deps; **Dependabot** keeps module and Action versions current (`.github/dependabot.yml`) |
| Tests | `make test` runs the suite race-free by design (`-race` requires a C toolchain — windows/amd64 needs gcc, which dev boxes may lack); `make racetest` (and CI's Linux jobs) add `-race`. Docker-backed integration tests per engine. |
| Packaging | Per-OS/arch **archives** of the static binary, plus **`.deb` and `.rpm`** packages (nfpm, amd64 + arm64) and a minimal distroless multi-arch Docker image; an **SPDX SBOM** (syft), **Sigstore `cosign`-signed** checksums and image, and a **GitHub build-provenance attestation** over `SHA256SUMS` (`.github/workflows/release.yml`) |
