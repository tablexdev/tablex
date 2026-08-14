# Changelog

All notable changes to TableX are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.1] - 2026-08-14

**1.0.0 is withdrawn and retracted** (along with both release candidates). It was
tagged from a tree that predates the fixes below, and a published version cannot
be re-cut: the module proxy and checksum database keep serving what they already
recorded, so re-tagging `v1.0.0` on corrected code would make `go install` fail
verification instead of delivering the fix. `go.mod` retracts all three, which
hides them from `go list -m -versions`, `go get` and pkg.go.dev. Upgrade to
1.0.1; there is no compatible way back to 1.0.0.

Users of the published container image should re-pull: the `latest` tag was
built from the same withdrawn tree and carries the `database_allowlist` bypass
fixed in 1.0.0's own history but never re-released.

### Security

- Built with Go 1.26.6, which fixes seven standard-library vulnerabilities
  reachable from TableX: `html/template` (GO-2026-6091 — the auto-escaping
  every rendered page depends on), `net/http` (GO-2026-6089, GO-2026-5026),
  `crypto/tls` (GO-2026-6090), `net/url` (GO-2026-6218), `encoding/xml`
  (GO-2026-6088 — the XML export), and `encoding/asn1` (GO-2026-5972).
  Rebuilding from source requires the same toolchain floor.

### Fixed

- A password typed into the SQL console or an imported script could reach the
  audit trail in cleartext when `[audit] statements = true`. The scrub covered
  `IDENTIFIED BY` but not MySQL 8's `IDENTIFIED WITH <plugin> BY '…'`, nor the
  `REPLACE '<current password>'` clause. Both are redacted now.
- A PostgreSQL **structure-only** database or schema export could not be
  restored when a partition tree mixed local and foreign partitions: each local
  leaf was created twice — once standalone, once by the root's `PARTITION OF` —
  and the restore stopped at `relation already exists`.
- A PostgreSQL **data-only** database export emitted no `setval` for a sequence
  owned by a partition CHILD, so the restored table reissued ids its restored
  rows already held (a primary key rejects the next insert).
- Changing a column between `ENUM` and `SET` without editing its member list
  was silently dropped on MySQL/MariaDB: the column kept its old type while the
  UI reported success.
- MySQL/MariaDB identifiers are limited to 64 CHARACTERS, not 64 bytes. TableX
  refused to create names the server accepts and TableX itself already browses
  — a 22-character CJK table name is 66 bytes.
- On tablets 768px and wider, the navigation toggle appeared next to the
  permanently-visible sidebar and, when tapped, ran the mobile drawer's modal
  focus contract — trapping keyboard focus in the tree until Escape.
- The rows-per-page control on Browse also fired on the "sort by key" select,
  sending a second competing request that carried the previous sort.
- SQLite row estimates could read a PARTIAL index's row count as the table's,
  which made every Browse and Structure render fall back to an exact
  `COUNT(*)` full scan on a large table.

### Changed

- **Upgrade note:** an ad-hoc login now requires a host. An empty host field
  used to fall through to the driver's local default — MySQL/MariaDB dialed
  127.0.0.1:3306, PostgreSQL fell back to its Unix socket — a target the
  `host_allowlist` / `host_denylist` checks never saw, because there was no
  name to match. Both the login form and the SSRF pre-flight now refuse the
  empty host outright; type the target explicitly (`127.0.0.1` for a local
  server). Predefined `[[servers]]` entries are unaffected.

- The account forms refuse a blank password with a 400 in both the
  create-account and per-row Set branches. A blank used to be flashed as
  success while doing something engine-divergent: MySQL/MariaDB created (or
  reset) the account to authenticate with an *empty* password, and PostgreSQL
  emitted `PASSWORD NULL`, removing password authentication. This closes the
  only UI path to PostgreSQL's `PASSWORD NULL`; a separate, explicit
  "disable password authentication" action is deliberately out of scope.

- A blank entry in `sso.allowed_emails` / `sso.allowed_domains` now refuses
  startup. A blank domain entry used to match an email with an empty domain
  part; it is refused rather than silently dropped, because filtering a
  blank-only list down to nothing would disable the allowlist entirely and
  admit every provider-verified identity. (The environment overrides are
  unchanged: blanks are already dropped there, and a separator-only value
  still clears the list, as documented.)
- A `[storage]` block containing only `max_sessions` (no `engine`) now refuses
  startup like every other partly-configured block — it used to start with the
  key silently doing nothing. `max_sessions` is presence-tracked, so its
  documented explicit `0` (uncapped) keeps meaning exactly that.
- An *enabled* `_texttotime` or `_inttotime` SQLite driver parameter — under
  `[[servers]].params` or `[storage.params]` — now refuses startup, naming the
  key. Those options make the driver return a `time.Time` for a text- or
  integer-stored column, which TableX's browse, export and row-edit-save paths
  would silently narrow or misencode; TableX assumes those storage classes
  round-trip verbatim. Only an enabled value is refused — the disabled spellings
  (`…=false`, `…=0`) still start, and an unrelated `_pragma` is untouched.
- **Upgrade note:** a configuration file containing a key TableX does not
  recognise now refuses startup, naming the key. TOML decoding used to ignore
  unknown keys silently, so a mistyped or misplaced hardening key (`readonly`
  instead of `read_only` under `[restrict]`, `database_allowlist` at top level)
  left its permissive default in force with no error, warning or log line. A
  file the previous binary accepted can therefore stop the new binary from
  starting — fix or remove the named key(s) to proceed; rolling back is safe,
  since the previous binary still ignores what it does not know. Known
  limitation: keys *inside* the free-form maps `[storage.params]` and
  `[[servers]].params` are absorbed as decoded, so a typo there stays silent —
  the guard is strong, not total.
- **Upgrade note:** the same refusal now covers the environment: an unknown
  `TABLEX_`-prefixed variable (`TABLEX_READONLY` for `TABLEX_READ_ONLY`,
  `TABLEX_ALLOW_DLL` for `TABLEX_ALLOW_DDL`) refuses startup, naming the
  variable, instead of silently keeping the permissive default. `TABLEX_TEST_*`
  and the install scripts' own variables (`TABLEX_VERSION`,
  `TABLEX_INSTALL_DIR`, `TABLEX_BASE_URL`, `TABLEX_NO_MODIFY_PATH`,
  `TABLEX_PS1_URL`) are exempt — they legitimately share a process environment
  with the binary. Unset or rename the variable to proceed; rolling back is
  safe.

### Security

- A partial index's `WHERE` predicate was validated by a hand-rolled scan that
  tracked only `'`, so a payload using any other quoting form an engine has —
  dollar quotes, double quotes, backticks, brackets, `E'…'` escapes — could carry
  a `;` past it. The clause is now split under the dialect's own lexer and must
  BE the single statement it returns. PostgreSQL and SQLite were affected; MySQL
  has no partial indexes and never reached the field.
- `allow_console = false` did not close that predicate, which is the fourth place
  a user's own SQL reaches the server. It does now, checked in the handler
  because the route also carries ordinary DDL that must keep working.
- `database_allowlist` split the DECODED request path while `net/http` routes on
  the escaped one, so `/db/app%2Fbackup/…` was checked as `app` and handled as
  `app/backup`. Both the allowlist and the audit trail now segment the escaped
  path and unescape each segment, as the router does.
- PostgreSQL string literals assumed `standard_conforming_strings = on`. A value
  containing a backslash is now emitted as an `E'…'` escape string, which means
  the same thing in either mode, and the GUC is pinned on for every session.
- The process list and cross-database foreign keys disclosed metadata from
  databases outside `database_allowlist` on pages the allowlist had narrowed.
- Single sign-on: a verified identity is preserved across `/auth/sso/start`
  instead of being discarded, and is cleared on every denial past the state
  check — so removing somebody from `allowed_emails` locks them out immediately
  rather than at session expiry.
- `tx_confirm` was derived from the presence of an inherited `hx-confirm`
  attribute, so links that never prompted — including two that use
  `hx-confirm="unset"` to cancel inheritance — told the server a confirmation had
  been given.

### Added

- `max_concurrent_imports` (default 4) bounds concurrent import uploads on its
  own semaphore, ahead of the CSRF middleware that parses them.
- `max_script_statements` (default 500000) bounds how many statements one script
  may lex into, refusing an over-limit script whole rather than running a prefix.
- `storage.max_sessions` (default 20000, per replica) bounds the durable sessions
  table; over it a session runs process-local. `security.session_create_window` /
  `session_create_max` throttle session creation per client (off by default).
- `tablex_import_ops_*` and `tablex_storage_session_*_refusals_total` metrics for
  the new caps, and a startup warning when TableX listens on a non-loopback
  address without TLS.
- The `sslmode` selector is now offered for MySQL/MariaDB, with per-engine help
  text: the vocabulary is PostgreSQL's, the behaviour is not, and `require` does
  not authenticate the server on either.

### Fixed

- SQLite's partial-index predicate reader indexed an uppercased copy of the DDL
  with offsets from the original, which panicked on some multi-byte input and
  silently mis-parsed others; comments are now neutralized too.
- A `DROP DATABASE` that failed BEFORE the statement was issued was reported with
  the statement attached, and its (dial) error was rendered without redaction.
- Focus outlines are no longer removed from the SQL editor.

## [1.0.0] - 2026-08-05

The first public release. TableX's development history predates this
repository going public, so 1.0.0 describes the whole tool rather than a
delta; see [`SECURITY.md`](https://github.com/tablexdev/tablex/blob/master/SECURITY.md)
for how to verify the signed binaries, packages and images this release
introduces.

### Added

- **Multi-engine support** for MySQL, MariaDB, PostgreSQL and SQLite behind one
  `Dialect` interface with 48 opt-in capability interfaces, so an engine that
  lacks a feature degrades rather than breaking. Adding a fifth engine means
  implementing `Dialect` and registering it — see
  [`docs/adding-an-engine.md`](./docs/adding-an-engine.md) and the reusable
  conformance suite in `internal/driver/drivertest`.
- **The classic database-admin UI**: browse with multi-column
  sort, filtering, column visibility and bulk row actions; structure editing with
  column rename, reorder, ENUM/SET editing and index depth; the SQL console;
  export in SQL, CSV, JSON and XML (SQL only at server scope) and import in SQL,
  and in CSV at table scope, with gzip on both sides; a schema
  designer; users and privileges down to column and routine scope; stored
  routines, triggers and events with full CRUD; table maintenance operations.
- **Enterprise platform layer**: a durable session store and metadata database
  (`internal/storage`), a pluggable audit trail recording who changed what from
  where (`internal/audit`), restricted mode (`read_only`, `allow_console`,
  `allow_ddl`, `database_allowlist`) enforced in middleware *and* reflected in
  the UI, a Prometheus `/metrics` endpoint with no new dependency, and a
  per-session query budget.
- **Release artifacts** — none of which previously existed, since CI
  cross-compiled to `/dev/null` and discarded its image. Every tag now publishes:
  - **archives** for six OS/arch pairs (`.tar.gz`, `.zip` on Windows), each
    carrying the static binary plus `LICENSE` and `THIRD-PARTY-NOTICES` — a bare
    binary would not be notice-compliant;
  - **`.deb` and `.rpm` packages** for linux amd64 and arm64;
  - an **SPDX SBOM** of the source tree;
  - **`SHA256SUMS`** covering all of the above, keylessly **signed with cosign**
    (`.sig` + `.pem`) and additionally covered by a **GitHub build-provenance
    attestation**;
  - **multi-arch container images**, also cosign-signed.
- **A startup version check.** Connecting a server older than the documented
  engine floor now says so at login instead of degrading silently at the point of
  use.
- **Optional single sign-on (`[sso]`)** — an OpenID Connect provider in front of
  the login form, as an extra factor rather than a replacement for it: the
  connection still uses your own database credentials, so per-user audit
  attribution and the never-store-a-credential guarantee both survive. Code flow
  with PKCE, written against the standard library with no new dependency.
- **A global per-account lockout** (`login_account_max`, on by default). Every
  other login throttle key starts with the client IP, so an attacker with an
  IPv6 /64 or a botnet previously got the full per-IP budget *per address* against
  one account.

### Changed

- **Both themes meet WCAG AA contrast**, enforced by a test that parses the
  shipped stylesheet and resolves every token pair. Dark mode is now entirely a
  re-spec of token values: no rule in the stylesheet carries a raw colour, and a
  test fails the build if one appears.
- **Every request reports that it is running** — a progress bar, `aria-busy` on
  the region being replaced, and disabled submit controls, so a slow query no
  longer looks like an ignored click.
- **Assets are fingerprinted and cached for a year** rather than revalidated
  hourly, and htmx's page cache is off so query results are no longer written to
  `sessionStorage`.
- **The accessibility baseline is asserted, not asserted-to**: one `<h1>` per
  page naming it, `scope` on every column header, accessible names on every
  row-editor control, one permanent live region, and an off-canvas drawer that
  leaves the tab order when closed.

### Fixed

- The SQL console ran on an unspecialized dialect, so `RETURNING` rows were
  silently discarded on MariaDB and PostgreSQL 17.
- Imports buffered up to 32 MiB per request in memory; text cells were uncapped;
  views paid a full `COUNT(*)` on every render.
- PostgreSQL dumps were not byte-deterministic (a map iteration leaked into
  output ordering).
- Leaving a half-finished edit discarded it silently — there was no dirty
  tracking and, because htmx swaps without navigating, no browser prompt either.

[Unreleased]: https://github.com/tablexdev/tablex/compare/v1.0.1...HEAD
[1.0.1]: https://github.com/tablexdev/tablex/releases/tag/v1.0.1
[1.0.0]: https://github.com/tablexdev/tablex/releases/tag/v1.0.0
