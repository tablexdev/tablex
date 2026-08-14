# TableX — Security Design

> "All secure" is a top requirement. This document is normative: code must follow it, and reviews check against it.

## 1. Threat model

TableX is a privileged tool: it holds database credentials and executes arbitrary SQL on the user's behalf. Primary risks:

1. **Credential theft** (from cookies, logs, memory dumps, config).
2. **Session hijacking / CSRF** (acting as a logged-in user).
3. **SQL injection** via identifiers/values we build into queries.
4. **XSS** via reflected DB content or user input in HTML.
5. **Brute-force** against the login.
6. **Transport interception** (TableX↔browser and TableX↔database).
7. **SSRF / arbitrary-server abuse** when ad-hoc server hosts are allowed.

The SQL console runs arbitrary SQL **by design** — that is the product. It executes under the *user's own* DB credentials and privileges; TableX grants no extra power and adds no privilege escalation path.

---

## 2. Authentication & sessions

- **Login** collects engine + host/port + user/password (or selects a predefined server). Credentials are validated by actually opening a DB connection.
- **Session IDs:** 256-bit, generated with `crypto/rand`, stored server-side. The cookie carries only the opaque ID.
- **Session cookie flags:** `HttpOnly`, `SameSite=Lax`, host-only, no `Domain` widening, and `Secure` whenever served over TLS — or behind a TLS-terminating proxy when the operator sets `secure_cookies`. In that secure mode the cookie also gains the **`__Host-` name prefix** (forces `Secure`, `Path=/`, and no `Domain`) so the browser enforces host-only scoping. (State-changing routes are additionally POST + CSRF-token protected, so `SameSite=Lax` is sufficient.)
- **Server-side session store:** an in-memory map (mutex-guarded) by default, or — when the operator configures `[storage]` — TableX's own metadata database (see below). Both sit behind one `Store` interface. Sessions have absolute + idle timeouts; expired sessions are swept and their DB pools closed.
- **Logout** destroys the session and closes all its DB pools.
- **Fixation:** rotate the session ID on successful login.

### Credential handling (critical)
- DB credentials live **only in server-side session memory**. They are **never** written to the cookie, **never** logged, and **never** persisted to disk.
- The **only** place credentials may be stored at rest is an admin-authored config file for *predefined servers* — and there they should reference environment variables/secrets rather than inline plaintext where possible. Document the trade-off; default deployments use ad-hoc login (nothing persisted).
- Logs and error pages are scrubbed of credentials and connection strings.

### Single sign-on as an extra factor (`[sso]`, optional)

An OpenID Connect provider stands **in front of** the login form. It is not a
replacement for it, and that is a deliberate design decision rather than a
limitation:

- TableX opens every database connection with the **user's own credentials**. That
  is what makes the audit trail's `account` field the truthful answer to *whose
  privileges* a statement ran under, and what lets "credentials are never
  persisted" (above) stand.
- Authenticating a **person** does not produce database credentials. So passing
  the provider gets you to the login form; you still supply your own credentials
  there. The verified subject and email are recorded **alongside** the database
  account in the audit trail, never instead of it — which is precisely what lets
  an auditor join "which person" to "which privileges".

Two alternatives were considered and rejected. Mapping SSO users onto predefined
servers gives one-click access but makes every user share one database identity,
collapsing the audit trail to "someone who passed SSO". Storing per-user
credentials encrypted in the metadata database gives both, at the cost of
reversing the guarantee above and making the encryption key the most valuable
secret in the deployment.

How the flow is secured (`internal/auth/oidc.go`, no new dependency):

- **Authorization code with PKCE (S256)** only. No implicit or hybrid flow, and no
  acceptance of an ID token that arrived through the browser.
- The ID token's **signature is not verified**, and that is sound *here and only
  here*: the token is fetched by TableX itself over a direct TLS connection to the
  provider's token endpoint, which OIDC Core §3.1.3.7 explicitly permits for a
  confidential client. Everything the signature would otherwise stand in for is
  checked explicitly — `iss` (against the configured issuer), `aud` (against the
  client id), `exp`, and a `nonce` bound to the browser's session. `state` and
  PKCE cover the redirect. The reasoning collapses for a token from any other
  source, which is why the front-channel flows are unsupported rather than merely
  unused.
- **Discovery runs once, at startup, and a failure is fatal.** A gate whose
  provider was unreachable at boot would otherwise be silently absent. The
  document's own `issuer` must equal the configured one, so a hijacked discovery
  URL cannot redirect the whole flow and then satisfy the `iss` check with its own
  claim.
- The handshake is **single-use** by atomic compare-and-consume at the `state`
  check: the callback consumes it only when the presented `state` matches, in
  one operation, so a matching handshake can never be redeemed twice. A request
  that fails *before* that check (no session, no handshake, wrong `state`)
  deliberately leaves the stored handshake intact — clearing it on any stray
  hit would let an unauthenticated GET with a garbage `state` cancel a login
  mid-flight. Every denial *after* the state check clears the session's whole
  SSO state, so a failed attempt leaves nothing reusable.
- A **half-configured provider refuses startup**, and the issuer must be `https`
  (loopback excepted, for testing).
- `allowed_emails` / `allowed_domains` narrow which verified identities may
  proceed. When either is set, an identity the provider reported **no** email for
  is refused — the operator asked for something narrower than "anyone".
- The ID token's `azp` is checked when present (an authorized party that is not
  this client means the token was minted for somebody else), and `iat` is
  rejected if it is implausibly far in the future — a small skew allowance, not
  an unbounded one.
- Exempt from the gate: its own two routes (or it could never be passed),
  `/healthz`, `/favicon.ico`, `/static/`, `/metrics` (a machine endpoint with its
  own token and allowlist), and `/logout` — someone with a session must always be
  able to end it, even if the provider has stopped answering.

One deployment note follows from where this state lives. The SSO handshake and
the verified-identity record are fields of the **in-memory** session only; they
are never part of the durable envelope the metadata database stores (its
sessions table is exactly id, CSRF token and two instants — see below). A
multi-replica deployment with `[sso]` and no sticky sessions therefore fails
**closed** at the callback: the replica that receives it finds no handshake
state to match, refuses the response, and redirects to the provider again —
never a bypass. The durable store's cross-replica promise is scoped to the
pre-auth CSRF token; completing SSO across replicas requires sticky sessions.

### The metadata database (`[storage]`, optional)

TableX can be given a database of its own, for the state the application needs to
outlive a process. It is off by default; with no `[storage]` block nothing here
applies and sessions live in process memory exactly as before.

- **What is stored:** the session *envelope* — its id, its CSRF token, and its
  created/last-seen instants. That is the whole sessions table
  (`internal/storage/migrate.go`; the only other table is a two-column `meta`
  row holding the schema version), and a test asserts against LIVE introspection
  of a migrated store that the sessions table has exactly those four columns and
  no others.
- **What is never stored:** a database credential, or anything derived from one.
  The password a user types stays in that session's in-memory payload and is
  dropped when the session ends. Encrypting it into the store was considered and
  **rejected**: the key would have to be readable by the same process, so one
  read of the database would compromise every server TableX can reach.
- **Consequence, stated plainly:** the *identity* of a session is durable and
  shared; its *connections* are not. A pre-auth session therefore works fully
  across replicas — which is the case that matters, because otherwise a login
  form rendered by one replica carries a CSRF token another has never issued and
  every login behind a round-robin balancer fails. An authenticated session
  stays bound to the process that opened its pools; another replica sees the
  row, accepts the id and the token, finds no payload, and shows the login page.
  Sticky sessions avoid the extra login; correctness does not depend on them.
- **Treat the metadata database as being as sensitive as the session cookies it
  stands in for.** It holds live session ids, so anything that can read it can
  impersonate every live session — the same property every server-side session
  store has. Give TableX its own database and its own account.
- **Credentials for it** are the second instance of the predefined-server
  exception above: operator-authored, and best supplied through
  `TABLEX_STORAGE_PASSWORD` rather than inline in the file. Its `sslmode` earns
  the same startup advisory a user's server gets.
- **Failure policy — errors degrade, answers are obeyed.** A metadata database
  that cannot be reached must not log everybody out, so a storage *error* falls
  back to that process's own view: precisely TableX's default configuration, and
  never anything weaker (an id the process never issued is still refused). A
  storage *answer* is authoritative — "no such row" means the session is over,
  which is what makes a logout on one replica take effect on all of them. While
  degraded, a logout performed elsewhere is not observed until storage returns;
  both timeouts keep applying throughout.
- **Startup is fail-fast:** a metadata database that cannot be opened or migrated
  refuses to start, rather than silently falling back to non-durable sessions
  that the operator would discover only after a restart lost them.

### The audit trail (`[audit]`, optional)

Distinct from the access log, which has always gone to stderr and answers "what
HTTP traffic did this process serve". The audit trail answers **"who changed my
database"**, and is written somewhere an auditor can keep
(`internal/audit`).

- **What is recorded:** the identity the *database* reports for the connection
  (an account name — on MySQL including the host part the server resolved, which
  is the form a grant is written against), the predefined server and engine, the
  client address, the object acted on in dotted form (`sales.orders`), the
  outcome, the status, and the duration. Every record carries the request id the
  access line carries, so the two can be joined.
- **What is never recorded:** a password, a DSN, a CSRF token, or a session id.
  Nothing in the trail can be replayed to gain access, and a test asserts that
  against the whole file rather than field by field. This holds for statement
  auditing too, in both halves: TableX-generated account DCL rides with exact
  redaction needles, and DCL the user *types* (a `CREATE USER … IDENTIFIED BY`
  in the console or an import) has the literal in every password-bearing
  position masked by grammar shape before recording — the statement stays in
  the trail, the credential does not, and the scrub errs only toward masking.
- **Three event kinds, for three different reasons.** `action` is emitted for
  every state-changing request from **one** middleware, so the trail is complete
  *by construction* — a route added tomorrow is audited the day it is added,
  whereas auditing each handler would be ~35 sites a new one silently fails to
  join. `auth` is emitted by the login and logout handlers, because a rejected
  login re-renders the form and its status code therefore describes an ordinary
  page; only the handler knows which account was tried and that it was refused —
  and by the **SSO gate**, which is a third emitter of the same kind, since
  passing or failing the provider is an authentication event with no database
  account attached to it yet. `statement` is the optional per-statement half
  (`audit.statements`), which answers "what exactly" with the SQL itself.
- Safe methods are deliberately not recorded: a GET changes nothing, and every
  page view in the trail would bury the events that matter.
- **The `action` record does not carry the posted `action` field** (the
  `drop_column`/`truncate` discriminator). It is not readable from the emitting
  middleware — the body is parsed several request copies deeper — and a field
  populated only on the no-JS path would be worse than none. `statement` records
  answer "what exactly" with the SQL itself.
- **The honest limit:** a sink that cannot be written is reported at ERROR
  (throttled, with a count) and the request still proceeds. TableX does **not**
  refuse to serve when its audit sink is unwritable, because a full disk would
  then be a total outage. Write-or-refuse semantics are not available.
- Rotation at `max_bytes` keeps **one** generation. That is a floor against
  filling a disk unattended, not a retention policy — point `audit.file` at a
  path your own rotation handles, or ship the lines, which is what JSON Lines is
  for.
- The file is created `0600`: it names accounts and client addresses, and with
  `statements` on it carries SQL that may contain row data.

---

## 3. CSRF protection

- A per-session CSRF token (synchronizer token) is embedded in every form as a hidden field. htmx sends it via an `htmx:configRequest` hook that sets the `X-CSRF-Token` header (`app.js`); a no-JS form submits it in the hidden field, read from the form body.
- All **unsafe methods** require a valid token; mismatches return 403.
- **"Safe" means GET, HEAD and OPTIONS — one definition, used by both gates.**
  The CSRF gate and restricted mode each decide what a method may do, and they
  must not disagree about which methods those are. Only GET and POST are ever
  registered, so nothing else is reachable, but a single definition is what keeps
  it that way. TRACE is **not** safe under this definition.
- The CSRF middleware runs before the auth gate. For an unauthenticated request to a protected route it short-circuits to `/login` **before** parsing the body (the auth gate would redirect it anyway), so an anonymous flood cannot make the server parse a request body at all.

---

## 4. SQL injection prevention

1. **Values are always parameterized** (`?` / `$n`) — never concatenated into SQL.
2. **Identifiers** (db/schema/table/column names) supplied by the client are:
   - validated against the objects returned by introspection (must actually exist), and
   - emitted only through `Dialect.QuoteIdent` (engine-correct quoting with proper escaping).
   We never interpolate a raw identifier from a URL/form into SQL.
3. **Generated DDL/DML** (create/alter/insert/edit) is built from validated `model` metadata, not raw strings.
4. The **SQL console** passes the user's text straight to their DB — intentional, scoped to their session connection and privileges. We do not attempt to sanitize it (that would be both futile and wrong); we simply never run it under any identity other than the user's. **SQL import** is the same bargain by a different route: a script is the user's own SQL, split into statements and run under their own credentials. So are **a stored program's body** (a `CREATE TRIGGER`/`ROUTINE`/`EVENT` wraps SQL that runs on the server; `validateProgramDDL` constrains only the outermost statement) and **a partial index's `WHERE` predicate** (item 5 below, where its guard is described — it is listed there because it also sits in a DDL position, not because it is a different bargain). All **four** are closed together by `allow_console = false` (§9); the last two are enforced in a handler rather than by the route table, for the reason §9 gives.
5. **The exceptions to rule 1 are DDL positions that accept no placeholder.**
   That is the whole rule, and it is worth stating as a shape rather than as a
   list of two, because the list is longer than two and grows with the DDL
   surface. A value in a DML statement can always be parameterized. A value that
   is part of a **type definition, an expression, or a clause of a `CREATE` /
   `ALTER`** cannot: no engine accepts a placeholder there. Everything below is
   a position of that kind, and every one of them goes through
   `Dialect.QuoteString`.
   - **`ENUM`/`SET` member lists** (`driver.ValueListTyper`). Each member is a
     user string, emitted through `Dialect.QuoteString` — the same escaping the
     dump path relies on — so a member containing a quote or a backslash cannot
     end its literal. Duplicates and (for `SET`) the 64-member ceiling are
     refused before the builder runs, and a NUL byte is refused outright because
     `QuoteString` renders one as `CONCAT(…, CHAR(0), …)`, an expression, which
     is not valid in a member list.
   - **A column's `DEFAULT` literal** (`buildDefault`). Reached from the column
     editor (add and modify) and from create-table, and emitted for all three
     engines. Every value the form can express goes through `QuoteString`: the
     control offers a literal, `NULL`, or the fixed `CURRENT_TIMESTAMP` keyword,
     and *"The form can only express literals"* (`columnform.go`) is the whole
     of it — there is no user-written expression arm. An introspected expression
     default (a sequence's `nextval(...)`, an engine's own function call) is
     REINSTALLED verbatim by `applyExprDefault` when the user did not touch the
     control, which is preservation of what the database already held rather
     than a new expression the form accepted.
   - **A column's `COMMENT`** (MySQL and PostgreSQL). Free text with nowhere to
     bind it — `COMMENT ON` and MySQL's inline `COMMENT` both take a literal.
   - **A partial index's `WHERE` predicate** (`driver.IndexSpec.Where`). This is
     genuinely the user's own SQL, not merely a string in a syntactic slot. It is
     checked, not trusted: the clause is split under the **dialect's own lexer
     grammar** and must BE the single statement that comes back — so a `;` that
     would end it is refused, while one inside a quoted span is data, exactly as
     it always was inside `'…'`. On top of that guarantee three cheaper scans are
     retained as belt-and-braces, because the splitter reports neither of the
     things they cover: no comment introducer that could hide a tail, balanced
     parentheses outside string literals, and a length cap. The property being
     established is that the clause cannot close the `CREATE INDEX` and begin
     something else.

     Stated honestly, "one statement" is what the splitter REPORTS, not a proof.
     Two constructs come back whole where a naive scan would refuse — an
     unterminated quoted span, and a `BEGIN…END` routine body under a profile
     that tracks one. Neither is exploitable, and the reason is specific: the
     predicate is appended LAST, so statement 1 is always the `CREATE INDEX`
     itself, which fails to parse or fails to prepare before anything runs.

     It grants no privilege the user lacks (same session, same credentials,
     console next door), and it is offered only on engines whose
     `IndexOptions().SupportsPartial` is true. Because it is arbitrary SQL rather
     than a quoted literal, `allow_console = false` closes it (§9) — enforced in
     `runStructureOp` rather than on the route, because the endpoint also carries
     `add_column`, `drop_index` and `add_fk`, which are ordinary DDL and must
     keep working.
   - **Account parts and passwords in DCL** — item 6 below, which is where the
     validate-first rules for them live.

   A new position of this kind needs the same treatment and the same write-up.
   None of these is an exception to *identifier* validation (rule 2): an
   identifier still has to exist in introspection and still goes through
   `QuoteIdent`.
6. **Account & privilege DCL** (create/drop user, set password, GRANT/REVOKE) follows the same validate-first rule with account-shaped validators: account names pass engine-specific checks (the `ValidNewIdentifier` character policy with MySQL/MariaDB vs PostgreSQL length caps), MySQL hosts pass a host-pattern check, drop/alter targets and grantees must match a freshly introspected account (or PostgreSQL's `PUBLIC` pseudo-role), grant keywords must be in the dialect's curated allowlist, and revoke keywords must be present in a fresh re-introspection of the displayed grants plus pass a strict keyword-shape gate. MySQL account parts are emitted via `QuoteString`, PostgreSQL roles via `QuoteIdent` (`PUBLIC` as the bare keyword). Passwords are emitted only inside the builders via `QuoteString` and never logged, flashed or rendered; a failed password-carrying statement reports a fixed generic message (engine errors can echo the statement) and the log line is redacted with both the raw and the quoted password.

---

## 5. XSS prevention

- All templates use Go `html/template`, which applies **context-aware auto-escaping** (HTML, attribute, JS, URL contexts). DB content rendered into pages is escaped by default.
- Any use of `template.HTML`/raw output is rare, explicit, constructed only from trusted/escaped fragments, and flagged for review.
- **Content-Security-Policy** restricts script/style/img/connect sources to `self` (assets are embedded/local — no CDNs), blocking injected inline scripts. `script-src 'self'` with **no `unsafe-inline` and no `unsafe-eval`**.
  - This is only achievable because we deliberately picked CSP-safe front-end builds: the **`@alpinejs/csp` build of Alpine** (the standard build uses `new Function()` and would force `unsafe-eval`), htmx without its `js:`/`hx-on:` eval features, and CodeMirror (no eval). Bootstrap is vendored **CSS-only** — no Bootstrap JS, no Popper. See [`tech-stack.md`](./tech-stack.md) → *CSP compatibility*.
  - **`style-src`:** `'unsafe-inline'` is allowed for styles because two features write inline `style` attributes: Alpine's `x-show` toggles inline `display:none` (login form's ad-hoc fields, export form options), and the server renders the persisted sidebar width as a `--tx-nav-width` inline style on `<html>`. Styles can't execute script, so the XSS risk is far lower than for scripts; per-response nonces remain the tightening path if those inline writes are ever removed.

---

## 6. HTTP security headers

Applied by middleware to every response:

| Header | Value |
|---|---|
| `Content-Security-Policy` | `default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'` (no `unsafe-eval`/`unsafe-inline` for scripts — see §5; `style-src` allows inline styles for Alpine `x-show` toggles and the server-rendered `--tx-nav-width` style) |
| `X-Content-Type-Options` | `nosniff` |
| `Referrer-Policy` | `no-referrer` |
| `Cross-Origin-Opener-Policy` | `same-origin` |
| `Cross-Origin-Resource-Policy` | `same-origin` |
| `Permissions-Policy` | `camera=(), microphone=(), geolocation=(), interest-cohort=()` (disable unused browser features) |
| `Strict-Transport-Security` | `max-age=63072000; includeSubDomains` when serving TLS (add `preload` only after deliberate review) |
| `Cache-Control` | `no-store` on every response except `/static/` — not only authenticated pages. A page is not the only thing worth keeping out of a shared cache, and deciding per response which ones are would be one more thing to get wrong |

`frame-ancestors 'none'` (plus legacy `X-Frame-Options: DENY`) prevents clickjacking.

---

## 7. Transport security

- **Browser ↔ TableX:** support direct TLS (`--tls-cert`/`--tls-key`) and running behind a TLS-terminating reverse proxy (set `secure_cookies = true` / `TABLEX_SECURE_COOKIES=1` so `Secure`/`__Host-` cookies and HSTS are still emitted when TableX itself speaks plain HTTP to the proxy). `Secure` cookies + HSTS whenever the secure posture is active. **Minimum TLS 1.2** (`crypto/tls` `MinVersion: tls.VersionTLS12`). No cipher suite policy is configured: Go's `crypto/tls` defaults apply, which is the deliberate choice — the standard library's list tracks the current consensus and a hand-pinned one would drift. Do not read "modern cipher suites only" into this; the minimum version is the only thing TableX sets.
- **TableX ↔ database:** connections to remote databases can be encrypted and certificate-verified, not just encrypted-but-unauthenticated. Both network engines are configured through **one** option, `sslmode` — the MySQL dialect maps PostgreSQL's vocabulary onto go-sql-driver's `tls` setting, and a literal `tls` param is a hard error rather than a second spelling. **PostgreSQL's default `sslmode` is `prefer`, which silently falls back to plaintext if the server declines TLS**; for untrusted networks set `verify-full`. Predefined servers pin it in config. The login form exposes the selector for engines whose `ShowsSSLModeUI` is set — both network engines — so an **ad-hoc** login can choose its transport on either. The vocabulary is shared and the behaviour is not, which is why each engine ships an `SSLModeNote` rendered beside the selector (server-side, so it is there without JavaScript): on MySQL/MariaDB the twelve accepted tokens collapse to four behaviours, `prefer`/`allow` are opportunistic **and unverified**, and `require` maps to `skip-verify` — it encrypts without authenticating the server. On both engines only `verify-ca`/`verify-full` authenticate. A file-backed engine has no transport and the posted value is discarded.

---

## 8. Brute-force & abuse controls

- **Login rate limiting / throttling** over a sliding window (`login_rate_window` / `login_rate_max`) on **three** keys: the bare client IP, `(IP, username)`, and `(IP, predefined-server)` — the last closes a bypass where a predefined server resolves its username from config, so blanking or rotating the posted username would otherwise dodge the `(IP, username)` counter. The reservation is **two-stage**: the coarse bare-IP key is reserved in the CSRF middleware **before the body is parsed** (so a flood cannot even make the server parse `/login` bodies), and the identity keys are reserved atomically inside the `Login` handler. Each stage reserves its keys atomically as a group, so a concurrent burst cannot slip a key past its window. A CSRF-invalid or otherwise-failed `/login` attempt still consumes the coarse IP budget. **That is deliberate and it has a cost worth stating: any third-party page can spend it.** The reservation is taken before the CSRF check, so a cross-site `POST /login` — which cannot succeed, and cannot read the response — still burns a slot against the victim's address. A page a user is merely visiting can therefore throttle that address out of logging in for the rest of the window, and behind a NAT or a corporate egress that is everyone sharing it. The alternative is worse: reserving *after* the CSRF check would mean parsing the body of every unauthenticated `/login` POST before deciding whether to throttle it, which is precisely the flood the pre-parse stage exists to shed. The mitigation is not to move the reservation but to size `login_rate_max` for the address population behind it, and to prefer `trusted_proxy_cidrs` so the key is the real client rather than a shared egress. A successful login releases only the identity keys (`Reset`); the bare-IP hit is deliberately retained so a single valid credential on a shared IP cannot wipe the IP-wide brute-force counter. A pre-parse coarse-IP rejection returns a fresh login form (no posted sticky values, since the body was never parsed). Error messages stay generic and don't reveal whether a username exists.
- **Global per-account lockout** (`login_account_max`, default **50** per
  `login_rate_window`). Every key above starts with the client IP, so the throttle
  they give is *per source*: an attacker holding an IPv6 /64, or a botnet, gets
  `login_rate_max` attempts **each** against the same account. This is the one key
  that is not keyed on the attacker's choice of address — the account name alone
  (or, for a predefined server whose username comes from config, the server name,
  so blanking the posted username cannot dodge it). It is deliberately more
  permissive than `login_rate_max` because the key is **shared**: several people
  behind different addresses may be typing the same account name, and one of them
  mistyping must not lock out the rest. A successful login clears it. `0` disables
  it, with a startup warning saying what was given up. It rides the same limiter
  implementation on a second instance, because the two need different thresholds.
- **The two SSO routes are throttled on their own keys** (`sso:start|<ip>` and
  `sso:cb|<ip>`), namespaced because the limiter's keyspace is flat and `/login`
  reserves the bare IP — sharing it would let a start loop exhaust an address's
  password-login capacity. They inherit `login_rate_window`/`login_rate_max`
  (so `max <= 0` disables them with it) and are never `Reset`, since resetting
  on success would permit unlimited *successful* exchanges. `/auth/sso/start`
  charges only a request that **mints** a session, which is the unbounded
  resource an anonymous loop consumes; a request arriving with a live session
  is exempt, because its handshake overwrites that session's own slot in place
  and the route never contacts the provider (the token exchange is the
  callback's, budgeted separately). That exemption is load-bearing rather than
  a courtesy: the SSO gate redirects *every* unverified request to this route,
  so charging each arrival would spend the budget on ordinary page loads and
  lock an entire shared-egress office out of the sign-in entry point. The test
  is whether the request's cookie resolves to a live session — **not** whether
  a cookie is present, which a forged header would satisfy while still minting
  a session per request.
- **Request body caps.** Every unsafe-method body is bounded by a `MaxBytesReader`. Unauthenticated requests get a tight **1 MiB pre-auth cap** (the CSRF middleware parses the body for the token before the auth gate runs, so this bounds what an anonymous client can buffer); authenticated requests get the **64 MiB** global cap, and the import route its **32 MiB** cap. An over-cap body surfaces as a 413 (or, on the no-JS body-token path, a 403 when the token cannot be read).
- **Decompression bomb guard.** An import may be gzip-compressed (detected from the file's own magic bytes, not its name), so the upload cap alone no longer bounds the work: gzip's ratio is unbounded in principle, and the importer holds the whole script in memory. The decompressed stream is therefore capped separately at **128 MiB** (`MaxImportExpandedBytes`, 4× the upload cap so compression is still worth using) and the overflow is detected by **reading one byte past the cap** — never by trusting the gzip trailer's `ISIZE`, which the uploader writes and which records the size only modulo 2³².
- **Client IP behind proxies:** `X-Forwarded-For` is honored only when the request arrives from an address in `trusted_proxy_cidrs`, and is parsed right-to-left skipping trusted hops — the rightmost untrusted address is the client. A client-supplied header is never trusted (a bare `trusted_proxy = true` without CIDRs is ignored with a startup warning), so rate-limit keys and access-log identities cannot be spoofed.
- **Arbitrary-server (SSRF) control:** ad-hoc host login is enabled by default for zero-config local use (`allow_adhoc`, set it to `false` to require predefined servers). Classification is an explicit `netip.Prefix` table (`internal/auth/host.go`), applied to the canonicalized address **and to any IPv4 it embeds** — IPv4-mapped (`::ffff:a.b.c.d`), IPv4-compatible (`::a.b.c.d`) and well-known NAT64 (`64:ff9b::/96`) all resolve to the same rules, and an IPv6 zone (`fe80::1%eth0`) is stripped rather than silently failing to parse.
  - **Always refused**, whatever else is configured: `0.0.0.0/8`, `169.254.0.0/16` (incl. the `169.254.169.254` cloud-metadata endpoint), `100.100.100.200/32` (Alibaba metadata, inside CGNAT), `192.0.0.0/24`, `198.18.0.0/15`, `224.0.0.0/4`, `255.255.255.255/32`, `::/128`, `fe80::/10`, `fec0::/10`, `ff00::/8`.
  - **Refused only under `block_private`** (off by default so local DB admin works out of the box): `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `100.64.0.0/10`, `::1/128`, `fc00::/7`.
  - An allowlist/denylist further constrains targets by name. The SSRF policy is also re-checked **at dial time** (the resolved peer IP per connection) so a DNS-rebinding answer cannot slip past the pre-flight resolution.
- **SQLite trust model:** SQLite has no credentials, so an ad-hoc SQLite login would be *unauthenticated* and could open — historically even create — arbitrary files on the host. TableX therefore **disables ad-hoc SQLite entirely**: SQLite is reachable only through an operator-defined predefined server, whose database file is fixed in config (`file = "…"`). A logged-in user can never name or change that path (the posted `file` field is ignored for predefined SQLite), and a missing file is reported rather than silently created. Predefined SQLite servers require a non-empty `file` at startup.
- **Per-session query budget** (`session_query_budget` / `session_query_window`,
  off by default). `max_concurrent_db_ops` bounds how much work runs at once;
  this bounds how much **one session** may ask for over time, which is the
  dimension a single authenticated user can otherwise saturate alone. It charges
  the SQL a user *wrote* — the console, `EXPLAIN`, and a SQL import — and
  deliberately **not** the queries TableX generates for them: one page render
  costs several introspection reads, so charging those would spend a browsing
  user's budget on navigation, and they are already bounded by
  `read_stmt_timeout` and the pool caps. Over the budget a statement is refused
  through the same per-statement channel a SQL error uses, so a script is
  **truncated at the budget** rather than silently part-run, and the refusal
  names the setting and quotes a real wait. The window is fixed rather than
  sliding: a sliding one would need the timestamp of every charged statement,
  which is a per-session unbounded allocation to enforce a limit whose purpose is
  to bound resource use, so the accepted cost is that a session may spend two
  budgets' worth across a window boundary.
- **Capacity refusals are recorded as refusals.** When `max_concurrent_db_ops` is
  reached the request gets a 503 + `Retry-After`; the audit trail records it as
  `denied`, not `error`, because the server declining work is not the work
  failing — filed as an error it would send an auditor hunting a fault that does
  not exist.
- *(Not implemented)* A CAPTCHA hook on login. Listed here as a known absence
  rather than a plan: nothing in the code provides it today.

---

## 9. Operational hardening

- **Panics never crash the process** (recover middleware → 500, logged with request id, no stack to client).
- **Restricted mode (`[restrict]`, optional)** narrows what a logged-in user may do
  *below* what their grants allow. It is **defence in depth, not a boundary**: the
  database's own privileges remain the real control, and an operator who needs a
  user not to drop a table should also not grant them DROP. What it buys is the
  case grants cannot express — an operator who must use a privileged account and
  wants TableX itself to refuse the dangerous half.
  - `read_only` refuses every state-changing request, **the SQL console and SQL
    import included**. TableX will not try to decide whether somebody's SQL
    writes; a statement classifier is the wrong thing to stake a read-only
    guarantee on. Reads, browsing and exports are unaffected.
  - `allow_console = false` removes arbitrary SQL while leaving the generated
    operations working. It closes **four** paths, not one — every place a user's
    own SQL reaches the server, whose reach TableX cannot describe:
    - the **SQL console**;
    - **SQL import**, which is a script of the same statements by another route;
    - the **stored-program editor** (`CREATE TRIGGER` / `PROCEDURE` / `FUNCTION`
      / `EVENT`). The editor validates that the outermost statement is a single
      `CREATE` of the page's kind; the **body it wraps is unconstrained** and
      runs on the server. Dropping a stored program is ordinary DDL and stays
      under `allow_ddl` — the two share one endpoint, which is why the save half
      is checked in the handler rather than on the route (see below);
    - a **partial index's `WHERE` predicate** (§4 item 5), which is an expression
      the user wrote.

    Everything else generated — the structure editor, table and database
    operations, search, QBE, create-table, foreign-key actions, DCL — is built
    from validated metadata and is unaffected. That negative was established by
    sweeping every sink, and is recorded so the question is settled rather than
    re-opened.
  - `allow_ddl = false` refuses schema and access-control changes but **not row
    edits**: "fix the data, do not reshape it" is the common ask, and that
    distinction is the reason it is a separate setting from `read_only`.
  - `database_allowlist` refuses every route naming a database outside it, and
    narrows every listing that offers one: the sidebar tree, the home page, the
    Databases page, the **process list** — and the **contents of a server-scope
    dump**, whose route names no database at all and which would otherwise hand
    over in one file exactly what the rest of the UI declines to show. The two
    routes that carry a database somewhere other than the path — the sidebar's
    own `/nav/children` fragment, which carries it as a query parameter, and
    create-database, which takes it from the body — check it in the handler, for
    the same reason.

    The process list is in that set deliberately, and it costs more than the
    others. A row TableX cannot attribute to an allowlisted database is hidden,
    which covers PostgreSQL background workers and — on MySQL/MariaDB — every
    connection that has not issued a `USE`, plus the replication and
    event-scheduler threads: under an allowlist those become invisible, and
    therefore **unkillable**, through TableX. The **query text is blanked on
    every remaining row** as well, because the `datname`/`db` column names a
    connection's *default* database and says nothing about what its statement
    references — an allowlisted connection reading `otherdb.customers` would
    otherwise print that table's name in full. Diagnostic value traded for
    confinement, which is the trade the allowlist is for. Two consequences of
    filtering outside the query rather than inside it: the 1,000-row read cap is
    applied first, so the visible count can sit well below it while the
    "truncated" banner still fires, and the same narrowing applies to the kill
    path — a session that is not listed cannot be terminated.

    Foreign keys get the same treatment for the same reason: on MySQL/MariaDB a
    key's referenced schema *is* a database, so a key pointing outside the
    allowlist is masked whole — database, table and columns — on the structure
    page and in the designer. Masking only the qualifier would still print the
    referenced table and column names. On PostgreSQL the field is an ordinary
    schema and nothing is masked.

    Two limits, both deliberate. While the console is enabled a user can still
    name any database their credentials reach *in a statement*, and TableX does
    not parse SQL to stop them; startup warns about that combination. And the
    allowlist scopes **post-auth navigation** — it does not constrain which
    database an **ad-hoc** login connects to in the first place. A predefined
    server takes its database from config and ignores the posted field, so
    pairing the allowlist with predefined servers closes that one. With
    `allow_console = false` it is a real confinement. On its own it is more than
    navigation scoping — it also withholds the metadata the narrowed listings
    above would otherwise disclose — but it is still not a confinement, because
    the console reaches whatever the credentials do.
  - Enforcement is a middleware keyed on the route, inside the auth gate, and
    **never** in the templates — every restriction holds against a request typed
    by hand. Each route declares what it needs where it is registered, and the
    policy **fails closed**: a state-changing request that resolves to no entry
    is treated as needing DDL permission, so a route added without one is refused
    under `allow_ddl = false` until somebody declares its needs deliberately.
    - **Two exceptions, and both are in a handler on purpose.** Each is a route
      whose console-class work shares an endpoint with something that must keep
      working, so the route's need is the DDL one and the handler takes the
      console check where the request is finally specific enough to judge.
      Saving a stored program and dropping one share a single POST endpoint,
      told apart by a form field the route cannot see, so `saveProgram` checks
      it. A partial index's `WHERE` predicate is one optional field of one
      structure action on an endpoint that also carries `add_column`,
      `drop_index` and `add_fk`, so `runStructureOp` checks it — and refuses only
      the predicate, never index creation itself. Both refuse through the same
      path the middleware does — same 403, same `denied` audit outcome, same
      metric — so which layer said no is not visible from outside.
    - A refusal names the setting responsible and is recorded in the audit trail
      as `denied`. Its **status depends on the caller, not the method**: a
      full-page request gets a real 403, while an **htmx** request gets wire
      **200** with `HX-Retarget: #page_content` and the refusal rendered in the
      panel — htmx discards the body of a non-2xx response, so a 403 there would
      leave the page silently unchanged. A hand-typed GET is a 403; an htmx POST
      is a 200 carrying a refusal.
  - **The UI reflects the policy, and is not the policy.** A restricted TableX
    does not offer what it would refuse: the tab set drops the SQL, Import,
    Insert and schema tabs it cannot serve; the Browse grid drops its row
    actions; the structure editor, the grant forms, the account forms, the
    create-database control and the process list's kill button all disappear,
    while the *listings* beside them stay, because reading a schema or seeing who
    is connected is not a change. A standing note on every page states what is
    withheld, so a user reads the policy instead of inferring it from missing
    buttons — a UI that quietly drops half its features looks broken.
    - Derived in ONE place from the same config the middleware enforces
      (`Handlers.allowance`), so the two cannot disagree about what is
      permitted. The tab filter sits at the single exit every tab set already
      passed through, and each page's existing capability flag is narrowed
      rather than each button being gated separately — a per-affordance check
      would be one chance per affordance to forget.
    - Two independent test suites keep the halves honest: one posts directly to
      every restricted route (the enforcement), the other reads the rendered
      page (the reflection). Three of the reflection assertions have to run
      against MySQL or PostgreSQL, because the affordances they check — CREATE
      DATABASE, the process list, more than one database — do not exist on
      SQLite, where they passed whether the policy worked or not.
- **Metrics (`[metrics]`, optional, off by default)** expose `GET /metrics` in
  the Prometheus text format. There is no client library and no new dependency:
  the format is a few lines of text per series over a handful of atomics.
  - The endpoint is **access-controlled, not public**. The numbers describe
    TableX's internals — how many sessions exist, how much work is in flight,
    whether the audit trail is failing to write — and none of that belongs to an
    anonymous caller. `metrics.token` is required as `Authorization: Bearer …`
    and compared in **constant time**; `metrics.allow_cidrs` restricts scraping
    by address, resolved with the same trusted-proxy rules as everything else so
    it is not a header away from meaningless. When both are set **both** must
    pass.
  - **Enabling it with neither refuses startup.** The mistake is otherwise
    silent — a scrape succeeds either way — and there is no defensible default:
    "loopback only" would break a Prometheus on another host, "anyone" would
    publish the internals of a database admin tool.
  - A token is **not** accepted in the query string: it would be written to
    TableX's own access log, and usually the proxy's, on every scrape. Over plain
    HTTP the header token still crosses the wire in cleartext, which startup
    warns about.
  - The path is fixed at `/metrics`. A movable path is obscurity, not a control.
  - **Cardinality is bounded by construction.** Requests are labelled by method
    and status *class* only; nothing is labelled by path, database or account, so
    a user browsing tables cannot grow the series count. An unrecognised method
    or an impossible status falls into an `other`/`5xx` catch-all rather than
    minting a label.
  - `/metrics` takes **no session and sets no cookie** (a scraper would otherwise
    add a session per interval, forever), and its own scrape is excluded from the
    request counters and the latency histogram so an idle instance measures
    TableX rather than the act of measuring it.
  - `/healthz` deliberately stays a bare `ok`: a container probe must never need
    a credential, so nothing about the metadata database, session count or audit
    health is answered there. **`/metrics` is where that belongs**, behind the
    controls above — which is also why the metadata-database probe
    (`tablex_storage_up`) lives only here.
  - Series for a subsystem that is not configured are **omitted, not zero**: a
    flat zero on a dashboard is how an operator comes to believe a trail is being
    written when none is. The signals worth alarming on are
    `tablex_audit_write_failures_total` (the trail is *losing* records),
    `tablex_storage_degraded_total` (sessions are not currently durable),
    `tablex_db_ops_refused_total` / `tablex_import_ops_refused_total` /
    `tablex_query_budget_refused_total` (work is being turned away),
    `tablex_storage_session_cap_refusals_total` /
    `tablex_storage_session_marker_refusals_total` (sessions are being admitted
    without a durable row), `tablex_restricted_refused_total`, and
    `tablex_logins_total{result="denied"}`.
- **Least privilege:** docs recommend connecting with a DB account scoped to the task; TableX itself needs no special OS privileges.
- **Minimal, pure-Go dependencies** (see [`tech-stack.md`](./tech-stack.md)) shrink the supply-chain surface; pin versions and review transitive deps.
- **No telemetry, and no external calls** at runtime — **except the configured
  OIDC provider when `[sso]` is enabled**, which TableX reaches at startup for
  discovery and on every login for the token exchange. That is the only outbound
  connection to a third party in the process; the sole other `http.Client` in the
  tree is `--healthcheck`, which probes TableX's own listen address for the
  container HEALTHCHECK. Assets are embedded, so nothing is fetched to render a
  page.
- Graceful shutdown closes all pools so credentials don't linger.
- **Account & privilege administration runs under the operator's own DB credentials.** TableX builds the DCL but the engine enforces authority — a login without CREATE USER / GRANT OPTION rights simply gets the engine's refusal; TableX adds no escalation path. Operator notes: (a) **PostgreSQL writes `CREATE ROLE … PASSWORD '…'` to its own server log in cleartext** when `log_statement` covers DDL — TableX's client-side redaction cannot prevent server-side capture (MySQL masks these statements in its general log by default); (b) MySQL host wildcards (`%`/`_`) are **deprecated as of MySQL 8.0.35** (still functional; MariaDB unaffected) — the create-user form's blank-host default of `%` is the engine's conventional any-host wildcard, but consider explicit hosts on new deployments; (c) PostgreSQL `DROP ROLE` fails with a dependency error while the role still owns objects — reassign or drop owned objects via the SQL console first (`REASSIGN OWNED`/`DROP OWNED` are out of scope for v1).
- **CSV export & "formula injection":** exported CSV cells are written verbatim. A cell whose value begins with `=`, `+`, `-`, `@`, or a tab/CR can be evaluated as a formula by a spreadsheet application when the file is opened. TableX deliberately does **not** rewrite such values: the only safe neutralization mutates the data (prefixing a quote/tab), which would make the export unfaithful and break TableX's own CSV re-import round-trip. The exposure is in the spreadsheet that opens an untrusted file, not in TableX. Operators handling untrusted data should import CSVs as text or disable automatic formula evaluation.

---

## 10. Security review checklist (per feature/PR)

- [ ] No string-concatenated SQL values; identifiers go through `QuoteIdent` + existence check.
- [ ] State-changing route is POST and CSRF-protected.
- [ ] No credential or full DSN in logs/errors/responses. (PostgreSQL SQL
      exports apply this to foreign-data options: every option is redacted
      unless allowlisted for a PROVENANCE-recognized `postgres_fdw`/`file_fdw`
      wrapper — extension membership + extension-owned handler, never the
      name — with user-mapping options always redacted and a DSN-shaped
      `dbname` value-level redacted; see docs/database-drivers.md §8.)
- [ ] Output rendered via `html/template`; any raw HTML justified.
- [ ] New route correctly behind the auth gate.
- [ ] Cookies keep `HttpOnly`/`SameSite`/`Secure` semantics.
- [ ] Destructive actions re-check authorization server-side (existence via
      introspection, plus the writable/data-table guards) and prompt for
      confirmation.
      Confirmation is enforced **server-side** by `handlers.requireConfirm`
      (`internal/server/handlers/confirm.go`): a destructive POST that does not
      carry the `tx_confirm` field is answered with an interstitial page that
      re-posts the original fields, so the action works safely with JavaScript
      disabled. With JavaScript, `app.js` adds the field once htmx's
      `hx-confirm` dialog has been accepted, keeping that path to one round trip
      and one prompt.
      Call `requireConfirm` **last**, immediately before the mutation: every
      existence and authority check runs first, so a request that would be
      refused stays refused instead of becoming a prompt.
      Scope, stated plainly: this is an **accidental-click guard, not an
      authorization control**. The field is not a secret and is not checked
      against anything. Authorization is the CSRF token plus each handler's own
      re-checks (the object must exist in fresh introspection, the account must
      be permitted). Do not cite it as a defence against a hostile request.
