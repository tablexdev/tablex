# Security policy

## Reporting a vulnerability

Email **info@tablex.dev**. Please do not open a public issue for something
exploitable.

Include whatever you have: the version (`tablex -version`), the engine and
version behind it, a request or configuration that triggers it, and what you
believe an attacker gains. A proof of concept is welcome but not required — a
clear description of the flaw is more useful than a working exploit.

You will get an acknowledgement within **3 working days**. If a report turns out
to be valid, the fix ships in the next release and the advisory credits you
unless you ask otherwise.

## What is in scope

TableX is a database administration tool: it is *designed* to run whatever SQL
the logged-in user is entitled to run. That makes the boundary worth stating
precisely.

**In scope** — anything that lets a request do more than the credentials it
arrived with should allow:

- Executing SQL as a user who did not supply that user's credentials.
- SQL injection outside the documented exceptions in
  [`docs/security.md`](./docs/security.md) §4. Two shapes: the user's OWN SQL
  run under their own credentials (the SQL console, SQL import,
  a stored program's body, and a partial index's WHERE predicate — which also
  sits in a DDL position, but is listed here because that is the bargain), and
  the DDL positions that accept no placeholder (ENUM/SET member lists, a
  column's DEFAULT literal and COMMENT, account parts and passwords in DCL).
  Each runs under the user's own credentials and is documented as such; §4 is
  the authoritative list.
- Session fixation, session theft, or CSRF on any state-changing route.
- XSS, or any bypass of the `script-src 'self'` CSP.
- SSRF: reaching a host the connection guard is meant to refuse.
- Reading or writing outside the configured databases — including the metadata
  database and the audit trail.
- Bypassing `[restrict]` (read-only, `allow_console`, `allow_ddl`,
  `database_allowlist`) through any route, not merely through a hidden button.
- Credential disclosure: a password in a log, a flash message, an export, an
  error page, or the audit trail.
- Denial of service that is disproportionate — one request exhausting the process
  rather than one connection.

**Not in scope**, because it is the tool working as designed:

- A privileged database user doing privileged things (dropping a database,
  reading any table, running `DELETE`). Authorization is the database's job;
  TableX runs statements under the user's own credentials and does not grant
  anything.
- Reaching a database an operator deliberately made reachable.
- Anything requiring an already-compromised `tablex.toml` — it holds predefined
  server credentials by design, and protecting it is the operator's job (see
  [`docs/security.md`](./docs/security.md) §2).
- Missing hardening that the docs already name as absent. If the docs claim a
  control that does not exist, **that** is in scope, and worth reporting.

## Supported versions

Only the latest release. TableX is a single binary with no plugin surface, so
upgrading is replacing one file.

## Verifying a download

Release artifacts are checksummed and the checksum file is signed keylessly with
[cosign](https://docs.sigstore.dev/) — the signature is bound to the release
workflow's identity, not to a private key someone has to keep:

```bash
sha256sum -c SHA256SUMS --ignore-missing

cosign verify-blob \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp 'https://github.com/tablexdev/tablex/.github/workflows/release.yml@.*' \
  --signature SHA256SUMS.sig --certificate SHA256SUMS.pem \
  SHA256SUMS
```

Each release also carries a GitHub build-provenance attestation over the same
checksum file — an independent second proof, verified with the GitHub CLI:

```bash
gh attestation verify SHA256SUMS --repo tablexdev/tablex \
  --signer-workflow tablexdev/tablex/.github/workflows/release.yml
```

Container images are signed the same way:

```bash
cosign verify \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp 'https://github.com/tablexdev/tablex/.github/workflows/release.yml@.*' \
  ghcr.io/tablexdev/tablex:<tag>
```

And each release carries an SPDX SBOM, itself listed in `SHA256SUMS`.

## Recovering a release the post-publication check flagged

`release.yml` dispatches `install-verify` against the real public install paths
after publishing, watches it, and — on an *allowlisted*, deterministic failure of
a *stable* release — demotes it from `latest` (`--prerelease`) and appends a
delimited warning to the release notes. It never deletes the release or the GHCR
image (both may already be fetched), and it never files an issue. Recovery is
manual and branches on what the version already was — the version string is the
discriminator, a hyphen meaning it was always a prerelease:

- **Originally a prerelease** (e.g. `v1.2.3-rc.1`): demotion was a no-op, so
  recovery is *only* removing the marked warning block from the notes. Never pass
  `--latest` — that would promote a release candidate.
- **Originally stable, then demoted** (e.g. `v1.2.3`): remove the warning block,
  then `gh release edit "$VERSION" --prerelease=false`. Add `--latest` **only** if
  no newer stable release exists (`gh release list`); otherwise leave it a full,
  non-latest release.

Do this only after re-running `install-verify` (its `workflow_dispatch` accepts a
`version`) and confirming the failure was transient (a host outage, a Docker Hub
rate-limit) rather than a real regression.
