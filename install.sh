#!/bin/sh
# TableX installer for Linux and macOS.
#
#   curl -fsSL https://tablex.dev/install.sh | sh
#
# Environment overrides:
#   TABLEX_VERSION        version to install, with or without the leading v
#                         (default: the latest GitHub release)
#   TABLEX_INSTALL_DIR    where the binary goes (default: /usr/local/bin when
#                         run as root, otherwise ~/.local/bin)
#   TABLEX_NO_MODIFY_PATH set to anything to stop the script from touching
#                         your shell profile
#   TABLEX_BASE_URL       alternate artifact directory (CI/testing). Requires
#                         TABLEX_VERSION; skips the GitHub attestation check,
#                         which only applies to GitHub-released artifacts.
#
# What it does: detect OS/arch, download the release archive and SHA256SUMS,
# verify the checksum (and, when the GitHub CLI is available and logged in,
# the build-provenance attestation), install atomically, offer to add the
# install dir to PATH, and prove the installed binary runs.
#
# The whole script is wrapped in main() and main runs on the LAST line, so a
# truncated download executes nothing.

set -eu

REPO="tablexdev/tablex"

say() { printf 'tablex install: %s\n' "$1" >&2; }
err() { printf 'tablex install: error: %s\n' "$1" >&2; exit 1; }

fetch() {
  # $1 = url, $2 = output file. TLS floors only make sense for https URLs;
  # TABLEX_BASE_URL may legitimately be plain http on localhost in CI.
  if command -v curl >/dev/null 2>&1; then
    case "$1" in
      https://*) curl -fsSL --proto '=https' --tlsv1.2 --retry 3 -o "$2" "$1" ;;
      *)         curl -fsSL --retry 3 -o "$2" "$1" ;;
    esac
  elif command -v wget >/dev/null 2>&1; then
    wget -q --tries=3 -O "$2" "$1"
  else
    err "neither curl nor wget found; install one and re-run"
  fi
}

resolve_latest() {
  # The /releases/latest REDIRECT carries the tag and is not rate-limited the
  # way the API is. wget cannot surface the effective URL portably, so it
  # falls back to the API.
  if command -v curl >/dev/null 2>&1; then
    resolve_latest_url=$(curl -fsSLI --proto '=https' --tlsv1.2 -o /dev/null \
      -w '%{url_effective}' "https://github.com/${REPO}/releases/latest") \
      || err "could not reach github.com to resolve the latest release"
    resolve_latest_tag=${resolve_latest_url##*/}
  else
    resolve_latest_tag=$(wget -qO- "https://api.github.com/repos/${REPO}/releases/latest" \
      | sed -n 's/.*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)
  fi
  case "$resolve_latest_tag" in
    v[0-9]*) printf '%s\n' "$resolve_latest_tag" ;;
    *) err "could not determine the latest release (got '${resolve_latest_tag}'); pass TABLEX_VERSION=vX.Y.Z" ;;
  esac
}

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  elif command -v openssl >/dev/null 2>&1; then
    openssl dgst -sha256 "$1" | awk '{print $NF}'
  else
    err "no SHA-256 tool found (need sha256sum, shasum or openssl)"
  fi
}

verify_attestation() {
  # $1 = path to SHA256SUMS. Second, independent proof beyond the checksum:
  # GitHub's build-provenance attestation, pinned to the exact producing
  # workflow so an attestation from a different workflow (or a fork) cannot
  # satisfy it. Only applies to GitHub-released artifacts, and gh only talks
  # to the API when logged in - both conditions degrade to a loud skip, but a
  # FAILED verification is fatal.
  if [ -n "${TABLEX_BASE_URL:-}" ]; then
    return 0
  fi
  if ! command -v gh >/dev/null 2>&1; then
    say "provenance: GitHub CLI not installed; skipping attestation verify (checksum already verified)"
    return 0
  fi
  if ! gh auth status >/dev/null 2>&1; then
    say "provenance: GitHub CLI not logged in; skipping attestation verify (checksum already verified)"
    return 0
  fi
  say "verifying build provenance attestation..."
  if gh attestation verify "$1" --repo "$REPO" \
    --signer-workflow "${REPO}/.github/workflows/release.yml" >/dev/null; then
    say "attestation OK (built by ${REPO}'s release workflow)"
  else
    err "attestation verification failed for SHA256SUMS; refusing to install"
  fi
}

add_block_once() {
  # $1 = profile file, $2 = line to add inside the markers. Idempotent: the
  # marker is the contract, so a second install never appends a second block.
  if [ -f "$1" ] && grep -q '>>> tablex >>>' "$1"; then
    return 0
  fi
  {
    printf '\n# >>> tablex >>>\n'
    printf '%s\n' "$2"
    printf '# <<< tablex <<<\n'
  } >>"$1"
  say "added the install dir to PATH via $1 (new shells pick it up)"
}

maybe_add_path() {
  # $1 = install dir. Exact-entry match: a substring test would false-match a
  # directory that merely contains this one as a prefix.
  case ":${PATH}:" in
    *":$1:"*) return 0 ;;
  esac
  say "note: $1 is not in your PATH; for this session run:"
  say "  export PATH=\"$1:\$PATH\""
  if [ -n "${TABLEX_NO_MODIFY_PATH:-}" ]; then
    return 0
  fi
  case "$(basename "${SHELL:-}")" in
    bash) add_block_once "${HOME}/.bashrc" "export PATH=\"$1:\$PATH\"" ;;
    zsh)  add_block_once "${HOME}/.zshrc" "export PATH=\"$1:\$PATH\"" ;;
    fish)
      mkdir -p "${HOME}/.config/fish/conf.d"
      add_block_once "${HOME}/.config/fish/conf.d/tablex.fish" \
        "contains -- \"$1\" \$PATH; or set -gx PATH \"$1\" \$PATH"
      ;;
    *) say "unrecognized shell; add $1 to your PATH in your shell profile" ;;
  esac
}

main() {
  case "$(uname -s)" in
    Linux)  os=linux ;;
    Darwin) os=darwin ;;
    MINGW* | MSYS* | CYGWIN*)
      err "this is a Windows environment; use the PowerShell installer instead:
  powershell -ExecutionPolicy Bypass -c \"irm https://tablex.dev/install.ps1 | iex\"
if tablex.dev is unreachable, the same script is served from the repository:
  https://raw.githubusercontent.com/tablexdev/tablex/master/install.ps1" ;;
    *) err "unsupported OS: $(uname -s) (supported: Linux, macOS)" ;;
  esac

  case "$(uname -m)" in
    x86_64 | amd64)  arch=amd64 ;;
    aarch64 | arm64) arch=arm64 ;;
    *) err "unsupported architecture: $(uname -m) (supported: x86_64/amd64, arm64/aarch64)" ;;
  esac

  # An Apple-silicon Mac running this under Rosetta reports x86_64; install
  # the native binary instead of the emulated one.
  if [ "$os" = darwin ] && [ "$arch" = amd64 ]; then
    if [ "$(sysctl -n hw.optional.arm64 2>/dev/null || echo 0)" = 1 ]; then
      arch=arm64
      say "Apple silicon detected behind Rosetta; installing the native arm64 build"
    fi
  fi
  say "detected ${os}/${arch}"

  version="${TABLEX_VERSION:-latest}"
  if [ "$version" = latest ]; then
    if [ -n "${TABLEX_BASE_URL:-}" ]; then
      err "TABLEX_BASE_URL requires an explicit TABLEX_VERSION"
    fi
    tag=$(resolve_latest)
  else
    # Normalize: accept 1.0.0 and v1.0.0 alike; artifacts use the v-form.
    case "$version" in
      v*) tag="$version" ;;
      *)  tag="v$version" ;;
    esac
  fi
  say "installing tablex ${tag}"

  if [ -n "${TABLEX_BASE_URL:-}" ]; then
    base="${TABLEX_BASE_URL%/}"
  else
    base="https://github.com/${REPO}/releases/download/${tag}"
  fi

  archive="tablex_${tag}_${os}_${arch}.tar.gz"

  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' EXIT INT HUP TERM

  say "downloading ${archive}..."
  fetch "${base}/${archive}" "${tmp}/${archive}" || err "download failed: ${base}/${archive}"
  fetch "${base}/SHA256SUMS" "${tmp}/SHA256SUMS" || err "download failed: ${base}/SHA256SUMS"

  say "verifying checksum..."
  expected=$(awk -v f="$archive" '($2 == f) || ($2 == "*"f) { print $1; exit }' "${tmp}/SHA256SUMS")
  [ -n "$expected" ] || err "no entry for ${archive} in SHA256SUMS"
  actual=$(sha256_of "${tmp}/${archive}")
  if [ "$expected" != "$actual" ]; then
    err "checksum mismatch for ${archive}: expected ${expected}, got ${actual}. Nothing was installed."
  fi

  verify_attestation "${tmp}/SHA256SUMS"

  say "extracting..."
  tar -xzf "${tmp}/${archive}" -C "$tmp"
  [ -f "${tmp}/tablex" ] || err "archive did not contain the tablex binary"

  if [ -n "${TABLEX_INSTALL_DIR:-}" ]; then
    install_dir="$TABLEX_INSTALL_DIR"
  elif [ "$(id -u)" = 0 ]; then
    install_dir=/usr/local/bin
  else
    install_dir="${HOME}/.local/bin"
  fi
  mkdir -p "$install_dir"

  # Atomic install: stage under a temporary name IN the target directory,
  # then rename - rename within one filesystem cannot leave a half-written
  # binary at the final path.
  target="${install_dir}/tablex"
  staged="${target}.new.$$"
  cp "${tmp}/tablex" "$staged"
  chmod 0755 "$staged"
  mv -f "$staged" "$target"
  say "installed ${target}"

  got=$("$target" -version) || err "the installed binary failed to run"
  if [ "$got" != "tablex ${tag}" ]; then
    err "installed binary reports '${got}', expected 'tablex ${tag}'"
  fi
  say "verified: ${got}"

  maybe_add_path "$install_dir"

  say "done. Run 'tablex' and open http://localhost:8080"
}

main "$@"
