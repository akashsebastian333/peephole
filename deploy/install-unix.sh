#!/bin/sh
# peephole fleet installer — macOS and Linux. Run as root (JumpCloud Command).
#
# Idempotent: safe to run on every check-in. Exits 0 if already at the pinned
# version, so it can be scheduled rather than run once.
#
#   PEEPHOLE_VERSION   pinned release tag, e.g. v0.5.1   (REQUIRED — never "latest")
#   PEEPHOLE_MODE      guided (default) | audit | strict | hardened
#   PEEPHOLE_BASE_URL  artifact source. STRONGLY PREFERRED: an internal mirror,
#                      e.g. https://artifacts.corp/peephole/v0.5.1
#                      It must serve the asset files and SHA256SUMS verbatim.
#   PEEPHOLE_REPO      owner/repo — GitHub fallback, only if no mirror is set
#   GH_TOKEN           required for the GitHub fallback while the repo is PRIVATE
#
# On the artifact source: the upstream repo is private, so an unauthenticated
# GitHub download returns HTTP 404 — an MDM Command has no credential. Mirror the
# release assets to internal storage once, verify the checksums at mirror time, and
# point PEEPHOLE_BASE_URL at it. That gives change control and avoids putting a
# GitHub token on every endpoint.
#
# Exit codes: 0 ok/already current · 1 usage · 2 download or checksum failure
#             3 install failure · 4 verification failure
set -eu

VERSION="${PEEPHOLE_VERSION:?set PEEPHOLE_VERSION to a pinned tag, e.g. v0.5.1}"
MODE="${PEEPHOLE_MODE:-guided}"
REPO="${PEEPHOLE_REPO:-akashsebastian333/peephole}"
BIN=/usr/local/bin/peephole

log() { echo "[peephole-install] $*"; }
die() { log "ERROR: $2"; exit "$1"; }

[ "$(id -u)" -eq 0 ] || die 1 "must run as root"

# --- 1. target detection -----------------------------------------------------
os=$(uname -s | tr '[:upper:]' '[:lower:]')
arch=$(uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/')
case "$os/$arch" in
  darwin/arm64|darwin/amd64|linux/amd64|linux/arm64) ;;
  *) die 1 "unsupported target $os/$arch — no published binary" ;;
esac
asset="peephole-${os}-${arch}"

# --- 2. skip if already at the pinned version --------------------------------
want="${VERSION#v}"
if [ -x "$BIN" ] && "$BIN" version 2>/dev/null | head -1 | grep -q "peephole ${want} "; then
  log "already at ${want}; verifying integrity"
  "$BIN" selfcheck >/dev/null 2>&1 || log "WARN: selfcheck failed on an existing install"
  exit 0
fi

# --- 3. download + verify checksum (never install an unverified binary) ------
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
if [ -n "${PEEPHOLE_BASE_URL:-}" ]; then
  base="${PEEPHOLE_BASE_URL%/}"
  set -- -fsSL --retry 3 --retry-delay 2
else
  base="https://api.github.com/repos/${REPO}/releases/assets"
  [ -n "${GH_TOKEN:-}" ] || die 1 "the repo is private: set PEEPHOLE_BASE_URL to an internal mirror, or GH_TOKEN for the GitHub fallback"
  set -- -fsSL --retry 3 --retry-delay 2 -H "Authorization: Bearer ${GH_TOKEN}" -H "Accept: application/octet-stream"
  # Resolve asset ids: on a private repo browser_download_url needs a session
  # cookie, while the assets API accepts a bearer token.
  command -v python3 >/dev/null 2>&1 || die 1 "GitHub fallback needs python3 to parse the release JSON; use PEEPHOLE_BASE_URL instead"
  meta=$(curl -fsSL -H "Authorization: Bearer ${GH_TOKEN}" \
    "https://api.github.com/repos/${REPO}/releases/tags/${VERSION}") || die 2 "cannot read release ${VERSION}"
  ids=$(printf '%s' "$meta" | python3 -c '
import json,sys
want=sys.argv[1:]
a={x["name"]:x["id"] for x in json.load(sys.stdin).get("assets",[])}
print(" ".join(str(a.get(n,"")) for n in want))' "$asset" "SHA256SUMS")
  aid=$(printf '%s' "$ids" | cut -d" " -f1)
  sid=$(printf '%s' "$ids" | cut -d" " -f2)
  [ -n "$aid" ] && [ -n "$sid" ] || die 2 "cannot resolve asset ids for ${VERSION}"
fi

log "downloading ${asset} @ ${VERSION} from ${base}"
if [ -n "${PEEPHOLE_BASE_URL:-}" ]; then
  curl "$@" "${base}/${asset}"      -o "$tmp/$asset"      || die 2 "download failed"
  curl "$@" "${base}/SHA256SUMS"    -o "$tmp/SHA256SUMS"  || die 2 "SHA256SUMS download failed"
else
  curl "$@" "${base}/${aid}"        -o "$tmp/$asset"      || die 2 "download failed"
  curl "$@" "${base}/${sid}"        -o "$tmp/SHA256SUMS"  || die 2 "SHA256SUMS download failed"
fi

( cd "$tmp" && if command -v sha256sum >/dev/null 2>&1; then
      sha256sum -c SHA256SUMS --ignore-missing
  else
      shasum -a 256 -c SHA256SUMS --ignore-missing
  fi ) || die 2 "CHECKSUM MISMATCH — refusing to install"
log "checksum verified"

# --- 4. install --------------------------------------------------------------
# Atomic replace so a concurrently-running hook never sees a partial binary.
chmod 0755 "$tmp/$asset"
# curl does not set com.apple.quarantine, but strip it defensively in case the
# asset was staged by something that does. Harmless on Linux.
if [ "$os" = darwin ]; then xattr -d com.apple.quarantine "$tmp/$asset" 2>/dev/null || true; fi
install -d -m 0755 "$(dirname "$BIN")"
if ! mv -f "$tmp/$asset" "$BIN.new"; then die 3 "staging failed"; fi
if ! mv -f "$BIN.new" "$BIN";        then die 3 "install failed"; fi

# --- 5. managed hook config (admin-owned, not user-editable) -----------------
# Uses the managed-settings.d drop-in directory so we never merge into, or
# clobber, a shared managed-settings.json owned by another tool.
case "$os" in
  darwin) MDIR="/Library/Application Support/ClaudeCode/managed-settings.d" ;;
  linux)  MDIR="/etc/claude-code/managed-settings.d" ;;
esac
install -d -m 0755 "$MDIR"
cat > "$MDIR/10-peephole.json" <<JSON
{
  "hooks": {
    "SessionStart":      [{ "hooks": [{ "type": "command", "command": "$BIN hook", "timeout": 10 }] }],
    "UserPromptSubmit":  [{ "hooks": [{ "type": "command", "command": "$BIN hook", "timeout": 10 }] }],
    "PreToolUse":        [{ "matcher": "Write|Edit|MultiEdit|NotebookEdit|Bash|mcp__.*",
                            "hooks": [{ "type": "command", "command": "$BIN hook", "timeout": 10 }] }],
    "PostToolUse":       [{ "matcher": "Write|Edit|MultiEdit|NotebookEdit|Bash",
                            "hooks": [{ "type": "command", "command": "$BIN hook", "timeout": 10 }] }],
    "Stop":              [{ "hooks": [{ "type": "command", "command": "$BIN hook", "timeout": 10 }] }]
  }
}
JSON
chmod 0644 "$MDIR/10-peephole.json"

# --- 6. verify the install we just made -------------------------------------
"$BIN" version   >/dev/null 2>&1 || die 4 "installed binary will not execute"
"$BIN" selfcheck >/dev/null 2>&1 || die 4 "selfcheck failed after install"
got=$("$BIN" version | head -1)
case "$got" in *"peephole ${want} "*) ;; *) die 4 "version mismatch: $got" ;; esac

log "OK — $got"
log "mode default: ${MODE} (per-project; ${BIN} mode <m> to change)"
log "hooks: $MDIR/10-peephole.json"
log "REMINDER: exclude **/.peephole/ from endpoint on-access scanning"
exit 0
