#!/bin/sh
# =============================================================================
# peephole — Kandji (Iru) Custom Script
# =============================================================================
# Paste this whole file into: Kandji > Library > Add > Custom Script
#   Execution Frequency : Run on a schedule / every check-in  (NOT "run once" —
#                         it is idempotent and refreshes the hooks on each run)
#   Execute as          : root
#   Assign to           : a Blueprint scoped to Macs that run Claude Code
#
# A Kandji-ready wrapper around deploy/install-unix.sh: the env is pre-exported
# at the top (Kandji has no env-var field) and the fleet prerequisites are
# documented inline. Same checksum-verified install logic as install-unix.sh.
#
# What it does, in one run:
#   1. Detects macOS arch (arm64 / amd64).
#   2. Downloads the pinned peephole binary + SHA256SUMS from a GitHub release.
#   3. REFUSES to install on a checksum mismatch.
#   4. Installs /usr/local/bin/peephole and writes a hash pin next to it.
#   5. Writes the Claude Code managed-settings hook so Claude Code calls it.
#   6. Verifies `version` + `selfcheck` (a failure exits non-zero -> Kandji fails
#      the device, which is what you want).
#
# -----------------------------------------------------------------------------
# PREREQUISITES — read these, the script cannot create them for you:
#
#   * A PUBLISHED GitHub RELEASE on the repo below (PEEPHOLE_REPO), pinned by
#     PEEPHOLE_VERSION, with these assets attached:
#       peephole-darwin-arm64  peephole-darwin-amd64  SHA256SUMS
#     The official release workflow (.github/workflows/release.yml) attaches
#     them when you push a v* tag. If you forked, set PEEPHOLE_REPO to your
#     fork, or host a copy of that asset directory yourself and set
#     PEEPHOLE_BASE_URL below.
#
#   * ALLOWLIST the two darwin binaries by SHA-256 (Kandji Library / Blocking,
#     or Santa). They are NOT notarized — Gatekeeper/blocking will kill the
#     binary after a clean install until you allowlist the hash from SHA256SUMS.
#
#   * CLAUDE CODE SOURCE must be "file". This script drops a managed-settings
#     file. If Claude Code is already managed from Kandji via a Custom Settings
#     plist (domain com.anthropic.claudecode), or server-managed, the file is
#     SILENTLY IGNORED. Verify on a pilot: `/status` must show (drop-ins) or
#     (file + drop-ins). See docs/ENTERPRISE.md §3.
#
#   * EXCLUDE **/.peephole/ from endpoint on-access AV scanning.
#
# Exit codes: 0 ok/already current · 1 usage · 2 download/checksum · 3 install
#             4 verification failure
# =============================================================================

# --- CONFIGURE ME ------------------------------------------------------------
export PEEPHOLE_VERSION="v0.5.1"               # pinned release tag — NEVER "latest"
export PEEPHOLE_REPO="akashsebastian333/peephole"  # set to your fork if you forked
# export PEEPHOLE_BASE_URL="https://artifacts.your-org.internal/peephole/v0.5.1"
#                                              # ^ ONLY if you self-host the assets
#                                              #   instead of using GitHub releases
# export GH_TOKEN="…"                          # ONLY for a PRIVATE fork (avoid in MDM;
#                                              #   prefer PEEPHOLE_BASE_URL)
# -----------------------------------------------------------------------------

set -eu

VERSION="${PEEPHOLE_VERSION:?set PEEPHOLE_VERSION to a pinned tag, e.g. v0.5.1}"
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

write_hooks() {
  case "$os" in
    darwin) MDIR="/Library/Application Support/ClaudeCode/managed-settings.d" ;;
    linux)  MDIR="/etc/claude-code/managed-settings.d" ;;
  esac
  install -d -m 0755 "$MDIR"
  cat > "$MDIR/10-peephole.json" <<JSON
{
  "hooks": {
    "SessionStart":        [{ "hooks": [{ "type": "command", "command": "$BIN", "args": ["hook"], "timeout": 10 }] }],
    "SubagentStart":       [{ "hooks": [{ "type": "command", "command": "$BIN", "args": ["hook"], "timeout": 10 }] }],
    "UserPromptSubmit":    [{ "hooks": [{ "type": "command", "command": "$BIN", "args": ["hook"], "timeout": 10 }] }],
    "PreToolUse":          [{ "matcher": "Write|Edit|MultiEdit|NotebookEdit|Bash|mcp__.*",
                              "hooks": [{ "type": "command", "command": "$BIN", "args": ["hook"], "timeout": 10 }] }],
    "PostToolUse":         [{ "matcher": "Write|Edit|MultiEdit|NotebookEdit|Bash",
                              "hooks": [{ "type": "command", "command": "$BIN", "args": ["hook"], "timeout": 10 }] }],
    "Stop":                [{ "hooks": [{ "type": "command", "command": "$BIN", "args": ["hook"], "timeout": 10 }] }],
    "ConfigChange":        [{ "hooks": [{ "type": "command", "command": "$BIN", "args": ["hook"], "timeout": 10 }] }],
    "InstructionsLoaded":  [{ "hooks": [{ "type": "command", "command": "$BIN", "args": ["hook"], "timeout": 10 }] }]
  }
}
JSON
  chmod 0644 "$MDIR/10-peephole.json"
}

write_pin() {
  if command -v sha256sum >/dev/null 2>&1; then
    h=$(sha256sum "$BIN" | awk '{print $1}')
  else
    h=$(shasum -a 256 "$BIN" | awk '{print $1}')
  fi
  [ -n "$h" ] || die 4 "cannot hash installed binary"
  printf '{"%s":"%s"}\n' "$(basename "$BIN")" "$h" > "$(dirname "$BIN")/manifest.sha256"
  chmod 0644 "$(dirname "$BIN")/manifest.sha256"
}

# --- 2. skip if already at the pinned version --------------------------------
want="${VERSION#v}"
if [ -x "$BIN" ] && "$BIN" version 2>/dev/null | head -1 | grep -q "peephole ${want} "; then
  log "already at ${want}; refreshing hooks"
  write_hooks
  [ -f "$(dirname "$BIN")/manifest.sha256" ] || write_pin
  "$BIN" selfcheck >/dev/null 2>&1 || die 4 "selfcheck failed on an existing install"
  exit 0
fi

# --- 3. download + verify checksum (never install an unverified binary) ------
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
if [ -n "${PEEPHOLE_BASE_URL:-}" ]; then
  base="${PEEPHOLE_BASE_URL%/}"
  log "downloading ${asset} @ ${VERSION} from ${base}"
  curl -fsSL --retry 3 --retry-delay 2 "${base}/${asset}"   -o "$tmp/$asset"     || die 2 "download failed"
  curl -fsSL --retry 3 --retry-delay 2 "${base}/SHA256SUMS" -o "$tmp/SHA256SUMS" || die 2 "SHA256SUMS download failed"
elif [ -n "${GH_TOKEN:-}" ]; then
  command -v python3 >/dev/null 2>&1 || die 1 "private-fork fallback needs python3; set PEEPHOLE_BASE_URL instead"
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
  log "downloading ${asset} @ ${VERSION} from GitHub assets API"
  curl -fsSL --retry 3 --retry-delay 2 -H "Authorization: Bearer ${GH_TOKEN}" -H "Accept: application/octet-stream" \
    "https://api.github.com/repos/${REPO}/releases/assets/${aid}" -o "$tmp/$asset" || die 2 "download failed"
  curl -fsSL --retry 3 --retry-delay 2 -H "Authorization: Bearer ${GH_TOKEN}" -H "Accept: application/octet-stream" \
    "https://api.github.com/repos/${REPO}/releases/assets/${sid}" -o "$tmp/SHA256SUMS" || die 2 "SHA256SUMS download failed"
else
  base="https://github.com/${REPO}/releases/download/${VERSION}"
  log "downloading ${asset} @ ${VERSION} from ${base}"
  curl -fsSL --retry 3 --retry-delay 2 -L "${base}/${asset}"   -o "$tmp/$asset"     || die 2 "download failed"
  curl -fsSL --retry 3 --retry-delay 2 -L "${base}/SHA256SUMS" -o "$tmp/SHA256SUMS" || die 2 "SHA256SUMS download failed"
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
write_pin
write_hooks

# --- 6. verify the install we just made -------------------------------------
"$BIN" version   >/dev/null 2>&1 || die 4 "installed binary will not execute"
"$BIN" selfcheck >/dev/null 2>&1 || die 4 "selfcheck failed after install"
got=$("$BIN" version | head -1)
case "$got" in *"peephole ${want} "*) ;; *) die 4 "version mismatch: $got" ;; esac

log "OK — $got"
log "hooks: $MDIR/10-peephole.json"
log "mode is per-project; org floor is .peephole-policy.json in the repo"
log "REMINDER: exclude **/.peephole/ from endpoint on-access scanning"
log "REMINDER: if Claude Code /status shows (remote), (plist), or (HKLM), this drop-in is ignored — put hooks in that source (docs/ENTERPRISE.md)"
exit 0
