#!/usr/bin/env sh
# Launch the platform binary. Optimized for latency: the fast path is fork-free
# (a cached exe path read via the `read` builtin, then exec). The slow path runs
# ONE `uname` and resolves the binary, caching the result for next time.
#
# Fail-safe: if no binary matches, exit 0 — peephole never blocks the workflow
# because it cannot run (distinct from fail-closed, which is for in-binary errors).
ROOT="${CLAUDE_PLUGIN_ROOT:-$(CDPATH= cd "$(dirname "$0")/.." && pwd)}"
BIN="$ROOT/bin"
CACHE="${CLAUDE_PLUGIN_DATA:-$BIN}/.peephole-exe"

# Trim the Go runtime's startup work for a sub-10ms serial process: fewer init
# threads (GOMAXPROCS=1), no GC (GOGC=off), and no async-preemption handler/timer
# (asyncpreemptoff=1). The 2s watchdog in the binary still fails closed, so a hung
# regexp cannot run un-preempted forever. inittrace confirms package init is <1ms;
# the residual startup cost is OS exec/page-in, which no flag can touch.
GOMAXPROCS=1
GOGC=off
GODEBUG=asyncpreemptoff=1
export GOMAXPROCS GOGC GODEBUG

# Fast path: cached exe path, no forks. Only trust a cached path that is under
# our own bin/ dir, so a tampered cache cannot redirect exec to another binary.
if [ -r "$CACHE" ]; then
  read -r exe < "$CACHE"
  case "$exe" in
    "$BIN"/*) if [ -x "$exe" ]; then exec "$exe" "$@"; fi ;;
  esac
fi

# Slow path: one uname, split with builtin parameter expansion (no extra forks).
plat=$(uname -sm 2>/dev/null)
os=${plat% *}
arch=${plat#* }
exe=
case "$os" in
  Darwin) case "$arch" in arm64) exe=peephole-darwin-arm64 ;; x86_64) exe=peephole-darwin-amd64 ;; esac ;;
  Linux)  case "$arch" in x86_64|amd64) exe=peephole-linux-amd64 ;; aarch64|arm64) exe=peephole-linux-arm64 ;; esac ;;
  MINGW*|MSYS*|CYGWIN*) exe=peephole-windows-amd64.exe ;;
esac

if [ -z "$exe" ] || [ ! -x "$BIN/$exe" ]; then
  echo "peephole: no binary for $os/$arch — enforcement disabled (workflow not blocked)" >&2
  exit 0
fi
printf '%s\n' "$BIN/$exe" > "$CACHE" 2>/dev/null
exec "$BIN/$exe" "$@"
