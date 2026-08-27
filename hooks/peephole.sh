#!/usr/bin/env sh
ROOT="${CLAUDE_PLUGIN_ROOT:-$(CDPATH= cd "$(dirname "$0")/.." && pwd)}"
BIN="$ROOT/bin"
CACHE="${CLAUDE_PLUGIN_DATA:-$BIN}/.peephole-exe"

GOMAXPROCS=1
GOGC=off
GODEBUG=asyncpreemptoff=1
export GOMAXPROCS GOGC GODEBUG

if [ -r "$CACHE" ]; then
  read -r exe < "$CACHE"
  case "$exe" in
    "$BIN"/*) if [ -x "$exe" ]; then exec "$exe" "$@"; fi ;;
  esac
fi

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
