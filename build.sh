#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

go run ./cmd/kbgen

targets="darwin/arm64 darwin/amd64 linux/amd64 linux/arm64 windows/amd64"
for t in $targets; do
  os=${t%/*}; arch=${t#*/}
  out="bin/peephole-$os-$arch"; [ "$os" = windows ] && out="$out.exe"
  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -trimpath -buildvcs=false -ldflags="-s -w" -o "$out" .
  echo "built $out"
done

native="bin/peephole-$(uname -s | tr '[:upper:]' '[:lower:]')-$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')"
if [ -x "$native" ]; then
  "$native" genmanifest
  "$native" selfcheck
else
  echo "warn: no native binary to generate manifest ($native)" >&2
fi
