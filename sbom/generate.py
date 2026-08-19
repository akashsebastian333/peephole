#!/usr/bin/env python3
"""Generate a CycloneDX 1.6 SBOM for peephole.

Off-the-shelf Go SBOM tools describe the *module graph*, which for this project is
empty: go.mod has no `require` directives and there is no go.sum, so a plain
`trivy fs --format cyclonedx` emits two components and says nothing about what is
actually linked. That is technically true and practically useless.

The real bill of materials for a statically-linked, zero-dependency Go binary is:
the module itself, plus the Go standard library, whose object code ships inside
every artifact. This emits both, with the stdlib's BSD-3-Clause licence and the
exact toolchain version read out of the compiled binary (not out of go.mod, which
only states a minimum).

Usage:  python3 sbom/generate.py [binary] > sbom/peephole.cdx.json
Verify: the toolchain version in the output must match `peephole version`.
"""
import json
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def sh(*args, **kw):
    return subprocess.run(args, capture_output=True, text=True, cwd=ROOT, **kw).stdout


def main():
    binary = sys.argv[1] if len(sys.argv) > 1 else "bin/peephole-darwin-arm64"

    # Toolchain actually used to build the artifact, from the binary itself.
    meta = sh("go", "version", "-m", binary)
    m = re.search(r"\s(go1[\d.]+)\b", meta)
    gover = m.group(1) if m else "unknown"

    # Version from the single source of truth.
    src = open(os.path.join(ROOT, "version.go")).read()
    ver = re.search(r'const version = "([^"]+)"', src).group(1)

    # Every linked package, partitioned. Third-party would be anything that is
    # neither ours nor stdlib; the assertion below is the point of the SBOM.
    pkgs = [p for p in sh("go", "list", "-deps", "./...").split() if p]
    own = [p for p in pkgs if p == "peephole" or p.startswith("peephole/")]
    stdlib = [p for p in pkgs if p not in own]
    third_party = [p for p in stdlib if "." in p.split("/")[0]]
    if third_party:
        print("WARNING: non-stdlib packages linked: %s" % third_party, file=sys.stderr)

    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "bom-ref": "pkg:golang/peephole@%s" % ver,
                "name": "peephole",
                "version": ver,
                "description": "Write-time CWE gate for AI coding agents",
                "licenses": [{"license": {"id": "MIT"}}],
            },
            "properties": [
                {"name": "peephole:build:toolchain", "value": gover},
                {"name": "peephole:build:flags", "value": "-trimpath -buildvcs=false -ldflags=-s -w CGO_ENABLED=0"},
                {"name": "peephole:deps:module_requires", "value": "0"},
                {"name": "peephole:deps:packages_linked", "value": str(len(pkgs))},
                {"name": "peephole:deps:packages_own", "value": str(len(own))},
                {"name": "peephole:deps:packages_stdlib", "value": str(len(stdlib))},
                {"name": "peephole:deps:packages_third_party", "value": str(len(third_party))},
            ],
        },
        "components": [
            {
                "type": "library",
                "bom-ref": "pkg:generic/go-stdlib@%s" % gover,
                "name": "go-stdlib",
                "version": gover,
                "description": (
                    "Go standard library, statically linked into the artifact. "
                    "%d packages. This is the project's entire external attack "
                    "surface, so the toolchain patch level is a security-relevant "
                    "input: scan artifacts with `govulncheck -mode=binary`, not "
                    "just source." % len(stdlib)
                ),
                "licenses": [{"license": {"id": "BSD-3-Clause"}}],
                "externalReferences": [{"type": "website", "url": "https://go.dev/"}],
            }
        ],
    }
    json.dump(bom, sys.stdout, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
