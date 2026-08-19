# Peephole — security assessment (0.5.0)

Assessment of peephole *as a product being deployed*, not of the code it scans.
Date: 2026-08. Every finding was reproduced against the shipped binary; commands to
re-verify are in §6.

**Verdict:** deployable in `guided` mode on developer endpoints. Two findings were
remediated during this assessment (one High). Three residual items are accepted and
must be disclosed rather than fixed, because they follow from the same-user threat
model. Do **not** present the audit log as compliance evidence, and do not rely on
it as a fleet enforcement control.

---

## 1. Findings summary

> **Correction.** An earlier revision of this document reported SA-1 as *High — 32
> reachable stdlib CVEs*. That was wrong, and the error is instructive enough to
> keep on the record as SA-0. The real figure is **1**. See SA-0 and SA-1 below.

| ID | Severity | Finding | Status |
|---|---|---|---|
| **SA-0** | **Medium (methodology)** | `govulncheck -mode=binary` over-reports by **32×** on stripped binaries. It needs a symbol table to establish reachability; with `-ldflags="-s -w"` it degrades to listing every stdlib advisory for the detected Go version as though called. A release gate built on it fails on any toolchain that is not the newest patch | **FIXED** |
| **SA-1** | **Low** | The shipped binaries were built by a toolchain **6 patch releases stale** (go1.26.0), reachable-affected by **1** stdlib vulnerability: `GO-2026-4602`, Root escape via `os.ReadDir`, fixed in go1.26.1 | **FIXED** |
| **SA-2** | **Medium** | CI's `govulncheck` runs in *source* mode against a freshly-resolved toolchain, so it reported "0 vulnerabilities" while the shipped artifact was affected. It structurally cannot detect a stale **build** toolchain | **FIXED** |
| **SA-3** | **Medium** | The daily `security-scan` workflow had been **failing for ≥4 consecutive days** on 3 trivial staticcheck issues, so nobody read its govulncheck output | **FIXED** |
| **SA-4** | **Low** | Statically-linked binaries redistributed with no notice reproducing Go's BSD-3-Clause copyright (clause 2 requires it for binary redistribution) | **FIXED** — `NOTICE` |
| **SA-5** | **Low** | Dead state writes (`secrel`, `n3sec`) on the decision path — written every gated decision, never read | **FIXED** |
| **SA-6** | **Info** | `benchmark/corpus.py` uses a `sk_live_` Stripe prefix on a documented example key body; may trip GitHub/Stripe secret scanning | **Open — cosmetic** |
| **SA-7** | Accepted | Agent can disable enforcement (argv indirection, write-then-run, `~/.claude/settings.json`) | **Accepted** — same-user model |
| **SA-8** | Accepted | Audit chain is unkeyed SHA-256; forgeable and deletable by the same user | **Accepted** — must not be called compliance evidence |
| **SA-9** | Accepted | No release signing or provenance attestation | **Accepted** for internal use; blocker for public distribution |

### SA-0 — the scanner over-reports on stripped binaries (32× measured)

The first pass of this assessment reported 32 reachable CVEs. That number came from
`govulncheck -mode=binary` on the shipped artifacts, and it was an artifact of the
build flags, not a property of the code. Controlled test — identical source,
identical toolchain (go1.26.0), only `-ldflags="-s -w"` differing:

| build | govulncheck verdict |
|---|---|
| stripped (what ships) | *"affected by **32** vulnerabilities"* |
| unstripped | *"affected by **1** vulnerability"* |

Binary mode needs a symbol table to decide reachability. Stripped, it cannot, so it
falls back to enumerating every stdlib advisory for the detected Go version. The
tool says as much in the part of its own output that is easy to skip past:

> This scan also found 1 vulnerability in packages you import and 30 vulnerabilities
> in modules you require, **but your code doesn't appear to call these**.

Two consequences, both acted on:

1. **The count in this document was corrected from 32 to 1.**
2. **The gate built on it was wrong and was replaced before merge.** A release gate
   that scans stripped `dist/*` fails on any toolchain that is not the newest
   patch — it would have blocked every release for a non-issue. Replaced with two
   accurate checks: govulncheck against a throwaway **unstripped** build of the same
   source (real symbols, real reachability, never published), plus an assertion that
   every published artifact's embedded toolchain equals the `go.mod` pin. Both were
   validated, including a negative control confirming the stale go1.26.0 artifact is
   caught.

Corroborating evidence that the 31 were never reachable: `go list -deps .` does not
list `net/http`, `crypto/tls`, `html/template`, `encoding/xml`, `net/url`,
`archive/tar`, `encoding/asn1`, `crypto/x509` or `net`, and the binary contains **0**
string references to any of them (control: `regexp` 218, `encoding/json` 193). That
is by design — `slopsquat.go:267` shells out to `curl` specifically to *"keep the
heavy net/http + crypto/tls packages out of the binary."* The advisories that
dominated the inflated list were for packages peephole does not link at all.

### SA-1 / SA-2 — stale build toolchain, invisible to source-mode scanning

What remains after the correction is real but small:

```
$ govulncheck -mode=binary <unstripped, go1.26.0>
GO-2026-4602 — FileInfo can escape from a Root in os
  Fixed in: os@go1.26.1     Vulnerable symbols: os.ReadDir, os.File.ReadDir
Your code is affected by 1 vulnerability from the Go standard library.
```

Peephole calls `os.ReadDir` in `integrity.go` to enumerate its own `bin/` directory,
i.e. on program-controlled paths, not attacker-supplied ones — hence **Low**. The
real defect is currency: the artifacts were built six patch releases behind.

And SA-2 stands on its own, independent of the magnitude error. CI reported *"0
vulnerabilities"* the same day the shipped binary was affected, and it was not
lying: source mode resolves the standard library from the toolchain `setup-go` just
installed — a floating `go-version: '1.26'`, the newest patch. It audits the
source's dependency graph while the risk lives in the artifact.

Remediation, all verified:

- Rebuilt on go1.26.6 → **0 reachable vulnerabilities**, confirmed unstripped.
- `toolchain go1.26.6` pinned in `go.mod` so a local `./build.sh` cannot silently go
  stale; `release.yml` pinned to the same exact patch (a floating minor also defeated
  reproducibility).
- Artifact-level toolchain assertion added to `release.yml` and `security-scan.yml`.

The generalisable lesson survives the correction, and so does a second one:

- **Zero dependencies does not mean zero supply chain.** It concentrates the supply
  chain into one input — the compiler — which is exactly what source-mode scanning
  cannot see.
- **Read the scanner's own caveats before acting on its headline.** A 32× inflation
  passed straight into a High-severity finding and a release gate. The tell was in
  the output the whole time.

## 2. Dependency and SBOM analysis

| Property | Result |
|---|---|
| `go.mod` require directives | **0** |
| `go.sum` | absent |
| Packages linked | 120 — 3 own, 117 stdlib, **0 third-party** |
| Vendored trees | none |
| Foreign copyright headers in source | none |
| CGO | disabled (`CGO_ENABLED=0`) — no native library linkage |
| Trivy vuln scan (`go.mod`) | 0 |

SBOM: [`sbom/peephole.cdx.json`](../sbom/peephole.cdx.json), CycloneDX 1.6,
regenerable via `python3 sbom/generate.py`. It deliberately records the Go standard
library as a component with its BSD-3-Clause licence and the **toolchain version
read out of the compiled binary**, because off-the-shelf Go SBOM tooling describes
the (empty) module graph and therefore says nothing useful about a zero-dependency
static binary.

This is a genuinely strong supply-chain posture. It is the single best structural
property of the project: there is no transitive dependency tree to audit, no
`node_modules`, no Python environment, and nothing to resolve at install time.

## 3. Licence compliance

| Item | Result |
|---|---|
| Declared licence | MIT — consistent across `LICENSE`, `plugin.json`, `marketplace.json` |
| Copyleft contamination | **None.** No third-party code is compiled in or vendored |
| Rule corpus provenance | **No evidence of derivation** from Semgrep, CodeQL, Bandit, Brakeman, gitleaks, Checkov or any other corpus. No attribution strings, no rule-id or schema fingerprints. All "derived from" strings in the tree are prose about *taint provenance*, not code provenance |
| Assets | `assets/*.svg` are original path artwork — no embedded fonts, no external references |
| Go stdlib BSD-3-Clause | **Was missing** for binary redistribution → now reproduced in [`NOTICE`](../NOTICE) (SA-4) |

No licence violations. One obligation gap, closed.

Rule-corpus provenance deserves the emphasis: for a tool whose value is 181 curated
rules, "did these come from an LGPL corpus?" is the question an acquirer asks
first, and the answer here is clean.

## 4. Secret hygiene

Trivy flagged 18 secret matches. **All are synthetic**, in four expected locations:

| Location | Nature |
|---|---|
| `benchmark/corpus.py` | Labeled benchmark corpus — fake secrets are the test fixtures |
| `rules/*.json`, `rules_gen.go` | Rule exemplars and negative-test hints |
| `benchmark/live/out_*/` | Model-generated benchmark artifacts where writing a hardcoded secret *was* the task |
| `benchmark/__pycache__/*.pyc` | Local build artifact — **gitignored, not tracked** |

Verified values are placeholders (`AKIAXXXXXXXXXXXXXXXX`, `xxxxxxxx`,
`examplesecretkeyreplacewithrealvalue`) or vendor-documented examples
(`AKIAIOSFODNN7EXAMPLE`). **No live credential is committed.** Only SA-6 remains: a
`sk_live_` prefix on a Stripe doc example, worth changing to `sk_test_` purely to
avoid tripping third-party scanners.

## 5. Static analysis

| Tool | Result |
|---|---|
| `go vet` | clean |
| `gofmt` | clean |
| `go test ./...` and `-race` | green |
| staticcheck | 3 issues → **fixed** (2 dead functions, 1 `S1011`) |
| gosec | runs daily with documented exclusions (`G104,G204,G304,G703,G306,G122`) — architectural, reviewed, high-value classes retained |
| `govulncheck` source + binary | **0** |

The staticcheck fix has a second benefit: the two dead functions were the only
readers of two state files that were still being **written on the decision path**,
so removing them removed dead I/O (SA-5).

## 6. Re-verification

```sh
go vet ./... && gofmt -l *.go cmd internal && go test ./... -count=1 && go test -race ./...
govulncheck -mode=binary bin/peephole-darwin-arm64        # expect: 0
python3 sbom/generate.py bin/peephole-darwin-arm64        # expect: third_party = 0
trivy fs --scanners vuln,secret,license .                 # expect: 0 vulns; secrets only in the 4 locations above
./bin/peephole-darwin-arm64 version && ./bin/peephole-darwin-arm64 selfcheck
```

## 7. Deployment conditions

Deploy in `guided` mode subject to these, all of which come from findings above or
from [THREAT_MODEL.md](THREAT_MODEL.md):

1. **Install a pinned tag or a pinned commit**, never `releases/latest`, so every
   endpoint runs a known ruleset and a known toolchain.
2. **Verify `selfcheck` and `version` post-install**; treat a mismatch as a failed
   install. `version` output is the fleet inventory record.
3. **Exclude `**/.peephole/` from endpoint on-access scanning** — the difference
   between ~4ms and ~15–50ms per event.
4. **Do not present the audit log as compliance evidence** (SA-8).
5. **Keep CI SAST as the blocking control.** Held-out blocking recall is ~40%;
   peephole reduces what reaches CI, it does not replace it.
6. **Do not claim fleet enforcement.** Org policy is repo-local and deletable
   (SA-7); it raises a floor for cooperative repos, not against an agent.
7. **Track the toolchain.** With zero dependencies, "patch Tuesday" for this tool
   is a Go release. The artifact-mode `govulncheck` gate makes that visible.
