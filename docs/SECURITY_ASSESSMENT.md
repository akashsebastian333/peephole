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

| ID | Severity | Finding | Status |
|---|---|---|---|
| **SA-1** | **High** | Shipped binaries carried **32 reachable Go stdlib CVEs** (committed `bin/`, built on go1.26.0); the published v0.5.0 assets carried 7 | **FIXED** |
| **SA-2** | **Medium** | CI's `govulncheck` runs in *source* mode against a freshly-resolved toolchain, so it reported "0 vulnerabilities" while the artifact had 32. It structurally cannot detect a stale **build** toolchain | **FIXED** |
| **SA-3** | **Medium** | The daily `security-scan` workflow had been **failing for ≥4 consecutive days** on 3 trivial staticcheck issues, so nobody read its govulncheck output | **FIXED** |
| **SA-4** | **Low** | Statically-linked binaries redistributed with no notice reproducing Go's BSD-3-Clause copyright (clause 2 requires it for binary redistribution) | **FIXED** — `NOTICE` |
| **SA-5** | **Low** | Dead state writes (`secrel`, `n3sec`) on the decision path — written every gated decision, never read | **FIXED** |
| **SA-6** | **Info** | `benchmark/corpus.py` uses a `sk_live_` Stripe prefix on a documented example key body; may trip GitHub/Stripe secret scanning | **Open — cosmetic** |
| **SA-7** | Accepted | Agent can disable enforcement (argv indirection, write-then-run, `~/.claude/settings.json`) | **Accepted** — same-user model |
| **SA-8** | Accepted | Audit chain is unkeyed SHA-256; forgeable and deletable by the same user | **Accepted** — must not be called compliance evidence |
| **SA-9** | Accepted | No release signing or provenance attestation | **Accepted** for internal use; blocker for public distribution |

### SA-1 / SA-2 in detail

This is the finding that mattered, and the reason it survived is instructive.

```
$ govulncheck -mode=binary bin/peephole-darwin-arm64     # before
32 reachable vulnerabilities — net/url, html/template, crypto/tls, net/http,
encoding/xml, encoding/asn1, net, crypto/x509, os, archive/tar, mime, net/mail …
all fixed in ≤ go1.26.6

$ CI: govulncheck ./...                                  # same day
"Your code is affected by 0 vulnerabilities."
```

Both statements were true. Source mode resolves the standard library from the
toolchain `setup-go` just installed — a floating `go-version: '1.26'`, i.e. the
newest patch. The **committed binaries** were built months of patches earlier on
go1.26.0, and `bin/` is committed to git and is what the plugin install path
executes. The scanner was looking at the source's dependency graph; the risk was in
the artifact.

Remediation, all verified:

- Rebuilt on go1.26.6 → **0 reachable vulnerabilities** across all five targets.
- `toolchain go1.26.6` pinned in `go.mod`, so a local `./build.sh` cannot silently
  go stale; `release.yml` pinned to the same exact patch (a floating minor also
  defeated reproducibility).
- **`govulncheck -mode=binary` added to both `release.yml` (on `dist/*`) and
  `security-scan.yml` (on committed `bin/*`).** A stale toolchain now fails the
  release rather than shipping.

The generalisable lesson: **zero dependencies does not mean zero supply chain.** It
concentrates the supply chain into a single input — the compiler — which is exactly
the input source-mode scanning cannot see.

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
