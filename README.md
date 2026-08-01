<p align="center">
  <img src="assets/wordmark.svg" alt="peephole" width="420">
</p>

<p align="center">
  <b>Born-secure enforcement for AI coding assistants.</b>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/license-MIT-C79A3B" alt="MIT license">
  <img src="https://img.shields.io/badge/go-1.26-00ADD8" alt="Go 1.26">
  <img src="https://img.shields.io/badge/rules-176%20CWE-0F1420" alt="176 CWE rules">
  <img src="https://img.shields.io/badge/languages-31-0F1420" alt="31 languages">
  <img src="https://img.shields.io/badge/deps-0-brightgreen" alt="zero dependencies">
</p>

A Claude Code plugin that gates insecure code at *write time* — before it lands
on disk — with a CWE-mapped, tamper-evident audit log. The security analogue of
ponytail: *never open the door before checking who's on the other side, and never
ship code before checking what's in it.*

**Docs:** [Design](docs/DESIGN.md) · [Benchmark](docs/BENCHMARK.md) · [Review history](docs/REVIEW.md) · [Contributing](CONTRIBUTING.md) · [Security](SECURITY.md) · [Changelog](CHANGELOG.md)

## The difference

The incumbent (`security-guidance`) wires its regexes to **PostToolUse** — it
warns *after* the insecure code is already written, then hopes the model
regenerates it. That proves code was *repaired* secure.

Peephole wires the same class of check to **PreToolUse** and returns
`permissionDecision: deny` *before* the write lands. In strict/hardened mode the
insecure hunk never touches disk. That proves code was *born* secure — and it
closes the Bash escape hatch (`cat > f <<EOF …`) that a plain Write-tool gate
misses.

## How it's built (and why you won't feel it)

A single **static Go binary**, cross-compiled for macOS/Linux/Windows and shipped
in `bin/`. You install **no runtime** — not Node, not Python. The full hook path
(launcher + binary + scan) measures **~8.5ms per event** on this machine (46%
faster after three optimizations: the launcher hot path execs the cached binary
with zero extra shell, the KB ships as build-time-generated Go literals with
precomputed prefilters — `loadKB` is ~7µs, not ~2ms — and a detached SessionStart
`warmcache` pre-warms the slopsquat cache so the first install verdict skips the
cold-registry ~500ms). If your platform has no matching binary, the launcher exits
cleanly with a notice and never blocks your work.

The CWE knowledge base is embedded into the binary (`go:embed`), so a local
attacker can't quietly edit rule files the binary ignores, and there's no file
I/O to load rules on the hot path.

## Install (local)

```sh
# from the plugin marketplace, or point Claude Code at this directory as a plugin
```

The plugin auto-registers its hooks via `hooks/hooks.json`. Default mode is
**strict**.

## Modes

| Mode | Behavior |
|---|---|
| `audit` | warn + log only; never blocks. Measure before you enforce. |
| `strict` | **deny** high-confidence CWE patterns, **ask** on lower-confidence ones. *(default)* |
| `hardened` | deny-by-default; deny unverified installs and uninspectable writes. |
| `off` | enforcement disabled. |

Switch with `/peephole strict` (or `audit`/`hardened`/`off`), or
`sh "$CLAUDE_PLUGIN_ROOT/hooks/peephole.sh" mode strict`.

## What it catches

Enforced at write time (high-confidence *presence* patterns, Python + JS/TS):
SQL injection (CWE-89), code injection (94), unsafe deserialization (502), XSS
(79), OS command injection (78), path traversal (22), hardcoded secrets (798),
weak crypto (327), disabled security controls (1188), and hallucinated/
slopsquatted package installs. Bash payloads (heredocs, `python -c`, redirects)
are extracted and scanned through the same engine.

Beyond application code, it also covers **smart contracts** (Solidity:
reentrancy, `tx.origin` auth, `delegatecall`/`selfdestruct`, block-property
randomness), **infrastructure-as-code** (Terraform, Kubernetes, Dockerfile:
public ingress, wildcard IAM, privileged/host-namespace pods, root containers,
unencrypted storage), and **CI / supply-chain** config (GitHub Actions
expression injection, secrets echoed to logs, `curl | sh` and unpinned remote
fetches, registry tokens in `.npmrc`), **mobile** (iOS Objective-C: ATS
disabled, weak CommonCrypto, insecure Keychain class, WebView string-built
JS/HTML; Android: `addJavascriptInterface`, world-readable storage, mutable
`PendingIntent`, hostname-verifier bypass), **SQL scripts** (`GRANT ALL`,
`xp_cmdshell`, `LOAD_FILE`/`INTO OUTFILE`, dynamic-SQL concat), **web-server
config** (nginx/Apache: deprecated TLS, weak ciphers, `proxy_pass` SSRF,
directory listing, permissive CORS), and **framework-specific** footguns across
Django/Flask, Express/Next, Spring, Rails/Laravel, and Go templates. 31
language/format buckets in all.

Advisory only (can't be proven from one hunk, so never blocks): missing
authorization (862/863), IDOR (639), CSRF (352), missing auth (306). These
surface as review checklists via `/sec-review`, never as a block.

## Skills

- `/peephole` — show or change enforcement mode.
- `/sec-review` — review the current changes, including the absence-of-guard classes.
- `/sec-debt` — explain and list human-authorized security trade-offs.
- `/sec-audit` — mode, integrity, born-secure decomposition, decision tally by CWE and OWASP 2025, tamper-evident log status.

## Reporting & compliance

`peephole scan <files>` prints CWE findings; `peephole sarif <files>` emits a
SARIF 2.1.0 report (with `security-severity` and CWE/OWASP-2025 tags) for GitHub
code scanning, Azure DevOps, and most SAST dashboards — machine-readable
evidence for regulated teams. `/sec-audit` rolls decisions up to OWASP 2025.

## Build & test

```sh
./build.sh      # regenerate rules_gen.go, cross-compile all targets, regen integrity manifest
go test ./...   # end-to-end hook contract tests + KB self-consistency + tamper tests
```

## Does it actually work?

Measured two ways, honestly (`docs/BENCHMARK.md`, harness in `benchmark/`,
re-runnable end to end).

**Detection benchmark — three engines, identical inputs.** 151 labeled
vulnerable cases across 24 CWE classes + 50 benign everyday-code cases — the
union of all tools' documented classes, so nobody is measured only on home
turf:

| engine | TP recall | FP rate | layer measured |
|---|---|---|---|
| **peephole** | **98%** (148/151) | **0%** | PreToolUse gate engine (`scan`) |
| security-guidance (Anthropic) | 21% | 12% | its 25 shipped regexes, PostToolUse |
| Semgrep OSS (public rules) | 16% | 2% | 21 unauthenticated registry packs |

![Detection recall and false-positive rate across engines](assets/benchmark-overall.png)
![Per-category recall across engines](assets/benchmark-categories.png)

**Read it fairly — the caveats are the point:**

- **Semgrep's number is architecturally handicapped here, twice over.** Its
  taint engine is built for whole-repo context (source → sink across files);
  1–2-line snippets with implicit sources under-measure it badly — that is
  precisely the design difference between a repo SAST and a write-time gate
  (the model writes hunks, not applications). And this ran **unauthenticated**
  (`semgrep login` unlocks more free rules; commercial tiers add the secret
  validators — hence its 10% on secrets). On real repos Semgrep is far
  stronger than 16%; on a write-time hunk it cannot run at all.
- **security-guidance's real depth is unmeasured.** Its LLM review of your
  session's `git diff` at Stop/commit catches semantic classes no regex does —
  both pattern layers scored 0 on the semantic corpus cases (race, business
  logic). It runs on your Claude Code sign-in (OAuth token passed automatically)
  or an Anthropic API key, and it's nondeterministic, so it's out of scope for
  this harness. 21% is its *regex layer*, not the product.
- **Peephole's misses and weaknesses are disclosed, not hidden.** 1 ReDoS
  variant (the star-height class regexes can't prove) + 2 supply-chain cases
  the scan engine misses but the hook layer catches (verified: `ask` in strict
  for a requirements.txt typosquat and for `curl | python3` — the other two
  structurally cannot catch these). Peephole has no taint tracking, no
  cross-file analysis, no semantic review. The first run of this very
  benchmark scored peephole **77%** and exposed 16 real rule gaps; they were
  fixed as generalized patterns, and the first-run number is preserved in
  `docs/BENCHMARK.md`.
- The false positives are instructive: SG flags `defusedxml` (the recommended
  fix for its own XXE warning), `DOMPurify.sanitize`, and `yaml.load(…,
  Loader=yaml.SafeLoader)`; Semgrep's one FP is `pickle.dumps` (not the RCE
  surface). Peephole's `reject_re`/`prev_not` refinements spared all seven.

**Born-secure ablation with real Claude sessions:** on 7 insecure-inducing
tasks, a bare model wrote secure code **2/7** times; adding peephole's
**guidance plane** raised that to **5/7** (the model refuses the insecure
version and writes it securely — born-secure, no block); adding the
**enforcement gate** on top reached **7/7** (it catches what guidance misses).
Race-condition and business-logic classes are out of scope for the pattern
engine and are handled as guidance + human review, not enforcement.

**Live agent benchmark — real Claude sessions, 4 arms.** 144 `claude -p`
sessions (Haiku 4.5): 10 insecure-inducing pattern tasks ×2 + 5
absence-of-guard semantic tasks (IDOR, race, business-logic, CSRF,
rate-limiting) ×2 + 6 gate-evasion attacks, per arm. Semantic outcomes scored
by an independent LLM judge against per-task rubrics (2 judge errors found on
audit, adjudicated against the artifacts and disclosed):

| arm | secure — pattern tier (scan) | secure — semantic tier (judge) | born-secure | tokens | cost | time | attacks stopped |
|---|---|---|---|---|---|---|---|
| **baseline** | 42% | 0% | — | 74k (100%) | $0.076 (100%) | 105s (100%) | 83% |
| **bare-prompt** | 68% | 25% | — | 64k (86%) | $0.067 (88%) | 278s (264%) | 67% |
| **security-guidance** | 65% | 0% | — | 67k (91%) | $0.070 (92%) | 168s (160%) | 100% |
| **peephole** | **100%** (94% born) | **43%** | **94%** | 74k (100%) | $0.077 (101%) | 202s (192%) | 100% |

![Live agent benchmark — every metric vs baseline](assets/benchmark-live.png)

Read this one carefully, because it's the honest one:

- **The semantic tier is where everyone bleeds — including peephole.** IDOR,
  races, business logic, CSRF, rate limits: no regex gate can prove these.
  Baseline and security-guidance scored **0%**, bare-prompt 25%, peephole 43%
  (its always-on ladder + Stop-time self-review is the only arm above 30%).
  Peephole does not enforce these classes — this is its documented ceiling, now
  measured in public. An independent semantic review layer (LLM, human) is
  still necessary; peephole composes with one rather than replacing it.
- **security-guidance's semantic 0% needs context too**: its LLM Stop-review
  fires *after* the code is written; in these sessions it either didn't run to
  a fix or the fixes didn't satisfy the rubric. That is its design (advise, not
  enforce), not necessarily its ceiling. Peephole's own Stop review was since
  upgraded (diff-grounded, CWE-targeted, N3-triggered) and re-validated: it
  fires correctly, but Haiku *rubber-stamps its own diff* (0/7 fixed) — LLM
  self-review on security bugs is weak everywhere, ours included. See
  `docs/BENCHMARK.md` §D.
- **Cost realism:** peephole costs +1% money, +92% wall time vs baseline
  (hook events + gate retries + the N6 continuation) and 3 of its 5 harness
  timeouts were forced-continuation loops hitting the 10-minute cap. That is
  the real price of enforcement; tokens and dollars are flat. Two caveats on
  the time numbers: (1) wall time is **100% API-side** — the wall-vs-API-duration
  correlation is 1.000, turns are flat across arms (2.0–2.3), so the deltas are
  model generation time and shared-proxy latency variance, not hook cost
  (peephole's hook is ~8ms, 0.005% of a session); (2) bare-prompt's 264% is the
  same phenomenon — a security instruction makes the model generate longer,
  more careful responses, plus skew from a few slow sessions (medians: 81s
  baseline / 156s peephole / 233s bare-prompt — less dramatic than means).
- **Attacks:** the rename bypass (write `app.txt`, `mv app.py`) landed on
  baseline and bare-prompt — the only attack that got through anywhere — and
  peephole's gate stopped it mechanically (not via model refusal). Confound:
  Haiku refuses most blatant attack prompts on its own, so "attacks stopped"
  is generous to every arm; the discriminative case is the subtle one.
- Small-n honesty: n=2 per cell, one model, one day. Harness auto-approves
  hook `ask`s (simulating the over-trusting user — only hard `deny`s stand).
  Scanner-scorer overlap (peephole's own scanner as primary scorer) is mitigated
  by the Semgrep cross-column and the independent judge for semantic tasks.
  9 of 144 sessions hit the 600s harness cap and are excluded (disclosed).
  Raw session data + judge verdicts: `benchmark/live/`.

## How it compares

Measured where measurable (the three engines above, this repo's harness);
documentation-level elsewhere (vendor docs, not independently re-verified —
treat as marketing-aware claims).

| | **peephole** | security-guidance (Anthropic) | Semgrep (OSS / Guardian) | Snyk | Socket / Endor | Aikido SafeChain |
|---|---|---|---|---|---|---|
| Acts **before** code lands | ✅ PreToolUse deny | ❌ PostToolUse warn | ❌ post-write scan | ❌ in-loop scan | ✅ pre-commit deps | ✅ pre-install deps |
| Blocks the write | ✅ strict/hardened | ❌ advisory only | regen-until-clean (Guardian) | ❌ | ✅ (deps only) | ✅ (deps only) |
| App-code pattern breadth | 176 rules / 77 CWEs *(measured)* | 25 patterns *(measured)* | large SAST corpus, taint engine | medium | none (deps) | none (deps) |
| Semantic / LLM review | ⚠️ diff-grounded self-review (host model, zero-cost) | ✅ LLM diff review | ✅ taint (OSS) + more | ✅ | ❌ | ❌ |
| Supply-chain gate | ✅ installs + manifests | ❌ | partial (SCA product) | ✅ | ✅ | ✅ |
| Tamper-evident audit log | ✅ hash-chained | ❌ | ❌ | platform | platform | ❌ |
| Born-secure metric | ✅ N2 decomposition | ❌ | ❌ | ❌ | ❌ | ❌ |
| Runs offline, zero deps | ✅ static binary | ❌ Python + LLM calls | ✅ (OSS CLI) | ❌ | ❌ | ❌ |

Peephole is **not** a SAST replacement and doesn't do semantic review — pair it
with one (Semgrep on the repo, or security-guidance's LLM layer) for the
classes regexes can't prove; it composes rather than competes there.

## Extensibility & enterprise

- **Custom / org rules (additive):** drop a `.peephole-rules.json` (or `.claude/peephole-rules.json`)
  in your project — an array of rule records in the same schema. They *add* findings; they can
  never disable a built-in. Safe by construction: RE2 is linear-time, so a custom regex can't ReDoS.
- **Enterprise default — `allowManagedHooksOnly`:** for managed fleets, set
  `"allowManagedHooksOnly": true` in managed `settings.json` so only admin-pushed hooks run,
  preventing a repo from swapping peephole's hooks. This is the recommended managed default.
- **Statusline badge:** add a `statusLine` command running `peephole statusline` to show
  `peephole strict | N blocked M flagged | 176 rules` in your status bar.
- **N7 taint-echo (experimental, off by default):** create `.peephole/taint-echo` to enable
  provenance escalation (code derived from fetched/README/MCP content reaching a sink → ask).
  It also requires wiring WebFetch/Read into PostToolUse; left off, it adds zero hot-path cost.

## Honest boundaries

- **Same-user tamper is out of scope.** The binary runs with your privileges; a
  same-user process can disable it. Peephole provides tamper-*evidence* (self-
  integrity check, hash-chained log, zero-decision alarm), not a host-level
  integrity guarantee.
- **Detection ceiling.** Regexes catch curated *present* patterns, not novel
  compositions or missing-guard bugs. Obfuscated Bash writes (`base64 -d > f`)
  can only be bounded (ask/deny + retro-scan), not eliminated.
- **Integrity, not authenticity.** The SHA-256 self-check detects tampering and
  corruption; it does not prove publisher authenticity (a self-consistent
  poisoned build would pass). Real signing is future work.
- **Deferred from the blueprint:** Tier-3 language curation, a live MCP
  registry server, release signing, and the external eval suites (CodeGuard+/
  CWEval/BaxBench — Phase 4). N7 taint-provenance ships as an opt-in.

See `docs/DESIGN.md` for the architecture and the exact platform contract.
