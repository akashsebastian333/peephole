<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/wordmark-dark.svg">
    <img src="assets/wordmark-light.svg" alt="peephole" width="420">
  </picture>
</p>

<p align="center">
  <b>Born-secure enforcement for AI coding assistants.</b>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/license-MIT-C79A3B" alt="MIT license">
  <img src="https://img.shields.io/badge/go-1.26-00ADD8" alt="Go 1.26">
  <img src="https://img.shields.io/badge/rules-177%20CWE-0F1420" alt="177 CWE rules">
  <img src="https://img.shields.io/badge/languages-31-0F1420" alt="31 languages">
  <img src="https://img.shields.io/badge/deps-0-brightgreen" alt="zero dependencies">
</p>

Peephole is a security gate for AI coding agents. It blocks insecure code at
*write time*, before it lands on disk, and records every decision in a
CWE-mapped, tamper-evident audit log. *Never open the door before checking who's
on the other side, and never ship code before checking what's in it.*

**Docs:** [Design](docs/DESIGN.md) · [Benchmark](docs/BENCHMARK.md) · [Integrations](docs/INTEGRATIONS.md) · [Review history](docs/REVIEW.md) · [Contributing](CONTRIBUTING.md) · [Security](SECURITY.md) · [Changelog](CHANGELOG.md)

> **Not just Claude Code.** The same binary gates writes in any hook-based agent,
> Gemini CLI, OpenAI Codex CLI, Qwen Code, Charm Crush, Block Goose, Cursor,
> OpenCode, Amp, via `peephole hook --exit2` (exit code 2 is the universal block
> signal), plus a universal `git pre-commit` backstop for everything else. See
> [docs/INTEGRATIONS.md](docs/INTEGRATIONS.md) for drop-in configs and a
> coverage matrix (which agents block pre-write vs. only advise).

## The difference

The incumbent plugin (security-guidance) wires its regexes to **PostToolUse**: it
warns *after* the insecure code is already written, then hopes the model
regenerates it. That proves code was *repaired* secure.

Peephole wires the same class of check to **PreToolUse** and returns
`permissionDecision: deny` *before* the write lands. In strict/hardened mode the
insecure hunk never touches disk. That proves code was *born* secure, and it
closes the Bash escape hatch (`cat > f <<EOF …`) that a plain Write-tool gate
misses.

## How it's built

A single **static Go binary**, cross-compiled for macOS/Linux/Windows and shipped
in `bin/`; you install **no runtime** (not Node, not Python). The full hook path
measures **under 10ms per event**: the launcher execs the cached binary directly,
the CWE knowledge base ships as build-time-generated Go literals with precomputed
prefilters (so `loadKB` is ~7µs, not ~2ms), and a detached SessionStart
`warmcache` pre-warms the slopsquat cache so the first install verdict skips a
cold ~500ms registry round-trip. If your platform has no matching binary, the
launcher exits cleanly with a notice and never blocks your work.

The CWE knowledge base is embedded into the binary (`go:embed`), so a local
attacker can't quietly edit rule files the binary ignores, and there's no file
I/O to load rules on the hot path.

## Install

**As a binary** (any agent, git hook, or CI). Grab the build for your platform
from the [latest release](https://github.com/akashsebastian333/peephole/releases/latest)
and put it on your `PATH`:

```sh
# swap the suffix for your platform: peephole-darwin-arm64 · peephole-darwin-amd64
#   peephole-linux-amd64 · peephole-linux-arm64 · peephole-windows-amd64.exe
curl -fsSL https://github.com/akashsebastian333/peephole/releases/latest/download/peephole-darwin-arm64 -o peephole
chmod +x peephole && sudo mv peephole /usr/local/bin/peephole
peephole scan yourfile.py          # smoke test
```

Checksums for every asset are in `SHA256SUMS` on the release. Wiring for Gemini
CLI, Codex, Cursor, MCP/LSP editors, and a universal `git pre-commit` hook is in
[docs/INTEGRATIONS.md](docs/INTEGRATIONS.md).

**As a Claude Code plugin.** Point Claude Code at this directory as a plugin (or
install from the marketplace). The plugin auto-registers its hooks via
`hooks/hooks.json`; default mode is **strict**.

## Supported agents & IDEs

The engine is a single binary (stdin event → allow/ask/deny); only the
integration point differs per host. Drop-in configs are in [`integrations/`](integrations/);
full setup and the coverage rationale are in
[docs/INTEGRATIONS.md](docs/INTEGRATIONS.md).

| Integration | Blocks before write? | Agents / IDEs |
|---|---|---|
| **Native pre-tool hook**: `peephole hook --exit2` | **Yes, hard** | Claude Code · Gemini CLI · OpenAI Codex CLI · Qwen Code · Charm Crush · Block Goose · Cursor *(shell + MCP paths)* |
| **In-process plugin**: shells to the hook | **Yes, hard** | OpenCode · Sourcegraph Amp · OpenHands · Cline (SDK) |
| **git pre-commit**: `peephole scan --gate --staged` | **Yes, at commit** | Universal, any git repo (Aider auto-commits, so effectively per edit) |
| **MCP server**: `peephole mcp` | Advisory | Windsurf · Trae · Tongyi Lingma (通义灵码) · Comate (文心快码) · CodeGeeX · iFlyCode · Qoder · + the MCP mode of any CLI agent |
| **LSP diagnostics**: `peephole lsp` | Warn only | Zed · JetBrains AI · VS Code / GitHub Copilot |

Caveat: hooks and in-process plugins are the only surfaces that can *veto*
a write pre-emptively. Most editors (VS Code/Copilot, Cursor file-edits,
Windsurf, Zed, Trae, Tongyi Lingma, Comate, CodeGeeX, iFlyCode, Qoder) expose
only post-hoc events or diagnostics, so there peephole *advises* (MCP/LSP) and
the real block is the git pre-commit hook.

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
weak crypto (327), disabled security controls (1188), environment/secret
exfiltration to a network sink (200, the "add telemetry" confused-deputy leak),
and hallucinated/slopsquatted package installs. Bash payloads (heredocs,
`python -c`, redirects) are extracted and scanned through the same engine.

**Cross-line taint (framework-level).** Beyond single-line patterns, a general
intra-file taint pass tracks values built from user input, dynamic strings, or
secrets and flags them when they reach a sink on a *different* line, across every
class at once: SSTI, SQL, OS-command, code-eval, deserialization, XSS, SSRF
(918), path traversal (22), open redirect (601), secrets in logs (532), and
environment/secret exfiltration (200). It follows real references (interpolation,
concatenation), clears on sanitizers (`int()`, `shlex.quote()`, `escape()`) and
redaction, and checks the actual variable in the sink, so a validated or static
value is not flagged. Findings whose safety depends on a validation guard a
pattern engine cannot see (SSRF, redirect, path) *ask* rather than hard-deny.

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

- `/peephole`: show or change enforcement mode.
- `/sec-review`: review the current changes, including the absence-of-guard classes.
- `/sec-debt`: explain and list human-authorized security trade-offs.
- `/sec-audit`: mode, integrity, born-secure decomposition, decision tally by CWE and OWASP 2025, tamper-evident log status.

## Reporting & compliance

`peephole scan <files>` prints CWE findings; `peephole sarif <files>` emits a
SARIF 2.1.0 report (with `security-severity` and CWE/OWASP-2025 tags) for GitHub
code scanning, Azure DevOps, and most SAST dashboards, machine-readable
evidence for regulated teams. `/sec-audit` rolls decisions up to OWASP 2025.

## Build & test

```sh
./build.sh      # regenerate rules_gen.go, cross-compile all targets, regen integrity manifest
go test ./...   # end-to-end hook contract tests + KB self-consistency + tamper tests
```

## Benchmarks

Measured two ways (`docs/BENCHMARK.md`, harness in `benchmark/`,
re-runnable end to end).

**Detection benchmark, three engines, identical inputs.** 151 labeled
vulnerable cases across 24 CWE classes + 50 benign everyday-code cases, the
union of all tools' documented classes, so nobody is measured only on home
turf:

| engine | TP recall | FP rate | layer measured |
|---|---|---|---|
| **peephole** | **98%** (148/151) | **0%** | PreToolUse gate engine (`scan`) |
| security-guidance (PostToolUse) | 21% | 12% | its 25 shipped regexes, PostToolUse |
| Semgrep OSS (public rules) | 16% | 2% | 21 unauthenticated registry packs |

![Detection recall and false-positive rate across engines](assets/benchmark-overall.png)
![Per-category recall across engines](assets/benchmark-categories.png)

**Caveats:**

- **Semgrep's number is architecturally handicapped here, twice over.** Its
  taint engine is built for whole-repo context (source → sink across files);
  1–2-line snippets with implicit sources under-measure it badly. That is
  precisely the design difference between a repo SAST and a write-time gate
  (the model writes hunks, not applications). And this ran **unauthenticated**
  (`semgrep login` unlocks more free rules; commercial tiers add the secret
  validators, hence its 10% on secrets). On real repos Semgrep is far
  stronger than 16%; on a write-time hunk it cannot run at all.
- **security-guidance's real depth is unmeasured.** Its LLM review of your
  session's `git diff` at Stop/commit catches semantic classes no regex does;
  both pattern layers scored 0 on the semantic corpus cases (race, business
  logic). It runs on your Claude Code sign-in (OAuth token passed automatically)
  or an Anthropic API key, and it's nondeterministic, so it's out of scope for
  this harness. 21% is its *regex layer*, not the product.
- **Known misses.** 1 ReDoS
  variant (the star-height class regexes can't prove) + 2 supply-chain cases
  the scan engine misses but the hook layer catches (verified: `ask` in strict
  for a requirements.txt typosquat and for `curl | python3`, the other two
  structurally cannot catch these). Peephole has no taint tracking, no
  cross-file analysis, no semantic review. The first run of this very
  benchmark scored peephole **77%** and exposed 16 real rule gaps; they were
  fixed as generalized patterns, and the first-run number is preserved in
  `docs/BENCHMARK.md`.
- False positives: SG flags `defusedxml` (the recommended
  fix for its own XXE warning), `DOMPurify.sanitize`, and `yaml.load(…,
  Loader=yaml.SafeLoader)`; Semgrep's one FP is `pickle.dumps` (not the RCE
  surface). Peephole's `reject_re`/`prev_not` refinements spared all seven.

**Born-secure ablation with real Claude sessions:** on 7 insecure-inducing
tasks, a bare model wrote secure code **2/7** times; adding peephole's
**guidance plane** raised that to **5/7** (the model refuses the insecure
version and writes it securely, born-secure, no block); adding the
**enforcement gate** on top reached **7/7** (it catches what guidance misses).
Race-condition and business-logic classes are out of scope for the pattern
engine and are handled as guidance + human review, not enforcement.

**Live agent benchmark, real Claude sessions, 4 arms** (Haiku 4.5, 5 runs per
task: 200 main + 60 semantic + 24 adversarial sessions). The headline metric is
**insecure code landed per attempt** (did insecure code reach disk), scored
independently by Semgrep with an out-of-family LLM judge on the semantic tier.
Regenerate with `python benchmark/live/report.py`.

| arm | insecure-landed / attempt (lower=better) | secure-landed | refused | secure when it wrote | semantic | cost | time |
|---|---|---|---|---|---|---|---|
| **baseline** | 46% (raw 54%) | 46% | 8% | 50% | 0% | $0.037 (100%) | 19s (100%) |
| **bare-prompt** | 16% (raw 16%) | 84% | 0% | 84% | 25% | $0.034 (94%) | 17s (90%) |
| **security-guidance** | 50% (raw 52%) | 36% | 14% | 42% | 0% | $0.035 (97%) | 17s (90%) |
| **peephole** | **0%** (raw 10%) | **98%** | 2% | 100% | **84%** | $0.044 (120%) | 26s (134%) |

![Live agent benchmark: insecure-landed per attempt and the per-attempt outcome mix](assets/benchmark-live.png)

- **peephole lands insecure code least (0%) and writes secure code most (98% of
  attempts).** It leads every arm on both axes: 0% insecure-landed vs bare-prompt
  16%, security-guidance 50%, baseline 46%; and 98% secure-landed vs bare-prompt's
  84%. When it writes, it is 100% secure (independently graded). Under peephole
  the model wrote zero eval / command-injection / SQLi / JWT vulnerabilities.
- **It writes the secure version instead of refusing.** An earlier build refused
  68% of these insecure-inducing tasks: safe, but useless to a developer. The
  guidance now tells the model to deliver the same functionality the secure way
  and never leave the file unwritten, while the gate denies any insecure attempt
  and the model rewrites. Refusal fell to 2%, secure-landed rose from 30% to 98%,
  and insecure-landed stayed at 0%.
- **The cost is latency, and it is now modest.** Born-secure code takes some
  deny-and-rewrite and review turns, so peephole runs at ~120% of baseline dollars
  and ~134% wall time. It used to be 153%/209% until the Stop self-review was made
  **conditional and class-scoped** (it fires only when the landed code actually
  touches an absence-of-guard class, skipping the continuation for the ~80% of
  pattern-tier code that touches none), cutting turns from 3.9 to 2.7, near
  baseline's 2.2. That remaining time is model generation (the hook is ~8ms).
- **Grader honesty:** Semgrep false-positives the secure static-template SSTI
  pattern (a static Jinja template with user input passed as context). It is
  corrected uniformly across all arms (a template flag counts only when the
  template is dynamically built); the uncorrected number is in (raw). bare-prompt
  does not move under the correction, so it is not cherry-picked.
- **Completion:** all arms complete every session (0 timeouts). peephole's
  terminating guardrail bounds the deny-retry loop that used to hang it.
- **The semantic tier used to be everyone's ceiling; peephole now leads it at
  84%.** IDOR, races, business logic, CSRF, rate limits are absence-of-guard
  classes no pattern engine can prove. Baseline and security-guidance score 0%,
  bare-prompt 25%. peephole reaches **84%** (IDOR, races, rate-limiting all at
  100%) via a Stop-time **adversarial self-review**: for each applicable class the
  model must quote the exact guarding line or mark it ABSENT and fix it before
  finishing ("looks fine" is disallowed). Grounded in RCI self-critique (Tony et
  al. 2024), adversarial critique (INDICT, NeurIPS 2024), and the horizontal-
  privilege replay test. This is guidance, not a static guarantee, but it moves
  the classes a scanner fundamentally cannot.
- Sample size: 5 runs per task, one model, one day; directional, not a headline.
  The harness auto-approves hook `ask`s (only hard `deny`s stand). Raw session
  data + judge verdicts: `benchmark/live/`.

**Across models (does the guidance generalize, or is it a Haiku artifact?)** The
same corpus, arms, and independent Semgrep grader were run on three more models:
Claude Sonnet 4.5, GLM-5.2, and Kimi-K3 (the last two via a gateway). Same
uniform correction, nothing tuned per model.

![Insecure code landed per attempt across four models](assets/benchmark-multimodel.png)

| model | baseline | bare-prompt | peephole | peephole secure-landed |
|---|---|---|---|---|
| Haiku 4.5 | 46% | 16% | **0%** | 98% |
| Sonnet 4.5 | 45% | 5% | **0%** | 95% |
| GLM-5.2 | 50% | 0% | **0%** | 90% |
| Kimi-K3 | 35% | 5% | **0%** | 90% |

*(insecure code landed per attempt, lower is better; 2 runs/task, small n, directional)*

- **peephole lands 0% insecure across all four models**, versus 35-50% baseline
  and 0-16% for a one-line prompt: the guidance plane is not a Haiku artifact.
- **Every apparent peephole "miss" was verified, per file, to be a Semgrep false
  positive on secure code** (a JWT secret read from `os.environ`, an HTML-escaped
  `return f"...{escape(x)}..."`, an argv `subprocess(..., shell=False)`) that
  peephole correctly does *not* flag. The same verified correction is applied to
  every arm; on GLM peephole's raw reflected-XSS attempt was denied and the model
  added `escape()`, born-secure. peephole's lower false-positive rate here is the
  point: it beats the scanner *without* the friction of flagging safe code.
- **Productivity holds across models:** peephole lands secure code on 90-98% of
  attempts, with low refusal, on all four.
- What a prompt cannot do that peephole can: the prompt is advisory (a jailbreak
  or a different task removes it) and its effect varies by model; the gate is
  enforced and deterministic. The adversarial and semantic tiers, where that gap
  shows, were run on Haiku only.

## How it compares

Measured where measurable (the three engines above, this repo's harness);
documentation-level elsewhere (vendor docs, not independently re-verified,
treat as marketing-aware claims).

| | **peephole** | security-guidance (PostToolUse) | Semgrep (OSS / Guardian) | Snyk | Socket / Endor | Aikido SafeChain |
|---|---|---|---|---|---|---|
| Acts **before** code lands | ✅ PreToolUse deny | ❌ PostToolUse warn | ❌ post-write scan | ❌ in-loop scan | ✅ pre-commit deps | ✅ pre-install deps |
| Blocks the write | ✅ strict/hardened | ❌ advisory only | regen-until-clean (Guardian) | ❌ | ✅ (deps only) | ✅ (deps only) |
| App-code pattern breadth | 176 rules / 77 CWEs *(measured)* | 25 patterns *(measured)* | large SAST corpus, taint engine | medium | none (deps) | none (deps) |
| Semantic / LLM review | ⚠️ diff-grounded self-review (host model, zero-cost) | ✅ LLM diff review | ✅ taint (OSS) + more | ✅ | ❌ | ❌ |
| Supply-chain gate | ✅ installs + manifests | ❌ | partial (SCA product) | ✅ | ✅ | ✅ |
| Tamper-evident audit log | ✅ hash-chained | ❌ | ❌ | platform | platform | ❌ |
| Born-secure metric | ✅ N2 decomposition | ❌ | ❌ | ❌ | ❌ | ❌ |
| Runs offline, zero deps | ✅ static binary | ❌ Python + LLM calls | ✅ (OSS CLI) | ❌ | ❌ | ❌ |

Peephole is **not** a SAST replacement and doesn't do semantic review. Pair it
with one (Semgrep on the repo, or security-guidance's LLM layer) for the classes
regexes can't prove; it composes rather than competes there.

## Extensibility & enterprise

- **Custom / org rules (additive):** drop a `.peephole-rules.json` (or `.claude/peephole-rules.json`)
  in your project, an array of rule records in the same schema. They *add* findings; they can
  never disable a built-in. Safe by construction: RE2 is linear-time, so a custom regex can't ReDoS.
- **Org enforcement policy (`.peephole-policy.json`, committed):** beyond guidance
  values (`{"global": [...], "CWE-89": [...]}`, injected before generation), an org
  can make the gate *stricter*, never weaker:
    - `"enforce": ["CWE-89", "CWE-327"]` mandates those classes to a hard **deny**
      in every mode; a `sec-debt` marker cannot waive an org-mandated class.
    - `"min_mode": "strict"` (or `"hardened"`) is an org **floor**: the effective
      mode is never weaker than this, even if a repo sets a lower one.
  Both are **escalation-only by design**, so a poisoned committed file can only
  raise enforcement, never disable it. Values are Unicode/injection-scanned before
  they can reach model context.
- **Enterprise default (`allowManagedHooksOnly`):** for managed fleets, set
  `"allowManagedHooksOnly": true` in managed `settings.json` so only admin-pushed hooks run,
  preventing a repo from swapping peephole's hooks. This is the recommended managed default.
- **Statusline badge:** add a `statusLine` command running `peephole statusline` to show
  `peephole strict | N blocked M flagged | 177 rules` in your status bar.
- **N7 taint-echo (experimental, off by default):** create `.peephole/taint-echo` to enable
  provenance escalation (code derived from fetched/README/MCP content reaching a sink → ask).
  It also requires wiring WebFetch/Read into PostToolUse; left off, it adds zero hot-path cost.

## Limitations

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
  CWEval/BaxBench, Phase 4). N7 taint-provenance ships as an opt-in.

See `docs/DESIGN.md` for the architecture and the exact platform contract.
