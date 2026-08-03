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

Where the incumbent plugin warns *after* a write lands (PostToolUse,
detect-then-regenerate), peephole denies *before* it (PreToolUse): in
strict/hardened mode the insecure hunk never touches disk, so code is *born*
secure, not repaired. It's a single **static Go binary** — no Node, no Python,
no runtime — with a hook path under 10ms per event. See
[docs/DESIGN.md](docs/DESIGN.md) for the architecture and platform contract.

**Docs:** [Design](docs/DESIGN.md) · [Benchmark](docs/BENCHMARK.md) · [Integrations](docs/INTEGRATIONS.md) · [Review history](docs/REVIEW.md) · [Contributing](CONTRIBUTING.md) · [Security](SECURITY.md) · [Changelog](CHANGELOG.md)

> **Not just Claude Code.** The same binary gates writes in any hook-based agent,
> Gemini CLI, OpenAI Codex CLI, Qwen Code, Charm Crush, Block Goose, Cursor,
> OpenCode, Amp, via `peephole hook --exit2` (exit code 2 is the universal block
> signal), plus a universal `git pre-commit` backstop for everything else. See
> [docs/INTEGRATIONS.md](docs/INTEGRATIONS.md) for drop-in configs and a
> coverage matrix (which agents block pre-write vs. only advise).

## Install

**As a binary** (any agent, git hook, or CI). This detects your OS and
architecture, installs to your `PATH`, and smoke-tests it — macOS and Linux:

```sh
os=$(uname -s | tr '[:upper:]' '[:lower:]'); arch=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')
curl -fsSL "https://github.com/akashsebastian333/peephole/releases/latest/download/peephole-${os}-${arch}" -o peephole
chmod +x peephole && sudo mv peephole /usr/local/bin/peephole
peephole scan yourfile.py
```

Windows: download `peephole-windows-amd64.exe` from the
[latest release](https://github.com/akashsebastian333/peephole/releases/latest)
and add it to your `PATH`.

To verify the download against the release checksums before installing:

```sh
curl -fsSLO "https://github.com/akashsebastian333/peephole/releases/latest/download/SHA256SUMS"
shasum -a 256 -c SHA256SUMS --ignore-missing   # 'sha256sum -c' on Linux
```

Wiring for Gemini CLI, Codex, Cursor, MCP/LSP editors, and a universal
`git pre-commit` hook is in [docs/INTEGRATIONS.md](docs/INTEGRATIONS.md).

**As a Claude Code plugin** (local CLI, desktop, or the web/cloud IDE). Add the
marketplace and install — hooks auto-register, default mode is **strict**:

```
/plugin marketplace add akashsebastian333/peephole
/plugin install peephole@peephole
```

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

Only hooks and in-process plugins can *veto* a write pre-emptively. Most editors
expose only post-hoc events or diagnostics, so there peephole *advises* (MCP/LSP)
and the real block is the git pre-commit hook.

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

Beyond single-line patterns, a framework-level **cross-line taint** pass tracks
values built from user input, dynamic strings, or secrets and flags them when
they reach a sink on a *different* line (SSTI, SQL, OS-command, eval,
deserialization, XSS, SSRF, path, open redirect, secrets-in-logs, exfiltration).
It clears on sanitizers (`int()`, `shlex.quote()`, `escape()`), so validated or
static values are not flagged; guard-dependent classes (SSRF, redirect, path)
*ask* rather than hard-deny.

Coverage spans **31 language/format buckets** — beyond app code, also smart
contracts (Solidity), infrastructure-as-code (Terraform/K8s/Dockerfile),
CI/supply-chain config, mobile (iOS/Android), SQL scripts, web-server config, and
framework footguns (Django/Flask, Express/Next, Spring, Rails/Laravel, Go
templates). Full list in [docs/DESIGN.md](docs/DESIGN.md).

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
code scanning, Azure DevOps, and most SAST dashboards — machine-readable evidence
for regulated teams. `/sec-audit` rolls decisions up to OWASP 2025.

## Benchmarks

Measured two ways; full methodology, latency analysis, multi-model runs, and
honesty caveats are in [docs/BENCHMARK.md](docs/BENCHMARK.md) (harness in
`benchmark/`, re-runnable end to end).

**Detection benchmark, three engines, identical inputs.** 151 labeled vulnerable
cases across 24 CWE classes + 50 benign cases, the union of all tools' documented
classes so nobody is measured only on home turf:

| engine | TP recall | FP rate | layer measured |
|---|---|---|---|
| **peephole** | **98%** (148/151) | **0%** | PreToolUse gate engine (`scan`) |
| security-guidance (PostToolUse) | 21% | 12% | its 25 shipped regexes, PostToolUse |
| Semgrep OSS (public rules) | 16% | 2% | 21 unauthenticated registry packs |

![Detection recall and false-positive rate across engines](assets/benchmark-overall.png)
![Per-category recall across engines](assets/benchmark-categories.png)

Caveats matter here (Semgrep is architecturally handicapped on 1–2-line hunks;
security-guidance's LLM diff-review layer is out of scope for this harness) — see
[docs/BENCHMARK.md](docs/BENCHMARK.md).

**Live agent benchmark, real Claude sessions, 4 arms** (Haiku 4.5). The headline
metric is **insecure code landed per attempt** — did insecure code reach disk —
scored independently by Semgrep with an out-of-family LLM judge on the semantic
tier:

| arm | insecure-landed / attempt (lower=better) | secure-landed | semantic | time |
|---|---|---|---|---|
| baseline | 46% (raw 54%) | 46% | 0% | 19s (100%) |
| bare-prompt | 16% (raw 16%) | 84% | 25% | 17s (90%) |
| security-guidance | 50% (raw 52%) | 36% | 0% | 17s (90%) |
| **peephole** | **0%** (raw 10%) | **98%** | **84%** | 26s (134%) |

![Live agent benchmark: insecure-landed per attempt and the per-attempt outcome mix](assets/benchmark-live.png)

peephole lands insecure code least (0%) *and* writes secure code most (98% of
attempts), while leading the absence-of-guard semantic tier at 84% via a
Stop-time adversarial self-review. The cost is ~134% wall time (deny-and-rewrite
turns; the hook itself is ~8ms).

**Across models (is it a Haiku artifact?)** The same corpus, arms, and
independent Semgrep grader were re-run on three more models — Claude Sonnet 4.5,
GLM-5.2, and Kimi-K3 (the last two via a gateway). Same uniform correction,
nothing tuned per model.

![Insecure code landed per attempt across four models](assets/benchmark-multimodel.png)

| model | baseline | bare-prompt | security-guidance | peephole | peephole secure-landed |
|---|---|---|---|---|---|
| Haiku 4.5 | 46% | 16% | 50% | **0%** | 98% |
| Sonnet 4.5 | 45% | 5% | 25% | **0%** | 95% |
| GLM-5.2 | 45% | 0% | 15% | **0%** | 80% |
| Kimi-K3 | 35% | 5% | 30% | **0%** | 90% |

*(insecure code landed per attempt, lower is better; 2 runs/task, small n, directional)*

- **peephole lands 0% insecure across all four models** — versus 35-46% baseline,
  0-16% for a one-line prompt, and 15-50% for security-guidance: the guidance
  plane is not a Haiku artifact.
- **The 0% rests on a false-positive correction, and that is disclosed and
  audited.** Uncorrected, Semgrep flags peephole on 10/15/20/10% of attempts;
  every one was verified per file as a genuine Semgrep FP on secure code (a JWT
  secret from `os.environ`, an HTML-escaped `return f"...{escape(x)}..."`, an argv
  `subprocess(..., shell=False)`). The **same** correction is applied to every arm
  — it lowers competitors' rates too (Haiku baseline 54→46%), so it is not a
  peephole thumb on the scale. Full audit: [docs/BENCHMARK.md](docs/BENCHMARK.md).
- **Productivity holds:** peephole lands secure code on 80-98% of attempts across
  models. GLM is the low end (80%): its deny on the reflected-XSS task cost two
  sessions a final file rather than an insecure one — reported, not hidden.

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
regexes can't prove; it composes rather than competes there. Extensibility, org
policy, enterprise defaults, and the full limitations list are in
[docs/DESIGN.md](docs/DESIGN.md).
