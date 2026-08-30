<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/wordmark-dark.svg">
    <img src="assets/wordmark-light.svg" alt="peephole" width="420">
  </picture>
</p>

<p align="center">
  <b>A seatbelt for coding agents — they ship secure code.</b>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-0.5.1-C79A3B" alt="version 0.5.1">
  <img src="https://img.shields.io/badge/license-MIT-C79A3B" alt="MIT license">
  <img src="https://img.shields.io/badge/go-1.26-00ADD8" alt="Go 1.26">
  <img src="https://img.shields.io/badge/rules-181-0F1420" alt="181 rules">
  <img src="https://img.shields.io/badge/deps-0-brightgreen" alt="zero dependencies">
</p>

Peephole is a **plugin for coding agents**. It shows the model the secure
pattern as it works, then can **ask or deny before a file is saved**, so
insecure code does not land. It installs on Claude Code, Grok Code, Gemini CLI,
Codex, Cursor, OpenCode, Qwen Code, and Crush, and also at `git pre-commit` or
as an MCP/LSP checker. Default mode is **`guided`**: you see the finding and decide.
**`strict`** and **`hardened`** block high-confidence issues at write time.
Every decision is recorded in a tamper-evident audit log, kept for 30 days.

**Docs:** [Design](docs/DESIGN.md) · [Architecture](docs/ARCHITECTURE.md) · [Threat model](docs/THREAT_MODEL.md) · [Benchmark](docs/BENCHMARK.md) · [Integrations](integrations/README.md) · [Organizations](docs/ENTERPRISE.md) · [Changelog](CHANGELOG.md)

## Install

**Claude Code** — those two commands clone the plugin, enable it, and register
hooks and skills. Default mode is `guided`. Restart Claude Code once. There is
no extra `settings.json` to write.

```
/plugin marketplace add akashsebastian333/peephole
/plugin install peephole@peephole
```

**Grok Code** — same marketplace, then install with `--trust` so hooks run.
Default mode is `guided`. Grok has no ask prompt: deny still blocks the write;
ask is allow. Restart Grok once. There is no extra `settings.json` to write.

```
grok plugin marketplace add akashsebastian333/peephole
grok plugin install peephole --trust
```

**Gemini CLI, Codex, Cursor, OpenCode, Qwen Code, Crush** — drop-in hook or
plugin configs. Install the engine, then add the host file from
[`integrations/`](integrations/). How each host is wired:
[integrations/README.md](integrations/README.md).

```sh
os=$(uname -s|tr '[:upper:]' '[:lower:]'); arch=$(uname -m|sed 's/x86_64/amd64/;s/aarch64/arm64/')
curl -fsSL "https://github.com/akashsebastian333/peephole/releases/latest/download/peephole-${os}-${arch}" -o peephole
chmod +x peephole && sudo mv peephole /usr/local/bin/peephole
peephole version
```

Windows: `peephole-windows-amd64.exe` from the
[latest release](https://github.com/akashsebastian333/peephole/releases/latest).
Checksums are in `SHA256SUMS`. Pin a fleet to `v0.5.1`. From source: `./build.sh`.
`peephole selfcheck` needs the plugin tree (`bin/manifest.sha256`) or the pin
the fleet installer writes next to the binary — a bare copy into `/usr/local/bin`
will not pass it. Fleet installers: [`deploy/`](deploy/). Org policy, custom
rules, and rollout: [docs/ENTERPRISE.md](docs/ENTERPRISE.md). git / MCP / LSP:
[`integrations/`](integrations/).

## Agents

Plugin and hook files: [`integrations/`](integrations/). The engine answers
allow, ask, or deny.

| Path | Blocks before write? | Hosts |
|---|---|---|
| `peephole hook` | **Yes** (deny; ask is a prompt) | Claude Code |
| `peephole hook` | **Yes** (deny; ask is allow) | Grok Code |
| `peephole hook --exit2` | **Yes** (deny only) | Gemini CLI · Codex CLI · Qwen Code · Crush · Cursor |
| OpenCode plugin | **Yes** | OpenCode |
| `peephole scan --gate --staged` | At commit | Any git repo |
| `peephole mcp` / `peephole lsp` | Advisory | MCP/LSP editors |

Claude Code uses the JSON dialect (`permissionDecision`) without `--exit2`.
Grok Code uses the same binary and also reads top-level `decision`; ask is
allow. Exit-2 hosts honor **deny** only; `ask` findings pass through. Details:
[integrations/README.md](integrations/README.md).

## Modes

| Mode | Behavior |
|---|---|
| `guided` | **Default.** Findings are asks. Self-protection and org mandates still deny. |
| `audit` | Log only. Org-`enforce` CWEs and self-protection still deny. |
| `strict` | Deny high-confidence CWEs; ask on lower-confidence. |
| `hardened` | Deny-by-default, including unverified installs. |
| `off` | Disabled. Self-protection still denies writes to peephole's own paths. |

`/peephole strict` or `peephole mode strict`. Tamper of the mode file fail-closes to `strict`.

## What it catches

At the prompt it injects the secure pattern. At the write it scans presence plus
Python/JS/Go/Rust cross-line taint: SQLi, command injection, eval/exec, XSS,
pickle/yaml, path traversal, secrets, weak crypto, SSTI, JWT verify-off, SSRF,
exfil. Bash heredocs and `python -c` go through the same engine. Slopsquat
installs and manifest typos are hook-layer, not `scan`.

Not blocked from one hunk (can't be proven): IDOR, CSRF, missing auth, races.
Those are forced at **Stop** and on **commit**, and listed by `/sec-review`.

## Skills

`/peephole` mode · `/sec-review` current diff · `/sec-debt` authorized exceptions · `/sec-audit` CWE/OWASP tally.

`peephole scan <files>` · `peephole sarif <files>` (SARIF 2.1.0).

## Benchmarks

Complete mini-files, sliced so an engine is not scored on a class it does not
ship. Methodology: [docs/BENCHMARK.md](docs/BENCHMARK.md).

| engine | shared TP (45) | FP (40 benign) |
|---|---|---|
| **peephole** | **45/45** | **0/40** |
| security-guidance | 37/45 | 4/40 |
| Semgrep OSS | 25/45 | 3/40 |

SAST slice (SQLi / JWT / secrets / SSTI / path, 28 files): peephole **28/28**, Semgrep **20/28**.

![Detection recall and false-positive rate](assets/benchmark-overall.png)
![Recall by class](assets/benchmark-categories.png)

Live agents (requested vuln on disk, independent grader, n=20/arm Haiku):

| arm | insecure landed | refused | semantic (n=10) |
|---|---|---|---|
| baseline | 60% | 10% | 0% |
| security-guidance | 55% | 10% | 0% |
| **peephole** | **0%** | 0% | **80%** |

![Live per-attempt outcome](assets/benchmark-live.png)

Same grader, other models (insecure landed, n=20):

| model | baseline | security-guidance | peephole |
|---|---|---|---|
| Haiku 4.5 | 60% | 55% | **0%** |
| Sonnet 4.5 | 60% | 25% | **0%** |
| GLM | 75% | 30% | **10%** |
| Kimi | 80% | 35% | **0%** |

![Insecure landed across models](assets/benchmark-multimodel.png)

Small n, directional. GLM 10% is two saved artifacts (JWT `options=` dict
without a key, and a placeholder `AKIAxxxx…` AWS key) still on disk in
`benchmark/live/out_glm`. The current detector flags both as high. Kimi was a
comment-only grader false positive and is 0%.

## Compared to

Peephole is the **agent plugin**: it steers the model toward secure code, then
can block the write. It is not a whole-repo SAST. Missing-guard classes (IDOR,
CSRF, races) are reviewed at Stop and on commit. Pair with other SAST
tools in CI for cross-file taint.

| | peephole | security-guidance | Semgrep OSS |
|---|---|---|---|
| What it is | Agent plugin | Agent plugin | Repo scanner |
| Steers the agent | Before the write | After the write (LLM) | no |
| Blocks the write | strict/hardened | no | no |
| Missing-guard review | Stop + commit | LLM API | no |
| Offline, zero deps | static binary | Python + LLM | CLI |
| Audit log | hash-chained | no | no |
