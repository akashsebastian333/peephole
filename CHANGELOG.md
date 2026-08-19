# Changelog

All notable changes to Peephole are documented here. This project adheres to
[Semantic Versioning](https://semver.org/).

## [0.5.0] - 2026-08

Default mode is now **`guided`**: findings surface as prompts, never as a hard
block, unless an operator opts into `strict`/`hardened`. Everything below landed
after the `v0.4.0` tag was cut; see the note under 0.4.0.

### Developer-first default: `guided` mode
- A gate whose default hard-denies is only as good as its precision, and a wrong
  block is the single most reliable way to get a security tool switched off. The
  new default surfaces every finding as an `ask` and reserves hard denies for
  operators who choose `strict`/`hardened`, or for an org policy that mandates a
  CWE. Measured on live sessions: `deny=0 ask=0` on ordinary work, and an
  interruption rate of 0.0 per 20 write-gate decisions.

### Org enforcement policy (escalation-only)
- `.peephole-policy.json` / `.claude/peephole-policy.json` can raise a repo's
  floor (`min_mode`) and mandate hard denies for named CWEs (`enforce`). It can
  only ever escalate, never weaken a repo's own mode, and the floor is applied at
  every write surface (Write family, Bash write-path, MCP) rather than the Write
  tool alone. An org-mandated deny is not downgradable by the terminating-guardrail
  budget.

### Cross-host gating
- The exit-code dialect gated only Claude Code in practice; every other hook host
  was a silent no-op. All hook-based hosts are now gated, and eight further
  normalizer bypasses (Codex, Cline, Goose, Cursor spellings of the same event)
  are closed. Coverage claims in `docs/INTEGRATIONS.md` were corrected to stop
  overstating hosts with no working pre-tool hook.

### Deployability: precision, false negatives, and review cost
Found by driving the real hook in a project-local install plus live sessions.
- **Hard-coded secrets with compound names were invisible.** The generic
  credential pattern matched `secret` and then required `[:=]` immediately, so
  `SECRET_KEY`, `app.secret_key`, `JWT_SECRET_KEY`,
  `app.config["SECRET_KEY"]`, `signing_key`, `encryption_key` and the JS
  `secretKey` spelling all scanned clean — including Django's and Flask's
  session-signing secret.
- **PHP SQL injection via an intermediate variable** (`$q = "SELECT …" . $id;`
  then `$pdo->query($q)`) and the interpolated-string form are now caught; only
  the concat-directly-from-`$_GET` shape was covered before.
- **Prose files ran every language-agnostic pattern**, because `langOf()` has no
  entry for `.md`/`.rst`/`.adoc`. A README line reading "never run chmod 777" was
  denied, and a hardening guide's BAD example tripped the rule it was teaching.
  Documentation now keeps only the classes still real in prose (a committed
  credential is a leak in a README too) and skips the taint pass. `.txt` is
  deliberately excluded: `requirements.txt` is a dependency manifest.
- **Go's canonical file-creation idiom no longer hard-denies.**
  `os.WriteFile/OpenFile/Mkdir(…, 0666|0777)` requests a umask-masked mode, and
  `0666` is what `os.Create` itself uses, so it drops to `medium` (ask). Only
  `os.Chmod`, which sets the mode absolutely, stays `high`.
- A disabled control named inside a **comment or a message constant** is
  documentation, not a disabled control. A credential whose host is **loopback, a
  docker service name, or `*.local`** is a dev fixture; real RDS / `mongodb+srv` /
  prod-host DSNs still flag `high`.
- **`secureRewrite` no longer offers to corrupt working code.** Its argument
  pattern terminated at the inner `)` of a nested call, so
  `yaml.load(open(p), Loader=yaml.SafeLoader)` was rewritten to
  `yaml.safe_load(open(p), Loader=…)` — a runtime `TypeError` one keystroke from
  approval, because the post-rewrite scan passes. And `verify=False` in a function
  *signature* is a declared default, not a call argument; flipping it changed the
  contract for every caller. Substitution is now line-aware and skips declaration
  lines including multi-line signature continuations.
- **Stop self-review cost 274s vs 27s on a plain GET read endpoint**, because
  three classes fired spuriously: `ratelimit` on the word "authenticated" inside
  an error *string*, `csrf` on a bare session *read*, `race` on any `+=`. Each
  spurious class adds a block the model must answer. Detectors now require
  evidence the class applies, and the output contract is one line per class
  instead of a report. Same task after: 47s / 17s / 55s, still landing clean code
  with the IDOR guard added unprompted.

### Born-secure completion (productivity)
- The guidance plane used to make the model **refuse** insecure-inducing tasks
  (68% of them in the benchmark): safe but useless to a developer. The Security
  Ladder and task-CWE context now instruct the model to deliver the same
  functionality the secure way and never leave the file unwritten; the deny
  message is "rewrite with this secure pattern and continue," not just "blocked."
  Refusal fell **68% -> 6%**, secure code landed **30% -> 94%** of attempts, and
  insecure-landed stayed at **0%** (corrected). The cost is latency (deny-rewrite
  cycles): ~153% of baseline dollars, ~209% wall time.
- Closed a taint gap the change surfaced: sandboxed `eval(expr, ns)` / two-arg
  `exec` are still injectable and are now caught (the sink spec matches a second
  argument).

### Semantic tier: adversarial self-review (25% -> 84%)
- The absence-of-guard classes (IDOR, TOCTOU race, CSRF, business logic, rate
  limiting) that no pattern engine can prove were peephole's documented ceiling.
  The Stop-time self-review, previously a passive checklist a small model
  rubber-stamps, is now a **red-team cite-or-exploit review**: for each applicable
  class the model must quote the exact guarding line or mark it ABSENT and fix it
  before finishing ("looks fine" is disallowed). Independently judged, peephole's
  semantic-tier secure rate rose **25% -> 84%** (IDOR, race, rate-limiting all
  0% -> 100%; CSRF and business-logic 60%). Grounded in RCI self-critique (Tony
  et al. 2024, the most effective secure-generation prompt technique), adversarial
  critique (INDICT, NeurIPS 2024), and the horizontal-privilege (越权) replay test.

### Latency: conditional, class-scoped self-review (209% -> 134% wall time)
- The Stop-time adversarial self-review forces a model continuation and was the
  dominant extra turn on pattern-tier sessions where it helped nothing (they touch
  no absence-of-guard class). The landed code is now classified at write time
  (cheap regex, `selfreview.go`) and the review fires ONLY for the classes present,
  scoped to those - skipping the continuation entirely for the ~80% of code that
  touches none. Turns fell 3.9 -> 2.7 (baseline 2.2), wall time 209% -> 134% of
  baseline, cost 153% -> 120%, and secure-landed rose to 98%, all with insecure-
  landed still 0% and the semantic tier still 84%. The cascade principle
  (FrugalGPT / AutoMix; Chinese low-latency-guardrail practice: heavy review only
  for the risky minority). Also unified two divergent review-text paths onto the
  adversarial version (real git repos previously got weaker passive text).

### Taint performance
- The cross-line taint pass now shares the presence-rule literal prefilter: it is
  skipped entirely on files with no sink anchor, keeping large files within the
  latency budget.

### Benchmark honesty
- The headline live metric is now **insecure-landed per attempt** (the security
  outcome), with a refusal shown as safe-but-unproductive rather than counted as
  a failure. "secure over code-writers" is kept but labeled as the conditional
  quality it is, since it flatters arms that refuse less. Re-run at 5 runs/arm
  (200 main sessions) for a stable ranking.
- Competing arm named as itself (`security-guidance`); completion chart replaced
  with a per-attempt outcome view now that all arms complete (0 timeouts).

### Versioning
- One source of truth (`version.go`). The MCP handshake, the LSP handshake and the
  SARIF tool driver each carried their own literal and had drifted to `0.3.0`,
  `0.3.0` and `0.2.0` while the plugin manifest said `0.4.0`.
- `peephole version` now exists. It previously fell through to the hook handler
  and printed `{}`, so an operator could not tell what build was deployed. It
  reports the version, build target, Go version, and rule/pattern/taint-spec
  counts.

### Rules and language parity
- Cross-language injection gaps closed for Java, Go, Terraform and Solidity;
  C#/.NET, Android SQLite `rawQuery`, PHP `eval`, Ruby SSTI and Swift SQL string
  interpolation added; GitHub Actions pwn-request, C format-string and
  CloudFormation rules added; cookie-flag disabling in the bracket-subscript
  config form; hard-coded cloud credential variables regardless of placeholder
  value; `verify_signature=False` when the option is assigned across lines.
- False positives that blocked safe, idiomatic code removed, plus a real-world
  false-positive audit pass with path scoping. Taint no longer treats
  environment/file reads as user input.

### Hardening
- Closed manifest/slopsquat robustness bugs (a panic, an Edit bypass, a freshness
  spoof), the Stop-gate org floor, exact sec-debt approval matching, a
  language-scoped hunk memo, four red-team evasions (augmented-assignment taint
  and three Bash write paths), and a heredoc parser `O(n²)` bomb that was both a
  CPU-DoS and an audit fail-open. Fixed an unsound `litset` prefilter on nested
  alternations that caused silent false negatives. Per-session set files are now
  serialized and written atomically. SARIF/scan output correctness (OWASP-2025
  tags, unreadable paths, severity).

### Performance
- Prefilters recovered via regex AST (6.8× on clean scans) after the taint pass
  had defeated them; char-class prefilter recovery; one `ToLower` per scan shared
  across the presence and taint prefilters; fast-path pattern match for the ~90%
  of patterns with no refinements.

### Benchmarks
- Fresh 4-model live re-runs (Haiku 4.5, Sonnet 4.5, GLM-5.2, Kimi-K3) after the
  hardening rounds, with the GLM peephole cell reported at 5% for its own run
  rather than carried over from a different build.

## [0.4.0] - 2026-08

> **Note on this tag.** `v0.4.0` was cut before several items previously listed
> here had landed. The tag contains the cross-line taint engine and the release
> workflow below; born-secure completion, the adversarial self-review, the
> latency work, the taint-performance pass and the benchmark-honesty changes all
> post-date it and are listed under 0.5.0 where they belong.

### New capability: intra-file cross-line taint (framework-level)
- The single-line presence patterns missed the shape where a dangerous value is
  built into a variable on one line and reaches a sink on another (`tmpl = f"..{req}.."`
  then `render_template_string(tmpl)`). A new additive taint pass tracks
  user-derived and dynamically-built variables (propagating through interpolation
  and concatenation, cleared by `int()`/`shlex.quote()`/`escape()`/... sanitizers)
  and flags them at **every** sink class: SSTI, SQLi, OS-command, code-eval,
  deserialization, and XSS. It checks the actual variable in the sink, not
  proximity, so an unrelated dynamic string near a static-const sink does not
  misfire. Strictly additive: it never changes existing rule behavior.
- The sink catalog is **declarative data** (`taint/*.json`, compiled into Go
  literals by `cmd/kbgen`) over one generic engine, so adding a class is a spec
  file plus exemplars, verified by `TestTaintSpecExemplars`, not new engine code.
  Findings whose exploitability depends on a validation guard a pattern engine
  cannot see (SSRF, redirect, path) `ask` rather than hard-deny.
- Measured on the live-benchmark corpus, this raises the gate's catch rate on
  insecure code that landed from 45/64 to **57/64** across all arms, and takes
  peephole's own cross-line SSTI misses to zero. `TestTaintCrossLineCatches` /
  `TestTaintNoFalsePositives` lock the behavior.

### Distribution
- Tag-triggered release workflow ships signed binaries (5 platforms + SHA256SUMS).
  CI `setup-go` cache disabled (a zero-`go.sum` module hard-failed the runner).

## [0.3.0] - 2026-08

Driven by a deep read-only review (Go code, rules, benchmark validity, repo
maturity) that found real flaws and an inflated self-benchmark. Fixes the flaws,
makes the benchmark honest, adds a novel capability, and expands beyond Claude
Code to a universal multi-agent gate.

### Security / correctness
- **Self-protection: closed the mode-lowering bypass.** Shell variable indirection
  (`P=peephole; $P mode off`) evaded the guard and disabled enforcement.
  `resolveAssignments` substitutes simple aliases before matching; the guard also
  blocks agent-initiated `strict`.
- **Prefilter soundness:** an optional `(?:a|b)?`/`*` group is no longer treated as
  a required literal (could false-skip a real match = missed vuln).
- **Audit log:** deletion while the head sidecar records entries is now tamper;
  `withLock` steals a stale lock to avoid chain-desync false alarms.

### False positives (framework-level)
- Injection-class rules only reach `high` (hard deny) when the tainted position is
  visible; otherwise `ask`. Applied to SSRF, NoSQL, path traversal, weak-cred,
  crypto (sha256 is not weak), Rust silent-failure, header injection.
  `TestNoHighConfidenceFalsePositives` locks it.

### Terminating guardrail (timeout fix)
- A blocking gate the model kept retrying could livelock the agent to the session
  cap. A **per-rule (mutation-invariant) deny counter** plus a global floor
  escalates to "stop retrying" and finally `ask` (hand to human), so the agent
  always terminates. The finding always stands.

### New capability
- **Confused-deputy exfil-sink gate (CWE-200):** hard-deny when the whole
  environment or a raw secret flows into a network sink — the "add telemetry"
  indirect-prompt-injection attack the model won't refuse and an advisory warns
  about too late. Near-zero FP.

### Beyond Claude Code
- `peephole hook --exit2` (universal exit-2 block signal), `peephole scan --gate
  --staged` (git pre-commit), `peephole mcp` (MCP server), `peephole lsp` (LSP
  diagnostics). `docs/INTEGRATIONS.md` + `integrations/` cover Gemini CLI, Codex,
  Qwen, Crush, Goose, Cursor, OpenCode, Amp, plus the MCP/LSP editor cohort.

### Benchmark honesty
- `report.py` rewritten: independent grader (Semgrep / out-of-family judge) is the
  headline, not peephole's own scanner; empty output ≠ secure; timeouts counted;
  nothing hardcoded. Real live numbers (peephole 90% independent, not 100%).
- `judge_v2.py`: blinded, rubric-guided, reason-before-verdict, escalate-on-
  disagreement independent judge.

### Repo / CI
- CI scans its own code (gosec, govulncheck, staticcheck). Reproducible binary
  builds (`-buildvcs=false`). Dropped product-name references.

## [0.2.1] - 2026-08

Latency + review-quality release, driven by the live-benchmark findings
(wall time is 100% API-side; the hook is the cheap part — see
`docs/BENCHMARK.md` §D).

### Latency (measured, this machine)
- Full production hook path **15.9ms -> 8.5ms (-46%)**: hooks.json now execs the
  cached platform binary directly (read-builtin fast path, zero extra shell;
  falls back to `peephole.sh` when unprimed).
- **KB as generated Go literals** (`rules_gen.go`, built by `cmd/kbgen` from
  `rules/*.json` with prefilters precomputed via `internal/litset`): `loadKB`
  ~2ms -> ~7µs per event. CI fails the build if the JSON and the generated file
  drift (`go run ./cmd/kbgen --check`).
- **Slopsquat warm-cache priming**: SessionStart spawns a detached
  `peephole warmcache` (setsid, fire-and-forget) that pre-checks manifest deps
  against the registry, so the session's first install verdict is served from
  cache (~90ms) instead of a cold ~500ms curl. Cache writes are atomic
  (tmp+rename) for concurrent gate/warmcache access.

### Review quality
- Stop self-review is now **diff-grounded and CWE-targeted** (injects the
  bounded session `git diff` + the N3-classified CWE classes into the same
  single forced continuation - zero extra turns, no LLM call of our own).
- N6 trigger fixed to blueprint spec: fires on N3-classified security tasks
  with writes, not only on presence findings (IDOR/ratelimit-class sessions
  were previously never reviewed). Validation documented honestly in
  `docs/BENCHMARK.md` §D: mechanism verified, Haiku self-review rubber-stamps
  (0/7), consistent with published ~25% LLM self-repair rates.

## [0.2.0] - 2026-08

Hardening + blueprint-completeness release. Four more confirmed logic blunders
fixed (each regression-tested), the KB completed to full schema, and the
remaining v1 blueprint gaps closed.

### Fixed (enforcement integrity)
- **Mode-lowering obfuscation bypass**: `peephole mode o''ff` / `m\ode audit`
  normalized to a real lowering command at exec but slipped the raw-text guard.
  All self-protection guards now run on the normalized command text.
- **Secure-rewrite partial-fix bypass**: a `yaml.load -> safe_load` rewrite was
  offered when it removed only *some* findings; approving it landed the rest
  ungated. Rewrites are now offered only when the file scans fully clean.
- **Sec-debt marker scope**: any marker anywhere in a file downgraded any deny
  to ask. Markers now apply only on the finding's line or just above it, are
  audit-logged (`marker: true`), and unapproved markers are flagged at Stop and
  in `/sec-audit` as evasion (blueprint N4).
- **Audit-log rule_id corruption**: the confidence tier (`high`/`medium`) was
  logged as `rule_id`. The rule's name is logged; the sec-debt section of
  `/sec-audit` (dead code) now works.

### Fixed (quality / false positives)
- Zero-decision tamper alarm false-fired on clean Bash-only write sessions
  (clean Bash writes now log an allow, like Write-tool writes do).
- `.peephole-rules.json` (the committed, user-editable org-rules file) was
  denied via Bash by the blunt `.peep` substring guard; the guard is now
  path-aware and still catches `.pee""phole`, `.peep*/mode`, `$D=.peephole`.
- Retro-scan silently missed findings past the 256KB hot-path window; it now
  scans up to 4MB (`scanFull`, also used by commit review).
- Redirect ask-fatigue: `git diff > notes.txt`-style benign producers writing
  program output to plain-data files (.log/.txt/.md/...) no longer ask;
  code/config targets and obfuscated producers stay gated.

### Blueprint completeness
- **KB full schema (§4.1)**: all 174 rules now ship a `negative_test_hint` with
  an extractable adversarial payload; authoring meta-commentary cleaned from
  exemplar explanations; CI schema test (`schema_test.go`) enforces the contract.
- **N6 blueprint semantics (§5)**: audit mode warns (never blocks); at most 2
  forced continuations; exhaustion is logged as an `n6-exhausted` sec-debt event
  with a loud human-acknowledgment warning, not a silent release.
- **N2 metric honesty (§5/§7.1)**: born-secure is computed over
  security-relevant hunks only (sink-token heuristic, labeled), audit-mode
  warns count as *landed insecure* (never as "born"), plus the born-secure rate
  and the §7.4 interruption-rate (asks+denies per 20 write decisions) metrics.
- **N5 manifest gating**: manifest edits now get the full offline signal set
  (homoglyph, known-bad, typosquat, ecosystem-mismatch) plus a bounded live
  registry check (parallel, 1s cap) for unverifiable packages - never a silent
  allow in strict/hardened.
- **N3 org policy (§5)**: `.peephole-policy.json` (global + per-CWE values) is
  injected by the context compiler; KEV flags shown; SubagentStart re-injects
  the ladder plus task-classified CWE context.
- **OWASP Top 10:2025 rollup** (was 2021): A03 = Software Supply Chain
  Failures, SSRF merged into A01; SARIF tags updated.
- **§7.4 hunk-hash memoization**: a hunk that already landed this session
  (allowed or ask-approved) is not re-gated.
- **User-rule poisoning resistance (§4.4)**: project-local rules are
  Unicode/injection-scanned and schema-validated at load; tainted rules are
  rejected loudly.
- **Self-hardening**: integrity manifest now covers skills + plugin.json;
  state schema-version with migrate-or-reset; internal timeouts are logged and
  advisory fail-open is visible; commit review dedupes on HEAD; N7 gains the
  documented deny opt-in (`.peephole/taint-deny`, off by default).

## [0.1.0] - 2026-08

Initial release.

### Enforcement
- PreToolUse gate that denies insecure code before it lands (Write / Edit /
  MultiEdit / NotebookEdit and write-capable MCP tools).
- Bash write-path inspection: heredocs, echo/printf redirects, interpreter
  `-c`/`-e`, cp/mv/dd, and the raw command surface (chmod 777, `--acl public-read`).
- Four modes: `audit`, `strict` (default), `hardened`, `off`. Never exits 1
  (fail-closed on internal error in strict/hardened).
- Self-protection: writes to peephole's own state/plugin dir are denied in all
  modes; the mode file is signed and fail-closes to strict if changed out-of-band.

### Detection
- 38 CWE rule families across 18 languages (Python, JS/TS, PHP, Go, Java/Kotlin/
  Scala, Ruby, C#, C/C++, Rust, Swift, Dart, Elixir, Shell, PowerShell, Lua,
  Perl, R). Injection, deserialization (multi-language), secrets, weak/default
  credentials, crypto, SSRF, XXE, SSTI, NoSQL/LDAP/XPath, insecure defaults,
  supply-chain (slopsquat), and AI-confession comment markers.

### Guidance
- Security Ladder injected every session; task-to-CWE context compiler at
  UserPromptSubmit; Stop-time semantic self-review for race/logic/authz classes
  no regex can catch.

### Supply chain
- Slopsquat gate: registry existence, offline allowlist, Damerau-Levenshtein
  typosquat, ecosystem-mismatch, homoglyph, install-hook/index/git smells.

### Integrity & audit
- SHA-256 self-integrity manifest (binary + hook wiring); hash-chained,
  tamper-evident decision log; commit/push-time review; `/sec-audit`, `/sec-debt`,
  `/sec-review`, `/peephole` skills.

### Extensibility
- Project-local `.peephole-rules.json` custom rules (additive, RE2-safe).
- Experimental N7 diff-provenance taint echo (opt-in, off by default).

### Performance
- Single static binary per platform, zero runtime dependencies. ~8ms hot-path
  latency; net/http removed from the binary, launcher forks reduced 4 to 1.
