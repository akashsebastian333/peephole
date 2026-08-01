# Changelog

All notable changes to Peephole are documented here. This project adheres to
[Semantic Versioning](https://semver.org/).

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
