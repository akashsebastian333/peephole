# Peephole — build status & blueprint coverage

Living record of what's implemented against the blueprint, the review history, and
what's deliberately deferred. Updated as work proceeds.

## Blueprint mechanism coverage (N1–N7)

| # | Mechanism | Status | Where |
|---|---|---|---|
| N1 | Security Ladder (ordered pre-write gate, session context) | **done** | `kb.go` ladder, SessionStart/SubagentStart (mode-aware, task-classified for subagents) |
| N2 | Born-Secure Metric (born/gate/fix-loop decomposition) | **done** | decision log + `/sec-audit`: security-relevance heuristic, born-secure rate, interruption rate |
| N3 | Threat-Model-Aware Context Compiler (task→CWE, exemplars, attack scenarios, KEV, org policy) | **done** | `handlers.go` classify + compileContext; `policy.go` org-policy loader |
| N4 | Sec-Debt Ledger + human-authorized waivers | **done** | line-scoped marker deny→ask, waiver audit-logged, unapproved markers flagged at Stop + `/sec-audit`; `/sec-debt` harvest |
| N5 | Slopsquat Gate (install + manifest edits) | **done** | `slopsquat.go` (offline signals + bounded live checks) + `manifest.go` |
| N6 | Adversarial Self-Check Mandate (Stop negative-test gate + diff-grounded, CWE-targeted self-review, N3-triggered) | **done** | `handlers.go` handleStop + `diff.go`; audit warns, max 2 continuations, exhaustion logged; effect on Haiku self-review documented honestly (BENCHMARK §D) |
| N7 | Diff-Provenance Taint Echo | **done (experimental opt-in)** | `taint.go`; ask by default, deny behind `.peephole/taint-deny`; off unless enabled |

**KB: 181 rules, 78 distinct CWEs, 558 presence patterns** across ~31 language
buckets (python, js/ts, go, java/kotlin, php, ruby, rust, c/c++, c#, sql, yaml,
webserver, objc, bicep, solidity, terraform-adjacent, shell, powershell, and
lang-agnostic). Every rule ships the full §4.1 record — task triggers, attack
scenario, exemplar pair, and a negative-test hint with an extractable adversarial
payload — enforced by `schema_test.go`.

Enforced presence classes: 89 SQLi, 94/95 code-injection, 502 deserialization
(multi-lang), 79 XSS, 78 command-injection, 22 path-traversal + 409 zip-slip +
98 LFI, 798/321 secrets, 521 weak creds, 327/328/329/323/326/916 crypto,
330 insecure-randomness, 347 JWT/SAML/webhook-verify, 1336 SSTI, 601
open-redirect, 943 NoSQL, 90 LDAP, 643 XPath, 1333 ReDoS, 915 mass-assignment,
918 SSRF, 611 XXE, 532/359/598 secrets-and-PII-in-logs, 117 log-injection,
113 header/CRLF, 470 unsafe-reflection, 377 temp-file, 1321 prototype-pollution,
538 sensitive-file-exposure, 400 missing-timeout, 732/276/1188/942/614/693/749
insecure defaults + disabled controls, 190 integer overflow, 676 dangerous
functions, 703 swallowed security errors, 841 reentrancy, 284 tx.origin,
829/494 untrusted-code fetch, 1104/1357 supply chain. Advisory (guidance-only):
862/863/639 authz, 362 race/TOCTOU, 840 business-logic.

**Three-layer defense for "all scenarios" (incl. non-regex classes):**
1. Hot path — RE2 presence-pattern enforcement at PreToolUse + Bash
   command-surface + write-payload scan (literal-set prefilters keep clean-file
   scans ~6ms at 16KB / ~60ms at 160KB).
2. Always-on guidance — the Security Ladder (9 rungs) every SessionStart, plus
   N3 task-conditional CWE context (exemplars, attack scenarios, KEV, org policy).
3. Stop-time semantic self-review + N6 negative-test mandate for the classes no
   regex can catch (race/logic/authz/defaults).

Plus: secure-default `updatedInput` rewrite (offered only when it leaves the file
fully clean), commit/push-time review (HEAD-deduped), statusline badge.

Hot-path latency (measured, this machine): **~8.5ms end-to-end** (46% faster
than the 15.9ms phase-9 baseline). Wins: hooks.json inline read+exec fast path
(no second shell); KB as build-time-generated Go literals with precomputed
prefilters (`loadKB` ~7µs; was ~2ms of JSON+prefilter work); detached
SessionStart `warmcache` priming (install verdicts ~90ms vs ~500ms cold);
earlier: launcher forks 4->1, curl instead of net/http (binary 6.1M->2.8M),
GOMAXPROCS=1/GOGC=off, literal-set prefilters (135 unfiltered patterns -> 27).
Session wall-time is 100% API-side (correlation 1.000) - the hook is 0.005% of
a session. See docs/BENCHMARK.md §D and docs/REVIEW.md.

## §8 self-hardening controls

| # | Control | Status |
|---|---|---|
| 7 | Instruction-file Unicode scan (bidi/zero-width/homoglyph) | **done** — `unicode.go`, SessionStart/ConfigChange alarm; user rules + org policy scanned at load |
| 8 | MCP pinning + data sanitization | **partial** — no local MCP server shipped in v1 (deferred); MCP write *tools* are gated; registry output never enters context |
| 9 | Full Bash parse + write-path inspection | **done** — `bashparse.go` (heredoc/echo/interp/cp/mv/dd/git apply/sed; benign-producer carve-out for plain-data redirects) |
| 10 | Dependency ground truth | **done** — N5 incl. freshness-window + bounded live checks on manifest edits |
| 11 | Fail-closed defaults (never exit 1) | **done** — `io.go`/`main.go`, tested; timeouts logged, advisory fail-open is visible |
| 12 | Minimal attack surface | **done** — no network on hot path; self-protection (path-aware); bounded reads; state files 0600 |
| 13 | Self-integrity & tamper evidence | **done** — binary + hooks + skills + plugin.json manifest; signed mode file; hash-chained log; zero-decision alarm |

## Mode matrix (audit / strict / hardened)

Implemented in `handlers.go` (`decisionFor`, `enforce`, `unreachableDecision`):
high-confidence→deny (strict/hardened), medium→ask (strict) / deny (hardened),
audit→warn+log+allow. Self-protection is non-waivable in ALL modes (runs before
the mode check). A **line-scoped** sec-debt marker downgrades deny→ask in strict
(hardened stays deny — a hook cannot collect the typed confirmation; the waiver
is audit-logged and Stop cross-checks approval). Slopsquat hallucinated/
unreachable → ask (strict) / deny (hardened). updatedInput rewrite → ask+preview,
never silent, only when it leaves the file fully clean. Every logged decision
equals the emitted decision.

## Review history

Passes 1–4: 60 + 13 + 21 + 3 confirmed findings across four adversarial
multi-agent rounds — all fixed + regression-tested (see docs/REVIEW.md).

**Pass 5 (blueprint-completeness + full-code audit, 2026-08):** 11 confirmed
blunders/gaps — obfuscated mode-lowering bypass, secure-rewrite partial-fix
bypass, sec-debt marker scope, audit-log rule_id corruption, zero-decision false
alarm, `.peep` substring over-match (`.peephole-rules.json` unreadable via Bash),
retro-scan 256KB truncation, N6 exhaustion silent release + audit-mode blocking
(blueprint: audit warns), manifest gating missing offline signals + live checks,
N2 metric counting non-security hunks as born-secure, redirect ask-fatigue. All
fixed with regression tests; KB completed to full §4.1 schema (all rules);
OWASP rollup moved to 2025. See docs/REVIEW.md § pass 5.

## Test coverage

`go test ./...` green (also `-race`). Contract tests assert exit codes are never
1, decisions per mode, all bypasses closed, self-protection in every mode, MCP
gating, manifest hallucination/typosquat, KB exemplar self-consistency + schema
completeness + prefilter soundness, log-chain tamper detection, Unicode alarm,
sec-debt scoping + evasion flag, N6 force/exhaustion/audit-warn, hunk memo,
commit-review dedupe, org-policy injection, user-rule poisoning rejection,
100KB scan budget. Corpus: TP/FP edge cases + red-team evasion suite + hostile
input robustness.

## Deferred (blueprint also defers these)

Tier-3 language *curation* (patterns exist for many, without per-language
review); a live local MCP registry server (curl+cache covers npm/PyPI, the
blueprint's "npm/PyPI first"); release signing / transparency log (Phase-4+);
SIEM export (Phase-4+); the external benchmark suites (CodeGuard+/CWEval/
BaxBench/SecRepoBench — need running harnesses, blueprint Phase 4); pre-registered
kill-criteria evaluation (process step; the interruption-rate metric for it is
now emitted by `/sec-audit`).
