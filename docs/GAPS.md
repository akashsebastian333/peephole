# Blueprint → Implementation gap register

Audit of the implementation against `Peephole_Secure_Coding_Plugin_Blueprint`
(§1–§10 + Appendices). Ranked by priority. Items marked ✅ were closed in the
research/hardening cycle; the rest are tracked, open work.

## Closed

- ✅ **H1 — N5 freshness check.** `registryExists` fetches the registry body and
  `freshlyCreated` flags packages first published within `freshWindow` (45 days).
- ✅ **H2 — N6 hint-literal match.** `payloadOf`/`testExercised` require the
  armed adversarial payload in the model's Stop message.
- ✅ **Classifier relevance ranking.** `classify` ranks by trigger-match count,
  then Top-25 rank.
- ✅ **Hot-path latency (§7.4).** Literal prefilters; upgraded to alternation-aware
  literal *sets* in pass 5 (unfiltered patterns 135 → 27; 160KB clean scan
  216ms → 60ms).
- ✅ **H3 — Adversarial red-team suite.** `redteam_test.go` evasion corpus.
- ✅ **M1 — OWASP rollup / severity / SARIF.** `report.go`; **pass 5 moved the
  rollup to OWASP Top 10:2025** (A03 = supply chain; SSRF merged into A01).
- ✅ **Claude-in-the-loop born-secure benchmark.** `benchmark/live/driver.py` (formerly `scratchpad/claude_loop*.sh`),
  28/28 secure across three batches.
- ✅ **M2 — N3 org-policy injection (pass 5).** `.peephole-policy.json` /
  `.claude/peephole-policy.json` (global + per-CWE values), injected by
  `compileContext`; values Unicode/injection-scanned, length-capped.
- ✅ **M4 — CI-gated performance budget (pass 5).** `TestScan100KBUnderBudget`
  (500ms p99 native, scaled under -race) + `TestLatencyUnderBudget` end-to-end.
- ✅ **M5 — N4 waiver accountability (pass 5).** Markers are line-scoped (on or
  above the finding), waiver requests audit-logged (`marker: true`), unapproved
  markers flagged at Stop + `/sec-audit` as evasion. (Precondition *rot
  detection* remains open — see M5′ below.)
- ✅ **L1–L6 batch (pass 5).** L4 state schema-version (`migrateState`); L5 CI
  rule-schema validation (`schema_test.go`: full §4.1 record per rule, incl.
  hint payload); L6 N7 deny opt-in (`.peephole/taint-deny`); N2 per-CWE
  breakdown + relevance heuristic in `/sec-audit`.
- ✅ **Pass-5 blunders (11).** Obfuscated mode-lowering bypass (`mode o''ff`);
  secure-rewrite partial-fix bypass; sec-debt scope; rule_id = confidence in the
  audit log; zero-decision false alarm on Bash-only writes; `.peep` substring
  over-match blocking `.peephole-rules.json`; retro-scan 256KB truncation;
  N6 exhaustion silent-release + audit-mode block (blueprint: audit warns);
  manifest gating missing offline signals/live checks; N2 counting non-security
  hunks as born; redirect ask-fatigue (`git diff > notes.txt`).
- ✅ **KB full schema (pass 5).** All rules carry task triggers, attack
  scenario, exemplar pair, and a negative-test hint with an extractable
  adversarial payload; exemplar explanations cleaned of authoring meta-commentary.

## Open — High

_(none)_

## Open — Medium

- **M3 — Degraded-mode exemplar refusal (§4.4.2).** On integrity mismatch the
  gate keeps running with full exemplars. NOTE: KB is folded into the binary
  hash here, so a tampered KB already fails `verifySelf` wholesale and alarms —
  the separate "core floor" the blueprint assumed doesn't apply. PARTIAL-by-
  design. *Effort: S if pursued.*
- **M5′ — N4 rot detection (§5).** Re-evaluating a marker's stated precondition
  (e.g. "internal only" becoming public) needs semantic judgment; not built.
  *Effort: M.*
- **M6 — Pre-registered kill criteria + dogfood metrics (§7.4/§7.5).** The
  `/sec-audit` interruption-rate metric now exists; registered thresholds and
  ask-fatigue latency tracking remain process work. *Effort: S/M.*
- **M7 — External benchmark integration (§7.2).** CodeGuard+/CWEval/BaxBench/
  SecRepoBench/SecurityEval not wired. Blueprint-deferred to Phase 4. *Effort: L.*

## Open — Low

- **L1** Ladder is not mode-filtered (single const + mode line in all modes).
- **L2** Statusline badge not wired into settings; no per-language enforced-vs-
  guidance breakdown.
- **L3** InstructionsLoaded hook not wired — runs at SessionStart/ConfigChange
  (the blueprint's documented fallback). Acceptable.
- **L7** N2 relevance is a sink-token heuristic (labeled as such in the report);
  per-CWE born rates are aggregate.

## Verified done (no gap)

N1 ladder, N2 born-secure instrumentation (relevance-tagged), N3 classifier +
compiler + KEV + org policy, N4 line-scoped marker→ask + waiver logging +
Stop/audit evasion flags, N5 gate wiring (typosquat/homoglyph/ecosystem/cache/
freshness/live manifest checks/unreachable→ask), N6 Stop force-continuation
(max 2 + exhaustion logging + audit-warns), N7 opt-in taint echo (+deny opt-in),
Bash write-path inspection (+ benign-producer carve-out), PreToolUse gate + mode
matrix, updatedInput secure-rewrite (full-clear only), non-waivable path-aware
self-protection (normalized-text matching), fail-closed watchdog (+ timeout
logging), self-integrity (binary+hooks+skills+plugin.json) + hash-chained log +
signed mode file + state schema-version, Unicode/backdoor scanner (instruction
files + user rules + org policy), ConfigChange handler, hunk-hash memoization,
commit-review dedupe, SubagentStart task context, 4 skills, FP guardrail,
plane ablation.
