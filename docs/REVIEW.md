# Peephole — review & research record

Two adversarial multi-agent review passes and two research workflows drove this
build past the blueprint. Every confirmed finding was verified against the actual
code before fixing.

## Review pass 1 — 5 lenses + adversarial verify (69 agents)

60 confirmed findings, 4 rejected. All 60 addressed. The load-bearing ones:

**Critical enforcement bypasses (all closed + regression-tested):**
- The model could disable enforcement with one allowed Bash command
  (`peephole mode off`, `rm -rf .peephole`).
- `echo`/`printf`/`cp`/`dd` redirect writes skipped the scanner entirely
  (only heredoc/interpreter payloads were inspected).
- Only the *last* redirect target was self-protected (a second redirect hid a
  write to `.peephole/mode`).

**High:**
- Emitting an explicit `allow` on clean writes overrode the user's own
  permission rules → changed to no-decision passthrough.
- `reject_re`/`require_re` matched the whole hunk → scoped to the matched line.
- An RE2-invalid pattern (`vm.runIn*Context` lookahead) was silently disabled →
  surfaced at SessionStart + rewritten with a declarative refinement.
- Per-session state was keyed per-project → keyed by session id.
- The log chain didn't detect tail truncation → verifyChain checks the head sidecar.
- MCP write tools were ungated → matcher extended + schema-agnostic scan.

Plus dead-code removal, a watchdog/exit race fixed with `sync.Once`, and panic
recovery that fails closed.

## Review pass 2 — 3 lenses on the fixes + new code (19 agents)

13 confirmed. The two criticals shared one root cause — self-protection reasoned
over the *pre-expansion* command text while the shell writes to *post-expansion*
paths:
- interpreter file-API write (`python3 -c "open('.peephole/mode','w')…"`),
- glob / env-var / symlink targets (`echo off > .peep*/mode`, `$D/mode`).

Root-cause fix: any Bash command referencing `.peep` (case-insensitive) is
self-tampering (the legitimate launcher is `peephole.sh`, no leading dot, so mode
*raising* is unaffected); unresolvable redirect targets (glob/var/tilde) are
uninspectable; `ed`/`ex` line-editors added to the uninspectable set. Also:
worst-wins decision ordering (a weak `ask` could preempt a strong `deny`),
hardened mode no longer honors a `sec-debt` downgrade, manifest extraction covers
Poetry + optional/peer deps, and the Unicode scanner no longer false-positives on
legitimate Persian/Indic/emoji text or math notation.

## Research workflows

**Deep research (English + Chinese, 6 agents):** adopted the Reflexion-style deny
wording (block framed as "regenerate securely" — 70-77% vuln-density reduction in
the literature) and a ladder clause that no usability/perf request justifies
dropping validation. Queued for later: known-hallucinated blocklist, edit-distance
typosquat, ecosystem-mismatch, install-hook smells.

**Novel-attacks research (4 agents):** added 8 new detection classes as data-only
rules — CWE-330/338 insecure randomness for tokens, 347 JWT weak-verify, 1336
SSTI, 601 open redirect, 943 NoSQL injection, 1333 ReDoS-in-generated-regex, 915
mass assignment, and 798 env-fallback secrets. KB is now 18 rules; every rule is
self-tested against its own compliant/noncompliant exemplars.

## Review pass 3 (full-codebase, 6 lenses + verify, 30 agents) — 21 confirmed

One critical self-protection bypass (shell obfuscation `.pee""phole/mode` / `.pee[p]hole`
defeating the literal `.peep` check), plus HIGH inspection-evasions (`curl|python3`, echo/
interp payloads with cmd-substitution/base64), a false tamper-alarm on read-only Bash, and a
set of FP/FN rule bugs (CWE-330 `code`, CWE-79 bare innerHTML, CWE-798 doc DSN, CWE-532
mentions) + cleanups. All fixed and regression-tested; the shell-obfuscation guard now
normalizes away no-op metacharacters before the check.

## Review pass 4 (adversarial re-check of pass-3 fixes) — 3 confirmed, root-cause fix

Proved that **string-parsing an un-executed shell command can never robustly protect the
state file**: `cd $'\056peephole' && echo off > mode` (ANSI-C octal), `ln -s … $'\056…'`,
and `tar -C $'\056…'` all evade any command-level guard while resolving to `.peephole` at
exec. The robust fix is at the **effect layer**, matching blueprint §2c (tamper-evidence, not
a guarantee): the mode file is now **signed** — `getMode` fail-closes to strict and
SessionStart raises a MODE-TAMPER alarm whenever the mode file is changed out-of-band (no
valid signature). Every demonstrated bypass writes `mode` but not the signature, so
enforcement stays on regardless of how the shell spelled the path. A same-user process that
reads the key and forges the signature is the documented host-level residual.

## Review pass 5 (blueprint-completeness + full-code audit, 2026-08) — 11 confirmed

Full blueprint-vs-implementation audit plus line-by-line re-read of every Go file;
each finding reproduced against the built binary before fixing.

**Critical (enforcement integrity):**
- **Obfuscated mode-lowering bypass.** The round-3 normalization fix covered only the
  `.peep` check; `reModeLower`/`reSelfTamper` still matched the RAW command, so
  `peephole mode o''ff` (quote-stripped to a real lowering at exec) sailed through and
  produced a *validly signed* mode change. All guards now run on the normalized text.
- **Secure-rewrite partial-fix bypass.** The `updatedInput` rewrite was offered when it
  removed *fewer* findings than present (`len(scan(rw)) < len(findings)`): a
  `yaml.load -> safe_load` rewrite carried a hardcoded AWS key through the ask.
  Offered now only when the rewritten file scans fully clean.
- **Sec-debt marker scope.** `reSecDebt.MatchString(content)` waived ANY deny when a
  marker existed ANYWHERE in the file (verified: a line-1 CWE-798 marker waived a
  line-43 SQLi). Markers are now scoped to the finding's line / 5 lines above it,
  matching the documented placement; waivers are audit-logged (`marker: true`) and
  unapproved markers are flagged at Stop and in `/sec-audit` as evasion (blueprint N4,
  previously unimplemented).
- **Audit-log rule_id corruption.** Every finding path logged the confidence tier
  (`"rule_id":"high"`) instead of the rule identity — corrupting the CWE-mapped audit
  trail and leaving `/sec-audit`'s sec-debt section (`rule_id == "sec-debt"`) dead.

**High/Medium (quality):**
- Zero-decision tamper alarm false-fired on clean Bash-only write sessions (clean Bash
  writes logged no decision; Write-tool clean writes did). Clean Bash writes now log an allow.
- `.peep` substring guard denied `cat .peephole-rules.json` — the committed, user-editable
  org-rules file. Guard is now path-aware (`referencesPeepholeState`): exact component,
  name-boundary, and glob/var-truncated prefix detection; `.pee""phole`, `.peep*/mode`,
  `$D=.peephole` still denied.
- Retro-scan claimed to cover files beyond the 256KB hot-path window but used the same
  truncated scan — a finding at byte 300K never surfaced (verified). `scanFull` (4MB)
  now backs the retro-scan and commit review.
- N6 deviated from the blueprint twice: audit mode *blocked* (blueprint: "audit mode
  warns") and exhaustion was a silent release (blueprint: max 2 continuations, then a
  logged sec-debt event requiring human acknowledgment). Both aligned.
- Manifest gating used only allowlist+cache: no typosquat/homoglyph/known-bad/ecosystem
  checks, and strict mode silently allowed unverified deps (verified: `reqeusts` in
  requirements.txt passed). Now full offline signals + bounded parallel live checks.
- N2 metric counted every clean write (README typo fixes included) as "born secure",
  and counted audit-mode warns (landed vulns) as born too. Now computed over
  security-relevant hunks only (labeled sink-token heuristic), with born rate +
  §7.4 interruption rate emitted.
- Redirect ask-fatigue: `git diff > notes.txt` asked in strict (FP-kill territory per
  §7.5). Benign producers writing program output to plain-data extensions are now
  carved out; code/config targets and obfuscated producers stay gated.

**Completeness (blueprint §4.1/§5/§8):** all 174 rules now carry negative-test hints
with extractable payloads (was 42); org-policy loader (M2); user-rule Unicode/injection
scan at load (§4.4 extensibility path); OWASP 2025 rollup; hunk-hash memoization (§7.4);
SubagentStart task context; state schema-version; integrity manifest extended to skills
+ plugin.json; timeout logging; commit-review HEAD dedupe; N7 deny opt-in; SARIF tags
updated. Prefilter engine upgraded to alternation-aware literal sets (135 unfiltered
patterns → 27; 160KB clean scan 216ms → 60ms).

Each fix ships with a regression test (`fixes_test.go`, `schema_test.go`,
`unit_test.go` prefilter-soundness).

## Borrowed from the other marketplace plugins

Surveyed the official plugin set and adopted three techniques:
- **the advisory linter** — its `asyncRewake` + `if: Bash(git commit:*)` pattern → peephole now
  does a **non-blocking commit/push-time review** (scans the committed diff and surfaces any
  findings before they ship). Also its regex set (seeded the KB earlier) and its
  project-local custom-rule extensibility.
- **claude-security** — its 3-lens refutation panel (REACHABILITY / IMPACT / DEFENSES,
  "try to disprove it") → the `/sec-review` skill now challenges each finding from all three
  angles before reporting, cutting false positives.
- **pr-review-toolkit** — its silent-failure-hunter → new rule **CWE-703** (swallowed errors
  from security checks: `except: pass`, empty `catch {}`, ignored Go verify returns).

## Latency work (measured) & the daemon verdict

Deep research (incl. Chinese/Russian sources) + profiling drove three measured wins,
taking end-to-end from ~22ms to ~8ms: launcher forks 4->1 with a fork-free cached-exe
fast path; dropped net/http (moved the registry check to a curl subprocess), halving the
binary (6.1M->2.8M) and Go init (5.6ms->2.9ms); GOMAXPROCS=1/GOGC=off/asyncpreemptoff=1.

`GODEBUG=inittrace=1` proved total Go package init is <1ms (main init 0.38ms) — the
residual ~3ms is Go runtime bootstrap + OS exec/page-in/codesign, which no flag or code
change can touch. **Persistent daemon: rejected.** For a security tool it is a net
regression — a new always-listening local-IPC surface, plus it moves the per-event
integrity re-check and clean-per-event memory to once-per-lifetime, losing real security
properties, all to shave an imperceptible ~3ms off a 2s budget (~250x headroom).

Research also confirmed the KB already covers the classes the multilingual sources
suggested; the only genuine gaps added were CWE-676 (C/C++ dangerous functions — no C
bucket existed) and CWE-546 (AI-confession comment markers — an AI-specific heuristic
Western AST-based SAST ignores). 38 rules total.

## Honest boundary (race conditions & business logic)

Peephole's presence-pattern engine cannot detect race conditions or business-logic
flaws — those need semantic reasoning. It handles them via the guidance plane
(`/sec-review` checklist, the injected CWE context, the Stop-time negative-test
gate) and flags them for human review, never claiming enforcement it can't deliver.
The benchmark includes these classes precisely to show that boundary honestly.
