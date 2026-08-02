# Peephole — Local Build Design

Concrete engineering design for the v1 local build of the blueprint
(`Peephole_Secure_Coding_Plugin_Blueprint`). Scope, file layout, and the exact
platform contract each hook relies on. Verified against the real
advisory PostToolUse plugins installed locally.

## The one-sentence difference

The incumbent advisory approach wires its regexes to **PostToolUse** — it warns
*after* the insecure code lands on disk (detect-then-regenerate). Peephole wires
the same class of check to **PreToolUse** and returns `permissionDecision:deny`
*before* the write lands (born-secure enforcement), plus Bash write-path
inspection so `cat > f <<EOF` can't route around the Write tool.

## Platform contract (verified)

- Hooks declared in `hooks/hooks.json`: `{ "hooks": { EventName: [ { matcher, hooks:[{type:"command", command}] } ] } }`.
- `${CLAUDE_PLUGIN_ROOT}` = plugin dir; `${CLAUDE_PROJECT_DIR}` = project root.
- Each hook gets a JSON object on **stdin**; emits a JSON object on **stdout**.
- **Exit 0** → stdout JSON is applied. **Exit 2** → blocks, stderr → model. Any
  other exit → non-blocking soft error (silently permits). **We never exit 1.**
- PreToolUse decision: `{"hookSpecificOutput":{"hookEventName":"PreToolUse",
  "permissionDecision":"allow|deny|ask","permissionDecisionReason":str,
  "updatedInput":obj}}`.
- SessionStart / UserPromptSubmit inject via `additionalContext`.
- Stop forces continuation via top-level `{"decision":"block","reason":str}`.
- stdin field names: `hook_event_name`, `tool_name`, `tool_input`
  (Write/Edit: `file_path`/`content`/`new_string`; Bash: `command`), `prompt`,
  `source`, `cwd`, `session_id`.

## Runtime: a single static Go binary (no interpreter dependency)

Hooks are a compiled Go binary, cross-compiled to darwin/linux/windows and
shipped in `bin/`. The developer installs **no runtime** — not Node, not Python.
Rationale over an interpreted hook:
- **Portable:** `claude` may be a native binary that guarantees neither `node`
  nor `python3` on PATH. A shipped static binary needs nothing.
- **Fast:** native start ~1-5ms vs ~40-80ms interpreter cold-start. PreToolUse
  fires on every Write/Edit/Bash — the dev must not feel it.
- **Novel & hardened:** rules are `go:embed`-ed into the binary, so a local
  attacker cannot edit loose JSON the binary ignores; poisoning requires
  replacing the binary, which the self-integrity check detects.

RE2 has no lookaround, so KB exclusions are declarative refinements
(`prev_not`, `reject_re`, `require_re`) rather than lookahead/lookbehind.

Fail-safe boundary: if no binary matches the platform, the launcher exits 0 with
a visible notice — peephole never blocks the workflow because it cannot run.
This is distinct from fail-**closed**, which applies only when the binary ran and
hit an internal error mid-decision.

## Scope (what this build includes vs defers)

IN (v1 core, mechanisms N1–N6 + experimental N7, KB across ~28 language buckets):
- Mode resolution audit/strict/hardened/off + persisted, signed state.
- N1 Security Ladder injected at SessionStart/SubagentStart (task-classified for subagents).
- Enforcement plane: PreToolUse gate on Write/Edit/MultiEdit/NotebookEdit;
  Bash write-path payload extraction (with benign-producer carve-out); slopsquat
  gate on installs AND manifest edits; path-aware self-protection.
- CWE-keyed KB (174 rules embedded as JSON) with presence_patterns (enforced) vs
  absence_requirements (advisory checklist only); full §4.1 schema per rule.
- N3 task classifier at UserPromptSubmit (keyword → CWE candidates + exemplars +
  attack scenarios + KEV + org policy from .peephole-policy.json).
- N2 born-secure recording (security-relevance tagged) + hash-chained
  tamper-evident log at PostToolUse + retro-scan tripwire (full-file).
- N4 sec-debt markers: line-scoped deny→ask, waiver audit-logged, unapproved
  flagged at Stop + /sec-audit.
- N6 Stop negative-test gate (hint-literal match, audit warns, max 2
  continuations, exhaustion logged as sec-debt).
- N7 diff-provenance taint echo (experimental opt-in; deny opt-in).
- Integrity self-check (SHA-256 manifest of binary + hooks + skills + plugin.json)
  at SessionStart; signed mode file; state schema-version.
- Hunk-hash memoization (§7.4); commit/push-time review (HEAD-deduped).
- Skills: /peephole (mode), /sec-review, /sec-debt, /sec-audit.
- Runnable contract-test harness feeding real hook JSON, asserting exit codes.

DEFERRED (blueprint itself defers these):
- Tier-3 language curation (patterns exist for many, without per-language
  exemplar review); a live local MCP registry server (curl+cache covers
  npm/PyPI — the blueprint's "npm/PyPI first").
- Release signing / transparency log; SIEM export (Phase-4+).
- External benchmark suites (CodeGuard+/CWEval/BaxBench/SecRepoBench — need
  running harnesses, blueprint Phase 4); pre-registered kill-criteria evaluation
  (process step; the interruption-rate metric is emitted by /sec-audit).

## File layout

```
.claude-plugin/plugin.json   plugin manifest
hooks/hooks.json             event → command wiring (inline read+exec fast path -> cached binary, fallback peephole.sh)
hooks/peephole.sh            platform dispatcher: picks bin/peephole-<os>-<arch>
bin/peephole-<os>-<arch>     prebuilt static binaries (5 targets) + manifest.sha256
main.go                      CLI dispatch (hook/mode/selfcheck/audit/debt/scan/sarif/statusline/genmanifest) + watchdog
io.go                        stdin parse, decision emit, fail-closed, hardBlock
mode.go                      mode resolution + signed state file + state schema-version migration
kb.go                        embedded KB load, RE2 scan + refinements, literal-set prefilters, classifier, ladder
bashparse.go                 bash write-path payload + install extraction + benign-producer carve-out
slopsquat.go                 offline package signals + registry existence/freshness + cache
manifest.go                  manifest-edit dep extraction + N5 gate (offline + bounded live checks)
policy.go                    org-policy loader (.peephole-policy.json), scanned before injection
handlers.go                  per-event handlers + mode matrix + self-protection (path-aware, normalized)
session.go                   per-session state (N6 gate + counter, markers, hunk memo, zero-decision)
secdebt.go                   sec-debt harvest + approval cross-check
taint.go                     N7 diff-provenance taint echo (opt-in; deny opt-in)
taintlocal.go                intra-file cross-line taint engine (generic; specs in taint/*.json)
rewrite.go                   secure-default rewrites (syntactic-only)
audit.go                     running-hash tamper-evident log + decision counters
integrity.go                 self-binary + hooks + skills + plugin.json SHA-256 vs bin/manifest.sha256
unicode.go                   zero-width/bidi/homoglyph + injection-phrase scanner
report.go                    OWASP 2025 rollup + SARIF 2.1.0 export
embed.go                     go:embed rules/*.json
rules/*.json                 CWE-keyed KB records (data, never code)
skills/{peephole,sec-review,sec-debt,sec-audit}/SKILL.md
peephole_test.go             end-to-end hook contract tests (exit codes + decisions)
unit_test.go                 KB exemplar consistency, bashparse, log-chain tamper, prefilter soundness
fixes_test.go                pass-5 regression tests (bypasses, scoping, memo, dedupe, budgets)
schema_test.go               KB full-schema contract (§4.1): triggers/scenario/exemplar/hint per rule
corpus_test.go/fp_corpus_test.go/redteam_test.go/robustness_test.go  TP/FP/evasion/hostile-input corpora
build.sh                     cross-compile all targets + regen manifest
```

## Mode matrix (binding; all decisions generate from it)

| Event | audit | strict | hardened |
|---|---|---|---|
| High-confidence presence hit (KEV/Top-25) | warn+log | deny | deny |
| Other presence hit | warn+log | ask | deny |
| Absence_requirement | checklist guidance only, never blocks | same | same |
| Enforcement internal error / timeout | warn+log (fail open, logged) | **deny** (fail closed) | deny |
| Registry unreachable/unverifiable pkg | log | ask | deny new install / ask on manifest edit |
| sec-debt marker (line-scoped) on would-be-deny | n/a | deny→ask + waiver logged | stays deny (hook can't collect typed confirmation; human lowers mode to accept) |
| sec-debt without approval | flag at Stop + `/sec-audit` as evasion | same | same |
| Write to Peephole's own paths | **deny** (non-waivable) | deny | deny |
| updatedInput rewrite | never silent: ask+preview, only if file scans fully clean after rewrite | same | same |

Deny = structured `permissionDecision:deny` or exit 2. Never exit 1.

## State (`.peephole/` under project or CLAUDE_PROJECT_DIR)

- `mode` — one line: audit|strict|hardened|off, plus `mode.sig` (HMAC-style
  signature; out-of-band flips fail-close to strict) and `state-version`
  (schema version; migrate-or-reset on mismatch).
- `log.jsonl` — append-only decisions; every 50th entry carries a SHA-256 chain hash.
- `pkgcache.json` — 7-day registry-verdict cache; `lastcommit` — commit-review dedupe.
- `session/<id>.*` — per-session: neg-test hint + continuation counter, sec-debt
  markers seen, hunk digests (memo), write/decision counts, taint set (N7 opt-in).
- Self-protection: any Write/Edit/Bash/MCP targeting `.peephole/` or the plugin
  dir is denied in all modes (path-aware: `.peephole-rules.json` and
  `.peephole-policy.json` are committed project files and stay editable).
