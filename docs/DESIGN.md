# Peephole — Local Build Design

Concrete engineering design for the v1 local build of the blueprint
(`Peephole_Secure_Coding_Plugin_Blueprint`). Scope, file layout, and the exact
platform contract each hook relies on. Verified against the real
advisory PostToolUse plugins installed locally.

## The difference

The incumbent plugin (security-guidance) wires its regexes to **PostToolUse**: it
warns *after* the insecure code is already written, then hopes the model
regenerates it. That proves code was *repaired* secure.

Peephole wires the same class of check to **PreToolUse** and returns
`permissionDecision:deny` *before* the write lands. In strict/hardened mode the
insecure hunk never touches disk. That proves code was *born* secure, and it
closes the Bash escape hatch (`cat > f <<EOF …`) that a plain Write-tool gate
misses.

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
  InstructionsLoaded re-scans a just-loaded instruction file (nested
  `CLAUDE.md`, `.claude/rules/*`) for Unicode/injection backdoors.
- Stop forces continuation via top-level `{"decision":"block","reason":str}`.
- stdin field names: `hook_event_name`, `tool_name`, `tool_input`
  (Write/Edit: `file_path`/`content`/`new_string`; Bash: `command`), `prompt`,
  `source`, `cwd`, `session_id`. Grok Code uses the camelCase aliases
  (`hookEventName`, `toolName`, `toolInput`, `workspaceRoot`, `sessionId`)
  and `pre_tool_use` event values; deny is top-level `decision` on that
  dialect only.

## Runtime: a single static Go binary (no interpreter dependency)

Hooks are a compiled Go binary, cross-compiled to darwin/linux/windows and
shipped in `bin/`. The developer installs **no runtime** — not Node, not Python.
Rationale over an interpreted hook:
- **Portable:** `claude` may be a native binary that guarantees neither `node`
  nor `python3` on PATH. A shipped static binary needs nothing.
- **Fast:** native start ~1-5ms vs ~40-80ms interpreter cold-start. PreToolUse
  fires on every Write/Edit/Bash — the dev must not feel it.
- **Novel & hardened:** rules are compiled to Go literals baked into the binary
  (`cmd/kbgen` → `rules_gen.go`), so a local attacker cannot edit loose JSON the
  binary ignores; poisoning requires
  replacing the binary, which the self-integrity check detects.

RE2 has no lookaround, so KB exclusions are declarative refinements
(`prev_not`, `reject_re`, `require_re`) rather than lookahead/lookbehind.

Fail-safe boundary: if no binary matches the platform, the launcher exits 0 with
a visible notice — peephole never blocks the workflow because it cannot run.
This is distinct from fail-**closed**, which applies only when the binary ran and
hit an internal error mid-decision.

**Hot-path performance (~0.33ms of scanning; ~4ms end-to-end unencumbered, ~15–50ms
on an AV-managed endpoint).** PreToolUse fires on every
Write/Edit/Bash, so the whole path is tuned: the launcher execs the cached binary
directly; the CWE knowledge base ships as build-time-generated Go literals with
precomputed literal-set prefilters, so `loadKB` is ~7µs rather than ~2ms of JSON
parsing, and there is no file I/O to load rules on the hot path (compiled-in
literals also mean a local attacker can't quietly edit rule files the binary would
ignore); a detached SessionStart `warmcache` pre-warms the slopsquat cache so the
first install verdict skips a cold ~500ms registry round-trip.

**Measured components** (reproduce with `go test -run '^$' -bench 'LoadKB|Scan|Hot' -benchmem`):

| stage | cost | note |
|---|---|---|
| `loadKB` | ~6µs | generated Go literals, 1 alloc |
| scan, typical write (~400B, taint source present) | ~0.33ms | 103 allocs |
| scan, clean file with no sink literal | ~0.4µs/byte | 0 allocs — prefilter skips both passes |
| scan, full 256KB hot-path window | **~109ms** | linear at ~0.4µs/byte |
| `appendLog` (hash-chained audit entry) | **~16ms** | ~5 file ops: lock, read head, append, write head, unlock |
| `bumpDecisionCount` | **~6.7ms** | read + overwrite |

**Scanning is not the hot-path cost; state I/O is.** A clean 6-line Write measures
~49ms end-to-end on a developer laptop with endpoint AV active, against ~14ms for
the same write with `mode=off` (which short-circuits before the state writes) and a
~7.3ms floor for a do-nothing Go binary built with the same flags. The scan
accounts for 0.33ms of that. The remainder is the audit chain: on this machine a
single file open/write/close costs **~3–5ms** instead of the ~0.05ms an
unencumbered APFS write takes, because the endpoint agent inspects every file
operation. Peephole performs ~5–7 file operations per gated event.

Consequences worth stating plainly:

- On a machine with no endpoint agent in the file path, ~4ms end-to-end is
  achievable (~2.7ms Go process floor + ~0.33ms scan + state I/O at ~0.05ms/op).
- On a **managed corporate endpoint the realistic figure is ~15–50ms**, and it is
  dominated by AV-inspected writes to `.peephole/`, not by rule evaluation. Adding
  the state directory to the endpoint agent's exclusion list is the effective
  optimization; tuning the regex engine is not.
- This cost is close to irreducible for an append-only hash chain — the writes are
  the integrity property. Batching them would trade tamper-evidence for latency.
- 30-day retention and expired-archive deletion run at SessionStart (at most once
  a day) and `peephole audit`. `appendLog` does not scan or compact.

The taint pass skips files with no sink literal (prefilter recovery via the regex
AST), so scan allocations on clean files are zero. The rest of any observed
session latency is model generation.

## Scope (what this build includes vs defers)

IN (v1 core, mechanisms N1–N6 + experimental N7, KB across ~31 language buckets):
- Mode resolution off/audit/guided/strict/hardened + persisted, signed state.
- N1 Security Ladder injected at SessionStart/SubagentStart (task-classified for subagents).
- Enforcement plane: PreToolUse gate on Write/Edit/MultiEdit/NotebookEdit;
  Bash write-path payload extraction (with benign-producer carve-out); slopsquat
  gate on installs AND manifest edits; path-aware self-protection.
- CWE-keyed KB (181 rules as generated Go literals in `rules_gen.go`) with
  presence_patterns (enforced) vs absence_requirements (advisory checklist
  only); full §4.1 schema per rule.
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
  at SessionStart and ConfigChange (alarm, does not veto a write); signed mode
  file; state schema-version.
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
.claude-plugin/plugin.json   plugin metadata only (no hooks/skills paths — Claude Code auto-loads hooks/hooks.json and skills/)
.grok-plugin/marketplace.json Grok Code marketplace index (source ./ ; install with --trust)
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
audit.go                     running-hash tamper-evident log + 30-day retention + decision counters
integrity.go                 self-binary + hooks + skills + plugin.json SHA-256 vs bin/manifest.sha256
unicode.go                   zero-width/bidi/homoglyph + injection-phrase scanner
report.go                    OWASP 2025 rollup + SARIF 2.1.0 export
rules_gen.go                 generated KB: rules + taint specs as Go literals (from cmd/kbgen)
cmd/kbgen/main.go            code generator: rules/*.json + taint/*.json -> rules_gen.go
rules/*.json                 CWE-keyed KB records (data, never code)
skills/{peephole,sec-review,sec-debt,sec-audit}/SKILL.md
peephole_test.go             end-to-end hook contract tests (exit codes + decisions)
unit_test.go                 KB exemplar + schema contract, bashparse, log-chain tamper, prefilter soundness
corpus_test.go               TP/FP/evasion/hostile-input cases
bench_test.go                scan/load latency budgets
build.sh                     cross-compile all targets + regen manifest
```

## Mode matrix (binding; all decisions generate from it)

| Event | guided (default) | audit | strict | hardened |
|---|---|---|---|---|
| High-confidence presence hit (KEV/Top-25) | ask | warn+log | deny | deny |
| Other presence hit | ask | warn+log | ask | deny |
| Absence_requirement | checklist only | checklist only | checklist only | checklist only |
| Enforcement internal error / timeout | warn+log (fail open) | warn+log (fail open) | **deny** (fail closed) | deny |
| Registry unreachable/unverifiable pkg | ask | log | ask | deny new install / ask on manifest edit |
| sec-debt marker (line-scoped) on would-be-deny | n/a (already ask) | n/a | deny→ask + waiver logged | stays deny |
| sec-debt without approval | flag at Stop + `/sec-audit` | same | same | same |
| Write to Peephole's own paths | **deny** (non-waivable) | deny | deny | deny |
| updatedInput rewrite | ask+preview if fully clean | no rewrite | ask+preview if fully clean | ask+preview if fully clean |

Deny = structured `permissionDecision:deny` or exit 2. Never exit 1.
Self-protection denies in every mode, including `off` (checked before the
mode short-circuit). Org-`enforce` CWEs are a hard deny in every mode the
hook still runs, including `guided` and `audit`.

## State (`.peephole/` under project or CLAUDE_PROJECT_DIR)

- `mode` — one line: off|audit|guided|strict|hardened (default `guided` if
  missing), plus `mode.sig` (keyed SHA-256 of the mode line; out-of-band
  flips fail-close to strict) and `state-version` (schema version;
  migrate-or-reset on mismatch).
- `log.jsonl` — append-only decisions; every 50th entry carries a SHA-256 chain hash.
- `pkgcache.json` — 7-day registry-verdict cache; `lastcommit` — commit-review dedupe.
- `session/<id>.*` — per-session: neg-test hint + continuation counter, sec-debt
  markers seen, hunk digests (memo), write/decision counts, taint set (N7 opt-in).
- Self-protection: any Write/Edit/Bash/MCP targeting `.peephole/` or the plugin
  dir is denied in all modes (path-aware: `.peephole-rules.json` and
  `.peephole-policy.json` are committed project files and stay editable).

## Build & test

```sh
./build.sh      # regenerate rules_gen.go, cross-compile all targets, regen integrity manifest
go test ./...   # end-to-end hook contract tests + KB self-consistency + tamper tests
```

## Extensibility & enterprise

- **Custom / org rules (additive):** drop a `.peephole-rules.json` (or
  `.claude/peephole-rules.json`) in your project — an array of rule records in the
  same schema. They *add* findings; they can never disable a built-in. Safe by
  construction: RE2 is linear-time, so a custom regex can't ReDoS.
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
- **Enterprise default (`allowManagedHooksOnly`):** for the **fleet binary**
  path, set `"allowManagedHooksOnly": true` in the managed source that actually
  wins (MDM plist/HKLM **or** `managed-settings.d`, not a user `settings.json`)
  so only admin-pushed hooks run. Do **not** set it on a marketplace-plugin
  install — it blocks plugin hooks. See `docs/ENTERPRISE.md`.
- **Statusline badge:** add a `statusLine` command running `peephole statusline` to
  show `peephole strict | N blocked M flagged | 181 rules` in your status bar.
- **N7 taint-echo (experimental, off by default):** create `.peephole/taint-echo`
  to enable provenance escalation (code derived from fetched/README/MCP content
  reaching a sink → ask). It also requires wiring WebFetch/Read into PostToolUse;
  left off, it adds zero hot-path cost.

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
- **Not a SAST replacement.** No whole-repo taint, no cross-file analysis, no
  semantic proof. Missing-guard classes are reviewed at Stop and on commit by
  the host agent (no second model). Pair with other SAST tools in CI for
  cross-file taint; they compose rather than compete.
- **Deferred from the blueprint:** Tier-3 language curation, a live MCP registry
  server, release signing, and the external eval suites (CodeGuard+/CWEval/
  BaxBench, Phase 4). N7 taint-provenance ships as an opt-in.
