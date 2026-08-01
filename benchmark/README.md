# benchmark/ — detection benchmark harness

Labeled-corpus detection comparison, three engines on identical inputs:
**peephole**, **Anthropic's `security-guidance`** (pattern layer), and
**Semgrep OSS** (public registry rules). Reproducible end to end.

## Layout

- `corpus.py` — 203 labeled cases: 151 vulnerable (24 CWE classes), 50 benign
  everyday-code, 2 semantic (race/business-logic, reported separately). The
  vulnerable set is the *union* of all tools' documented detection classes
  plus independent edge cases.
- `run.py` — runs all engines over identical inputs and prints + writes
  `results.json`. Peephole is measured via the shipped binary's `scan` command
  (the same engine the PreToolUse gate runs); security-guidance via its own
  `patterns.py` imported read-only from the local plugin cache, executed with
  its exact `check_patterns()` semantics; Semgrep via one batch `semgrep scan`
  over 21 unauthenticated registry packs. Also measures the hook-layer
  (PreToolUse) outcome for the supply-chain cases.
- `charts.py` — renders `assets/benchmark-overall.png` +
  `assets/benchmark-categories.png` (needs matplotlib).
- `live/` — the **agent-level benchmark**: real `claude -p` sessions, 4 arms
  (baseline / bare-prompt / security-guidance / peephole), 10 insecure-inducing
  tasks × 2 runs + a 6-attack adversarial tier. `live/driver.py` runs the
  sessions into `live/results.jsonl`; `live/report.py` aggregates and renders
  `assets/benchmark-live.png` (ponytail-style: every metric vs baseline).
  Costs real API money (~$0.05–0.15/session, ~100 sessions) and takes hours —
  run it deliberately, not in CI.

## Re-run

```sh
# static corpus benchmark (pattern engines)
./build.sh                                # rebuild the peephole binary
python3 benchmark/run.py                  # writes results.json + prints tables
python3 -m venv /tmp/bench-venv && /tmp/bench-venv/bin/pip install matplotlib semgrep
/tmp/bench-venv/bin/python benchmark/charts.py

# live agent benchmark (hours, real API spend, ~100 sessions)
python3 benchmark/live/driver.py --tier both --workers 4 --runs 2
/tmp/bench-venv/bin/python benchmark/live/report.py
```

- security-guidance location: defaults to
  `~/.claude/plugins/marketplaces/claude-plugins-official/plugins/security-guidance/hooks`;
  pass another hooks dir as `run.py`'s first argument.
- Semgrep binary: `SEMGREP_BIN` env var, default `/tmp/bench-venv/bin/semgrep`.
  If absent, the Semgrep leg is skipped and the report falls back to 2-way.
  Note the corpus handicaps taint engines (short snippets, no cross-file
  context) and runs unauthenticated — see `docs/BENCHMARK.md` for the honest
  reading of its number.

## Rules of engagement (so the comparison stays honest)

- New vulnerable cases must be added as *classes*, never tuned to make any
  engine look good or bad; all engines always see byte-identical inputs.
- Cases a tool catches at a different layer (hook, LLM review, MCP) are
  reported at that layer and labeled as such — see the hook-layer and
  "not measured" sections in `docs/BENCHMARK.md`.
- FP cases are sacred: everyday correct code a developer writes all the time.
  A tool that flags one gets it counted, no matter how "understandable" the
  flag is.
- Benchmark-driven rule fixes are disclosed in `docs/BENCHMARK.md` with the
  before/after numbers, never silently folded in.
