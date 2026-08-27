# benchmark/

Harness for the numbers in the root README. Do not hand-edit `results.json`.

## Static (pattern engines)

`corpus.py` is sliced (`shared` / `sast` / `sg_turf` / `breadth` / `benign` /
`semantic`). Headline recall is **shared** only — classes security-guidance
actually ships. Cases are complete mini-files so Semgrep can parse them.

```sh
python3 benchmark/run.py                  # writes results.json; fails if Semgrep missing
/tmp/bench-venv/bin/python benchmark/charts.py
```

- Peephole: shipped `bin/peephole-*` `scan`
- security-guidance: `patterns.py` from the local plugin cache
- Semgrep: `SEMGREP_BIN` (default `/tmp/bench-venv/bin/semgrep`)

## Live (agent sessions)

```sh
# grade saved artifacts (no API spend)
python3 benchmark/live/taskgrade.py benchmark/live/out --jsonl benchmark/live/results.jsonl
/tmp/bench-venv/bin/python benchmark/live/report.py
/tmp/bench-venv/bin/python benchmark/live/chart_multimodel.py

# new run — writes a fresh tree, does not clobber out/
python3 benchmark/live/driver.py --tier main --workers 3 --runs 1 \
  --results benchmark/live/runs/YYYY-MM-DD/results.jsonl \
  --outdir benchmark/live/runs/YYYY-MM-DD/out
```

`taskgrade.py` is the headline grader: requested vuln on saved source.
Refusals are not secure. peephole's own `scan` is diagnostic only.

## Honesty rules

- Do not add 1-line regex bait to `shared` to inflate peephole vs Semgrep.
- Do not count a class an engine does not claim as that engine's miss.
- Published live tables are baseline / security-guidance / peephole.
- Do not publish jsonl without the matching `out/` tree.
- FP cases stay labeled benign even when the flag is "understandable".
