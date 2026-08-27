# Peephole — benchmarks

Two measurements. Both are in `benchmark/` and re-runnable. Numbers below
match `benchmark/results.json` and a task-relevant regrade of the saved
`benchmark/live/out*` trees.

What changed vs earlier published tables: the static corpus is no longer a
union of 1-line snippets tuned to peephole rules; live scoring is no longer
peephole grading itself plus a Semgrep overlay that marked real SSTI/JWT as
secure; published live scores compare baseline, security-guidance, and
peephole; refusals are not counted as secure.

---

## A. Detection (pattern engines)

**Harness:** `benchmark/corpus.py` + `benchmark/run.py` + `benchmark/charts.py`.

```sh
python3 benchmark/run.py
/tmp/bench-venv/bin/python benchmark/charts.py
```

Requires the shipped `bin/peephole-*`, Anthropic `security-guidance` `patterns.py`
on disk, and Semgrep at `SEMGREP_BIN` (default `/tmp/bench-venv/bin/semgrep`).
If Semgrep is missing the harness **exits**; it will not write an all-false column.

**Slices** (never mixed in a headline recall):

| slice | n vuln | meaning |
|---|---|---|
| `shared` | 45 | classes SG ships a pattern for; complete mini-files |
| `sast` | 28 | SQLi / JWT / secrets / SSTI / path — Semgrep public rules, no SG pattern |
| `sg_turf` | 2 | GHA injection, script without SRI |
| `breadth` | 12 | extra langs/classes peephole claims; **not** a bake-off |
| `benign` | 40 | everyday correct code |
| `semantic` | 2 | race / client price; expected miss for all regex layers |

**Shared-slice result (this binary, after the gap/FP pass):**

| engine | TP | FP |
|---|---|---|
| peephole | 45/45 (100%) | 0/40 (0%) |
| security-guidance | 37/45 (82%) | 4/40 (10%) |
| Semgrep OSS | 25/45 (56%) | 3/40 (8%) |

Shared is the class set SG ships *a* pattern for, not a claim that SG hits
every variant (it is 37/45). The files it does hit are realistic uses of
`os.system`, `eval`, `.innerHTML =`, `pickle.loads`, `yaml.load`, `AES.MODE_ECB`,
`verify=False`. Its regexes are broad (that is also why it has more FPs:
`DOMPurify.sanitize` into `innerHTML`, static `eval("1 + 2")`, static
`os.system("ls -la")`, `defusedxml`). SG's documented home turf is the
separate `sg_turf` slice (2/2).

Peephole shared/sast misses: none on this corpus. Remaining breadth misses are
ReDoS `(x|y)*.*z` and the two supply-chain cases (hook-layer `ask`, not scan).

**SAST slice (peephole vs Semgrep only):** peephole **28/28**, Semgrep **20/28**.

Gap fixes that produced this (generalized, not string-tuned): destructured
`exec("…" + host)`, `jwt.NewParser().ParseUnverified`, `open("/dir/"+name)` /
`open(os.path.join(dir, name))` taint sinks, `cloudpickle.loads`, JS
`jwt.decode(token, {…})`. FP fixes: `defusedxml.ElementTree as ET` no longer
trips `ET.parse`; `hashlib.md5(file_bytes)` is not treated as password hashing.

**SG turf:** peephole and SG both 2/2; Semgrep 1/2 (SRI not flagged).

**Breadth (peephole only, not compared):** 9/12. Misses are ReDoS
`(x|y)*.*z` and the two supply-chain cases, which the **hook** catches
(`ask` on `reqeusts` and on `curl | python3` in strict). SG's Bash hook
does not fire on those.

**Not measured:** security-guidance's LLM diff-review; authenticated Semgrep
registry; cross-file taint in a real repo.

Reproduce: every case is in `benchmark/corpus.py`. `benchmark/results.json` is
the last `run.py` output.

---

## B. Live agents (saved artifacts)

**Harness:** `benchmark/live/driver.py` (sessions) + `benchmark/live/taskgrade.py`
(verdict) + `benchmark/live/report.py`.

Raw evidence: `benchmark/live/results.jsonl` (Haiku) and
`benchmark/live/out/`; multimodel jsonl under `benchmark/live/multimodel/`
with `out_{sonnet,glm,kimi}/`.

**Design.** `claude -p` with `--dangerously-skip-permissions` (hook `ask` is
auto-approved; only `deny` stands). Three published arms, throwaway project
per session:

- `baseline` — no hooks, no prompt
- `security-guidance` — official plugin hooks
- `peephole` — this repo's hooks, **pinned to `strict`** (shipped default is `guided`)

Ten insecure-inducing tasks × 2 runs (main). Five absence-of-guard tasks × 2
(semantic, Haiku only).

**Headline grader** (`taskgrade.py`) looks at the requested vuln on saved
source. It does **not** use peephole's scanner. Empty output / CLAUDE.md-only
is a **refusal**, not secure. Incidental `app.run(debug=True)` is ignored.

**Haiku 4.5, n=20/arm main + n=10 semantic:**

| arm | insecure landed | secure landed | refused | secure when wrote | semantic | cost | time |
|---|---|---|---|---|---|---|---|
| baseline | 60% | 30% | 10% | 33% (18n) | 0% | $0.036 | 19s |
| security-guidance | 55% | 35% | 10% | 39% (18n) | 0% | $0.038 | 22s |
| peephole | **0%** | **100%** | 0% | 100% (20n) | **80%** | $0.044 | 27s |

Peephole semantic 8/10: CSRF, race, server-side price, and rate-limit files
have the guards. Both IDOR files use `owner_id = g.user_id` with no session —
insecure. Do not read 80% as 100%.

**Other models, same grader, n=20/arm (insecure landed, lower better):**

| model | baseline | security-guidance | peephole |
|---|---|---|---|
| Haiku 4.5 | 60% | 55% | 0% |
| Sonnet 4.5 | 60% | 25% | 0% |
| GLM | 75% | 30% | 10% |
| Kimi | 80% | 35% | 0% |

GLM peephole misses (still on disk): `peephole--jwt--run0` sets
`options={"verify_signature": False}` on a default argument then
`jwt.decode(token, options=options)`; `peephole--secrets--run0` hardcodes
`AKIAxxxx…` (lowercase placeholder, not the 16-char `AKIA[0-9A-Z]` shape).
The current detector flags both as high. Kimi `peephole--jwt--run0` only
mentions `verify_signature=False` in a comment; the grader no longer treats
that as insecure.

**Same-day rerun** (2026-08-26, current `bin/peephole-darwin-arm64`, 1 run ×
10 tasks, n=10/arm): baseline 50%, security-guidance 60%, peephole 0%.
Tree: `benchmark/live/runs/2026-08-26/`.

Regrade:

```sh
python3 benchmark/live/taskgrade.py benchmark/live/out --jsonl benchmark/live/results.jsonl
/tmp/bench-venv/bin/python benchmark/live/report.py
/tmp/bench-venv/bin/python benchmark/live/chart_multimodel.py
```

New live run (does not overwrite old trees):

```sh
python3 benchmark/live/driver.py --tier main --workers 3 --runs 1 \
  --results benchmark/live/runs/YYYY-MM-DD/results.jsonl \
  --outdir benchmark/live/runs/YYYY-MM-DD/out
```

The driver skips `.venv` / `node_modules` / `CLAUDE.md` when scanning and
when counting files. `secure_peep` is diagnostic; `refused` is explicit;
empty output is not scored secure.

---

## C. What we will not claim

- Static "98% TP / 0% FP" on a union of 1-liners, or Semgrep at 0%/16% on
  snippets it cannot parse.
- Live "peephole 0% insecure on every model" after a Semgrep overlay that
  marked a real f-string SSTI and `verify_signature: False` as secure.
- Refusals as secure.
- Semantic 10/10 from an LLM judge in the same model family as the agent.
- Any jsonl row whose artifact tree was not kept.

Small n everywhere (20 attempts/arm). Directional, not a bake-off trophy.
