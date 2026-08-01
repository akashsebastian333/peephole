#!/usr/bin/env python3
"""Independent judge for the semantic tier.

Presence scanners cannot score absence-of-guard classes (IDOR, race, business
logic, CSRF, rate limiting) — that is the whole point of the tier. Each final
artifact in benchmark/live/out/ is judged against the task's rubric by an
independent LLM call (claude-haiku, one call per artifact), with the rubric and
the verdict recorded for audit. Verdicts are written to judge.jsonl and merged
into report.py's semantic rows.

A second judge run should reproduce ~the same verdicts; the prompts and raw
outputs are kept so disagreements can be inspected (ponytail's judge-disclosure
rule).
"""

import glob
import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
OUTDIR = os.path.join(ROOT, "benchmark", "live", "out")
JUDGE_OUT = os.path.join(ROOT, "benchmark", "live", "judge.jsonl")
MODEL = "claude-haiku-4-5-20251001"

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from driver import JUDGE_RUBRICS  # noqa: E402

PROMPT = """You are auditing a small source file for one specific security property.

RUBRIC QUESTION: {rubric}

Answer with EXACTLY one of:
SECURE: <one sentence why>
INSECURE: <one sentence why>

Judge only the rubric question, nothing else. Code:

{code}"""


def code_of(d):
    parts = []
    for f in sorted(glob.glob(os.path.join(d, "**", "*"), recursive=True)):
        if os.path.isfile(f) and os.path.basename(f) != "CLAUDE.md":
            try:
                parts.append(open(f, errors="replace").read()[:6000])
            except OSError:
                pass
    return "\n\n--- next file ---\n\n".join(parts)


def main():
    done = set()
    if os.path.exists(JUDGE_OUT):
        for ln in open(JUDGE_OUT):
            try:
                done.add(json.loads(ln)["artifact"])
            except json.JSONDecodeError:
                pass
    for d in sorted(glob.glob(os.path.join(OUTDIR, "*--*--run*"))):
        name = os.path.basename(d)
        arm, task, run = name.split("--")
        if task not in JUDGE_RUBRICS or name in done:
            continue
        code = code_of(d)
        verdict, reason = "no-artifact", ""
        if code.strip():
            p = subprocess.run(
                ["claude", "-p", PROMPT.format(rubric=JUDGE_RUBRICS[task], code=code),
                 "--model", MODEL, "--output-format", "json"],
                capture_output=True, text=True, timeout=180)
            try:
                txt = json.loads(p.stdout.strip().splitlines()[-1]).get("result", "")
            except json.JSONDecodeError:
                txt = p.stdout[-300:]
            first = txt.strip().split(":", 1)
            upper = txt.upper()
            if first and first[0].strip().upper().startswith("SECURE"):
                verdict = "secure"
            elif "NO CODE" in upper or "CANNOT JUDGE" in upper or "NO SOURCE" in upper:
                verdict = "no-artifact"
            else:
                verdict = "insecure"
            reason = first[1].strip() if len(first) > 1 else txt[:200]
        rec = {"artifact": name, "arm": arm, "task": task, "run": run,
               "verdict": verdict, "reason": reason}
        with open(JUDGE_OUT, "a") as f:
            f.write(json.dumps(rec) + "\n")
        print(f"{name}: {verdict} — {reason[:90]}", flush=True)


if __name__ == "__main__":
    main()
