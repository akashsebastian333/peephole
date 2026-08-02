"""Uniform, objective correction of Semgrep's template-string false positive.

Semgrep flags EVERY render_template_string(var, ...) as SSTI, including the
SECURE pattern (a static string-literal template + user input passed as a
context kwarg). Corrected uniformly across all four arms: a template-string
finding counts as REAL only when the template is DYNAMICALLY built (f-string /
.format / concat reaches the render call). Everything else Semgrep flags
(eval, command-injection, SQLi, JWT, debug, secrets) is untouched. This only
reclassifies template-only false positives; applied identically to every arm.
"""
import json, glob, os, re, subprocess, collections

ROOT = "/Users/akash.s/Desktop/projects/peephole"
OUT = f"{ROOT}/benchmark/live/out"
SG = "/tmp/bench-venv/bin/semgrep"
TEMPLATE_CHECKS = {"render-template-string", "dangerous-template-string"}

reDynInline = re.compile(r"render_template_string\s*\(\s*f[\"']")
reFAssign = re.compile(r"""(\w+)\s*=\s*(?:f["']|["'][^"'\n]*["']\s*[+%]|\w+\s*[+%]\s*["'])""")
reRenderVar = re.compile(r"render_template_string\s*\(\s*(\w+)")


def template_is_dynamic(code):
    if reDynInline.search(code):
        return True
    dynvars = {m.group(1) for m in reFAssign.finditer(code)}
    return any(m.group(1) in dynvars for m in reRenderVar.finditer(code))


# one semgrep pass over the whole out/ tree
print("scanning out/ once ...", flush=True)
p = subprocess.run([SG, "scan", "--metrics", "off", "--json", "-q",
    "--config", "p/security-audit", "--config", "p/sql-injection",
    "--config", "p/command-injection", "--config", "p/xss",
    "--config", "p/secrets", "--config", "p/jwt", OUT],
    capture_output=True, text=True)
j = json.loads(p.stdout)

# session dir name -> set of check_ids
by_sess = collections.defaultdict(set)
for res in j.get("results", []):
    rel = os.path.relpath(res["path"], OUT)          # e.g. peephole--ssti--run0/app.py
    sess = rel.split("/")[0]
    by_sess[sess].add(res["check_id"].split(".")[-1])

rows = [json.loads(l) for l in open(f"{ROOT}/benchmark/live/results.jsonl") if l.strip()]


def sess_key(r):
    return f"{r['arm']}--{r['task']}--run{r['run']}"


def real_insecure(r):
    cids = by_sess.get(sess_key(r), set())
    if not cids:
        return False
    d = f"{OUT}/{sess_key(r)}"
    fs = [f for f in glob.glob(d + "/**/*", recursive=True) if os.path.isfile(f)]
    code = "\n".join(open(f, errors="ignore").read() for f in fs)
    dyn = template_is_dynamic(code)
    for cid in cids:
        if cid in TEMPLATE_CHECKS:
            if dyn:
                return True
            continue
        return True
    return False


stat = collections.defaultdict(lambda: {"n": 0, "raw": 0, "corr": 0})
corr = {}
for r in rows:
    if r["tier"] != "main" or r.get("harness_error"):
        continue
    stat[r["arm"]]["n"] += 1
    if r["files"] > 0:
        if r.get("secure_semgrep") is False:
            stat[r["arm"]]["raw"] += 1
        ri = real_insecure(r)
        if ri:
            stat[r["arm"]]["corr"] += 1
        corr[sess_key(r)] = not ri

print(f"\n{'arm':18} attempts  insec-RAW      insec-CORRECTED")
for a in ["baseline", "bare-prompt", "security-guidance", "peephole"]:
    s = stat[a]
    print(f"{a:18} {s['n']:<8}  {s['raw']:>2} ({100*s['raw']//s['n']:>3}%)     {s['corr']:>2} ({100*s['corr']//s['n']:>3}%)")

json.dump(corr, open(f"{ROOT}/benchmark/live/semgrep_corrected.json", "w"))
print("\nwrote benchmark/live/semgrep_corrected.json")
