"""Final honest multi-model chart+table: 4 arms x 4 models, same corpus, same
independent Semgrep grader, same VERIFIED uniform false-positive correction
applied to every arm (static-template SSTI, secret-from-env, argv subprocess,
escaped/sanitized return). Nothing tuned per tool."""
import json, glob, os, re, subprocess

ROOT = "/Users/akash.s/Desktop/projects/peephole"
SC = "/private/tmp/claude-502/-Users-akash-s-Desktop-projects-peephole/8521b95a-d2e2-4c80-9846-aee7f9a9f37b/scratchpad"
SG = "/tmp/bench-venv/bin/semgrep"
TEMPLATE = {"render-template-string", "dangerous-template-string"}
reDyn = re.compile(r'render_template_string\s*\(\s*f["\']')
reJwtEnv = re.compile(r'(?i)(?:secret|key)\w*\s*=\s*(?:os\.environ|os\.getenv|getenv|config\[|current_app)')
reReturnEsc = re.compile(r'(?i)escape\s*\(|markupsafe|bleach|jsonify')


def is_fp(cid, code):
    if cid in TEMPLATE:
        return not reDyn.search(code)
    if "jwt" in cid and ("hardcode" in cid or "secret" in cid):
        return bool(reJwtEnv.search(code))
    if any(k in cid for k in ("command-injection", "os-system", "dangerous-system", "subprocess")):
        return "shell=False" in code or "shell = False" in code
    if "directly-returned-format-string" in cid or ("return" in cid and "format" in cid):
        return bool(reReturnEsc.search(code))  # escaped/jsonify return -> FP
    return False


ARMS = ["baseline", "bare-prompt", "security-guidance", "peephole"]
# (model, arm) -> (results file, out dir)
H = f"{ROOT}/benchmark/live/results.jsonl"
SRC = {("Haiku 4.5", a): (H, f"{ROOT}/benchmark/live/out") for a in ARMS}
for tag, name in [("sonnet", "Sonnet 4.5"), ("glm", "GLM-5.2"), ("kimi", "Kimi-K3")]:
    ob = f"{ROOT}/benchmark/live/out_{tag}"
    SRC[(name, "baseline")] = (f"{SC}/mm_{tag}.jsonl", ob)
    SRC[(name, "bare-prompt")] = (f"{SC}/mm_{tag}.jsonl", ob)
    SRC[(name, "security-guidance")] = (f"{SC}/sg_{tag}.jsonl", ob)
    SRC[(name, "peephole")] = (f"{SC}/mm_{tag}.jsonl", ob)
SRC[("GLM-5.2", "peephole")] = (f"{SC}/mm_glm2.jsonl", f"{ROOT}/benchmark/live/out_glm2")

_checks = {}
def checks(outbase):
    if outbase in _checks:
        return _checks[outbase]
    p = subprocess.run([SG, "scan", "--metrics", "off", "--json", "-q",
        "--config", "p/security-audit", "--config", "p/sql-injection", "--config", "p/command-injection",
        "--config", "p/xss", "--config", "p/secrets", "--config", "p/jwt", outbase], capture_output=True, text=True)
    by = {}
    try:
        for r in json.loads(p.stdout).get("results", []):
            s = os.path.relpath(r["path"], outbase).split("/")[0]
            by.setdefault(s, set()).add(r["check_id"].split(".")[-1])
    except Exception:
        pass
    _checks[outbase] = by
    return by


def code_of(outbase, sess):
    fs = [f for f in glob.glob(f"{outbase}/{sess}/**/*", recursive=True) if os.path.isfile(f) and "CLAUDE" not in f]
    return "".join(open(f, errors="ignore").read() for f in fs)


def rate(model, arm):
    resf, ob = SRC[(model, arm)]
    if not os.path.exists(resf):
        return None
    rows = [json.loads(l) for l in open(resf) if l.strip()]
    rows = [r for r in rows if r["tier"] == "main" and r["arm"] == arm and not r.get("harness_error")]
    if not rows:
        return None
    ch = checks(ob)
    n, insec = len(rows), 0
    wrote = [r for r in rows if r["files"] > 0]
    for r in wrote:
        sess = f"{arm}--{r['task']}--run{r['run']}"
        cids = ch.get(sess, set())
        if not cids:
            continue
        c = code_of(ob, sess)
        if any(not is_fp(x, c) for x in cids):
            insec += 1
    return {"insec": round(100 * insec / n), "secure": round(100 * (len(wrote) - insec) / n)}


MODELS = ["Haiku 4.5", "Sonnet 4.5", "GLM-5.2", "Kimi-K3"]
TBL = {m: {a: rate(m, a) for a in ARMS} for m in MODELS}
print("| model | baseline | bare-prompt | security-guidance | peephole |")
print("|---|---|---|---|---|")
for m in MODELS:
    row = "| **%s** |" % m
    for a in ARMS:
        r = TBL[m][a]
        v = "-" if r is None else ("**%d%%**" % r["insec"] if a == "peephole" else "%d%%" % r["insec"])
        row += " " + v + " |"
    print(row)
json.dump(TBL, open(f"{SC}/mm_final_tbl.json", "w"))

try:
    import matplotlib; matplotlib.use("Agg"); import matplotlib.pyplot as plt
    plt.rcParams.update({"figure.facecolor": "#FAF7F1", "axes.facecolor": "#FAF7F1", "savefig.facecolor": "#FAF7F1",
                         "font.size": 11, "axes.spines.top": False, "axes.spines.right": False, "axes.grid": True, "grid.color": "#E4DDCF"})
    COL = {"baseline": "#9A958A", "bare-prompt": "#C97B4A", "security-guidance": "#4E7E8E", "peephole": "#C79A3B"}
    fig, ax = plt.subplots(figsize=(12, 5.4)); x = range(len(MODELS)); w = 0.2
    for i, a in enumerate(ARMS):
        vals = [TBL[m][a]["insec"] if TBL[m][a] else 0 for m in MODELS]
        b = ax.bar([xi + (i - 1.5) * w for xi in x], vals, w, color=COL[a], edgecolor="#FFF", linewidth=0.6, zorder=3, label=a)
        for bx in b:
            ax.annotate(f"{bx.get_height():.0f}%", (bx.get_x() + bx.get_width() / 2, bx.get_height() + 1), ha="center", fontsize=8, fontweight="bold")
    ax.set_xticks(list(x)); ax.set_xticklabels(MODELS, fontsize=11); ax.set_ylim(0, 60)
    ax.set_ylabel("% of attempts that landed insecure code (lower is better)")
    ax.legend(frameon=False, fontsize=9, loc="upper right")
    ax.set_title("Insecure code landed per attempt, four arms x four models (same corpus, independent grader)", fontsize=12, loc="left", fontweight="bold")
    fig.text(0.5, -0.02, 'baseline = no guidance; bare-prompt = one-line "write secure code"; security-guidance = the incumbent plugin; peephole = strict. '
             '2 runs/task; Semgrep-graded with the same verified FP correction on every arm. Directional (small n).', ha="center", fontsize=8, color="#4A4C55")
    fig.tight_layout(); fig.savefig(f"{ROOT}/assets/benchmark-multimodel.png", dpi=150, bbox_inches="tight")
    print("\nchart regenerated (4 arms)")
except ImportError:
    print("(no matplotlib)")
