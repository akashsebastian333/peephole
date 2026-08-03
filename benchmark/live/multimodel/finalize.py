"""Assemble the fresh headline (Haiku 4-arm) + multi-model tables and regenerate
both charts. All numbers computed from the fresh run; nothing hardcoded."""
import json, os
from collections import defaultdict
ROOT = "/Users/akash.s/Desktop/projects/peephole"
SC = os.path.dirname(os.path.abspath(__file__))
TBL = json.load(open(f"{SC}/fresh_tbl.json"))
ARMS = ["baseline", "bare-prompt", "security-guidance", "peephole"]
MODELS = ["Haiku 4.5", "Sonnet 4.5", "GLM-5.2", "Kimi-K3"]

# --- Haiku headline extras: refused, cost, wall from main tier; semantic from judge ---
rows = [json.loads(l) for l in open(f"{ROOT}/benchmark/live/results.jsonl") if l.strip()]
extra = {}
base_cost = base_wall = None
for arm in ARMS:
    m = [r for r in rows if r["tier"] == "main" and r["arm"] == arm and not r.get("harness_error")]
    refused = round(100 * sum(1 for r in m if r["files"] == 0) / len(m))
    cost = sum(r.get("cost_usd", 0) for r in m) / len(m)
    wall = sum(r.get("wall_s", 0) for r in m) / len(m)
    extra[arm] = {"refused": refused, "cost": cost, "wall": wall}
    if arm == "baseline":
        base_cost, base_wall = cost, wall
sem = defaultdict(lambda: [0, 0])
for r in (json.loads(l) for l in open(f"{ROOT}/benchmark/live/judge.jsonl") if l.strip()):
    sem[r["arm"]][1] += 1
    if str(r.get("verdict", "")).lower().startswith("secure"):
        sem[r["arm"]][0] += 1

print("HAIKU HEADLINE (n=20 main / n=10 semantic):")
print("| arm | insecure-landed / attempt (lower=better) | secure-landed | refused | secure when it wrote | semantic | cost | time |")
print("|---|---|---|---|---|---|---|---|")
for arm in ARMS:
    d = TBL["Haiku 4.5"][arm]
    wrote = d["wrote"]
    whenw = round(100 * (wrote - d["cor"]) / wrote) if wrote else 0
    s, n = sem[arm]
    e = extra[arm]
    label = f"**{arm}**" if arm == "peephole" else arm
    insec = f"**{d['insec_cor']}%**" if arm == "peephole" else f"{d['insec_cor']}%"
    print(f"| {label} | {insec} (raw {d['insec_raw']}%) | {d['secure']}% | {e['refused']}% | {whenw}% | "
          f"{round(100*s/n)}% | ${e['cost']:.3f} ({round(100*e['cost']/base_cost)}%) | {e['wall']:.0f}s ({round(100*e['wall']/base_wall)}%) |")

print("\nMULTI-MODEL:")
print("| model | baseline | bare-prompt | security-guidance | peephole | peephole secure-landed |")
print("|---|---|---|---|---|---|")
for m in MODELS:
    row = f"| {m} |"
    for a in ARMS:
        d = TBL[m][a]
        v = f" **{d['insec_cor']}%** |" if a == "peephole" else f" {d['insec_cor']}% |"
        row += v
    row += f" {TBL[m]['peephole']['secure']}% |"
    print(row)

# --- charts ---
try:
    import matplotlib; matplotlib.use("Agg"); import matplotlib.pyplot as plt
    plt.rcParams.update({"figure.facecolor": "#FAF7F1", "axes.facecolor": "#FAF7F1", "savefig.facecolor": "#FAF7F1",
        "font.size": 11, "axes.spines.top": False, "axes.spines.right": False, "axes.grid": True, "grid.color": "#E4DDCF"})
    COL = {"baseline": "#9A958A", "bare-prompt": "#C97B4A", "security-guidance": "#4E7E8E", "peephole": "#C79A3B"}
    # multi-model
    fig, ax = plt.subplots(figsize=(12, 5.4)); x = range(len(MODELS)); w = 0.2
    for i, a in enumerate(ARMS):
        vals = [TBL[m][a]["insec_cor"] for m in MODELS]
        b = ax.bar([xi + (i - 1.5) * w for xi in x], vals, w, color=COL[a], edgecolor="#FFF", linewidth=0.6, zorder=3, label=a)
        for bx in b:
            ax.annotate(f"{bx.get_height():.0f}%", (bx.get_x() + bx.get_width() / 2, bx.get_height() + 1), ha="center", fontsize=8, fontweight="bold")
    ax.set_xticks(list(x)); ax.set_xticklabels(MODELS); ax.set_ylim(0, 60)
    ax.set_ylabel("% of attempts that landed insecure code (lower is better)")
    ax.legend(frameon=False, fontsize=9, loc="upper right")
    ax.set_title("Insecure code landed per attempt, four arms x four models (same corpus, independent grader)", fontsize=12, loc="left", fontweight="bold")
    fig.text(0.5, -0.02, 'baseline = no guidance; bare-prompt = one-line "write secure code"; security-guidance = the incumbent plugin; peephole = strict. '
             '2 runs/task; Semgrep-graded with the same verified FP correction on every arm. Directional (small n).', ha="center", fontsize=8, color="#4A4C55")
    fig.tight_layout(); fig.savefig(f"{ROOT}/assets/benchmark-multimodel.png", dpi=150, bbox_inches="tight")
    print("\nregenerated benchmark-multimodel.png")

    # live headline chart (Haiku): insecure-landed vs secure-landed per arm, same grader
    fig2, ax2 = plt.subplots(figsize=(10, 5)); x = range(len(ARMS)); w = 0.38
    insec = [TBL["Haiku 4.5"][a]["insec_cor"] for a in ARMS]
    secure = [TBL["Haiku 4.5"][a]["secure"] for a in ARMS]
    b1 = ax2.bar([xi - w/2 for xi in x], insec, w, color="#B5482E", edgecolor="#FFF", zorder=3, label="insecure landed (lower better)")
    b2 = ax2.bar([xi + w/2 for xi in x], secure, w, color="#C79A3B", edgecolor="#FFF", zorder=3, label="secure landed (higher better)")
    for bs in (b1, b2):
        for bx in bs:
            ax2.annotate(f"{bx.get_height():.0f}%", (bx.get_x()+bx.get_width()/2, bx.get_height()+1), ha="center", fontsize=9, fontweight="bold")
    ax2.set_xticks(list(x)); ax2.set_xticklabels(ARMS); ax2.set_ylim(0, 105)
    ax2.set_ylabel("% of attempts")
    ax2.legend(frameon=False, fontsize=9, loc="upper center")
    ax2.set_title("Live agent benchmark (Haiku 4.5): insecure vs secure code landed per attempt", fontsize=12, loc="left", fontweight="bold")
    fig2.text(0.5, -0.02, "n=20/arm, Semgrep-graded with the same verified FP correction on every arm. Directional (small n).", ha="center", fontsize=8, color="#4A4C55")
    fig2.tight_layout(); fig2.savefig(f"{ROOT}/assets/benchmark-live.png", dpi=150, bbox_inches="tight")
    print("regenerated benchmark-live.png")
except ImportError:
    print("(no matplotlib)")
