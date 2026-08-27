#!/usr/bin/env python3
"""Multimodel chart from task-relevant grades on saved artifacts."""
import os
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)
from taskgrade import grade_jsonl, summarize

MODELS = [
    ("Haiku 4.5", os.path.join(HERE, "results.jsonl"), os.path.join(HERE, "out")),
    ("Sonnet 4.5", os.path.join(HERE, "multimodel", "mm_sonnet.jsonl"), os.path.join(HERE, "out_sonnet")),
    ("GLM", os.path.join(HERE, "multimodel", "mm_glm.jsonl"), os.path.join(HERE, "out_glm")),
    ("Kimi", os.path.join(HERE, "multimodel", "mm_kimi.jsonl"), os.path.join(HERE, "out_kimi")),
]
ARMS = ["baseline", "security-guidance", "peephole"]
COLORS = {"baseline": "#9A958A",
          "security-guidance": "#4E7E8E", "peephole": "#C79A3B"}

tbl = {}
print(f"{'model':<14}{'arm':<22}{'insec':>8}{'secure':>8}{'ref':>8} n")
for name, jf, ob in MODELS:
    rows = grade_jsonl(jf, ob, tiers=("main",))
    stats = summarize(rows, ARMS)
    tbl[name] = stats
    for a in ARMS:
        s = stats[a]
        print(f"{name:<14}{a:<22}{s['insecure_landed'] or 0:7.0f}%{(s['secure_landed'] or 0):7.0f}%{(s['refused_rate'] or 0):7.0f}% {s['attempted']}")

plt.rcParams.update({"figure.facecolor": "#FAF7F1", "axes.facecolor": "#FAF7F1",
                     "savefig.facecolor": "#FAF7F1", "font.size": 11,
                     "axes.spines.top": False, "axes.spines.right": False})
fig, ax = plt.subplots(figsize=(10, 5.2))
x = range(len(MODELS))
w = 0.24
for i, arm in enumerate(ARMS):
    off = (i - 1) * w
    vals = [tbl[n][arm]["insecure_landed"] or 0 for n, _, _ in MODELS]
    ax.bar([xx + off for xx in x], vals, w, color=COLORS[arm], edgecolor="#FFF",
           linewidth=0.6, zorder=3, label=arm)
ax.set_xticks(list(x))
ax.set_xticklabels([n for n, _, _ in MODELS])
ax.set_ylabel("% of attempts that landed the requested vuln (lower is better)")
ax.set_title("Insecure code landed — task-relevant grader on saved artifacts")
ax.set_ylim(0, 100)
ax.legend(loc="upper right", fontsize=8, frameon=False)
ax.grid(axis="y", color="#D8D2C6", zorder=0)
fig.tight_layout()
out = os.path.join(ROOT, "assets", "benchmark-multimodel.png")
fig.savefig(out, dpi=150, bbox_inches="tight")
print("chart:", out)
