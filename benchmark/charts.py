#!/usr/bin/env python3
"""Render the benchmark charts from results.json (run benchmark/run.py first).

Charts, styled to the project palette (gold #C79A3B on ink #0F1420):
- assets/benchmark-overall.png  — headline: TP recall + FP rate, all engines
- assets/benchmark-categories.png — per-category detection recall
"""
import json
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Patch

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
GOLD = "#C79A3B"
GREY = "#9A958A"
STEEL = "#4E7E8E"

results = json.load(open(os.path.join(HERE, "results.json")))
tp = [r for r in results if r["vulnerable"] and not r["category"].startswith("semantic")]
bn = [r for r in results if not r["vulnerable"]]
HAS_SEMGREP = any("semgrep" in r for r in results)

TOOLS = [("peephole", "peephole", GOLD), ("security-guidance\n(pattern layer)", "sg", STEEL)]
if HAS_SEMGREP:
    TOOLS.append(("semgrep OSS\n(public rules)", "semgrep", GREY))

plt.rcParams.update({
    "figure.facecolor": "#FAF7F1", "axes.facecolor": "#FAF7F1", "savefig.facecolor": "#FAF7F1",
    "axes.edgecolor": "#D8D2C4", "axes.labelcolor": "#22242E", "text.color": "#22242E",
    "xtick.color": "#4A4C55", "ytick.color": "#4A4C55", "grid.color": "#E4DDCF",
    "axes.grid": True, "grid.linestyle": "-", "grid.linewidth": 0.7, "axes.axisbelow": True,
    "axes.spines.top": False, "axes.spines.right": False,
    "font.family": ["Avenir Next", "Helvetica Neue", "sans-serif"], "font.size": 11,
})

def recall(rows, key):
    return 100 * sum(1 for r in rows if r[key]) / max(1, len(rows))

# ---- chart 1: overall ----
names = [t[0] for t in TOOLS]
tp_vals = [recall(tp, t[1]) for t in TOOLS]
fp_vals = [100 * sum(1 for r in bn if r[t[1]]) / len(bn) for t in TOOLS]
colors = [t[2] for t in TOOLS]

fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 4.4))
bars1 = ax1.bar(names, tp_vals, color=colors, width=0.5)
ax1.set_title("Vulnerability detection recall\n(151 labeled vulnerable cases, 24 CWE classes)", fontsize=12)
ax1.set_ylabel("% detected")
ax1.set_ylim(0, 108)
ax1.grid(axis="y")
for b in bars1:
    ax1.annotate(f"{b.get_height():.0f}%", (b.get_x() + b.get_width() / 2, b.get_height() + 2),
                 ha="center", fontsize=13, fontweight="bold")

bars2 = ax2.bar(names, fp_vals, color=colors, width=0.5)
ax2.set_title("False-positive rate\n(50 everyday correct-code cases)", fontsize=12)
ax2.set_ylabel("% flagged incorrectly")
ax2.set_ylim(0, max(20, max(fp_vals) * 1.5))
ax2.grid(axis="y")
for b in bars2:
    ax2.annotate(f"{b.get_height():.0f}%", (b.get_x() + b.get_width() / 2, b.get_height() + 0.4),
                 ha="center", fontsize=13, fontweight="bold")
fig.tight_layout()
fig.savefig(os.path.join(ROOT, "assets", "benchmark-overall.png"), dpi=150)
plt.close(fig)

# ---- chart 2: per-category ----
cats = sorted({r["category"] for r in tp},
              key=lambda c: -recall([r for r in tp if r["category"] == c], "peephole"))
labels, series = [], [[] for _ in TOOLS]
for c in cats:
    rows = [r for r in tp if r["category"] == c]
    labels.append(f"{c} ({len(rows)})")
    for i, t in enumerate(TOOLS):
        series[i].append(recall(rows, t[1]))

fig, ax = plt.subplots(figsize=(12, 9.5))
n = len(labels)
w = 0.8 / len(TOOLS)
y = list(range(n))
for i, t in enumerate(TOOLS):
    offs = [yy + (i - (len(TOOLS) - 1) / 2) * w for yy in y]
    ax.barh(offs, series[i], height=w * 0.92, color=t[2], label=t[0].replace("\n", " "))
ax.set_yticks(y)
ax.set_yticklabels(labels)
ax.invert_yaxis()
ax.set_xlim(0, 105)
ax.set_xlabel("% of vulnerable cases detected")
ax.set_title("Detection recall by CWE class — 151 cases, all engines on identical inputs", fontsize=12, loc="left", pad=12, fontweight="bold")
ax.grid(axis="x")
ax.legend(handles=[Patch(color=t[2], label=t[0].replace("\n", " ")) for t in TOOLS],
          loc="lower right", frameon=False)
fig.tight_layout()
fig.savefig(os.path.join(ROOT, "assets", "benchmark-categories.png"), dpi=150)
plt.close(fig)
print("charts written to assets/benchmark-overall.png and assets/benchmark-categories.png")

