#!/usr/bin/env python3
"""Render detection charts from results.json. Headline is the shared slice."""
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
shared = [r for r in results if r.get("slice") == "shared"]
sast = [r for r in results if r.get("slice") == "sast"]
bn = [r for r in results if r.get("slice") == "benign" or (
    not r["vulnerable"] and r.get("slice") in (None, "benign"))]

TOOLS = [("peephole", "peephole", GOLD),
         ("security-guidance\n(pattern layer)", "sg", STEEL),
         ("semgrep OSS\n(public rules)", "semgrep", GREY)]

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


names = [t[0] for t in TOOLS]
tp_vals = [recall(shared, t[1]) for t in TOOLS]
fp_vals = [100 * sum(1 for r in bn if r[t[1]]) / max(1, len(bn)) for t in TOOLS]
colors = [t[2] for t in TOOLS]

fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 4.6))
bars1 = ax1.bar(names, tp_vals, color=colors, width=0.5)
ax1.set_title(f"Shared-class recall\n({len(shared)} cases SG actually patterns for)", fontsize=12)
ax1.set_ylabel("% detected")
ax1.set_ylim(0, 108)
ax1.grid(axis="y")
for b in bars1:
    ax1.annotate(f"{b.get_height():.0f}%", (b.get_x() + b.get_width() / 2, b.get_height() + 2),
                 ha="center", fontsize=13, fontweight="bold")

bars2 = ax2.bar(names, fp_vals, color=colors, width=0.5)
ax2.set_title(f"False-positive rate\n({len(bn)} correct-code cases)", fontsize=12)
ax2.set_ylabel("% flagged incorrectly")
ax2.set_ylim(0, max(20, max(fp_vals) * 1.5 if fp_vals else 20))
ax2.grid(axis="y")
for b in bars2:
    ax2.annotate(f"{b.get_height():.0f}%", (b.get_x() + b.get_width() / 2, b.get_height() + 0.4),
                 ha="center", fontsize=13, fontweight="bold")
fig.tight_layout()
fig.savefig(os.path.join(ROOT, "assets", "benchmark-overall.png"), dpi=150)
plt.close(fig)

tp = shared + sast
cats = sorted({r["category"] for r in tp},
              key=lambda c: (-len([r for r in tp if r["category"] == c]), c))
labels, series = [], [[] for _ in TOOLS]
for c in cats:
    rows = [r for r in tp if r["category"] == c]
    slice_tag = rows[0].get("slice", "")
    labels.append(f"{c} ({len(rows)}, {slice_tag})")
    for i, t in enumerate(TOOLS):
        series[i].append(recall(rows, t[1]))

fig, ax = plt.subplots(figsize=(12, 9.0), layout="constrained")
n = len(labels)
w = 0.8 / len(TOOLS)
y = list(range(n))
for i, t in enumerate(TOOLS):
    offs = [yy + (i - (len(TOOLS) - 1) / 2) * w for yy in y]
    ax.barh(offs, series[i], height=w * 0.92, color=t[2], label=t[0].replace("\n", " "))
ax.set_yticks(y)
ax.set_yticklabels(labels)
ax.invert_yaxis()
ax.set_xlim(0, 102)
ax.set_xlabel("% of vulnerable cases detected")
ax.set_title("Recall by class — shared (3-way) + sast (peephole vs Semgrep)",
             fontsize=12, loc="left", fontweight="bold")
ax.grid(axis="x")
fig.legend(handles=[Patch(color=t[2], label=t[0].replace("\n", " ")) for t in TOOLS],
           loc="outside lower center", ncol=3, frameon=False, fontsize=10,
           handlelength=1.15, columnspacing=1.6)
fig.savefig(os.path.join(ROOT, "assets", "benchmark-categories.png"), dpi=150)
plt.close(fig)
print("charts written to assets/benchmark-overall.png and assets/benchmark-categories.png")
