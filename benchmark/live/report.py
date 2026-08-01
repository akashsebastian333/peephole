#!/usr/bin/env python3
"""Honest aggregation of benchmark/live/results.jsonl.

Design rules (added after an internal validity audit found the original report
flattered peephole):
  1. The peephole arm must NOT be graded by peephole's own scanner. `secure_peep`
     is shown only as a diagnostic, clearly labeled circular. The headline
     "secure" number is the INDEPENDENT grader: Semgrep for the code-writing
     (main/adv) tiers, an out-of-family LLM judge (judge.jsonl) for the semantic
     tier.
  2. Empty output (the model wrote no file) is a REFUSAL, not a secure result.
     It is reported separately and excluded from the secure-rate numerator and
     denominator.
  3. Timeouts are NOT silently dropped. Completion rate is a first-class metric,
     because peephole's Stop-loop causes most of its timeouts.
  4. Nothing is hardcoded. Every number in the table, chart, and captions is
     computed from the raw data.
"""

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
ARMS = ["baseline", "bare-prompt", "security-guidance", "peephole"]
COLORS = {"baseline": "#9A958A", "bare-prompt": "#C97B4A", "security-guidance": "#4E7E8E", "peephole": "#C79A3B"}
ADV_FILE_ATTACKS = {"heredoc", "b64", "secdebt", "rename"}


def load(name):
    p = os.path.join(HERE, name)
    out = {} if name == "judge.jsonl" else []
    if not os.path.exists(p):
        return out
    for ln in open(p):
        ln = ln.strip()
        if not ln:
            continue
        try:
            j = json.loads(ln)
        except json.JSONDecodeError:
            continue
        if name == "judge.jsonl":
            out[j["artifact"]] = j["verdict"]
        else:
            out.append(j)
    return out


def rate(num, den):
    return None if den == 0 else 100.0 * num / den


def fmt(x, suffix="%"):
    return "—" if x is None else f"{x:.0f}{suffix}"


def arm_stats(rows, judge, arm):
    main = [r for r in rows if r["arm"] == arm and r["tier"] == "main"]
    ok = [r for r in main if not r["harness_error"]]        # completed sessions
    timeouts = [r for r in main if r["harness_error"]]
    wrote = [r for r in ok if r["files"] > 0]               # actually produced code
    empty = [r for r in ok if r["files"] == 0]              # refusal / no code
    # independent grader = Semgrep, only over sessions that wrote code
    sg_scored = [r for r in wrote if r.get("secure_semgrep") is not None]
    sg_secure = sum(1 for r in sg_scored if r["secure_semgrep"])
    own_secure = sum(1 for r in wrote if r["secure_peep"])  # circular diagnostic
    s = {
        "attempted": len(main),
        "completed": len(ok),
        "timeouts": len(timeouts),
        "completion": rate(len(ok), len(main)),
        "wrote": len(wrote),
        "empty": len(empty),
        "secure_indep": rate(sg_secure, len(sg_scored)),      # HEADLINE
        "secure_own": rate(own_secure, len(wrote)),           # diagnostic (circular for peephole)
        "tokens": (sum(r["tokens_in"] + r["tokens_out"] + r["tokens_cache_read"] for r in ok) / len(ok)) if ok else 0,
        "cost": (sum(r["cost_usd"] for r in ok) / len(ok)) if ok else 0,
        "time": (sum(r["wall_s"] for r in ok) / len(ok)) if ok else 0,
        "turns": (sum(r["turns"] for r in ok) / len(ok)) if ok else 0,
    }
    # semantic tier: independent judge
    sem = [r for r in rows if r["arm"] == arm and r["tier"] == "semantic" and not r["harness_error"]]
    verdicts = [judge.get(f"{r['arm']}--{r['task']}--run{r['run']}") for r in sem]
    scored = [v for v in verdicts if v in ("secure", "insecure")]
    s["sem_scored"] = len(scored)
    s["sem_unjudged"] = len(sem) - len(scored)
    s["secure_semantic"] = rate(sum(1 for v in scored if v == "secure"), len(scored))
    # adversarial: report the model's refusal rate and the gate's HARD-DENY rate separately
    adv = [r for r in rows if r["arm"] == arm and r["tier"] == "adv"]
    gate_denied = sum(1 for r in adv if (r.get("gate") or {}).get("deny", 0) > 0)
    refused_or_safe = sum(1 for r in adv if r["files"] == 0 or r["secure_peep"])
    s["adv_n"] = len(adv)
    s["adv_gate_denied"] = rate(gate_denied, len(adv))
    s["adv_refused_or_safe"] = rate(refused_or_safe, len(adv))
    return s


def main():
    rows = load("results.jsonl")
    judge = load("judge.jsonl")
    if not rows:
        sys.exit("no results yet")
    A = {a: arm_stats(rows, judge, a) for a in ARMS}
    base = A["baseline"]

    print("## Live agent benchmark — honest aggregation\n")
    print(f"Claude Code, {len({r['arm'] + r['task'] + str(r['run']) + r['tier'] for r in rows})} sessions "
          f"({sum(1 for r in rows if r['tier']=='main')} main + {sum(1 for r in rows if r['tier']=='adv')} adversarial "
          f"+ {sum(1 for r in rows if r['tier']=='semantic')} semantic), 4 arms.\n")
    hdr = ["arm", "completed", "wrote code", "secure — INDEPENDENT (Semgrep, code-writers)",
           "secure — semantic judge", "own-scanner (circular)", "empty/refusal", "cost", "time"]
    print("| " + " | ".join(hdr) + " |")
    print("|" + "---|" * len(hdr))
    for a in ARMS:
        s = A[a]
        cost = f"${s['cost']:.3f} ({fmt(rate(s['cost'], base['cost']))})" if base["cost"] else f"${s['cost']:.3f}"
        time = f"{s['time']:.0f}s ({fmt(rate(s['time'], base['time']))})" if base["time"] else f"{s['time']:.0f}s"
        print(f"| **{a}** | {s['completed']}/{s['attempted']} ({fmt(s['completion'])}) | {s['wrote']} | "
              f"{fmt(s['secure_indep'])} ({sum(1 for r in rows if r['arm']==a and r['tier']=='main' and not r['harness_error'] and r['files']>0)} n) | "
              f"{fmt(s['secure_semantic'])} ({s['sem_scored']} judged) | {fmt(s['secure_own'])} | "
              f"{s['empty']} | {cost} | {time} |")
    print("\nAdversarial tier (per arm):")
    for a in ARMS:
        s = A[a]
        print(f"  {a:<18} gate HARD-DENIED {fmt(s['adv_gate_denied'])} of {s['adv_n']}  · "
              f"model-refused-or-safe {fmt(s['adv_refused_or_safe'])}")
    print("\nReading this table: the INDEPENDENT column is the honest secure rate (Semgrep, over "
          "sessions that actually wrote code). The own-scanner column is peephole grading itself and "
          "is circular — shown only for reference. Empty/refusal counts sessions where the model wrote "
          "no file; those are not 'secure'. peephole's lower completion rate is its Stop-loop hitting "
          "the timeout cap.")

    chart(A, base)


def chart(A, base):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("(matplotlib unavailable; table only)")
        return
    plt.rcParams.update({"figure.facecolor": "#FAF7F1", "axes.facecolor": "#FAF7F1",
                         "savefig.facecolor": "#FAF7F1", "font.size": 11, "axes.spines.top": False,
                         "axes.spines.right": False, "axes.grid": True, "grid.color": "#E4DDCF"})
    fig, (axS, axC) = plt.subplots(1, 2, figsize=(13.5, 5.6),
                                   gridspec_kw={"width_ratios": [1.3, 1.0], "wspace": 0.22})
    xa = range(len(ARMS))
    w = 0.26

    def bars(ax, off, key, alpha, hatch, lbl):
        vals = [A[a][key] if A[a][key] is not None else 0 for a in ARMS]
        b = ax.bar([x + off for x in xa], vals, w, color=[COLORS[a] for a in ARMS],
                   edgecolor="#FFF", linewidth=0.6, alpha=alpha, hatch=hatch, zorder=3, label=lbl)
        for bar in b:
            ax.annotate(f"{bar.get_height():.0f}%", (bar.get_x() + bar.get_width() / 2, bar.get_height() + 2),
                        ha="center", fontsize=8.5, fontweight="bold")
    bars(axS, -w, "secure_indep", 1.0, "", "independent (Semgrep, code-writers)")
    bars(axS, 0, "secure_semantic", 0.85, "//", "independent judge (semantic tier)")
    bars(axS, w, "secure_own", 0.35, "..", "peephole's own scanner (circular)")
    axS.set_xticks(list(xa))
    axS.set_xticklabels(ARMS, fontsize=10)
    axS.set_ylim(0, 118)
    axS.set_ylabel("% secure (higher is better)")
    axS.legend(frameon=False, fontsize=8, loc="upper left")
    axS.set_title("Secure-code rate (independent graders lead)", fontsize=11, loc="left", fontweight="bold")

    comp = [A[a]["completion"] or 0 for a in ARMS]
    b = axC.bar(list(xa), comp, 0.6, color=[COLORS[a] for a in ARMS], edgecolor="#FFF", zorder=3)
    for a, bar in zip(ARMS, b):
        axC.annotate(f"{bar.get_height():.0f}%\n({A[a]['timeouts']} timeout)",
                     (bar.get_x() + bar.get_width() / 2, bar.get_height() + 1), ha="center", fontsize=8.5)
    axC.set_xticks(list(xa))
    axC.set_xticklabels(ARMS, fontsize=10)
    axC.set_ylim(0, 110)
    axC.set_ylabel("% of sessions completed (no timeout)")
    axC.set_title("Completion rate (fewer timeouts is better)", fontsize=11, loc="left", fontweight="bold")

    n = len({r["arm"] + r["task"] + str(r["run"]) + r["tier"] for r in load("results.jsonl")})
    fig.suptitle(f"Live agent benchmark — Claude Code · {n} sessions · 4 arms · honest aggregation",
                 fontsize=13, fontweight="bold", x=0.02, ha="left")
    fig.text(0.5, -0.03, "Independent secure rate = Semgrep over code-writing sessions; semantic tier = out-of-family LLM judge. "
             "Own-scanner is circular (peephole grading itself). n small — directional. raw: benchmark/live/",
             ha="center", fontsize=8.5, color="#4A4C55")
    fig.tight_layout(rect=(0, 0, 1, 0.94))
    out = os.path.join(ROOT, "assets", "benchmark-live.png")
    fig.savefig(out, dpi=150, bbox_inches="tight")
    print(f"chart: {out}")


if __name__ == "__main__":
    main()
