"""Honest multi-model live benchmark: run baseline / bare-prompt / peephole across
several models (native Claude + GLM/Kimi via the gateway) on the SAME corpus and
grade with the SAME independent Semgrep pass. The corpus is the existing
insecure-inducing task set - not tuned for any tool. Per-model results go to
separate files + out_<tag>/ dirs.
  smoke:  RUNS=1 python multi_model.py --smoke   (1 peephole session per model)
  full:   RUNS=2 python multi_model.py
"""
import sys, os, threading
sys.path.insert(0, "/Users/akash.s/Desktop/projects/peephole/benchmark/live")
import driver

ROOT = "/Users/akash.s/Desktop/projects/peephole"
SCRATCH = "/private/tmp/claude-502/-Users-akash-s-Desktop-projects-peephole/8521b95a-d2e2-4c80-9846-aee7f9a9f37b/scratchpad"
GW = {"ANTHROPIC_BASE_URL": "https://grid.ai.juspay.net/", "ANTHROPIC_AUTH_TOKEN": os.environ["GW_KEY"]}
MODELS = [
    {"tag": "sonnet", "model": "sonnet", "gw": {}},
    {"tag": "glm", "model": "glm-latest", "gw": GW},
    {"tag": "kimi", "model": "kimi-latest", "gw": GW},
]
ARMS = ["baseline", "bare-prompt", "peephole"]
RUNS = int(os.environ.get("RUNS", "2"))
SMOKE = "--smoke" in sys.argv


def run_model(m):
    driver.MODEL = m["model"]
    driver.GW_ENV = m["gw"]
    driver.OUT = os.path.join(SCRATCH, f"mm_{m['tag']}.jsonl")
    driver.OUTBASE = os.path.join(ROOT, "benchmark", "live", f"out_{m['tag']}")
    os.makedirs(driver.OUTBASE, exist_ok=True)
    open(driver.OUT, "a").close()
    tasks = driver.MAIN_TASKS[:1] if SMOKE else driver.MAIN_TASKS
    arms = ["peephole"] if SMOKE else ARMS
    runs = 1 if SMOKE else RUNS
    jobs = [(arm, tid, prompt, r, "main") for arm in arms for tid, prompt in tasks for r in range(runs)]
    print(f"=== {m['tag']} ({m['model']}): {len(jobs)} sessions ===", flush=True)
    idx = {"i": 0}

    def worker():
        while True:
            with driver.LOCK:
                if idx["i"] >= len(jobs):
                    return
                job = jobs[idx["i"]]
                idx["i"] += 1
            try:
                driver.one_session(*job)
            except Exception as e:
                print("ERR", m["tag"], job[1], "run", job[3], repr(e), flush=True)

    nw = 1 if SMOKE else 3
    ts = [threading.Thread(target=worker) for _ in range(nw)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    print(f"=== {m['tag']} done ===", flush=True)


for m in MODELS:
    run_model(m)
print("MULTI-MODEL DONE", flush=True)
