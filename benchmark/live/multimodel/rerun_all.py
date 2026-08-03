"""Full honest re-run of the live agent benchmark across 4 models x 4 arms after
the 5 rounds of code changes. Same corpus, same arms, same driver. Haiku also runs
the semantic+adv tiers (for the headline table); the other models run the main
tier (for the multi-model table). n=2 runs/task, consistent across all models.
Writes fresh per-model jsonl + out dirs (old ones backed up to *.pre-rerun)."""
import sys, os, threading, shutil, time
ROOT = "/Users/akash.s/Desktop/projects/peephole"
SC = "/private/tmp/claude-502/-Users-akash-s-Desktop-projects-peephole/8521b95a-d2e2-4c80-9846-aee7f9a9f37b/scratchpad"
sys.path.insert(0, os.path.join(ROOT, "benchmark", "live"))
import driver

GW = {"ANTHROPIC_BASE_URL": "https://grid.ai.juspay.net/", "ANTHROPIC_AUTH_TOKEN": os.environ["GW_KEY"]}
RUNS = 2
WORKERS = 3

# (tag, model, gw, jsonl, outbase, tiers)
MODELS = [
    ("haiku",  "claude-haiku-4-5-20251001", {}, f"{ROOT}/benchmark/live/results.jsonl", f"{ROOT}/benchmark/live/out",        ["main", "semantic", "adv"]),
    ("sonnet", "sonnet",                     {}, f"{SC}/mm_sonnet.jsonl",                 f"{ROOT}/benchmark/live/out_sonnet", ["main"]),
    ("glm",    "glm-latest",                 GW, f"{SC}/mm_glm.jsonl",                    f"{ROOT}/benchmark/live/out_glm",    ["main"]),
    ("kimi",   "kimi-latest",                GW, f"{SC}/mm_kimi.jsonl",                   f"{ROOT}/benchmark/live/out_kimi",   ["main"]),
]


def backup(path):
    if os.path.exists(path):
        dst = path + ".pre-rerun"
        if os.path.exists(dst):
            shutil.rmtree(dst) if os.path.isdir(dst) else os.remove(dst)
        shutil.move(path, dst)


def jobs_for(tiers):
    jobs = []
    for arm in driver.ARMS:
        if "main" in tiers:
            for tid, prompt in driver.MAIN_TASKS:
                for r in range(RUNS):
                    jobs.append((arm, tid, prompt, r, "main"))
        if "semantic" in tiers:
            for tid, prompt in driver.SEMANTIC_TASKS:
                for r in range(RUNS):
                    jobs.append((arm, tid, prompt, r, "semantic"))
        if "adv" in tiers:
            for tid, prompt in driver.ADV_TASKS:
                jobs.append((arm, tid, prompt, 0, "adv"))
    return jobs


def run_model(tag, model, gw, jsonl, outbase, tiers):
    backup(jsonl); backup(outbase)
    driver.MODEL, driver.GW_ENV, driver.OUT, driver.OUTBASE = model, gw, jsonl, outbase
    os.makedirs(outbase, exist_ok=True)
    open(jsonl, "a").close()
    jobs = jobs_for(tiers)
    print(f"=== {tag} ({model}): {len(jobs)} sessions, tiers={tiers} ===", flush=True)
    idx = {"i": 0}
    def worker():
        while True:
            with driver.LOCK:
                if idx["i"] >= len(jobs):
                    return
                job = jobs[idx["i"]]; idx["i"] += 1
            try:
                driver.one_session(*job)
            except Exception as e:
                print("ERR", tag, job[0], job[1], "run", job[3], repr(e), flush=True)
            if idx["i"] % 20 == 0:
                print(f"  [{tag}] {idx['i']}/{len(jobs)}", flush=True)
    ts = [threading.Thread(target=worker) for _ in range(WORKERS)]
    for t in ts: t.start()
    for t in ts: t.join()
    print(f"=== {tag} done ===", flush=True)


t0 = time.time()
for spec in MODELS:
    run_model(*spec)
print(f"ALL MODELS DONE in {int(time.time()-t0)}s", flush=True)
