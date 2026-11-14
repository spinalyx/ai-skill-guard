"""Run one scanner over an extracted sample and write one JSON line per skill.

Usage:
    python run_scanner.py guard OUT_DIR/index.json results.jsonl [path/to/ai_skill_guard.py]
    python run_scanner.py skillspector OUT_DIR/index.json results.jsonl

SkillSpector runs with --no-llm and with API-key variables removed from its environment.
"""
import json
import os
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor

tool, index_path, out_path = sys.argv[1:4]
guard = sys.argv[4] if len(sys.argv) > 4 else os.path.join(os.path.dirname(__file__), "..", "..", "ai_skill_guard.py")
env = {k: v for k, v in os.environ.items()
       if not (k.endswith("_API_KEY") or k.startswith(("LANGSMITH", "LANGCHAIN", "NVIDIA_")))}
env["PYTHONIOENCODING"] = "utf-8"


def run(item):
    cmd = ([sys.executable, "-I", guard, "--json", "--fail-on", "never", item["dir"]] if tool == "guard"
           else ["skillspector", "scan", item["dir"], "--no-llm", "--format", "json"])
    rec = {k: item[k] for k in ("group", "label", "name")}
    t = time.time()
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=600, env=env)
        js = json.loads(p.stdout.decode("utf-8", "replace"))
        if tool == "guard":
            rec.update(verdict=js["verdict"], counts=js["counts"],
                       rules=sorted({f["rule"] for f in js["findings"] if f["severity"] in ("critical", "high")}))
        else:
            sev = {}
            for f in js["issues"]:
                sev[f["severity"]] = sev.get(f["severity"], 0) + 1
            rec.update(verdict=js["risk_assessment"]["recommendation"], score=js["risk_assessment"].get("score"), counts=sev,
                       cats=sorted({f.get("category") for f in js["issues"] if f["severity"] in ("CRITICAL", "HIGH")}))
    except subprocess.TimeoutExpired:
        rec["error"] = "timeout"
    except Exception as e:  # noqa: BLE001 - recorded, counted as "not blocked"
        rec["error"] = repr(e)[:200]
    rec["secs"] = round(time.time() - t, 2)
    return rec


items = json.load(open(index_path, encoding="utf-8"))
with open(out_path, "w", encoding="utf-8") as out, ThreadPoolExecutor(6) as ex:
    for rec in ex.map(run, items):
        out.write(json.dumps(rec, ensure_ascii=False) + "\n")
print("done", len(items))
