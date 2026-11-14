"""Score result files with the pre-registered rules in BENCHMARK.md.

Usage: python score.py [--exclude excluded.json] results_a.jsonl results_b.jsonl ...

"Blocks install": ai-skill-guard verdict starts with "DO NOT INSTALL" (any high/critical finding);
SkillSpector recommendation is DO_NOT_INSTALL. Errors and timeouts count as "not blocked".
--exclude takes a JSON list of skill names to leave out of every tool (e.g. quarantined by antivirus).
"""
import collections
import json
import math
import sys

args = sys.argv[1:]
exclude = set()
if args and args[0] == "--exclude":
    exclude = set(json.load(open(args[1], encoding="utf-8"))); args = args[2:]


def blocked(r):
    v = r.get("verdict", "")
    return v == "DO_NOT_INSTALL" or v.startswith("DO NOT")


runs = {p: {json.loads(l)["name"]: json.loads(l) for l in open(p, encoding="utf-8")} for p in args}
common = set.intersection(*(set(r) for r in runs.values())) - exclude
for path, rows in runs.items():
    g = collections.defaultdict(lambda: [0, 0])
    for n in common:
        r = rows[n]; g[r["group"]][1] += 1; g[r["group"]][0] += blocked(r)
    tp = sum(v[0] for k, v in g.items() if k != "benign"); pos = sum(v[1] for k, v in g.items() if k != "benign")
    fp, neg = g["benign"]
    rec, prec = tp / pos, tp / (tp + fp) if tp + fp else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    print(f"{path}\n  " + ", ".join(f"{k} {a}/{b}" for k, (a, b) in sorted(g.items())))
    print(f"  detection {rec:.1%}  false alarms {fp / neg:.1%}  precision {prec:.2f}  F1 {f1:.2f}")
if len(args) == 2:
    a, b = runs.values()
    for label in ("malicious", "benign"):
        c = collections.Counter((blocked(a[n]), blocked(b[n])) for n in common if a[n]["label"] == label)
        x, y = c[(True, False)], c[(False, True)]
        p = math.erfc(math.sqrt(((abs(x - y) - 1) ** 2 / (x + y)) / 2)) if x + y else 1.0
        print(f"McNemar {label}: only first {x}, only second {y}, p = {p:.4f}")
