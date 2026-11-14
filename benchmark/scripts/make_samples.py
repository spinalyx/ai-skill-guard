"""Draw the three benchmark samples from MalSkillBench, exactly as used in BENCHMARK.md.

Usage:
    git clone --filter=blob:none --no-checkout https://github.com/lxyeternal/MalSkillBench msb
    git -C msb ls-tree -r --format="%(objectname) %(path)" HEAD Dataset/Skills > tree.txt
    python make_samples.py tree.txt OUTDIR

Writes sample_first.json (first comparison), sample_dev.json (used to develop 0.3.0) and
sample_holdout.json (sealed final test). The three samples do not overlap.
"""
import collections
import json
import os
import random
import re
import sys

tree, out = sys.argv[1], sys.argv[2]
skills = collections.defaultdict(int)
for line in open(tree, encoding="utf-8"):
    _, path = line.rstrip("\n").split(" ", 1)
    parts = path.split("/")
    if len(parts) >= 5:
        skills[(parts[2], parts[3])] += 1
malware = sorted(k[1] for k in skills if k[0] == "malware")
benign = sorted(k[1] for k in skills if k[0] == "benign")
generated = [n for n in malware if re.search(r"__(CI|PI|MIXED)_B\d+$", n)]
gen_set = set(generated)
wild = [n for n in malware if n not in gen_set]


def draw(rng, exclude=frozenset()):
    s = {"wild": rng.sample([n for n in wild if n not in exclude], 150)}
    for v in ("CI", "PI", "MIXED"):
        s["gen_" + v] = rng.sample([n for n in generated if f"__{v}_B" in n and n not in exclude], 50)
    s["benign"] = rng.sample([n for n in benign if n not in exclude], 200)
    return s


def names(s):
    return {n for v in s.values() for n in v}


first = draw(random.Random(20261114))
dev = draw(random.Random(111), names(first))
holdout = draw(random.Random(999), names(first) | names(dev))
assert not names(holdout) & (names(first) | names(dev))
os.makedirs(out, exist_ok=True)
for name, s in (("sample_first", first), ("sample_dev", dev), ("sample_holdout", holdout)):
    json.dump(s, open(os.path.join(out, name + ".json"), "w", encoding="utf-8"), ensure_ascii=False, indent=0)
print("ok", len(names(first)), len(names(dev)), len(names(holdout)))
