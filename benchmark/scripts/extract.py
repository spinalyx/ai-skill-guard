"""Write the skills of one sample to disk from a MalSkillBench partial clone.

Usage: python extract.py MSB_CLONE TREE_TXT SAMPLE_JSON OUT_DIR

Characters that Windows does not allow in file names are replaced with "_"; contents are untouched.
Nothing is executed. Expect your antivirus to quarantine some of the malicious files: run
check_intact.py before and after each scanner and compare only skills that stayed complete.
"""
import collections
import json
import os
import re
import subprocess
import sys

clone, tree, sample, out = sys.argv[1:5]
clean = lambda s: re.sub('[<>:"|?*\\x5c]', "_", s).rstrip(" .")
files = collections.defaultdict(list)
for line in open(tree, encoding="utf-8"):
    oid, path = line.rstrip("\n").split(" ", 1)
    parts = path.split("/")
    if len(parts) >= 5:
        files[(parts[2], parts[3])].append((oid, parts[4:]))
sel = json.load(open(sample, encoding="utf-8"))
cat = subprocess.Popen(["git", "-C", clone, "cat-file", "--batch"], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
index = []
for group, names in sel.items():
    kind = "benign" if group == "benign" else "malware"
    for name in names:
        d = os.path.join(out, group, clean(name))
        index.append({"group": group, "label": "benign" if kind == "benign" else "malicious", "name": name, "dir": d})
        for oid, rel in files[(kind, name)]:
            cat.stdin.write((oid + "\n").encode()); cat.stdin.flush()
            size = int(cat.stdout.readline().split()[2])
            data = cat.stdout.read(size); cat.stdout.read(1)
            p = os.path.join(d, *[clean(x) for x in rel])
            os.makedirs(os.path.dirname(p), exist_ok=True)
            open(p, "wb").write(data)
json.dump(index, open(os.path.join(out, "index.json"), "w", encoding="utf-8"), ensure_ascii=False, indent=0)
print("skills", len(index))
