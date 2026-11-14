# Benchmark: ai-skill-guard vs NVIDIA SkillSpector

How well does ai-skill-guard catch malicious agent skills, and how often does it cry wolf on clean ones? We measured it on an independent, published dataset, against NVIDIA's SkillSpector, with the scoring rules written down before any run. Everything needed to repeat it is in [`benchmark/`](benchmark/).

## Result

On a sealed held-out sample of **281 malicious and 199 benign skills** from MalSkillBench:

| | ai-skill-guard 0.2.1 | **ai-skill-guard 0.3.0** | SkillSpector 2.12.0 (`--no-llm`) |
|---|---|---|---|
| Real-world malicious skills ("wild", 132) | 27% | **61%** | 30% |
| Generated: code injection (50) | 40% | **66%** | 40% |
| Generated: prompt injection (49) | 33% | **57%** | 16% |
| Generated: mixed text + code (50) | 34% | **58%** | 54% |
| **Malicious skills blocked (281)** | 31.7% | **60.5%** | 33.8% |
| **False alarms on clean skills (199)** | 12.6% | **11.1%** | 12.1% |
| Precision | 0.78 | **0.89** | 0.80 |
| F1 | 0.45 | **0.72** | 0.48 |
| Median time per skill | 0.26 s | 0.31 s | 16.0 s |

- ai-skill-guard 0.3.0 blocks **92** malicious skills that SkillSpector misses; SkillSpector blocks **17** that 0.3.0 misses (McNemar p < 0.001).
- The false-alarm rates are statistically indistinguishable (13 vs 15 discordant clean skills, p = 0.85).
- Run together, the two tools block 66.5% of malicious skills, with 18.6% false alarms.

**Read the limitations below before quoting these numbers.** In short: one dataset family, SkillSpector without its LLM layer, and roughly 4 in 10 malicious skills still get through. A clean report means "no known red flags", never "safe".

## Dataset

[MalSkillBench](https://github.com/lxyeternal/MalSkillBench) (Guo et al., 2026, [arXiv:2606.07131](https://arxiv.org/abs/2606.07131)): 3,944 malicious skills whose behavior was confirmed by running them in a sandbox, and 4,000 of the most-downloaded benign skills. Neither tool's authors built it.

Three non-overlapping random samples, each 150 malicious skills without a generator suffix ("wild": collected from public registries, plus some generated ones the dataset does not label by name), 50 generated code-injection (CI), 50 prompt-injection (PI), 50 mixed (MIXED) and 200 benign:

| Sample | Seed | Used for |
|---|---|---|
| `first` | 20261114 | First comparison (0.2.1 vs SkillSpector) |
| `dev` | 111 | Developing 0.3.0 (together with `first`) |
| `holdout` | 999 | **Final test only.** No tool was run on it, and no file was opened, before the final run |

[`benchmark/scripts/make_samples.py`](benchmark/scripts/make_samples.py) redraws all three exactly; the skill names are in [`benchmark/data/`](benchmark/data/). The skills themselves are not copied here: get them from MalSkillBench.

## Method (pre-registered)

- **Blocks install** (primary): ai-skill-guard's verdict is `DO NOT INSTALL` (at least one high or critical finding); SkillSpector's `risk_assessment.recommendation` is `DO_NOT_INSTALL`.
- **Needs attention** (secondary): ai-skill-guard has any medium or higher finding; SkillSpector says `DO_NOT_INSTALL` or `CAUTION`. On holdout, 0.3.0 reaches 77% detection with 19% false alarms; SkillSpector 59% with 34%.
- Errors or timeouts (600 s) count as "not blocked". There were none.
- Nothing was executed. Both tools only read files.
- **Antivirus:** Windows Defender quarantined some malicious files during the runs. Before every tool the sample was extracted fresh, a file manifest was taken before and after, and every skill that lost a file during any run (20 skills: 19 malicious, 1 benign) was excluded for **all** tools. The list is in [`benchmark/data/holdout_excluded.json`](benchmark/data/holdout_excluded.json).

## What changed in 0.3.0

The first comparison showed 0.2.1 behind SkillSpector (27% vs 33% detection on `first`). 0.3.0 was then developed on `first` + `dev` only:

- **New rules** for attack types 0.2.1 missed: reverse shells, crypto miners, ransomware traits, privilege escalation (admin users, SUID, `authorized_keys`), fork bombs, raw public IPs, and code that names its own functions as malware (`exfiltrate_…`, `steal_…`).
- **Combinations** of signals that are normal alone and malicious together (ideas from SkillSieve, MalSkills and Cisco's skill-scanner): download + make executable + run; read strong secrets + send; encrypt files across folders + delete originals; run-on-startup + remote source; several weak manipulation cues in one file.
- **Text attacks on the agent:** persona and identity takeover, safety bypass, system-prompt extraction, task hijacking, fake authorities, one-sided claims.
- **Base64 decoding:** encoded strings are decoded and scanned again.
- **Context to cut false alarms:** a pattern that is only *mentioned* in documentation (in quotes, a table, under a "Detection" or "Examples" heading, in `examples/` or `tests/`) drops to low; official installers (astral.sh, rustup, Homebrew and others) drop to medium; `export PATH >> ~/.zshrc`, `crontab -l`, ordinary npm build hooks and "never share your seed phrase" no longer block.

## Limitations

- **One dataset family.** `dev` and `holdout` both come from MalSkillBench, and the new rules were written while looking at its samples. Part of the gain may be fit to its style. The real-world "wild" group (61% vs 30%) is the strongest evidence against that; a test on a different source is the next step.
- **False alarms rose from dev to holdout** (7.7% → 11.1%). 11% is the honest number.
- **SkillSpector ran without its LLM layer** (`--no-llm`), which is its strength on text attacks. With an LLM it would likely do better, at the cost of speed and sending skill content to an API.
- **Prompt-injection detection is still pattern matching.** Purely semantic manipulation with no telltale phrasing is out of reach for any static scanner.
- **The first comparison did not control for antivirus quarantine.** ai-skill-guard ran before SkillSpector there, so SkillSpector may have seen fewer files. The holdout run fixes this.

## Repeat it

```bash
git clone --filter=blob:none --no-checkout https://github.com/lxyeternal/MalSkillBench msb
git -C msb ls-tree -r --format="%(objectname) %(path)" HEAD Dataset/Skills > tree.txt
python benchmark/scripts/make_samples.py tree.txt samples
# fetch the blobs you need (git fetches them on demand), then:
python benchmark/scripts/extract.py msb tree.txt samples/sample_holdout.json corpus
python benchmark/scripts/run_scanner.py guard corpus/index.json guard.jsonl
python benchmark/scripts/run_scanner.py skillspector corpus/index.json skillspector.jsonl
python benchmark/scripts/score.py --exclude benchmark/data/holdout_excluded.json guard.jsonl skillspector.jsonl
```

Extract into a folder your antivirus may scan, and check which files disappear before you score. To check our numbers without downloading anything, run `score.py` on the result files in [`benchmark/data/`](benchmark/data/).

Versions: ai-skill-guard 0.2.1 (commit 9007cc1) and 0.3.0 (this release); SkillSpector 2.12.0 (commit ce46d46); MalSkillBench HEAD on 2026-11-14.
