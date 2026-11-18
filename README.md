# SASTriager

LLM-assisted triage for static analysis findings, evaluated on
[OWASP Benchmark](https://owasp.org/www-project-benchmark/) v1.2.

Repository: [github.com/Xunan-zheng/sastriager](https://github.com/Xunan-zheng/sastriager)

Semgrep is good at recall but noisy. SASTriager keeps every Semgrep candidate,
gives an LLM the enclosing method plus same-file and cross-file helper bodies,
and drops only the findings the model confidently rejects. The result is
measured both before and after filtering, with the FP/recall trade-off reported
at several confidence thresholds.

## Results

### Baseline ruleset comparison

All 2,740 benchmark test cases, file-level scoring:

| Ruleset | TP | FP | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|
| `p/java` | 840 | 520 | 575 | 0.618 | 0.594 | 0.605 |
| `p/security-audit` | **1,094** | **520** | **321** | **0.678** | **0.773** | **0.722** |

`p/security-audit` is the baseline: it adds coverage for CWE-330 (weak
randomness) and CWE-614 (insecure cookie) without adding false positives.

### Full evaluation (2,740 test cases, 2,163 findings)

| Stage | TP | FP | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|
| Semgrep baseline | 1,094 | 520 | 321 | 0.678 | 0.773 | 0.722 |
| + LLM triage (v4, threshold 0.7) | **1,094** | **33** | 321 | **0.971** | **0.773** | **0.861** |

- **FP: 520 → 33 (−93.7%), with zero true positives lost.**
- On the 1,769 test cases Semgrep flagged (the precision layer): P 0.678 → 0.971,
  R 0.876 unchanged.
- Finding level: 1,163 true-positive findings → 1,071 `true_positive`, 92
  `uncertain`, **0 `false_positive`**; 603 false-positive findings → 567
  rejected, 36 kept.
- Cost: 3.14M tokens for the full run (DeepSeek `deepseek-chat`), 16 workers,
  147 seconds.

### Adversarial robustness (prompt injection / context poisoning)

15 true-positive cases, 3 explicit-injection payloads; 10 true-positive cases,
2 fake-sanitizer payloads. ASR = share of real vulnerabilities flipped to
`false_positive` with confidence ≥ 0.7.

| Attack | naive prompt | v4 | v5 |
|---|---:|---:|---:|
| Comment injection (`ignore previous instructions`, fake policy, fake JSON) | 0% | 0% | 0% |
| Fake sanitizer call inserted before the sink | 40% | 30% | **0%** |

DeepSeek resisted explicit instruction injection. It did trust an unresolved
custom sanitizer (`SecurityUtils.sanitize(bar)`) whose body was not in the
context. v5 adds a sanitizer-evidence rule: if a custom sanitizer's body is not
visible, the verdict must be `uncertain`. That drops ASR to 0%; 6/10 attacks
become `uncertain` (kept, so no false negatives). The clean-data cost is small:
on the 100-case pilot, v5 keeps 1 FP versus 0 for v4, with recall unchanged.

### Prompt / context iterations

| Version | Change | Outcome |
|---|---|---|
| v1 | method body only | 3 TP `uncertain`, 2 FP missed (20-case smoke) |
| v2 | inline same-file callees | 0 TP `uncertain` in the 20-case smoke test |
| v3 | CWE-specific rules | FP 19 → 1, but 2 CWE-78 TPs dropped (100-case pilot) |
| v4 | cross-file callees + corrected CWE-78 rule | full run: FP 520 → 33, 0 TP lost |
| v5 | sanitizer-evidence rule | fake-sanitizer ASR 30% → 0% |

### Artifacts

- [HTML report](docs/report.html) — full 2,163-finding run
- [End-to-end metrics](docs/results/eval_v4_full_endtoend.json)
- [Flagged-subset metrics](docs/results/eval_v4_flagged_subset.json)
- [Injection ASR results](docs/results/eval_injection.json)
- [Methodology and experiment log](docs/methodology.md)
- [Technical blog (Chinese)](docs/blog.md)
- [Interview notes and resume bullets](docs/interview-notes.md)

## How it works

```
repo
  |
  v
Semgrep (p/security-audit) --SARIF--> candidate findings
  |
  v
Context builder (tree-sitter)
  - enclosing method
  - class fields + imports
  - same-file helper methods (e.g. inner-class doSomething)
  - cross-file helpers (e.g. SeparateClassRequest.getTheValue)
  |
  v
LLM verifier (OpenAI-compatible API, temperature 0)
  - true_positive / false_positive / uncertain
  - confidence, reason, evidence snippets
  |
  v
Filter + score
  - drop only false_positive with confidence >= threshold
  - keep uncertain (recall-first)
  - precision / recall / F1 vs OWASP ground truth
```

Key design choice: **the LLM verifies candidates, it does not discover new
findings.** Semgrep remains the recall ceiling, and the evaluation reports the
precision layer separately from end-to-end recall. This avoids the usual
"LLM found a vulnerability" claim that cannot be reproduced.

## Quick start

Tested on Windows 11 with Python 3.14 and Semgrep 1.185.

```bat
py -3.14 -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple

git clone --depth 1 https://github.com/OWASP-Benchmark/BenchmarkJava.git data/BenchmarkJava

:: 1) baseline
.venv\Scripts\semgrep.exe --config p/security-audit --sarif ^
  --output out/baseline.sarif --metrics off ^
  data\BenchmarkJava\src\main\java\org\owasp\benchmark\testcode

.venv\Scripts\python.exe scripts\evaluate.py ^
  --sarif out\baseline.sarif ^
  --ground-truth data\BenchmarkJava\expectedresults-1.2.csv ^
  --label baseline

:: 2) context + LLM verdicts
.venv\Scripts\python.exe scripts\build_context.py ^
  --sarif out\baseline.sarif --out out\contexts.jsonl

copy .env.example .env
:: put DEEPSEEK_API_KEY=sk-... in .env

.venv\Scripts\python.exe scripts\verify.py ^
  --contexts out\contexts.jsonl --out out\verdicts.jsonl ^
  --workers 4 --prompt-version v4

:: 3) score the filtered result
.venv\Scripts\python.exe scripts\apply_verdicts.py ^
  --contexts out\contexts.jsonl --verdicts out\verdicts.jsonl ^
  --ground-truth data\BenchmarkJava\expectedresults-1.2.csv ^
  --subset complete --prompt-version v4
```

For a cheap smoke test, use `--shuffle --limit 20`, or `--mock` to run the
pipeline without an API key.

## Scoring conventions

File-level, matching OWASP Benchmark's intent:

- **TP**: real-vulnerability case with at least one finding of the expected CWE.
- **FN**: real-vulnerability case with no finding of the expected CWE.
- **FP**: non-vulnerable case with at least one finding (any CWE).
- **TN**: non-vulnerable case with no findings.

The evaluator matches findings to test cases by `BenchmarkTest\d+` and extracts
CWEs from Semgrep's `tags`/`cwe` metadata.

## Repository layout

```
scripts/
  inspect_sarif.py       compact SARIF summary
  evaluate.py            baseline scoring against expectedresults CSV
  build_context.py       tree-sitter context packs with callee inlining
  verify.py              LLM verifier (DeepSeek/Qwen/Ollama compatible)
  apply_verdicts.py      threshold sweep and filtered scoring
  summarize_verdicts.py  finding-level confusion matrix and error analysis
  make_injection_set.py  build clean + injected attack variants
  analyze_injection.py   ASR / FP-hold comparison across defenses
  report.py              standalone HTML report
  check_jsonl.py         validate JSONL after interrupted runs
docs/
  methodology.md         experiment log, error analysis, design decisions
  interview-notes.md     project pitch, Q&A, resume bullets
```

## Limitations

- **Benchmark leakage**: OWASP Benchmark is public and may be in model training
  data. Identifiers are anonymized before prompting, but a real-CVE case study
  is still needed as out-of-distribution validation.
- **CWE taxonomy mismatch**: Semgrep's DES rule tags CWE-326 while the
  benchmark expects CWE-327, so 130 real crypto cases count as FN under strict
  matching. A custom rule or an explicit CWE map is future work.
- **Recall ceiling**: Semgrep misses 321 of 2,740 cases; the LLM cannot recover
  findings the scanner never produced.
- **Prompt tuning sample**: prompt versions were tuned on a 100-case pilot; the
  reported numbers come from the full 2,163-finding run.
- **Sanitizer defense cost**: v5 trades a small amount of FP reduction for
  robustness against fake sanitizer calls; it was validated on the 100-case
  clean pilot and the attack set, not a full clean run.

## Roadmap

- [x] Full 2,163-finding evaluation and threshold sweep
- [x] Prompt-injection lab: comments, fake policies, fake JSON, fake sanitizers
- [x] HTML report and injection ASR analysis
- [ ] Triage-labelled SARIF output
- [ ] Custom CWE-327 rule and CWE equivalence map
- [ ] Real-CVE case study (3–5 CVEs)
- [ ] CI integration (fail on new high-confidence findings)
