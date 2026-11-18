"""Merge LLM verdicts with Semgrep findings and score the filtered result.

Only findings the verifier confidently rejects are removed; true positives,
uncertain verdicts, and low-confidence false positives are kept. This makes the
trade-off explicit: FP reduction versus recall loss.

Usage:
  python apply_verdicts.py --contexts out/contexts.jsonl \
      --verdicts out/verdicts.jsonl \
      --ground-truth data/BenchmarkJava/expectedresults-1.2.csv \
      --json-out out/eval_filtered.json
"""

import argparse
import json
from collections import defaultdict
from pathlib import Path

from evaluate import Case, Score, load_ground_truth


def load_contexts(path: Path) -> list[dict]:
    records = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return records


def load_verdicts(path: Path, model: str | None, prompt_version: str | None) -> dict[str, dict]:
    verdicts: dict[str, dict] = {}
    if not path.exists():
        return verdicts
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if "error" in record or "verdict" not in record:
            continue
        if model and record.get("model") != model:
            continue
        if prompt_version and record.get("prompt_version") != prompt_version:
            continue
        verdicts[record["id"]] = record
    return verdicts


def survives(verdict: dict | None, threshold: float) -> bool:
    if verdict is None:
        return True
    if verdict["verdict"] != "false_positive":
        return True
    return float(verdict.get("confidence", 0.0)) < threshold


def score_cases(
    cases: dict[str, Case],
    contexts_by_case: dict[str, list[dict]],
    verdicts: dict[str, dict],
    threshold: float,
) -> Score:
    result = Score()
    for name, case in cases.items():
        kept_cwes: set[int] = set()
        kept_any = False
        for record in contexts_by_case.get(name, []):
            if survives(verdicts.get(record["id"]), threshold):
                kept_any = True
                kept_cwes.update(record.get("cwes", []))

        if case.is_vuln:
            if case.cwe in kept_cwes:
                result.tp += 1
            else:
                result.fn += 1
        else:
            if kept_any:
                result.fp += 1
            else:
                result.tn += 1
    return result


def print_row(label: str, score: Score, baseline_fp: int) -> None:
    reduction = (baseline_fp - score.fp) / baseline_fp if baseline_fp else 0.0
    print(
        f"{label:>10}  TP={score.tp:>4}  FP={score.fp:>4}  FN={score.fn:>4}  "
        f"TN={score.tn:>4}  P={score.precision:.3f}  R={score.recall:.3f}  "
        f"F1={score.f1:.3f}  FP-reduction={reduction:+.1%}"
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--contexts", required=True, type=Path)
    parser.add_argument("--verdicts", required=True, type=Path)
    parser.add_argument("--ground-truth", required=True, type=Path)
    parser.add_argument("--thresholds", default="0.5,0.6,0.7,0.8,0.9")
    parser.add_argument("--subset", choices=["complete", "all"], default="complete")
    parser.add_argument("--model", default=None)
    parser.add_argument("--prompt-version", default=None)
    parser.add_argument("--json-out", type=Path)
    args = parser.parse_args()

    all_cases = load_ground_truth(args.ground_truth)
    contexts = load_contexts(args.contexts)
    verdicts = load_verdicts(args.verdicts, args.model, args.prompt_version)
    thresholds = [float(value) for value in args.thresholds.split(",")]

    contexts_by_case: dict[str, list[dict]] = defaultdict(list)
    for record in contexts:
        contexts_by_case[record["test_name"]].append(record)

    if args.subset == "complete":
        names = {
            name
            for name, records in contexts_by_case.items()
            if all(record["id"] in verdicts for record in records)
        }
    else:
        names = set(all_cases)

    cases = {name: all_cases[name] for name in names if name in all_cases}
    print(f"contexts: {len(contexts)}  verdicts: {len(verdicts)}  subset: {args.subset}")
    print(f"test cases in subset: {len(cases)} / {len(all_cases)}")

    baseline = score_cases(cases, contexts_by_case, {}, threshold=0.0)
    print("\nBaseline (all Semgrep findings kept):")
    print_row("baseline", baseline, baseline.fp)

    details = {}
    print("\nAfter LLM filtering:")
    for threshold in thresholds:
        filtered = score_cases(cases, contexts_by_case, verdicts, threshold)
        print_row(f"thr={threshold:.1f}", filtered, baseline.fp)
        details[f"{threshold:.1f}"] = {
            "baseline": baseline.as_dict(),
            "filtered": filtered.as_dict(),
        }

    # Per-CWE at the middle threshold (0.7 by default) for error analysis.
    analysis_threshold = 0.7 if 0.7 in thresholds else thresholds[len(thresholds) // 2]
    per_cwe: dict[int, dict[str, Score]] = {}
    for name, case in cases.items():
        bucket = per_cwe.setdefault(case.cwe, {"baseline": Score(), "filtered": Score()})
        for key, verdict_map, threshold in (
            ("baseline", {}, 0.0),
            ("filtered", verdicts, analysis_threshold),
        ):
            score = score_cases(
                {name: case},
                contexts_by_case,
                verdict_map,
                threshold,
            )
            target = bucket[key]
            target.tp += score.tp
            target.fp += score.fp
            target.fn += score.fn
            target.tn += score.tn

    print(f"\nPer-CWE at threshold {analysis_threshold}:")
    print(f"{'CWE':>6} {'base-P':>8} {'base-R':>8} {'filt-P':>8} {'filt-R':>8} {'FP-base':>8} {'FP-filt':>8}")
    for cwe in sorted(per_cwe):
        base = per_cwe[cwe]["baseline"]
        filt = per_cwe[cwe]["filtered"]
        print(
            f"{cwe:>6} {base.precision:>8.3f} {base.recall:>8.3f} "
            f"{filt.precision:>8.3f} {filt.recall:>8.3f} "
            f"{base.fp:>8} {filt.fp:>8}"
        )

    if args.json_out:
        payload = {
            "subset": args.subset,
            "cases": len(cases),
            "thresholds": details,
            "per_cwe": {
                str(cwe): {
                    "baseline": scores["baseline"].as_dict(),
                    "filtered": scores["filtered"].as_dict(),
                }
                for cwe, scores in sorted(per_cwe.items())
            },
        }
        args.json_out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(f"\nwrote {args.json_out}")


if __name__ == "__main__":
    main()
