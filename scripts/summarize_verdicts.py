"""Compare LLM verdicts with the benchmark ground truth, at finding level."""

import argparse
import json
from collections import Counter
from pathlib import Path

from evaluate import load_ground_truth


def truth_label(record: dict, cases: dict) -> str:
    case = cases.get(record.get("test_name", ""))
    if case is None:
        return "unknown"
    if case.is_vuln and case.cwe in record.get("cwes", []):
        return "TP"
    if not case.is_vuln:
        return "FP"
    return "wrong-CWE"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--verdicts", required=True, type=Path)
    parser.add_argument("--ground-truth", required=True, type=Path)
    parser.add_argument("--details", action="store_true")
    parser.add_argument("--errors-only", action="store_true")
    parser.add_argument("--prompt-version", default=None)
    parser.add_argument("--model", default=None)
    args = parser.parse_args()

    cases = load_ground_truth(args.ground_truth)
    records = []
    for line in args.verdicts.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    if args.prompt_version:
        records = [r for r in records if r.get("prompt_version") == args.prompt_version]
    if args.model:
        records = [r for r in records if r.get("model") == args.model]
    ok = [record for record in records if "verdict" in record and "error" not in record]
    errors = len(records) - len(ok)

    counts: Counter[tuple[str, str]] = Counter()
    for record in ok:
        counts[(truth_label(record, cases), record["verdict"])] += 1

    truths = ["TP", "FP", "wrong-CWE", "unknown"]
    verdicts = ["true_positive", "false_positive", "uncertain"]
    print(f"records: {len(records)}  ok: {len(ok)}  errors: {errors}\n")
    print(f"{'truth':>10} " + " ".join(f"{v:>15}" for v in verdicts) + f" {'total':>7}")
    for truth in truths:
        row = [counts.get((truth, verdict), 0) for verdict in verdicts]
        if sum(row):
            print(f"{truth:>10} " + " ".join(f"{value:>15}" for value in row) + f" {sum(row):>7}")

    if args.details:
        print("\nDetails:")
        for record in sorted(ok, key=lambda item: (truth_label(item, cases), item["verdict"])):
            truth = truth_label(record, cases)
            if args.errors_only and not (
                (truth == "TP" and record["verdict"] == "false_positive")
                or (truth == "FP" and record["verdict"] == "true_positive")
            ):
                continue
            cwes = ",".join(str(cwe) for cwe in record.get("cwes", []))
            print(
                f"[{truth:>9}] {record['verdict']:<14} conf={record.get('confidence', 0):.2f} "
                f"{record['test_name']} CWE={cwes} :: {record.get('reason', '')[:160]}"
            )


if __name__ == "__main__":
    main()
