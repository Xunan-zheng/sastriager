"""Evaluate a SARIF file against the OWASP Benchmark ground truth.

Scoring conventions (file-level, matching the Benchmark's intent):
  TP: a real-vulnerability test case with at least one finding of the expected CWE
  FN: a real-vulnerability test case with no finding of the expected CWE
  FP: a non-vulnerable test case with at least one finding (any CWE)
  TN: a non-vulnerable test case with no findings

Usage:
  python evaluate.py --sarif out/baseline.sarif \
      --ground-truth data/BenchmarkJava/expectedresults-1.2.csv \
      --label baseline
"""

import argparse
import csv
import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Case:
    name: str
    category: str
    is_vuln: bool
    cwe: int


@dataclass
class FileFindings:
    cwes: set[int] = field(default_factory=set)
    count: int = 0


@dataclass
class Score:
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0

    @property
    def precision(self) -> float:
        denom = self.tp + self.fp
        return self.tp / denom if denom else 0.0

    @property
    def recall(self) -> float:
        denom = self.tp + self.fn
        return self.tp / denom if denom else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    def as_dict(self) -> dict:
        return {
            "tp": self.tp,
            "fp": self.fp,
            "fn": self.fn,
            "tn": self.tn,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
        }


def load_ground_truth(path: Path) -> dict[str, Case]:
    cases: dict[str, Case] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        fields = [part.strip() for part in line.split(",")]
        if len(fields) < 4:
            continue
        name, category, is_vuln, cwe = fields[:4]
        cases[name] = Case(
            name=name,
            category=category,
            is_vuln=is_vuln.lower() == "true",
            cwe=int(cwe),
        )
    return cases


def extract_cwes(rule: dict, result: dict) -> set[int]:
    """Semgrep puts CWE metadata in a few different shapes; collect them all."""
    texts: list[str] = []
    for source in (rule.get("properties", {}), result.get("properties", {})):
        if not isinstance(source, dict):
            continue
        for key in ("cwe", "tags"):
            value = source.get(key)
            if isinstance(value, str):
                texts.append(value)
            elif isinstance(value, list):
                texts.extend(str(item) for item in value)

    cwes: set[int] = set()
    for text in texts:
        for match in re.finditer(r"CWE-(\d+)", text, re.IGNORECASE):
            cwes.add(int(match.group(1)))
    return cwes


def load_findings(sarif_path: Path) -> tuple[dict[str, FileFindings], int]:
    sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
    findings: dict[str, FileFindings] = defaultdict(FileFindings)
    skipped = 0

    for run in sarif.get("runs", []):
        rules = {rule["id"]: rule for rule in run["tool"]["driver"].get("rules", [])}
        for result in run.get("results", []):
            location = result.get("locations", [{}])[0].get("physicalLocation", {})
            uri = location.get("artifactLocation", {}).get("uri", "")
            match = re.search(r"(BenchmarkTest\d+)", uri)
            if not match:
                skipped += 1
                continue

            name = match.group(1)
            rule = rules.get(result.get("ruleId", ""), {})
            findings[name].cwes.update(extract_cwes(rule, result))
            findings[name].count += 1

    return dict(findings), skipped


def score(cases: dict[str, Case], findings: dict[str, FileFindings]) -> tuple[Score, dict[int, Score]]:
    overall = Score()
    per_cwe: dict[int, Score] = defaultdict(Score)

    for name, case in cases.items():
        found = findings.get(name, FileFindings())
        hit_expected = case.cwe in found.cwes

        if case.is_vuln:
            if hit_expected:
                overall.tp += 1
                per_cwe[case.cwe].tp += 1
            else:
                overall.fn += 1
                per_cwe[case.cwe].fn += 1
        else:
            if found.count > 0:
                overall.fp += 1
                per_cwe[case.cwe].fp += 1
            else:
                overall.tn += 1
                per_cwe[case.cwe].tn += 1

    return overall, dict(per_cwe)


def print_report(label: str, cases: dict[str, Case], overall: Score, per_cwe: dict[int, Score], skipped: int) -> None:
    print(f"\n=== {label} ===")
    print(f"cases: {len(cases)}  skipped findings: {skipped}")
    print(json.dumps(overall.as_dict(), indent=2))
    print(f"\n{'CWE':>6} {'TP':>5} {'FP':>5} {'FN':>5} {'TN':>5} {'P':>7} {'R':>7} {'F1':>7}")
    for cwe in sorted(per_cwe):
        s = per_cwe[cwe]
        print(
            f"{cwe:>6} {s.tp:>5} {s.fp:>5} {s.fn:>5} {s.tn:>5} "
            f"{s.precision:>7.3f} {s.recall:>7.3f} {s.f1:>7.3f}"
        )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sarif", required=True, type=Path)
    parser.add_argument("--ground-truth", required=True, type=Path)
    parser.add_argument("--label", default="run")
    parser.add_argument("--json-out", type=Path)
    args = parser.parse_args()

    cases = load_ground_truth(args.ground_truth)
    findings, skipped = load_findings(args.sarif)
    overall, per_cwe = score(cases, findings)

    print_report(args.label, cases, overall, per_cwe, skipped)

    if args.json_out:
        payload = {
            "label": args.label,
            "cases": len(cases),
            "overall": overall.as_dict(),
            "per_cwe": {str(cwe): s.as_dict() for cwe, s in sorted(per_cwe.items())},
            "skipped_findings": skipped,
        }
        args.json_out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(f"\nwrote {args.json_out}")


if __name__ == "__main__":
    main()
