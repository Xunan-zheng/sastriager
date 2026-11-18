"""Print a compact summary of a SARIF file produced by Semgrep."""

import json
import sys
from pathlib import Path


def main(path: str) -> None:
    sarif = json.loads(Path(path).read_text(encoding="utf-8"))

    for run in sarif.get("runs", []):
        driver = run["tool"]["driver"]
        rules = {rule["id"]: rule for rule in driver.get("rules", [])}
        results = run.get("results", [])
        print(f"Tool: {driver.get('name')} {driver.get('version')}")
        print(f"Results: {len(results)}\n")

        for result in results:
            rule_id = result.get("ruleId", "<unknown>")
            rule = rules.get(rule_id, {})
            props = rule.get("properties", {})
            location = result["locations"][0]["physicalLocation"]
            region = location.get("region", {})

            print("=" * 70)
            print(f"rule    : {rule_id}")
            print(f"level   : {result.get('level')}")
            print(f"message : {result['message']['text'][:300]}")
            print(
                "file    : "
                f"{location['artifactLocation']['uri']}:{region.get('startLine')}"
            )
            print(f"cwe     : {props.get('cwe')}")
            print(f"tags    : {props.get('tags')}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: python inspect_sarif.py <file.sarif>")
    main(sys.argv[1])
