"""Count valid and invalid JSONL lines."""

import json
import sys
from pathlib import Path


def main() -> None:
    path = Path(sys.argv[1])
    good = bad = 0
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            json.loads(line)
            good += 1
        except json.JSONDecodeError:
            bad += 1
    print(f"valid: {good}  invalid: {bad}")


if __name__ == "__main__":
    main()
