"""Render a standalone HTML report from an apply_verdicts JSON file."""

import argparse
import html
import json
from pathlib import Path

CSS = """
body { font-family: -apple-system, Segoe UI, Roboto, sans-serif; margin: 40px auto; max-width: 1100px; color: #1f2328; line-height: 1.5; }
h1, h2 { border-bottom: 1px solid #d0d7de; padding-bottom: 8px; }
table { border-collapse: collapse; width: 100%; margin: 16px 0; font-size: 14px; }
th, td { border: 1px solid #d0d7de; padding: 8px 10px; text-align: right; }
th { background: #f6f8fa; }
td:first-child, th:first-child { text-align: left; }
.cards { display: flex; gap: 16px; flex-wrap: wrap; margin: 20px 0; }
.card { border: 1px solid #d0d7de; border-radius: 8px; padding: 16px 20px; min-width: 180px; }
.card .value { font-size: 28px; font-weight: 650; }
.card .label { color: #57606a; font-size: 13px; }
.note { background: #fff8c5; border: 1px solid #d4a72c; padding: 12px 16px; border-radius: 6px; }
.good { color: #1a7f37; font-weight: 600; }
.bad { color: #cf222e; font-weight: 600; }
"""


def score_cards(label: str, data: dict) -> str:
    return f"""
    <div class="card">
      <div class="label">{html.escape(label)}</div>
      <div class="value">{data['precision']:.3f} / {data['recall']:.3f}</div>
      <div class="label">precision / recall</div>
      <div class="label">F1 {data['f1']:.3f} &nbsp; TP {data['tp']} &nbsp; FP {data['fp']} &nbsp; FN {data['fn']}</div>
    </div>
    """


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--eval", required=True, type=Path)
    parser.add_argument("--verdicts", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--limit", type=int, default=25)
    args = parser.parse_args()

    data = json.loads(args.eval.read_text(encoding="utf-8"))
    threshold_keys = list(data["thresholds"].keys())
    threshold = "0.7" if "0.7" in threshold_keys else threshold_keys[0]
    baseline = data["thresholds"][threshold]["baseline"]
    filtered = data["thresholds"][threshold]["filtered"]

    threshold_rows = "".join(
        f"<tr><td>{key}</td><td>{value['filtered']['tp']}</td>"
        f"<td>{value['filtered']['fp']}</td><td>{value['filtered']['fn']}</td>"
        f"<td>{value['filtered']['precision']:.3f}</td>"
        f"<td>{value['filtered']['recall']:.3f}</td>"
        f"<td>{value['filtered']['f1']:.3f}</td></tr>"
        for key, value in data["thresholds"].items()
    )

    cwe_rows = "".join(
        f"<tr><td>CWE-{cwe}</td>"
        f"<td>{value['baseline']['precision']:.3f}</td>"
        f"<td>{value['baseline']['recall']:.3f}</td>"
        f"<td>{value['filtered']['precision']:.3f}</td>"
        f"<td>{value['filtered']['recall']:.3f}</td>"
        f"<td>{value['baseline']['fp']}</td>"
        f"<td>{value['filtered']['fp']}</td></tr>"
        for cwe, value in data["per_cwe"].items()
    )

    verdicts = []
    for line in args.verdicts.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if "verdict" in record and "error" not in record:
            verdicts.append(record)
    verdicts = verdicts[-args.limit :]

    verdict_rows = "".join(
        f"<tr><td>{html.escape(record.get('test_name', ''))}</td>"
        f"<td>{html.escape(','.join(str(c) for c in record.get('cwes', [])))}</td>"
        f"<td>{html.escape(record['verdict'])}</td>"
        f"<td>{float(record.get('confidence', 0)):.2f}</td>"
        f"<td>{html.escape(record.get('reason', ''))}</td></tr>"
        for record in reversed(verdicts)
    )

    document = f"""<!doctype html>
<html><head><meta charset="utf-8">
<title>SASTriager report</title><style>{CSS}</style></head>
<body>
<h1>SASTriager report</h1>
<p>Subset: <b>{html.escape(data['subset'])}</b> &nbsp; Test cases: <b>{data['cases']}</b>
&nbsp; Threshold shown: <b>{threshold}</b></p>

<div class="cards">
{score_cards("Semgrep baseline", baseline)}
{score_cards("Semgrep + LLM triage", filtered)}
</div>

<h2>Threshold sweep</h2>
<table>
<tr><th>Threshold</th><th>TP</th><th>FP</th><th>FN</th><th>Precision</th><th>Recall</th><th>F1</th></tr>
{threshold_rows}
</table>

<h2>Per-CWE</h2>
<table>
<tr><th>CWE</th><th>Base P</th><th>Base R</th><th>Filtered P</th><th>Filtered R</th><th>FP base</th><th>FP filtered</th></tr>
{cwe_rows}
</table>

<h2>Recent verdicts</h2>
<table>
<tr><th>Test case</th><th>CWE</th><th>Verdict</th><th>Conf.</th><th>Reason</th></tr>
{verdict_rows}
</table>

<p class="note">The LLM verifies Semgrep candidates; it does not discover new
findings. Recall is therefore bounded by the Semgrep baseline. Only
false_positive verdicts with confidence at or above the threshold are dropped;
uncertain verdicts are kept.</p>
</body></html>"""

    args.out.write_text(document, encoding="utf-8")
    print(f"wrote {args.out}")


if __name__ == "__main__":
    main()
