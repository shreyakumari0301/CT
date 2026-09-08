"""Re-aggregate counterfactual JSONL outputs into summary tables (no API calls)."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from tcar.eval.counterfactual_core import summarize_records
from tcar.eval.run_counterfactual import _print_overall_table, _print_task_summary


def main() -> None:
    ap = argparse.ArgumentParser(description="Summarize counterfactual JSONL files")
    ap.add_argument("jsonl", nargs="+", type=Path, help="counterfactual_*.jsonl paths")
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args()

    summary: dict = {"tasks": {}}
    for path in args.jsonl:
        records = []
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            row = json.loads(line)
            if not row.get("error"):
                records.append(row)
        if not records:
            continue
        bench = records[0].get("benchmark", "unknown")
        task = records[0].get("task", path.stem)
        key = f"{bench}/{task}"
        metric = records[0].get("metric") or "item"
        summary["tasks"][key] = summarize_records(records, metric=metric)
        summary["tasks"][key]["pred_path"] = str(path)
        _print_task_summary(key, summary["tasks"][key])

    _print_overall_table(summary)
    if args.out:
        args.out.write_text(json.dumps(summary, indent=2), encoding="utf-8")
        print(f"\nWrote {args.out}")


if __name__ == "__main__":
    main()
