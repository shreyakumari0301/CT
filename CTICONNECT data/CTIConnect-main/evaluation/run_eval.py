#!/usr/bin/env python3
"""Score a predictions file against the CTIConnect benchmark.

Usage:

    python -m evaluation.run_eval --predictions preds.jsonl --out scores.json

`preds.jsonl` is one JSON object per line: {"id": "rcm-001", "prediction": "..."}

Entity Linking + Entity Attribution items are scored with identifier P/R/F1.
Multi-Doc Synthesis items (eval_type=judge) are listed under `skipped_judge`
and require the LLM judge (see `evaluation/judge/run_judge.py`); pass
`--with-judge` to run it inline (needs OPENAI_API_KEY).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from cticonnect import load_all  # noqa: E402
from cticonnect.schema import read_predictions  # noqa: E402
from evaluation.metrics import score_predictions  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Score CTIConnect predictions.")
    ap.add_argument("--predictions", required=True, type=Path,
                    help="JSONL of {id, prediction}")
    ap.add_argument("--out", type=Path, default=None,
                    help="Write full scores JSON here (default: stdout summary only)")
    ap.add_argument("--data-dir", type=Path, default=None,
                    help="Override benchmark data directory")
    ap.add_argument("--with-judge", action="store_true",
                    help="Run the MDS LLM judge inline (needs OPENAI_API_KEY)")
    args = ap.parse_args(argv)

    preds = {p.id: p.prediction for p in read_predictions(args.predictions)}
    qa_records = [qa for items in load_all(data_dir=args.data_dir).values()
                  for qa in items]

    scores = score_predictions(preds, qa_records)

    # Optional MDS judge.
    if args.with_judge and scores["skipped_judge"]:
        from evaluation.judge.run_judge import judge_mds_items
        judge_scores = judge_mds_items(
            preds, qa_records, only_ids=set(scores["skipped_judge"]),
        )
        scores["mds_judge"] = judge_scores

    # Summary to stdout.
    o = scores["overall"]
    print(f"ID-based items scored: {o['n']}")
    print(f"  Precision {o['precision']:.3f}  Recall {o['recall']:.3f}  "
          f"F1 {o['f1']:.3f}  ExactMatch {o['exact_match']:.3f}")
    print("Per task:")
    for task, m in scores["per_task"].items():
        print(f"  {task:5s} n={m['n']:<4} P={m['precision']:.3f} "
              f"R={m['recall']:.3f} F1={m['f1']:.3f} EM={m['exact_match']:.3f}")
    if scores["skipped_judge"]:
        tag = "scored via judge" if args.with_judge else "NOT scored (use --with-judge)"
        print(f"Multi-Doc Synthesis items ({len(scores['skipped_judge'])}): {tag}")
    if scores["missing_predictions"]:
        print(f"WARNING: {len(scores['missing_predictions'])} gold items "
              f"had no prediction")

    if args.out:
        args.out.write_text(json.dumps(scores, indent=2) + "\n")
        print(f"Full scores written to {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
