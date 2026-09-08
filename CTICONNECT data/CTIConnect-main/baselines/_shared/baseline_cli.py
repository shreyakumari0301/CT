"""Shared CLI scaffold for ID-task baselines (closed_book / vanilla_rag /
etr / dtr).

A baseline supplies a `predict(qa, ctx)` callable; this scaffold handles task
selection, the per-item loop (bounded parallelism), progress, and writing a
predictions JSONL the evaluation harness can score.
"""

from __future__ import annotations

import argparse
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from cticonnect import load_task, list_tasks  # noqa: E402
from cticonnect.schema import Prediction, write_predictions  # noqa: E402

# Baselines in this scaffold target the ID-based tasks (EL + EA).
ID_TASKS = ["rcm", "wim", "atd", "esd", "ata", "vca"]


def add_common_args(ap: argparse.ArgumentParser) -> None:
    ap.add_argument("--tasks", nargs="+", default=ID_TASKS,
                    help=f"tasks to run (default: all ID tasks {ID_TASKS})")
    ap.add_argument("--limit", type=int, default=None,
                    help="only run the first N items per task (smoke test)")
    ap.add_argument("--out", type=Path, required=True,
                    help="output predictions JSONL")
    ap.add_argument("--model", type=str, default=None,
                    help="answering model (default: env CTICONNECT_MODEL or gpt-4o)")
    ap.add_argument("--top-k", type=int, default=5, help="retrieval depth")
    ap.add_argument(
        "--concurrency",
        type=int,
        default=3,
        help="parallel LLM+retrieve workers (keep low; embedder cache is locked but "
        "high concurrency still stresses APIs)",
    )


def run(predict_fn, args, ctx: dict) -> None:
    """Run ``predict_fn(qa, ctx)`` over selected items and write predictions."""
    tasks = [t for t in args.tasks if t in ID_TASKS]
    bad = [t for t in args.tasks if t not in ID_TASKS]
    if bad:
        print(f"WARNING: skipping non-ID tasks {bad} "
              f"(this baseline targets EL+EA; MDS uses cskg_guided)")

    qas = []
    for t in tasks:
        items = load_task(t)
        if args.limit:
            items = items[:args.limit]
        qas.extend(items)
    print(f"Running on {len(qas)} items across tasks {tasks}")

    preds: list[Prediction] = []

    def _one(qa):
        try:
            text = predict_fn(qa, ctx)
        except Exception as e:  # noqa: BLE001
            print(f"  [{qa.id}] ERROR: {e}")
            text = ""
        return Prediction(id=qa.id, prediction=text)

    with ThreadPoolExecutor(max_workers=args.concurrency) as ex:
        for i, p in enumerate(ex.map(_one, qas), 1):
            preds.append(p)
            if i % 10 == 0 or i == len(qas):
                print(f"  {i}/{len(qas)} done", end="\r")
    print()

    write_predictions(preds, args.out)
    print(f"Wrote {len(preds)} predictions -> {args.out}")
