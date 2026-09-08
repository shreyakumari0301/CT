"""
Run TCAR on CTIConnect RCM+ATA without modifying eval/run_cticonnect.py.

Examples (from repo root, WSL venv recommended):
  python -m tcar.eval.run_benchmark --limit 5 --workers 1
  python -m tcar.eval.run_benchmark --limit 0 --workers 3 --compare
  python -m tcar.eval.run_benchmark --variant no_gate --limit 50
"""

from __future__ import annotations

import argparse
import json
import sys
import threading
import time
import traceback
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv
from tqdm import tqdm

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))
load_dotenv(ROOT / ".env")

from eval.cticonnect_kb import CTIConnectKBRetriever  # noqa: E402
from eval.cticonnect_loader import OVERLAP_TASKS, QARecord, load_tasks  # noqa: E402
from eval.cticonnect_metrics import aggregate_scores, score_id_item  # noqa: E402
from eval.run_cticonnect import (  # noqa: E402
    _cticonnect_chat,
    _resolve_cticonnect_model,
    print_summary,
)
from tcar.config import TCARConfig  # noqa: E402
from tcar.predict import predict_with_meta  # noqa: E402

OUT_DEFAULT = ROOT / "tcar" / "eval_results"
DATA_DEFAULT = ROOT / "CTICONNECT data" / "data"
CORPUS_DEFAULT = ROOT / "CTICONNECT data" / "CTIConnect-main" / "corpus_kb"

_WRITE_LOCK = threading.Lock()

VARIANTS = ["full", "no_gate", "no_confusion", "no_contrast", "closed_book"]


def _system_name(variant: str) -> str:
    return f"tcar_{variant}" if variant != "full" else "tcar"


def run_one(
    qa: QARecord,
    ctx: Dict[str, Any],
    variant: str,
) -> Dict[str, Any]:
    t0 = time.time()
    err: Optional[str] = None
    pred = ""
    meta: Dict[str, Any] = {}
    try:
        pred, meta = predict_with_meta(qa, ctx, variant=variant)
    except Exception as exc:  # noqa: BLE001
        err = f"{type(exc).__name__}: {exc}"
        traceback.print_exc()
    return {
        "system": _system_name(variant),
        "variant": variant,
        "id": qa.id,
        "task": qa.task,
        "question": qa.question[:500],
        "ground_truth": qa.ground_truth,
        "prediction": pred,
        "raw": pred[:4000],
        "tcar_meta": meta,
        "error": err,
        "elapsed_s": round(time.time() - t0, 2),
    }


def run_variant(
    variant: str,
    qas: List[QARecord],
    ctx: Dict[str, Any],
    workers: int,
    out_dir: Path,
    stamp: str,
    *,
    resume: bool = True,
) -> List[Dict[str, Any]]:
    system = _system_name(variant)
    out_path = out_dir / f"{system}_{stamp}.jsonl"
    done: Dict[str, Dict[str, Any]] = {}
    if resume and out_path.exists():
        for line in out_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            row = json.loads(line)
            rid = row.get("id")
            if rid and (rid not in done or (done[rid].get("error") and not row.get("error"))):
                done[rid] = row

    remaining = [qa for qa in qas if qa.id not in done or done[qa.id].get("error")]
    results = [done[qa.id] for qa in qas if qa.id in done and not done[qa.id].get("error")]

    def _write(row: Dict[str, Any]) -> None:
        with _WRITE_LOCK:
            with open(out_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(row, ensure_ascii=False) + "\n")

    if remaining:
        print(f"  {system}: running {len(remaining)}/{len(qas)}")
        with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
            for row in tqdm(pool.map(lambda qa: run_one(qa, ctx, variant), remaining), total=len(remaining), desc=system):
                _write(row)
                results.append(row)
    else:
        print(f"  {system}: all {len(qas)} cached")

    by_id = {r["id"]: r for r in results}
    ordered = [by_id[qa.id] for qa in qas if qa.id in by_id]
    items = [
        score_id_item(r["prediction"], r["ground_truth"], task=r["task"], item_id=r["id"])
        for r in ordered
        if not r.get("error")
    ]
    summary = aggregate_scores(items)
    summary["system"] = system
    summary["variant"] = variant
    summary["pred_path"] = str(out_path)
    summary["generator"] = _resolve_cticonnect_model()
    summary_path = out_dir / f"{system}_{stamp}_summary.json"
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print_summary(system, summary)

    # Gate stats
    admitted = sum(1 for r in ordered if (r.get("tcar_meta") or {}).get("mode") == "contrast_retrieval")
    summary["retrieval_admitted_rate"] = admitted / len(ordered) if ordered else 0.0
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return ordered


def main() -> None:
    ap = argparse.ArgumentParser(description="TCAR CTIConnect benchmark (isolated)")
    ap.add_argument("--tasks", default="rcm,ata")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--workers", type=int, default=2)
    ap.add_argument("--k", type=int, default=5)
    ap.add_argument("--variant", default="full", choices=VARIANTS + ["all"])
    ap.add_argument(
        "--compare",
        action="store_true",
        help="Run full + ablations: full, no_gate, no_confusion",
    )
    ap.add_argument("--out-dir", type=Path, default=OUT_DEFAULT)
    ap.add_argument("--data-dir", type=Path, default=DATA_DEFAULT)
    ap.add_argument("--stamp", default="")
    ap.add_argument("--no-resume", action="store_true")
    args = ap.parse_args()

    tasks = [t.strip() for t in args.tasks.split(",") if t.strip()]
    for t in tasks:
        if t not in OVERLAP_TASKS:
            raise SystemExit(f"TCAR eval supports {OVERLAP_TASKS}; got {t}")

    limit = None if args.limit == 0 else args.limit
    qas = load_tasks(tasks, data_dir=args.data_dir, limit=limit)
    print(f"Loaded n={len(qas)} tasks={tasks}")

    args.out_dir.mkdir(parents=True, exist_ok=True)
    stamp = args.stamp or datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    print("Loading CTIConnect KB retriever...")
    ctx: Dict[str, Any] = {
        "k": args.k,
        "cti_kb": CTIConnectKBRetriever(corpus_dir=CORPUS_DEFAULT),
        "chat": _cticonnect_chat,
    }

    if args.compare or args.variant == "all":
        variants = ["full", "no_gate", "no_confusion"]
    else:
        variants = [args.variant]

    scoreboard: Dict[str, Any] = {
        "stamp": stamp,
        "method": "TCAR (Taxonomy-Contrastive Adaptive RAG)",
        "tasks": tasks,
        "n": len(qas),
        "generator": _resolve_cticonnect_model(),
        "retrieval_k": args.k,
        "variants": {},
    }

    for v in variants:
        print(f"\n>>> TCAR variant={v}")
        cfg = TCARConfig(k_retrieve=args.k, variant=v)
        ctx["tcar_config"] = cfg
        records = run_variant(
            v,
            qas,
            ctx,
            args.workers,
            args.out_dir,
            stamp,
            resume=not args.no_resume,
        )
        items = [
            score_id_item(r["prediction"], r["ground_truth"], task=r["task"], item_id=r["id"])
            for r in records
            if not r.get("error")
        ]
        scoreboard["variants"][_system_name(v)] = aggregate_scores(items)

    board_path = args.out_dir / f"scoreboard_{stamp}.json"
    board_path.write_text(json.dumps(scoreboard, indent=2), encoding="utf-8")
    print(f"\nScoreboard: {board_path}")


if __name__ == "__main__":
    main()
