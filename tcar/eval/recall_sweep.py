"""
Retrieval recall@k sweep — find k needed to reach target recall (default 90%).

Examples:
  python -m tcar.eval.recall_sweep --benchmark cticonnect --tasks rcm,ata
  python -m tcar.eval.recall_sweep --benchmark ctibench --tasks rcm,ate,mcq,vsp
  python -m tcar.eval.recall_sweep --benchmark all --target 0.90 --max-k 200
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))
load_dotenv(ROOT / ".env")

from eval.cticonnect_kb import CTIConnectKBRetriever  # noqa: E402
from eval.cticonnect_loader import OVERLAP_TASKS, load_tasks  # noqa: E402
from eval.run_ctibench import TASK_CONFIG, load_rows  # noqa: E402
from tcar.eval.counterfactual_core import (  # noqa: E402
    _gold_ids_ctibench,
    _gold_ids_cticonnect,
    audit_retrieval,
)
from tcar.task_branches import audit_task_kind  # noqa: E402
from tcar.ctibench_kb import CTIBenchKBRetriever  # noqa: E402

CTICONNECT_DATA = ROOT / "CTICONNECT data" / "data"
CTICONNECT_CORPUS = ROOT / "CTICONNECT data" / "CTIConnect-main" / "corpus_kb"
OUT_DEFAULT = ROOT / "tcar" / "eval_results"

# Standard report ks + extended sweep
BASE_KS = (1, 3, 5, 10, 20, 30, 35, 40, 45, 50)
EXTRA_KS = tuple(range(55, 201, 5))  # 55, 60, ... 200


def _all_ks(max_k: int) -> Tuple[int, ...]:
    ks = [k for k in BASE_KS if k <= max_k]
    for k in EXTRA_KS:
        if k <= max_k:
            ks.append(k)
    return tuple(sorted(set(ks)))


def _audit_cticonnect(
    retriever: CTIConnectKBRetriever,
    *,
    task: str,
    question: str,
    gold_ids: set,
    retrieve_k: int,
    ks: Tuple[int, ...],
) -> Dict[str, Any]:
    kind = audit_task_kind(task)
    hits = retriever.retrieve_for_task(question, task, k=retrieve_k)
    audit = audit_retrieval(hits, gold_ids, task_kind=kind, ks=ks)
    return {
        "gold_rank": audit.gold_rank,
        "recall_at": audit.recall_at,
        "retrieved_n": len(audit.retrieved_ids),
    }


def _audit_ctibench(
    retriever: CTIBenchKBRetriever,
    *,
    task: str,
    question: str,
    gold_ids: set,
    retrieve_k: int,
    ks: Tuple[int, ...],
) -> Dict[str, Any]:
    kind = audit_task_kind(task)
    if task in ("rcm", "rcm2021"):
        _, _, kb_hits, cwe_hits = retriever.retrieve_rcm_context(
            question, k_kb=retrieve_k, k_cwe=retrieve_k
        )
        hits = cwe_hits or kb_hits
        if not hits:
            hits = retriever.retrieve(question, "cwe", k=retrieve_k)
    elif task == "ate":
        hits = retriever.retrieve_mem_chunks(question, k=retrieve_k)
    elif task == "mcq":
        hits = retriever.retrieve_for_task(question, "mcq", k=retrieve_k)
    else:
        hits = retriever.retrieve_for_task(question, task, k=retrieve_k)
    audit = audit_retrieval(hits, gold_ids, task_kind=kind, ks=ks)
    return {
        "gold_rank": audit.gold_rank,
        "recall_at": audit.recall_at,
        "retrieved_n": len(audit.retrieved_ids),
    }


def _summarize(records: List[Dict[str, Any]], *, ks: Tuple[int, ...]) -> Dict[str, Any]:
    n = len(records)
    if n == 0:
        return {"n": 0}

    recall_summary = {}
    for k in ks:
        recall_summary[f"recall@{k}"] = round(
            sum(1 for r in records if r.get("recall_at", {}).get(k, False)) / n, 4
        )

    ranks = [r["gold_rank"] for r in records if r.get("gold_rank")]
    mrr = round(sum(1.0 / r for r in ranks) / n, 4) if ranks else 0.0
    mean_rank = round(sum(ranks) / len(ranks), 2) if ranks else None

    min_k_90: Optional[int] = None
    for k in ks:
        if recall_summary.get(f"recall@{k}", 0) >= 0.90:
            min_k_90 = k
            break

    return {
        "n": n,
        "mrr": mrr,
        "mean_gold_rank": mean_rank,
        "n_gold_found": len(ranks),
        "min_k_for_90pct_recall": min_k_90,
        **recall_summary,
    }


def sweep_cticonnect(tasks: List[str], *, max_k: int, target: float) -> Dict[str, Any]:
    retriever = CTIConnectKBRetriever(corpus_dir=CTICONNECT_CORPUS)
    out: Dict[str, Any] = {"benchmark": "cticonnect", "max_k": max_k, "target": target, "tasks": {}}

    for task in tasks:
        if task not in OVERLAP_TASKS:
            continue
        ks = _all_ks(max_k)
        qas = load_tasks([task], data_dir=CTICONNECT_DATA)
        rows: List[Dict[str, Any]] = []
        for qa in qas:
            gold = _gold_ids_cticonnect(qa.ground_truth)
            row = _audit_cticonnect(
                retriever,
                task=task,
                question=qa.question,
                gold_ids=gold,
                retrieve_k=max_k,
                ks=ks,
            )
            row["id"] = qa.id
            rows.append(row)

        summary = _summarize(rows, ks=ks)
        out["tasks"][f"cticonnect/{task}"] = summary

    return out


def sweep_ctibench(tasks: List[str], *, max_k: int, target: float) -> Dict[str, Any]:
    retriever = CTIBenchKBRetriever()
    out: Dict[str, Any] = {"benchmark": "ctibench", "max_k": max_k, "target": target, "tasks": {}}

    for task in tasks:
        if task not in TASK_CONFIG:
            continue
        cfg = TASK_CONFIG[task]
        if not cfg["data"].exists():
            continue
        ks = _all_ks(max_k)
        data_rows = load_rows(cfg["data"], None)
        rows: List[Dict[str, Any]] = []
        for idx, row in enumerate(data_rows):
            gold = (row.get("GT") or "").strip()
            question = (row.get(cfg["context_field"]) or "").strip()
            if not question:
                question = (row.get("Prompt") or row.get("Text") or "").strip()
            gold_ids = _gold_ids_ctibench(task, gold)
            aud = _audit_ctibench(
                retriever,
                task=task,
                question=question,
                gold_ids=gold_ids,
                retrieve_k=max_k,
                ks=ks,
            )
            aud["id"] = f"{task}-{idx}"
            rows.append(aud)

        summary = _summarize(rows, ks=ks)
        out["tasks"][f"ctibench/{task}"] = summary

    return out


def main() -> None:
    ap = argparse.ArgumentParser(description="Recall@k sweep until target recall")
    ap.add_argument("--benchmark", choices=["cticonnect", "ctibench", "all"], default="all")
    ap.add_argument("--tasks", default="rcm,ata,ate,mcq,vsp")
    ap.add_argument("--max-k", type=int, default=200, help="Max retrieval depth")
    ap.add_argument("--target", type=float, default=0.90, help="Target recall to find min-k")
    ap.add_argument("--out-dir", type=Path, default=OUT_DEFAULT)
    ap.add_argument("--stamp", default="")
    args = ap.parse_args()

    stamp = args.stamp or datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    task_list = [t.strip() for t in args.tasks.split(",") if t.strip()]
    benchmarks = ["cticonnect", "ctibench"] if args.benchmark == "all" else [args.benchmark]

    summary: Dict[str, Any] = {
        "stamp": stamp,
        "max_k": args.max_k,
        "target_recall": args.target,
        "base_ks": list(BASE_KS),
        "tasks": {},
    }

    for bench in benchmarks:
        if bench == "cticonnect":
            cc_tasks = [t for t in task_list if t in OVERLAP_TASKS]
            part = sweep_cticonnect(cc_tasks, max_k=args.max_k, target=args.target)
            summary["tasks"].update(part["tasks"])
        if bench == "ctibench":
            cb_tasks = [t for t in task_list if t in TASK_CONFIG]
            part = sweep_ctibench(cb_tasks, max_k=args.max_k, target=args.target)
            summary["tasks"].update(part["tasks"])

    out_path = args.out_dir / f"recall_sweep_{stamp}.json"
    out_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    print(f"\nWrote {out_path}\n")
    print("| Task | n | R@5 | R@30 | R@50 | min k @90% | mean rank |")
    print("| --- | ---: | ---: | ---: | ---: | ---: | ---: |")
    for key, s in sorted(summary["tasks"].items()):
        r5 = s.get("recall@5", 0)
        r30 = s.get("recall@30", 0)
        r50 = s.get("recall@50", 0)
        mk = s.get("min_k_for_90pct_recall")
        mk_s = str(mk) if mk else f">{args.max_k}"
        mr = s.get("mean_gold_rank") or "—"
        print(f"| {key} | {s['n']} | {r5:.1%} | {r30:.1%} | {r50:.1%} | {mk_s} | {mr} |")

    # Print full extended ks for CTIConnect RCM/ATA if present
    for key in ("cticonnect/rcm", "cticonnect/ata"):
        if key not in summary["tasks"]:
            continue
        s = summary["tasks"][key]
        print(f"\n=== {key} extended recall ===")
        for k in BASE_KS:
            rk = f"recall@{k}"
            if rk in s:
                print(f"  {rk}: {s[rk]:.1%}  (miss: {(1-s[rk])*100:.1f}%)")
        mk = s.get("min_k_for_90pct_recall")
        if mk:
            print(f"  → 90% reached at k={mk}")
        else:
            print(f"  → 90% NOT reached by k={args.max_k} (best: recall@50={s.get('recall@50',0):.1%})")


if __name__ == "__main__":
    main()
