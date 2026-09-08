"""
Gate audit: summarize counterfactual JSONL or fill missing CB/RAG branches.

Reuses existing predictions when model, variant, k, and both branches align.
Only calls the API for missing counterfactual branches.

Examples:
  python -m tcar.eval.gate_audit --summarize tcar/eval_results/counterfactual_*.jsonl
  python -m tcar.eval.gate_audit --fill-missing --benchmark cticonnect --tasks rcm --limit 5
"""

from __future__ import annotations

import argparse
import json
import sys
from glob import glob
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))

from tcar.eval.counterfactual_core import (  # noqa: E402
    audit_retrieval,
    build_record,
    summarize_records,
)
from tcar.eval.run_counterfactual import (  # noqa: E402
    _print_overall_table,
    _print_task_summary,
    run_ctibench_item,
    run_cticonnect_item,
)


def _has_branch(row: Dict[str, Any], branch: str) -> bool:
    key = f"{branch}_prediction"
    val = row.get(key)
    return bool(val and str(val).strip() and not row.get("error"))


def _is_complete(row: Dict[str, Any]) -> bool:
    return _has_branch(row, "closed_book") and _has_branch(row, "retrieval")


def load_jsonl(path: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


def summarize_paths(paths: List[Path], *, out: Optional[Path]) -> Dict[str, Any]:
    summary: Dict[str, Any] = {"tasks": {}}
    for path in paths:
        records = [r for r in load_jsonl(path) if _is_complete(r)]
        if not records:
            print(f"SKIP {path} (no complete paired records)")
            continue
        bench = records[0].get("benchmark", "unknown")
        task = records[0].get("task", path.stem)
        key = f"{bench}/{task}"
        metric = records[0].get("metric") or "item"
        s = summarize_records(records, metric=metric)
        s["pred_path"] = str(path)
        s["model"] = records[0].get("model")
        s["variant"] = records[0].get("variant")
        summary["tasks"][key] = s
        _print_task_summary(key, s)
        gp = s.get("gate_policies") or {}
        if gp:
            print(
                f"  Policies: CB={gp.get('always_closed_book'):.1%} "
                f"RAG={gp.get('always_rag'):.1%} "
                f"gate={gp.get('current_gate'):.1%} "
                f"random={gp.get('random_matched_rate'):.1%} "
                f"oracle={gp.get('oracle_utility'):.1%}"
            )

    _print_decisive_table(summary)
    _print_overall_table(summary)
    if out:
        out.write_text(json.dumps(summary, indent=2), encoding="utf-8")
        print(f"\nWrote {out}")
    return summary


def _print_decisive_table(summary: Dict[str, Any]) -> None:
    print("\n### Decisive table\n")
    print(
        "| Task | CB | Forced RAG | Rescues | Damages | Net utility | Gate accuracy |"
    )
    print("| --- | ---: | ---: | ---: | ---: | ---: | ---: |")
    order = [
        "cticonnect/rcm",
        "cticonnect/ata",
        "ctibench/mcq",
        "ctibench/rcm",
        "ctibench/ate",
        "ctibench/vsp",
    ]
    tasks = summary.get("tasks", {})
    keys = [k for k in order if k in tasks] + sorted(k for k in tasks if k not in order)
    for key in keys:
        s = tasks[key]
        gp = s.get("gate_policies") or {}
        ga = gp.get("gate_accuracy_differing")
        ga_s = f"{ga:.1%}" if ga is not None else "—"
        print(
            f"| {key} | {s['closed_book_score']:.1%} | {s['forced_rag_score']:.1%} | "
            f"{s['rescues']} | {s['damages']} | {s['net_retrieval_utility']:+.1%} | {ga_s} |"
        )


def fill_missing_from_runner(
    *,
    benchmark: str,
    tasks: List[str],
    limit: Optional[int],
    model: str,
    variant: str,
    k: int,
    out_dir: Path,
    stamp: str,
) -> None:
    """Re-run only items missing a CB or RAG branch in existing JSONL."""
    from eval.cticonnect_loader import OVERLAP_TASKS, load_tasks
    from eval.run_ctibench import TASK_CONFIG, load_rows

    for task in tasks:
        if benchmark == "cticonnect":
            if task not in OVERLAP_TASKS:
                continue
            out_path = out_dir / f"counterfactual_cticonnect_{task}_{stamp}.jsonl"
            qas = load_tasks([task], limit=limit)
            existing = {r["id"]: r for r in load_jsonl(out_path)} if out_path.exists() else {}
            with open(out_path, "a", encoding="utf-8") as f:
                for qa in qas:
                    prev = existing.get(qa.id)
                    if prev and _is_complete(prev):
                        continue
                    row = run_cticonnect_item(qa, model=model, k=k, variant=variant)
                    row["model"] = model
                    row["variant"] = variant
                    row["k_retrieve"] = k
                    f.write(json.dumps(row, ensure_ascii=False) + "\n")
                    print(f"filled {qa.id}")
        else:
            if task not in TASK_CONFIG:
                continue
            cfg = TASK_CONFIG[task]
            rows = load_rows(cfg["data"], limit)
            out_path = out_dir / f"counterfactual_ctibench_{task}_{stamp}.jsonl"
            existing = {r["id"]: r for r in load_jsonl(out_path)} if out_path.exists() else {}
            with open(out_path, "a", encoding="utf-8") as f:
                for idx, row_data in enumerate(rows):
                    iid = f"{task}-{idx}"
                    prev = existing.get(iid)
                    if prev and _is_complete(prev):
                        continue
                    row = run_ctibench_item(
                        task, row_data, idx, model=model, k=k, variant=variant
                    )
                    row["model"] = model
                    row["variant"] = variant
                    row["k_retrieve"] = k
                    f.write(json.dumps(row, ensure_ascii=False) + "\n")
                    print(f"filled {iid}")


def main() -> None:
    ap = argparse.ArgumentParser(description="Gate audit on counterfactual JSONL")
    ap.add_argument("jsonl", nargs="*", help="JSONL paths or globs")
    ap.add_argument("--summarize", action="store_true", help="Summarize only (no API)")
    ap.add_argument("--fill-missing", action="store_true", help="Fill incomplete rows via API")
    ap.add_argument("--benchmark", choices=["cticonnect", "ctibench"], default="cticonnect")
    ap.add_argument("--tasks", default="rcm,ata")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--model", default="gpt-4-turbo")
    ap.add_argument("--variant", default="no_confusion")
    ap.add_argument("--k", type=int, default=5)
    ap.add_argument("--stamp", required=False, default="cf_audit")
    ap.add_argument("--out-dir", type=Path, default=ROOT / "tcar" / "eval_results")
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args()

    if args.fill_missing:
        limit = None if args.limit == 0 else args.limit
        fill_missing_from_runner(
            benchmark=args.benchmark,
            tasks=[t.strip() for t in args.tasks.split(",") if t.strip()],
            limit=limit,
            model=args.model,
            variant=args.variant,
            k=args.k,
            out_dir=args.out_dir,
            stamp=args.stamp,
        )

    paths: List[Path] = []
    for pat in args.jsonl:
        if "*" in pat:
            paths.extend(Path(p) for p in glob(pat))
        else:
            paths.append(Path(pat))

    if not paths and args.fill_missing:
        paths = list(args.out_dir.glob(f"counterfactual_{args.benchmark}_*_{args.stamp}.jsonl"))

    if paths:
        summarize_paths(paths, out=args.out)
    elif not args.fill_missing:
        ap.error("Provide JSONL paths or use --fill-missing")


if __name__ == "__main__":
    main()
