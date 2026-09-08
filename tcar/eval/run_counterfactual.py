"""
Paired counterfactual evaluation: closed-book vs forced-retrieval on every item.

Each task uses its own CTA-RAG pipeline prompt form (RCM → understanding/cta_rag_port,
ATA → cta_rag_port, ATE → reasoning_ate, MCQ → memorization, VSP → problem_solving).
Closed-book and forced-RAG differ only by whether retrieved context is included.

Examples:
  python -m tcar.eval.run_counterfactual --benchmark cticonnect --tasks rcm,ata --limit 5
  python -m tcar.eval.run_counterfactual --benchmark ctibench --tasks rcm,ate --limit 20
  python -m tcar.eval.run_counterfactual --benchmark all --tasks rcm,ata,ate,mcq --limit 0 --workers 2
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import threading
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from dotenv import load_dotenv
from tqdm import tqdm

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))
load_dotenv(ROOT / ".env")

from eval.cticonnect_kb import CTIConnectKBRetriever  # noqa: E402
from eval.cticonnect_loader import OVERLAP_TASKS, QARecord, load_tasks  # noqa: E402
from eval.run_ctibench import TASK_CONFIG, load_rows  # noqa: E402
from tcar.config import TCARConfig  # noqa: E402
from tcar.ctibench_kb import CTIBenchKBRetriever  # noqa: E402
from tcar.eval.counterfactual_core import (  # noqa: E402
    _gold_ids_ctibench,
    _gold_ids_cticonnect,
    _tcar_kind,
    audit_retrieval,
    build_record,
    summarize_records,
)
from tcar.task_branches import resolve_rcm_retrieval, run_task_branches  # noqa: E402
from utils.llm_client import chat_completion_kwargs, get_openai_client, resolve_model  # noqa: E402

OUT_DEFAULT = ROOT / "tcar" / "eval_results"
CTICONNECT_DATA = ROOT / "CTICONNECT data" / "data"
CTICONNECT_CORPUS = ROOT / "CTICONNECT data" / "CTIConnect-main" / "corpus_kb"

_WRITE_LOCK = threading.Lock()
_THREAD_LOCAL = threading.local()


def _make_chat(model: str, temperature: float) -> Callable[..., str]:
    def chat(user: str, *, max_tokens: int = 800, **_kw: Any) -> str:
        client = get_openai_client()
        resp = client.chat.completions.create(
            messages=[{"role": "user", "content": user}],
            **chat_completion_kwargs(model, max_tokens=max_tokens, temperature=temperature),
        )
        return (resp.choices[0].message.content or "").strip()

    return chat


def _task_temperature(benchmark: str, task: str) -> float:
    if benchmark == "cticonnect":
        return 0.0
    if task in ("mcq", "rcm", "rcm2021", "vsp"):
        return 0.1
    return 0.0


def _metric_label(benchmark: str, task: str) -> str:
    if benchmark == "cticonnect":
        return "F1>=1"
    return TASK_CONFIG[task]["metric"]


def _get_cticonnect_retriever() -> CTIConnectKBRetriever:
    if not hasattr(_THREAD_LOCAL, "cticonnect_retriever"):
        _THREAD_LOCAL.cticonnect_retriever = CTIConnectKBRetriever(corpus_dir=CTICONNECT_CORPUS)
    return _THREAD_LOCAL.cticonnect_retriever


def _get_ctibench_retriever() -> CTIBenchKBRetriever:
    if not hasattr(_THREAD_LOCAL, "ctibench_retriever"):
        _THREAD_LOCAL.ctibench_retriever = CTIBenchKBRetriever()
    return _THREAD_LOCAL.ctibench_retriever


def run_cticonnect_item(
    qa: QARecord,
    *,
    model: str,
    k: int,
    variant: str,
    rcm_retrieval: str,
) -> Dict[str, Any]:
    t0 = time.time()
    rec: Dict[str, Any] = {"id": qa.id, "benchmark": "cticonnect", "task": qa.task, "error": None}
    try:
        chat = _make_chat(model, _task_temperature("cticonnect", qa.task))
        cfg = TCARConfig(k_retrieve=k, variant=variant).apply_variant()
        if qa.task in ("rcm", "rcm2021") and resolve_rcm_retrieval(rcm_retrieval) == "ctibench":
            retriever = _get_ctibench_retriever()
        else:
            retriever = _get_cticonnect_retriever()

        cb_raw, rag_raw, gate, audit_hits, meta = run_task_branches(
            qa.task,
            qa.question,
            retriever,
            cfg,
            chat,
            benchmark="cticonnect",
            rcm_retrieval=rcm_retrieval,
            gold_ids=_gold_ids_cticonnect(qa.ground_truth),
        )
        # Empty RAG answers are usually truncation/abstain — fall back to CB so Forced RAG
        # does not lose items the model already answered closed-book.
        if not (rag_raw or "").strip() and (cb_raw or "").strip():
            rag_raw = cb_raw
            meta = {**(meta or {}), "rag_empty_fallback_cb": True}
        gold_ids = _gold_ids_cticonnect(qa.ground_truth)
        audit = audit_retrieval(
            audit_hits,
            gold_ids,
            task_kind=_tcar_kind(qa.task),
        )
        rec = build_record(
            item_id=qa.id,
            benchmark="cticonnect",
            task=qa.task,
            question=qa.question,
            gold=qa.ground_truth,
            gold_ids=gold_ids,
            closed_book_raw=cb_raw,
            retrieval_raw=rag_raw,
            gate=gate,
            audit=audit,
            meta=meta,
        )
    except Exception as exc:  # noqa: BLE001
        rec["error"] = f"{type(exc).__name__}: {exc}"
        traceback.print_exc()
    rec["model"] = model
    rec["variant"] = variant
    rec["k_retrieve"] = k
    rec["rcm_retrieval"] = rcm_retrieval if qa.task in ("rcm", "rcm2021") else None
    rec["latency_s"] = round(time.time() - t0, 2)
    return rec


def run_ctibench_item(
    task: str,
    row: Dict[str, str],
    idx: int,
    *,
    model: str,
    k: int,
    variant: str,
) -> Dict[str, Any]:
    t0 = time.time()
    item_id = f"{task}-{idx}"
    cfg_task = TASK_CONFIG[task]
    gold = (row.get("GT") or "").strip()
    question = (row.get(cfg_task["context_field"]) or "").strip()
    if not question:
        question = (row.get("Prompt") or row.get("Text") or "").strip()

    rec: Dict[str, Any] = {
        "id": item_id,
        "benchmark": "ctibench",
        "task": task,
        "idx": idx,
        "error": None,
    }
    try:
        temp = _task_temperature("ctibench", task)
        chat = _make_chat(model, temp)
        cfg = TCARConfig(k_retrieve=k, variant=variant).apply_variant()
        retriever = _get_ctibench_retriever()
        gold_ids = _gold_ids_ctibench(task, gold)

        cb_raw, rag_raw, gate, audit_hits, meta = run_task_branches(
            task,
            question,
            retriever,
            cfg,
            chat,
            benchmark="ctibench",
            gold_ids=gold_ids,
        )
        if not (rag_raw or "").strip() and (cb_raw or "").strip():
            rag_raw = cb_raw
            meta = {**(meta or {}), "rag_empty_fallback_cb": True}
        task_kind = _tcar_kind(task)

        audit = audit_retrieval(audit_hits, gold_ids, task_kind=task_kind)
        rec = build_record(
            item_id=item_id,
            benchmark="ctibench",
            task=task,
            question=question,
            gold=gold,
            gold_ids=gold_ids,
            closed_book_raw=cb_raw,
            retrieval_raw=rag_raw,
            gate=gate,
            audit=audit,
            meta=meta,
        )
        rec["idx"] = idx
        rec["url"] = row.get("URL", "")
        rec["model"] = model
        rec["variant"] = variant
        rec["k_retrieve"] = k
        # Empty ATE answers are usually truncated/API failures — mark for resume retry.
        if task == "ate" and not (rag_raw or "").strip():
            rec["error"] = "empty_ate_prediction"
    except Exception as exc:  # noqa: BLE001
        rec["error"] = f"{type(exc).__name__}: {exc}"
        traceback.print_exc()
    rec["latency_s"] = round(time.time() - t0, 2)
    return rec


def _write_jsonl(path: Path, row: Dict[str, Any]) -> None:
    with _WRITE_LOCK:
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")


def _run_pool(
    items: List[Any],
    worker_fn: Callable[[Any], Dict[str, Any]],
    *,
    workers: int,
    out_path: Path,
    resume: bool,
    id_key: Callable[[Any], str],
) -> List[Dict[str, Any]]:
    done: Dict[str, Dict[str, Any]] = {}
    if resume and out_path.exists():
        for line in out_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            row = json.loads(line)
            rid = str(row.get("id", ""))
            if rid and (rid not in done or (done[rid].get("error") and not row.get("error"))):
                done[rid] = row

    remaining = [it for it in items if id_key(it) not in done or done[id_key(it)].get("error")]
    results = [done[id_key(it)] for it in items if id_key(it) in done and not done[id_key(it)].get("error")]

    if remaining:
        with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
            futures = {pool.submit(worker_fn, it): it for it in remaining}
            with tqdm(total=len(remaining), desc=out_path.stem) as bar:
                for fut in as_completed(futures):
                    row = fut.result()
                    _write_jsonl(out_path, row)
                    results.append(row)
                    bar.update(1)
    return results


def main() -> None:
    ap = argparse.ArgumentParser(description="Counterfactual CB vs forced-RAG evaluation")
    ap.add_argument(
        "--benchmark",
        choices=["cticonnect", "ctibench", "all"],
        default="all",
    )
    ap.add_argument("--tasks", default="rcm,ata", help="Comma-separated task keys")
    ap.add_argument("--limit", type=int, default=5, help="0 = full dataset")
    ap.add_argument("--workers", type=int, default=1)
    ap.add_argument("--k", type=int, default=5)
    ap.add_argument("--variant", default="no_confusion", help="TCAR gate variant to log")
    ap.add_argument("--model", default="", help="Generator model (default: gpt-4-turbo)")
    ap.add_argument("--out-dir", type=Path, default=OUT_DEFAULT)
    ap.add_argument("--stamp", default="")
    ap.add_argument("--no-resume", action="store_true")
    ap.add_argument(
        "--rcm-retrieval",
        choices=["corpus_kb", "ctibench"],
        default="",
        help="CTIConnect RCM retrieval backend (default: corpus_kb; ctibench = memorization_vdb + MiniLM)",
    )
    ap.add_argument(
        "--ids-file",
        type=Path,
        default=None,
        help="Optional file of example IDs (one per line, e.g. vsp-12) to run; overrides --limit filter",
    )
    args = ap.parse_args()

    model = (args.model or os.getenv("COUNTERFACTUAL_MODEL") or "gpt-4-turbo").strip()
    rcm_retrieval = resolve_rcm_retrieval(args.rcm_retrieval or None)
    limit = None if args.limit == 0 else args.limit
    stamp = args.stamp or datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    args.out_dir.mkdir(parents=True, exist_ok=True)
    id_allow: set[str] | None = None
    if args.ids_file and args.ids_file.exists():
        id_allow = {
            ln.strip()
            for ln in args.ids_file.read_text(encoding="utf-8").splitlines()
            if ln.strip() and not ln.strip().startswith("#")
        }
        print(f"Filtering to {len(id_allow)} IDs from {args.ids_file}")

    benchmarks = ["cticonnect", "ctibench"] if args.benchmark == "all" else [args.benchmark]
    task_list = [t.strip() for t in args.tasks.split(",") if t.strip()]

    all_summaries: Dict[str, Any] = {
        "stamp": stamp,
        "model": resolve_model(model),
        "variant": args.variant,
        "k_retrieve": args.k,
        "gad_mode": (os.getenv("GAD_MODE") or "off").strip().lower(),
        "rcm_retrieval": rcm_retrieval,
        "tasks": {},
    }

    for bench in benchmarks:
        if bench == "cticonnect":
            for task in task_list:
                if task not in OVERLAP_TASKS:
                    print(f"Skipping CTIConnect task {task!r} (supported: {OVERLAP_TASKS})")
                    continue
                qas = load_tasks([task], data_dir=CTICONNECT_DATA, limit=limit)
                out_path = args.out_dir / f"counterfactual_cticonnect_{task}_{stamp}.jsonl"

                def _worker(qa: QARecord) -> Dict[str, Any]:
                    return run_cticonnect_item(
                        qa,
                        model=model,
                        k=args.k,
                        variant=args.variant,
                        rcm_retrieval=rcm_retrieval,
                    )

                records = _run_pool(
                    qas,
                    _worker,
                    workers=args.workers,
                    out_path=out_path,
                    resume=not args.no_resume,
                    id_key=lambda qa: qa.id,
                )
                scored = [r for r in records if not r.get("error")]
                key = f"cticonnect/{task}"
                all_summaries["tasks"][key] = summarize_records(
                    scored, metric=_metric_label("cticonnect", task)
                )
                all_summaries["tasks"][key]["pred_path"] = str(out_path)
                _print_task_summary(key, all_summaries["tasks"][key])

        if bench == "ctibench":
            for task in task_list:
                if task not in TASK_CONFIG:
                    print(f"Skipping CTIBench task {task!r}")
                    continue
                cfg = TASK_CONFIG[task]
                if not cfg["data"].exists():
                    print(f"Missing dataset: {cfg['data']}")
                    continue
                rows = load_rows(cfg["data"], limit if id_allow is None else None)
                indexed = list(enumerate(rows))
                if id_allow is not None:
                    indexed = [(i, r) for i, r in indexed if f"{task}-{i}" in id_allow]
                    print(f"{task}: {len(indexed)}/{len(rows)} rows after ID filter")
                out_path = args.out_dir / f"counterfactual_ctibench_{task}_{stamp}.jsonl"

                def _worker(pair: tuple[int, Dict[str, str]]) -> Dict[str, Any]:
                    idx, row = pair
                    return run_ctibench_item(
                        task, row, idx, model=model, k=args.k, variant=args.variant
                    )

                records = _run_pool(
                    indexed,
                    _worker,
                    workers=args.workers,
                    out_path=out_path,
                    resume=not args.no_resume,
                    id_key=lambda pair: f"{task}-{pair[0]}",
                )
                scored = [r for r in records if not r.get("error")]
                key = f"ctibench/{task}"
                all_summaries["tasks"][key] = summarize_records(
                    scored, metric=_metric_label("ctibench", task)
                )
                all_summaries["tasks"][key]["pred_path"] = str(out_path)
                _print_task_summary(key, all_summaries["tasks"][key])

    summary_path = args.out_dir / f"counterfactual_summary_{stamp}.json"
    summary_path.write_text(json.dumps(all_summaries, indent=2), encoding="utf-8")
    print(f"\nWrote summary -> {summary_path}")
    _print_overall_table(all_summaries)


def _print_task_summary(key: str, s: Dict[str, Any]) -> None:
    n = int(s.get("n") or 0)
    if n <= 0 or "closed_book_score" not in s:
        print(f"\n=== {key} (n={n}) ===\n  (no successful rows to score)")
        return
    print(
        f"\n=== {key} (n={n}) ===\n"
        f"  CB score: {s['closed_book_score']:.1%} | Forced RAG: {s['forced_rag_score']:.1%} | "
        f"Δ {s['score_delta']:+.1%}\n"
        f"  Rescues: {s['rescues']} | Damages: {s['damages']} | "
        f"Net utility: {s['net_retrieval_utility']:+.1%}\n"
        f"  False rejections: {s['false_rejections']} | Harmful admissions: {s['harmful_admissions']}\n"
        f"  Gate admit rate: {s['gate_admit_rate']:.1%} | "
        f"Gate accuracy (differing): {s['gate_decision_accuracy']}\n"
        f"  Recall@5: {s.get('recall@5', 0):.1%} | "
        f"P(RAG correct|gold@5): {s.get('p_rag_correct_given_gold_at_5')}"
    )


def _print_overall_table(summary: Dict[str, Any]) -> None:
    print("\n| Dataset/task | CB | Forced RAG | Rescues | Damages | Net utility | Gate acc |")
    print("| --- | ---: | ---: | ---: | ---: | ---: | ---: |")
    for key, s in sorted(summary.get("tasks", {}).items()):
        if int(s.get("n") or 0) <= 0 or "closed_book_score" not in s:
            print(f"| {key} | — | — | — | — | — | — |")
            continue
        gp = s.get("gate_policies") or {}
        ga = gp.get("gate_accuracy_differing")
        ga_s = f"{ga:.1%}" if ga is not None else "—"
        print(
            f"| {key} | {s['closed_book_score']:.1%} | {s['forced_rag_score']:.1%} | "
            f"{s['rescues']} | {s['damages']} | {s['net_retrieval_utility']:+.1%} | {ga_s} |"
        )


if __name__ == "__main__":
    main()
