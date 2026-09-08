"""
Run confidence-gated CTA-RAG (TCAR no_confusion) on full CTIBench.

Tasks: MCQ, RCM, VSP, ATE (+ optional TAA via --with-taa).
Same data, FAISS indices, gpt-4-turbo, and eval/scoring.py as eval/run_ctibench.py.

Examples:
  python -m tcar.eval.run_ctibench --task all --variant no_confusion --limit 5
  python -m tcar.eval.run_ctibench --task all --with-taa --limit 0 --workers 3
"""

from __future__ import annotations

import argparse
import json
import os
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

from eval.run_ctibench import (  # noqa: E402
    TASK_CONFIG,
    load_rows,
    parse_for_task,
    score_task,
)
from tcar.config import TCARConfig  # noqa: E402
from tcar.ctibench_corpus import CTIBenchCorpusStore  # noqa: E402
from tcar.ctibench_gated import predict_gated  # noqa: E402
from tcar.ctibench_kb import CTIBenchKBRetriever  # noqa: E402
from tcar.pipeline import TCARPipeline  # noqa: E402
from utils.llm_client import get_openai_client, resolve_model, chat_completion_kwargs  # noqa: E402

OUT_DEFAULT = ROOT / "tcar" / "eval_results"

FULL_CTIBENCH_TASKS = ["mcq", "rcm", "vsp", "ate"]
# RCM uses TCAR contrast specialist; ATE/MCQ/VSP use per-task CTA-RAG pipeline forms.
TCAR_PIPELINE_TASKS = {"rcm", "rcm2021"}
GATED_TASKS = {"mcq", "vsp", "ate"}

_WRITE_LOCK = threading.Lock()
_RETRIEVER: Optional[CTIBenchKBRetriever] = None
_STORE: Optional[CTIBenchCorpusStore] = None
_PIPELINES: Dict[str, TCARPipeline] = {}


def _ctibench_chat(
    user: str,
    *,
    system: Optional[str] = None,
    temperature: float = 0.0,
    max_tokens: int = 800,
    model: str = "",
) -> str:
    client = get_openai_client()
    messages: List[Dict[str, str]] = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": user})
    gen = (model or os.getenv("GENERATION_MODEL") or "gpt-4-turbo").strip()
    resp = client.chat.completions.create(
        messages=messages,
        **chat_completion_kwargs(gen, max_tokens=max_tokens, temperature=temperature),
    )
    return (resp.choices[0].message.content or "").strip()


def _shared_retriever() -> CTIBenchKBRetriever:
    global _RETRIEVER
    if _RETRIEVER is None:
        _RETRIEVER = CTIBenchKBRetriever()
    return _RETRIEVER


def _shared_store() -> CTIBenchCorpusStore:
    global _STORE
    if _STORE is None:
        _STORE = CTIBenchCorpusStore()
    return _STORE


def get_pipeline(variant: str, k: int) -> TCARPipeline:
    if variant not in _PIPELINES:
        cfg = TCARConfig(k_retrieve=k, variant=variant)
        _PIPELINES[variant] = TCARPipeline(
            cfg,
            retriever=_shared_retriever(),
            store=_shared_store(),
            chat=_ctibench_chat,
        )
    return _PIPELINES[variant]


def _task_temperature(task_key: str) -> float:
    if task_key in ("rcm", "rcm2021", "vsp", "mcq"):
        return 0.1
    return 0.0


def run_one(
    task_key: str,
    row: Dict[str, str],
    idx: int,
    variant: str,
    k: int,
) -> Dict[str, Any]:
    cfg = TASK_CONFIG[task_key]
    gold = (row.get("GT") or "").strip()
    context = (row.get(cfg["context_field"]) or "").strip()
    if not context:
        context = (row.get("Prompt") or row.get("Text") or "").strip()

    rec: Dict[str, Any] = {
        "idx": idx,
        "url": row.get("URL", ""),
        "task": task_key,
        "gold": gold,
        "gold_pipeline": cfg["pipeline"],
        "variant": variant,
        "raw": None,
        "parsed": None,
        "tcar_meta": None,
        "error": None,
        "latency_s": None,
    }

    t0 = time.time()
    temp = _task_temperature(task_key)

    def chat_fn(user: str, *, max_tokens: int = 800, **_kw: Any) -> str:
        return _ctibench_chat(user, temperature=temp, max_tokens=max_tokens)

    try:
        tcar_cfg = TCARConfig(k_retrieve=k, variant=variant).apply_variant()
        if task_key in TCAR_PIPELINE_TASKS:
            pipe = get_pipeline(variant, k)
            result = pipe.predict("rcm", context, chat=chat_fn)
            rec["raw"] = result.prediction
            rec["tcar_meta"] = result.meta
        elif task_key in GATED_TASKS:
            raw, meta = predict_gated(
                task_key,
                context,
                retriever=_shared_retriever(),
                cfg=tcar_cfg,
                chat=chat_fn,
            )
            rec["raw"] = raw
            rec["tcar_meta"] = meta
        else:
            raise ValueError(f"unsupported task {task_key!r}")

        rec["parsed"] = parse_for_task(task_key, rec["raw"])
        rec["latency_s"] = round(time.time() - t0, 3)
    except Exception as exc:  # noqa: BLE001
        rec["error"] = f"{type(exc).__name__}: {exc}"
        rec["latency_s"] = round(time.time() - t0, 3)
        traceback.print_exc()
    return rec


def run_task(
    task_key: str,
    *,
    variant: str,
    limit: Optional[int],
    workers: int,
    out_dir: Path,
    stamp: str,
    k: int,
    resume: bool,
) -> Dict[str, Any]:
    cfg = TASK_CONFIG[task_key]
    path = cfg["data"]
    if not path.exists():
        raise FileNotFoundError(f"Dataset not found: {path}")

    rows = load_rows(path, limit)
    system = f"tcar_{variant}_ctibench" if variant != "full" else "tcar_ctibench"
    out_path = out_dir / f"{task_key}_{system}_{stamp}.jsonl"

    done: Dict[int, Dict[str, Any]] = {}
    if resume and out_path.exists():
        for line in out_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            row = json.loads(line)
            idx = row.get("idx")
            if idx is not None and (idx not in done or (done[idx].get("error") and not row.get("error"))):
                done[idx] = row

    remaining = [(i, r) for i, r in enumerate(rows) if i not in done or done[i].get("error")]
    records = [done[i] for i in range(len(rows)) if i in done and not done[i].get("error")]

    def _write(row: Dict[str, Any]) -> None:
        dump = dict(row)
        parsed = dump.get("parsed")
        if isinstance(parsed, set):
            dump["parsed"] = sorted(parsed)
        with _WRITE_LOCK:
            with open(out_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(dump, ensure_ascii=False) + "\n")

    if remaining:
        print(f"  {task_key}: running {len(remaining)}/{len(rows)}")
        _shared_retriever()
        get_pipeline(variant, k)
        with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
            fn = lambda item: run_one(task_key, item[1], item[0], variant, k)
            for row in tqdm(pool.map(fn, remaining), total=len(remaining), desc=f"{task_key}:{variant}"):
                _write(row)
                records.append(row)
    else:
        print(f"  {task_key}: all {len(rows)} cached")

    by_idx = {r["idx"]: r for r in records}
    ordered = [by_idx[i] for i in range(len(rows)) if i in by_idx]

    summary = score_task(task_key, ordered, route_mode="oracle")
    summary["system"] = system
    summary["variant"] = variant
    summary["generator"] = resolve_model("gpt-4-turbo")
    summary["retrieval_k"] = k
    summary["predictions_file"] = str(out_path)

    admitted = sum(
        1 for r in ordered if (r.get("tcar_meta") or {}).get("mode") == "contrast_retrieval"
    )
    summary["retrieval_admitted_rate"] = round(admitted / len(ordered), 4) if ordered else 0.0

    summary_path = out_dir / f"{task_key}_{system}_{stamp}_summary.json"
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    print(
        f"{summary['task']} | tcar/{variant} | {summary['metric']} = {summary['score']} "
        f"(n={summary['n']}, errors={summary['n_errors']}, "
        f"retrieval_admitted={summary['retrieval_admitted_rate']})"
    )
    print(f"wrote {out_path}")
    print(f"wrote {summary_path}")
    return summary


def run_taa_gated(
    *,
    limit: Optional[int],
    workers: int,
    out_dir: Path,
    stamp: str,
) -> Dict[str, Any]:
    from eval.run_taa import (  # noqa: WPS433
        _run_mode,
        load_alias_related,
        load_rows as load_taa_rows,
    )

    alias_dict, related_dict = load_alias_related()
    rows = load_taa_rows(limit)
    print(f"\n>>> CTIBench task=taa (gated CTA-RAG pipeline)")
    _results, pred_path, summary_path, summary = _run_mode(
        "gated",
        rows,
        alias_dict,
        related_dict,
        workers,
        out_dir,
        stamp,
    )
    summary["retrieval_admitted_rate"] = None
    summary["note"] = (
        "TAA uses reasoning_taa gated mode (high-confidence closed-book else candidate-first), "
        "not TCAR retrieval-margin gate."
    )
    return summary


def _resolve_tasks(task_arg: str) -> List[str]:
    if task_arg.strip().lower() == "all":
        return list(FULL_CTIBENCH_TASKS)
    tasks = [t.strip() for t in task_arg.split(",") if t.strip()]
    for t in tasks:
        if t not in TASK_CONFIG:
            raise SystemExit(f"Unknown task {t!r}; valid: {sorted(TASK_CONFIG)} + all")
    return tasks


def main() -> None:
    ap = argparse.ArgumentParser(description="Confidence-gated CTA-RAG on full CTIBench")
    ap.add_argument("--task", default="all", help="all | mcq,rcm,vsp,ate | single task")
    ap.add_argument("--with-taa", action="store_true", help="Also run TAA (gated mode, n=50)")
    ap.add_argument("--limit", type=int, default=0, help="0 = full split")
    ap.add_argument("--workers", type=int, default=2)
    ap.add_argument("--k", type=int, default=5)
    ap.add_argument("--variant", default="no_confusion")
    ap.add_argument("--out-dir", type=Path, default=OUT_DEFAULT)
    ap.add_argument("--stamp", default="")
    ap.add_argument("--no-resume", action="store_true")
    args = ap.parse_args()

    if not os.getenv("OPENAI_API_KEY"):
        raise SystemExit("OPENAI_API_KEY missing. Set it in .env")

    tasks = _resolve_tasks(args.task)
    limit = None if args.limit == 0 else args.limit
    args.out_dir.mkdir(parents=True, exist_ok=True)
    stamp = args.stamp or datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    print(
        f"TCAR CTIBench | variant={args.variant} | generator={resolve_model('gpt-4-turbo')} "
        f"| k={args.k} | tasks={tasks}{'+taa' if args.with_taa else ''}"
    )

    scoreboard: Dict[str, Any] = {
        "stamp": stamp,
        "method": "Confidence-gated CTA-RAG (TCAR no_confusion + TAA gated)",
        "variant": args.variant,
        "generator": resolve_model("gpt-4-turbo"),
        "retrieval_k": args.k,
        "tasks": {},
        "oracle_cta_rag_reference": {
            "mcq": {"metric": "Acc", "score": 0.781},
            "rcm": {"metric": "Acc", "score": 0.781},
            "vsp": {"metric": "MAD", "score": 1.06},
            "ate": {"metric": "Macro-F1", "score": 0.9451},
            "taa": {"metric": "Correct Acc", "score": 0.52, "plausible_acc": 0.86},
        },
    }

    for task_key in tasks:
        print(f"\n>>> CTIBench task={task_key}")
        summary = run_task(
            task_key,
            variant=args.variant,
            limit=limit,
            workers=args.workers,
            out_dir=args.out_dir,
            stamp=stamp,
            k=args.k,
            resume=not args.no_resume,
        )
        scoreboard["tasks"][task_key] = summary

    if args.with_taa:
        taa_summary = run_taa_gated(
            limit=limit,
            workers=args.workers,
            out_dir=args.out_dir,
            stamp=stamp,
        )
        scoreboard["tasks"]["taa"] = taa_summary

    board_path = args.out_dir / f"scoreboard_ctibench_{args.variant}_{stamp}.json"
    board_path.write_text(json.dumps(scoreboard, indent=2), encoding="utf-8")
    print(f"\nScoreboard: {board_path}")

    print("\n========== GATED vs ORIGINAL CTA-RAG (oracle reference) ==========")
    ref = scoreboard["oracle_cta_rag_reference"]
    for key, summary in scoreboard["tasks"].items():
        if key not in ref:
            continue
        metric = ref[key].get("metric", summary.get("metric"))
        orig = ref[key].get("score")
        now = summary.get("score") or summary.get("correct_acc")
        print(f"  {key:<6} {metric:<12} original={orig}  gated={now}")


if __name__ == "__main__":
    main()
