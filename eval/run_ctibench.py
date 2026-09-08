"""
CTIBench evaluation with ORACLE or ROUTER pipeline selection.

Oracle:  gold task → correct specialized pipeline → score
Router:  classify_query(task, context) → predicted pipeline → same score

Only difference is who selects the pipeline. Parsers/scorers stay task-gold based.

Examples:
  python -m eval.run_ctibench --task mcq --limit 50 --route_mode oracle
  python -m eval.run_ctibench --task mcq --limit 50 --route_mode router
  python -m eval.run_ctibench --task all --limit 50 --route_mode router
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
import time
import traceback
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from dotenv import load_dotenv
from tqdm import tqdm

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
load_dotenv(ROOT / ".env")

from eval.scoring import (  # noqa: E402
    accuracy,
    instance_macro_f1,
    mad_cvss,
    mad_cvss_base_score,
    parse_ate_ids,
    parse_cwe_answer,
    parse_cvss_vector,
    parse_gold_ate,
    parse_mcq_answer,
)

TASK_CONFIG: Dict[str, Dict[str, Any]] = {
    "mcq": {
        "paper_name": "CTI-MCQ",
        "pipeline": "memorization",
        "data": ROOT / "data" / "cti-mcq.tsv",
        "metric": "Acc",
        "context_field": "Prompt",
        "task_instruction": (
            "You are given a multiple-choice question (MCQ) from a Cyber Threat "
            "Intelligence (CTI) knowledge benchmark dataset. Choose the best option "
            "among A, B, C, or D."
        ),
    },
    "rcm": {
        "paper_name": "CTI-RCM",
        "pipeline": "understanding",
        "data": ROOT / "data" / "cti-rcm.tsv",
        "metric": "Acc",
        "context_field": "Description",
        "task_instruction": (
            "Analyze the CVE description and map it to the appropriate CWE. "
            "Provide the CWE ID."
        ),
    },
    "rcm2021": {
        "paper_name": "CTI-RCM-2021",
        "pipeline": "understanding",
        "data": ROOT / "data" / "cti-rcm-2021.tsv",
        "metric": "Acc",
        "context_field": "Description",
        "task_instruction": (
            "Analyze the CVE description and map it to the appropriate CWE. "
            "Provide the CWE ID."
        ),
    },
    "vsp": {
        "paper_name": "CTI-VSP",
        "pipeline": "problem_solving",
        "data": ROOT / "data" / "cti-vsp.tsv",
        "metric": "MAD",
        "context_field": "Description",
        "task_instruction": (
            "Analyze the CVE description and calculate the CVSS v3.1 Base Score. "
            "Return the CVSS v3.1 vector string."
        ),
    },
    "ate": {
        "paper_name": "CTI-ATE",
        "pipeline": "reasoning_ate",
        "data": ROOT / "data" / "cti-ate.tsv",
        "metric": "Macro-F1",
        "context_field": "Description",
        "task_instruction": (
            "Extract all MITRE ATT&CK technique IDs from the threat description. "
            "Return main technique IDs only (no subtechniques)."
        ),
    },
}

PIPELINE_LABELS = [
    "memorization",
    "understanding",
    "problem_solving",
    "reasoning_ate",
    "reasoning_taa",
]


def load_rows(path: Path, limit: Optional[int]) -> List[Dict[str, str]]:
    with open(path, encoding="utf-8", errors="replace", newline="") as f:
        rows = list(csv.DictReader(f, delimiter="\t"))
    if limit is not None:
        rows = rows[:limit]
    return rows


_RUNNER_CACHE: Dict[str, Callable[[str], Any]] = {}


def get_pipeline_runner(pipeline_name: str) -> Callable[[str], Any]:
    if pipeline_name in _RUNNER_CACHE:
        return _RUNNER_CACHE[pipeline_name]
    if pipeline_name == "memorization":
        from pipelines import memorization_pipeline as mod
    elif pipeline_name == "understanding":
        from pipelines import understanding_pipeline as mod
    elif pipeline_name == "problem_solving":
        from pipelines import problem_solving_pipeline as mod
    elif pipeline_name == "reasoning_ate":
        from pipelines import reasoning_ate_pipeline as mod
    elif pipeline_name == "reasoning_taa":
        from pipelines import reasoning_taa_pipeline as mod
    else:
        raise ValueError(f"Unknown pipeline: {pipeline_name}")
    _RUNNER_CACHE[pipeline_name] = mod.run
    return mod.run


def parse_for_task(task_key: str, raw: str) -> Any:
    """Always parse with the GOLD task schema (E2E score for that CTIBench split)."""
    if task_key == "mcq":
        return parse_mcq_answer(raw)
    if task_key in ("rcm", "rcm2021"):
        return parse_cwe_answer(raw)
    if task_key == "vsp":
        return parse_cvss_vector(raw) or (raw.strip() or None)
    if task_key == "ate":
        return parse_ate_ids(raw)
    return raw


def routing_metrics(y_true: List[str], y_pred: List[str]) -> Dict[str, Any]:
    """Overall Acc + per-class precision / recall / F1 for predicted pipelines."""
    labels = sorted(set(y_true) | set(y_pred))
    n = len(y_true) or 1
    acc = sum(t == p for t, p in zip(y_true, y_pred)) / n

    per_class = {}
    for lab in labels:
        tp = sum(t == lab and p == lab for t, p in zip(y_true, y_pred))
        fp = sum(t != lab and p == lab for t, p in zip(y_true, y_pred))
        fn = sum(t == lab and p != lab for t, p in zip(y_true, y_pred))
        prec = tp / (tp + fp) if (tp + fp) else 0.0
        rec = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
        per_class[lab] = {
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1": round(f1, 4),
            "support": sum(t == lab for t in y_true),
        }

    macro_f1 = (
        sum(v["f1"] for v in per_class.values()) / len(per_class) if per_class else 0.0
    )
    return {
        "routing_accuracy": round(acc, 4),
        "routing_macro_f1": round(macro_f1, 4),
        "per_class": per_class,
        "confusion": _confusion(y_true, y_pred),
    }


def _confusion(y_true: List[str], y_pred: List[str]) -> Dict[str, Dict[str, int]]:
    labels = sorted(set(y_true) | set(y_pred))
    mat = {t: {p: 0 for p in labels} for t in labels}
    for t, p in zip(y_true, y_pred):
        mat[t][p] += 1
    return mat


def score_task(
    task_key: str,
    records: List[Dict[str, Any]],
    route_mode: str,
) -> Dict[str, Any]:
    cfg = TASK_CONFIG[task_key]
    metric = cfg["metric"]
    golds = [r["gold"] for r in records]
    preds = [r["parsed"] for r in records]

    if metric == "Acc":
        value = accuracy(preds, golds)
    elif metric == "MAD":
        value = mad_cvss(preds, golds)
    elif metric == "Macro-F1":
        pred_sets = [p if isinstance(p, set) else set() for p in preds]
        gold_sets = [parse_gold_ate(g) for g in golds]
        value = instance_macro_f1(pred_sets, gold_sets)
    else:
        raise ValueError(metric)

    summary: Dict[str, Any] = {
        "task": cfg["paper_name"],
        "gold_pipeline": cfg["pipeline"],
        "metric": metric,
        "score": round(value, 4),
        "n": len(records),
        "n_errors": sum(1 for r in records if r.get("error")),
        "route_mode": route_mode,
        "classifier_model": "gpt-4o-mini" if route_mode == "router" else None,
    }

    if metric == "MAD":
        # CTIBench reports MAD over CVSS base scores (0--10); our primary metric is
        # the fraction of the 8 base metrics that disagree (0--1). Both are recorded
        # so internal ablations and CTIBench comparisons each use the right scale.
        summary["score_base_score_mad"] = round(mad_cvss_base_score(preds, golds), 4)

    if route_mode == "router":
        y_true = [r["gold_pipeline"] for r in records]
        y_pred = [r["predicted_pipeline"] for r in records]
        summary.update(routing_metrics(y_true, y_pred))
        summary["n_route_correct"] = sum(r.get("route_correct") for r in records)
        summary["n_fallback_understanding"] = sum(
            1 for r in records if r.get("classifier_fallback")
        )

    return summary


def select_pipeline(
    route_mode: str,
    gold_pipeline: str,
    task_instruction: str,
    context: str,
) -> Tuple[str, Optional[str], bool]:
    """
    Returns (pipeline_name, raw_classifier_label_or_None, used_fallback_flag).
    """
    if route_mode == "oracle":
        return gold_pipeline, None, False

    from classifier.llm_classifier import classify_query

    raw = classify_query(task_instruction, context)
    # classify_query already falls back to "understanding" on invalid labels
    fallback = raw == "understanding" and raw not in PIPELINE_LABELS
    # We cannot see pre-fallback label from classify_query; track only if returned
    # label is understanding when gold is not (weak signal). Keep simple:
    used_fallback = False
    if raw not in PIPELINE_LABELS:
        raw = "understanding"
        used_fallback = True
    return raw, raw, used_fallback


def run_task(
    task_key: str,
    limit: Optional[int],
    out_dir: Path,
    route_mode: str,
    workers: int = 1,
) -> Dict[str, Any]:
    cfg = TASK_CONFIG[task_key]
    path = cfg["data"]
    if not path.exists():
        raise FileNotFoundError(
            f"Dataset not found: {path}\n"
            f"Download CTIBench TSVs from:\n"
            f"  https://github.com/xashru/cti-bench/tree/main/data"
        )

    rows = load_rows(path, limit)
    gold_pipeline = cfg["pipeline"]
    print(
        f"\n=== {cfg['paper_name']} | {route_mode} "
        f"(gold pipeline={gold_pipeline}) | n={len(rows)} ==="
    )
    print(f"data: {path}")

    if not os.getenv("OPENAI_API_KEY"):
        raise RuntimeError("OPENAI_API_KEY missing. Set it in .env")

    # Import the gold pipeline before starting workers: letting several threads race
    # to import the same module would multiply the (already slow) index load.
    get_pipeline_runner(gold_pipeline)

    def process(item: Tuple[int, Dict[str, str]]) -> Dict[str, Any]:
        i, row = item
        gold = (row.get("GT") or "").strip()
        context = (row.get(cfg["context_field"]) or "").strip()
        if not context:
            context = (row.get("Prompt") or row.get("Text") or "").strip()

        # Prefer dataset Prompt as classifier "task" cue when present (has CTIBench wording)
        task_for_clf = (row.get("Prompt") or "").strip() or cfg["task_instruction"]
        # Avoid duplicating huge Prompt as both task+context for MCQ
        if cfg["context_field"] == "Prompt":
            task_for_clf = cfg["task_instruction"]
        context_for_clf = context

        rec: Dict[str, Any] = {
            "idx": i,
            "url": row.get("URL", ""),
            "gold": gold,
            "gold_pipeline": gold_pipeline,
            "predicted_pipeline": None,
            "route_correct": None,
            "classifier_fallback": False,
            "raw": None,
            "parsed": None,
            "error": None,
            "latency_s": None,
            "route_mode": route_mode,
        }

        t0 = time.time()
        try:
            pipeline_name, _, used_fb = select_pipeline(
                route_mode, gold_pipeline, task_for_clf, context_for_clf
            )
            rec["predicted_pipeline"] = pipeline_name
            rec["route_correct"] = pipeline_name == gold_pipeline
            rec["classifier_fallback"] = used_fb

            runner = get_pipeline_runner(pipeline_name)
            raw = runner(context)
            if raw is None:
                raw = ""
            elif not isinstance(raw, str):
                raw = str(raw)
            rec["raw"] = raw
            rec["parsed"] = parse_for_task(task_key, raw)
            rec["latency_s"] = round(time.time() - t0, 3)
        except Exception as e:  # noqa: BLE001
            rec["error"] = f"{type(e).__name__}: {e}"
            rec["latency_s"] = round(time.time() - t0, 3)
            tqdm.write(f"[{task_key} #{i}] ERROR: {rec['error']}")
            tqdm.write(traceback.format_exc(limit=2))
        return rec

    # pool.map preserves input order, so records stay aligned with dataset rows.
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        records: List[Dict[str, Any]] = list(
            tqdm(
                pool.map(process, enumerate(rows)),
                total=len(rows),
                desc=f"{task_key}:{route_mode}",
            )
        )

    summary = score_task(task_key, records, route_mode)
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    pred_path = out_dir / f"{task_key}_{route_mode}_{stamp}.jsonl"
    with open(pred_path, "w", encoding="utf-8") as f:
        for rec in records:
            dump = dict(rec)
            if isinstance(dump.get("parsed"), set):
                dump["parsed"] = sorted(dump["parsed"])
            f.write(json.dumps(dump, ensure_ascii=False) + "\n")

    summary_path = out_dir / f"{task_key}_{route_mode}_{stamp}_summary.json"
    summary["predictions_file"] = str(pred_path)
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    print(
        f"{summary['task']} | {route_mode} | {summary['metric']} = {summary['score']} "
        f"(n={summary['n']}, errors={summary['n_errors']})"
    )
    if route_mode == "router":
        print(
            f"  routing Acc = {summary.get('routing_accuracy')} | "
            f"route correct {summary.get('n_route_correct')}/{summary['n']}"
        )
    print(f"wrote {pred_path}")
    print(f"wrote {summary_path}")
    return summary


def print_comparison(summaries: List[Dict[str, Any]], route_mode: str) -> None:
    print(f"\n========== {route_mode.upper()} SUMMARY ==========")
    hdr = f"{'Task':<14} {'Metric':<10} {'Score':>8} {'N':>6}"
    if route_mode == "router":
        hdr += f" {'RouteAcc':>9}"
    print(hdr)
    for s in summaries:
        line = f"{s['task']:<14} {s['metric']:<10} {s['score']:>8.4f} {s['n']:>6}"
        if route_mode == "router":
            line += f" {s.get('routing_accuracy', 0):>9.4f}"
        print(line)

    # Side-by-side vs known oracle medium runs if present (hardcoded latest known)
    ORACLE_REF = {
        "CTI-MCQ": ("Acc", 0.78, 50),
        "CTI-RCM": ("Acc", 0.66, 50),
        "CTI-VSP": ("MAD", 0.02, 50),
        "CTI-ATE": ("Macro-F1", 0.952, 60),
    }
    if route_mode == "router":
        print("\n========== ORACLE vs ROUTER (same metric; Loss = Oracle − Router for Acc/F1) ==========")
        print(
            f"{'Task':<14} {'Metric':<10} {'Oracle':>8} {'Router':>8} {'Loss':>8} {'RouteAcc':>9}"
        )
        for s in summaries:
            name = s["task"]
            if name not in ORACLE_REF:
                continue
            metric, o_score, o_n = ORACLE_REF[name]
            r_score = s["score"]
            # MAD: lower better → loss as Router − Oracle (positive = router worse)
            if metric == "MAD":
                loss = round(r_score - o_score, 4)
            else:
                loss = round(o_score - r_score, 4)
            print(
                f"{name:<14} {metric:<10} {o_score:>8.4f} {r_score:>8.4f} "
                f"{loss:>8.4f} {s.get('routing_accuracy', 0):>9.4f}"
            )
        print(
            "NOTE: Oracle column uses your last medium/full oracle runs "
            "(MCQ/RCM/VSP n=50, ATE n=60). Re-run matching --limit for a perfect pair."
        )

    print("NOTE: CTI-TAA skipped — no GT column.")
    print(
        "NOTE: Router uses classifier/llm_classifier.py (gpt-4o-mini). "
        "Generation pipelines unchanged (gpt-4-turbo)."
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="CTIBench oracle vs router end-to-end evaluation"
    )
    parser.add_argument(
        "--task",
        default="mcq",
        choices=list(TASK_CONFIG.keys()) + ["all"],
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=3,
        help="Max examples (default 3). Use 0 for full split.",
    )
    parser.add_argument(
        "--route_mode",
        default="oracle",
        choices=["oracle", "router"],
        help="oracle = gold pipeline; router = classify_query → pipeline",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=1,
        help="Concurrent examples (default 1). Generation dominates runtime, so 4-6 "
        "cuts full-split wall time roughly proportionally.",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=ROOT / "eval_results",
    )
    args = parser.parse_args()
    limit = None if args.limit == 0 else args.limit

    # Skip rcm2021 in --task all to match main paper table (use rcm)
    if args.task == "all":
        tasks = ["mcq", "rcm", "vsp", "ate"]
    else:
        tasks = [args.task]

    summaries = []
    for t in tasks:
        summaries.append(
            run_task(t, limit, args.out_dir, args.route_mode, args.workers)
        )

    print_comparison(summaries, args.route_mode)


if __name__ == "__main__":
    main()
