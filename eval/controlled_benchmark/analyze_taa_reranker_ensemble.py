"""Evaluate leakage-aware ensembles of the saved reranker rankings.

All source models reranked the exact frozen CTA/shared-BM25 pool. The script
compares score-normalized and rank-normalized weighted ensembles, reports an
exploratory full-set sweep, and separately reports five-fold out-of-fold (OOF)
metrics where weights are selected only from the other four folds.
"""
from __future__ import annotations

import itertools
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
OUT = ROOT / "eval_results/controlled_benchmark/full/taa_reranker_ensemble_analysis"
OUT.mkdir(parents=True, exist_ok=True)
SOURCES = {
    "qwen3_0.6b": ROOT / "eval_results/controlled_benchmark/full/taa_qwen3_union_audit/checkpoint.json",
    "qwen3_4b": ROOT / "eval_results/controlled_benchmark/full/taa_qwen3_4b_union_audit/checkpoint.json",
    "qwen3_8b": ROOT / "eval_results/controlled_benchmark/full/taa_qwen3_8b_union_audit/checkpoint.json",
    "jina_v3.5": ROOT / "eval_results/controlled_benchmark/full/taa_jina_v35_union_audit/checkpoint.json",
}
MODEL_NAMES = tuple(SOURCES)
GRID_STEP = 0.1


def weights() -> list[tuple[float, ...]]:
    """All four-model convex weights at 0.1 resolution."""
    units = round(1 / GRID_STEP)
    return [
        tuple(part / units for part in parts)
        for parts in itertools.product(range(units + 1), repeat=4)
        if sum(parts) == units
    ]


def load_rows() -> dict[str, dict]:
    rows_by_model = {
        name: {row["id"]: row for row in json.loads(path.read_text())}
        for name, path in SOURCES.items()
    }
    ids = sorted(rows_by_model["qwen3_4b"], key=lambda value: int(value.removeprefix("taa-")))
    aligned: dict[str, dict] = {}
    for item_id in ids:
        reference = rows_by_model["qwen3_4b"][item_id]
        pool = set(reference["candidate_pool"])
        if any(set(rows_by_model[model][item_id]["candidate_pool"]) != pool for model in MODEL_NAMES):
            raise ValueError(f"Candidate pool differs at {item_id}; cannot form a fair ensemble")
        aligned[item_id] = {
            "gold": reference["gold"],
            "pool": sorted(pool),
            "rankings": {model: rows_by_model[model][item_id]["ranking"] for model in MODEL_NAMES},
        }
    return aligned


def normalized_values(ranking: list[dict], pool: list[str], mode: str) -> dict[str, float]:
    if mode == "rank":
        total = max(len(ranking) - 1, 1)
        return {entry["actor"]: 1 - position / total for position, entry in enumerate(ranking)}
    raw = {entry["actor"]: float(entry["score"]) for entry in ranking}
    low, high = min(raw.values()), max(raw.values())
    if high == low:
        return {actor: 0.0 for actor in pool}
    return {actor: (raw[actor] - low) / (high - low) for actor in pool}


def ensemble_ranking(row: dict, model_weights: tuple[float, ...], mode: str) -> list[str]:
    scores = {actor: 0.0 for actor in row["pool"]}
    for model, weight in zip(MODEL_NAMES, model_weights):
        values = normalized_values(row["rankings"][model], row["pool"], mode)
        for actor, value in values.items():
            scores[actor] += weight * value
    return [actor for actor, _ in sorted(scores.items(), key=lambda item: (-item[1], item[0]))]


def evaluate(rows: dict[str, dict], model_weights: tuple[float, ...], mode: str, ids: list[str]) -> tuple[dict, list[dict]]:
    from eval.taa_protocol import benchmark_alias_match

    records = []
    for item_id in ids:
        row = rows[item_id]
        ranking = ensemble_ranking(row, model_weights, mode)
        rank = next((position for position, actor in enumerate(ranking, 1) if benchmark_alias_match(actor, row["gold"])), None)
        records.append({"id": item_id, "gold": row["gold"], "rank": rank, "ranking": ranking})
    return evaluate_records(records), records


def evaluate_records(records: list[dict]) -> dict:
    metrics = {
        f"Recall@{cutoff}": sum(bool(record["rank"] and record["rank"] <= cutoff) for record in records) / len(records)
        for cutoff in (1, 3, 5, 10, 20)
    }
    metrics["MRR@10"] = sum(1 / record["rank"] if record["rank"] and record["rank"] <= 10 else 0 for record in records) / len(records)
    return metrics


def objective(metrics: dict) -> tuple[float, float, float]:
    """Top-3 is primary; MRR and top-1 break a tie deterministically."""
    return metrics["Recall@3"], metrics["MRR@10"], metrics["Recall@1"]


def choose(rows: dict[str, dict], candidates: list[tuple[float, ...]], mode: str, ids: list[str]) -> tuple[tuple[float, ...], dict]:
    best_weights, best_metrics = None, None
    for candidate in candidates:
        candidate_metrics, _ = evaluate(rows, candidate, mode, ids)
        if best_metrics is None or objective(candidate_metrics) > objective(best_metrics):
            best_weights, best_metrics = candidate, candidate_metrics
    return best_weights, best_metrics


def main() -> None:
    rows = load_rows()
    ids = list(rows)
    candidates = weights()
    report = {"models": MODEL_NAMES, "grid_step": GRID_STEP, "n": len(rows), "methods": {}}
    all_records: dict[str, list[dict]] = {}
    for mode in ("rank", "score"):
        best_weights, best_metrics = choose(rows, candidates, mode, ids)
        _, full_records = evaluate(rows, best_weights, mode, ids)
        folds = {fold: [item_id for item_id in ids if int(item_id.removeprefix("taa-")) % 5 == fold] for fold in range(5)}
        oof_records: list[dict] = []
        fold_selection = {}
        for fold, held_out in folds.items():
            training = [item_id for item_id in ids if item_id not in held_out]
            fold_weights, training_metrics = choose(rows, candidates, mode, training)
            _, held_records = evaluate(rows, fold_weights, mode, held_out)
            oof_records.extend(held_records)
            fold_selection[str(fold)] = {
                "weights": dict(zip(MODEL_NAMES, fold_weights)),
                "training_metrics": training_metrics,
            }
        report["methods"][mode] = {
            "exploratory_full_set": {
                "weights": dict(zip(MODEL_NAMES, best_weights)),
                "metrics": best_metrics,
            },
            "five_fold_oof": {
                "metrics": evaluate_records(oof_records),
                "fold_selection": fold_selection,
            },
        }
        all_records[f"{mode}_exploratory"] = full_records
        all_records[f"{mode}_five_fold_oof"] = sorted(oof_records, key=lambda record: int(record["id"].removeprefix("taa-")))
    (OUT / "summary.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    (OUT / "per_case_rankings.json").write_text(json.dumps(all_records, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
