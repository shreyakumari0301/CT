"""Offline paired CTA/Qwen rank analysis and reciprocal-rank-fusion sweep."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
CTA_PATH = (
    ROOT
    / "eval_results/controlled_benchmark/full/taa_external_protocol"
    / "ctibench_frozen_retrieval/ft_idf_rrf_summary.json"
)
QWEN_PATH = (
    ROOT
    / "eval_results/controlled_benchmark/full/taa_qwen3_union_audit/checkpoint.json"
)
OUT_PATH = (
    ROOT
    / "eval_results/controlled_benchmark/full/taa_qwen3_union_audit"
    / "paired_rank_analysis.json"
)
RRF_K = 60
ALPHAS = [round(step / 20, 2) for step in range(20)]  # 0.00 through 0.95


def gold_rank(ranking: list[str], gold: str) -> int | None:
    from eval.taa_protocol import benchmark_alias_match

    return next(
        (position for position, actor in enumerate(ranking, 1) if benchmark_alias_match(actor, gold)),
        None,
    )


def metrics(ranks: list[int | None]) -> dict[str, float]:
    return {
        **{
            f"Recall@{cutoff}": sum(rank is not None and rank <= cutoff for rank in ranks) / len(ranks)
            for cutoff in (1, 3, 5, 10, 20)
        },
        "MRR@10": sum(1 / rank if rank is not None and rank <= 10 else 0 for rank in ranks) / len(ranks),
    }


def fuse(
    cta_ranking: list[str], qwen_ranking: list[str], alpha: float
) -> tuple[list[str], dict[str, float]]:
    """Fuse CTA and Qwen ranks. ``alpha`` is CTA's RRF contribution."""
    cta_rank = {actor: position for position, actor in enumerate(cta_ranking, 1)}
    qwen_rank = {actor: position for position, actor in enumerate(qwen_ranking, 1)}
    scores = {
        actor: (
            (alpha / (RRF_K + cta_rank[actor]) if actor in cta_rank else 0.0)
            + (1 - alpha) / (RRF_K + qwen_rank[actor])
        )
        for actor in qwen_ranking
    }
    ranking = sorted(
        qwen_ranking,
        key=lambda actor: (-scores[actor], qwen_rank[actor], cta_rank.get(actor, float("inf")), actor),
    )
    return ranking, scores


def transition_ids(
    rows: list[dict], old_key: str, new_key: str, cutoff: int
) -> dict[str, list[str]]:
    moved_in, moved_out = [], []
    for row in rows:
        old_rank, new_rank = row[old_key], row[new_key]
        old_hit = old_rank is not None and old_rank <= cutoff
        new_hit = new_rank is not None and new_rank <= cutoff
        if not old_hit and new_hit:
            moved_in.append(row["id"])
        elif old_hit and not new_hit:
            moved_out.append(row["id"])
    return {"moved_in": moved_in, "moved_out": moved_out}


def main() -> None:
    cta_rows = {row["id"]: row for row in json.loads(CTA_PATH.read_text())["rows"]}
    qwen_rows = json.loads(QWEN_PATH.read_text())
    if len(qwen_rows) != 50 or any("ranking" not in row for row in qwen_rows):
        raise ValueError("Qwen checkpoint must contain complete rankings for all 50 cases")

    paired = []
    sweep_ranks: dict[float, list[int | None]] = {alpha: [] for alpha in ALPHAS}
    for qwen_row in qwen_rows:
        item_id, gold = qwen_row["id"], qwen_row["gold"]
        cta_ranking = cta_rows[item_id]["ranking"]
        qwen_ranking = [entry["actor"] for entry in qwen_row["ranking"]]
        row = {
            "id": item_id,
            "gold": gold,
            "cta_rank": gold_rank(cta_ranking, gold),
            "qwen_rank": gold_rank(qwen_ranking, gold),
        }
        for alpha in ALPHAS:
            fused_ranking, _ = fuse(cta_ranking, qwen_ranking, alpha)
            fused_rank = gold_rank(fused_ranking, gold)
            row[f"rrf_{alpha:.2f}_rank"] = fused_rank
            sweep_ranks[alpha].append(fused_rank)
        paired.append(row)

    sweep = [
        {"cta_weight": alpha, "metrics": metrics(sweep_ranks[alpha])}
        for alpha in ALPHAS
    ]
    # Optimize top-3 first, then top-10, then MRR@10. This reflects the
    # benchmark's stated top-3 bottleneck instead of selecting on MRR alone.
    best = max(
        sweep,
        key=lambda result: (
            result["metrics"]["Recall@3"],
            result["metrics"]["Recall@10"],
            result["metrics"]["MRR@10"],
            -result["cta_weight"],
        ),
    )
    best_key = f"rrf_{best['cta_weight']:.2f}_rank"

    analysis = {
        "method": {
            "name": "reciprocal_rank_fusion",
            "formula": "cta_weight/(60 + CTA_rank) + (1-cta_weight)/(60 + Qwen_rank)",
            "rrf_k": RRF_K,
            "reason": "The frozen CTA artifact stores rankings but no calibrated retrieval scores.",
        },
        "baselines": {
            "cta": metrics([row["cta_rank"] for row in paired]),
            "qwen": metrics([row["qwen_rank"] for row in paired]),
        },
        "sweep": sweep,
        "recommended_fusion": {
            "selection_rule": "maximize Recall@3, then Recall@10, then MRR@10",
            "cta_weight": best["cta_weight"],
            "metrics": best["metrics"],
        },
        "paired_cases": paired,
        "transitions": {
            "qwen_vs_cta": {
                "top3": transition_ids(paired, "cta_rank", "qwen_rank", 3),
                "top10": transition_ids(paired, "cta_rank", "qwen_rank", 10),
                "still_qwen_ranks_4_to_10": [
                    row["id"]
                    for row in paired
                    if row["qwen_rank"] is not None and 4 <= row["qwen_rank"] <= 10
                ],
            },
            "recommended_fusion_vs_cta": {
                "top3": transition_ids(paired, "cta_rank", best_key, 3),
                "top10": transition_ids(paired, "cta_rank", best_key, 10),
            },
        },
    }
    OUT_PATH.write_text(json.dumps(analysis, indent=2))
    print(json.dumps(analysis["recommended_fusion"], indent=2))


if __name__ == "__main__":
    main()
