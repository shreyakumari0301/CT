"""Isolate multi-source candidate recall with the established Qwen evidence view.

This experiment deliberately keeps the query selector and full actor-profile
documents from the current top-3 Qwen baseline.  Only its candidate pool is
replaced with the gold-blind multi-source ATT&CK union.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from eval.controlled_benchmark.audit_taa_multisource_qwen_jina import candidate_rows
from eval.controlled_benchmark.audit_taa_qwen4b_evidence_query import (
    PROFILES,
    REPORTS,
    evidence_query,
    full_profile_passage,
)

OUT = ROOT / os.environ.get(
    "MS_EVIDENCE_PROFILES_OUTPUT",
    "eval_results/controlled_benchmark/full/taa_multisource_evidence_profiles_qwen4b_audit",
)
MODEL_NAME = os.environ.get("MS_EVIDENCE_PROFILES_MODEL", "Qwen/Qwen3-Reranker-4B")
BATCH_SIZE = int(os.environ.get("MS_EVIDENCE_PROFILES_BATCH_SIZE", "8"))
OUT.mkdir(parents=True, exist_ok=True)


def metrics(rows: list[dict]) -> dict[str, float]:
    ranks = [row["rank"] for row in rows]
    result = {
        f"Recall@{cutoff}": sum(bool(rank and rank <= cutoff) for rank in ranks) / len(ranks)
        for cutoff in (1, 3, 5, 10, 20)
    }
    result["MRR@10"] = sum(1 / rank if rank and rank <= 10 else 0 for rank in ranks) / len(ranks)
    return result


def main() -> None:
    from eval.taa_protocol import benchmark_alias_match
    from sentence_transformers import CrossEncoder
    from utils.multisource_attack_ingestion import build_attack_multisource_corpus

    by_name = {profile["canonical_actor"]: profile for profile in PROFILES}
    passages, manifest = build_attack_multisource_corpus(
        ROOT / "data/ctibench_taa/enterprise-attack.json"
    )
    candidates = candidate_rows(passages)
    missing = sorted({actor for row in candidates for actor in row["candidate_pool"] if actor not in by_name})
    if missing:
        raise ValueError(f"Candidates missing established actor profiles: {missing}")

    model = CrossEncoder(MODEL_NAME, max_length=2048, device="cuda")
    checkpoint = OUT / "checkpoint.json"
    completed = json.loads(checkpoint.read_text()) if checkpoint.exists() else []
    rows_by_id = {row["id"]: row for row in completed if "ranking" in row}

    for candidate in candidates:
        item_id = candidate["id"]
        if item_id in rows_by_id:
            continue
        query, selected = evidence_query(REPORTS[item_id], model.tokenizer)
        pool = candidate["candidate_pool"]
        scores = model.predict(
            [(query, full_profile_passage(by_name[actor])) for actor in pool],
            show_progress_bar=False,
            batch_size=BATCH_SIZE,
        )
        ranking = [
            {"actor": actor, "score": float(score)}
            for score, actor in sorted(zip(scores, pool), key=lambda item: float(item[0]), reverse=True)
        ]
        rank = next(
            (position for position, entry in enumerate(ranking, 1) if benchmark_alias_match(entry["actor"], candidate["gold"])),
            None,
        )
        rows_by_id[item_id] = {
            "id": item_id,
            "gold": candidate["gold"],
            "candidate_pool": pool,
            "cta_candidates": candidate["cta_candidates"],
            "shared_bm25_candidates": candidate["shared_bm25_candidates"],
            "multisource_dense_top": candidate["multisource_dense_top"],
            "multisource_bm25_top": candidate["multisource_bm25_top"],
            "evidence_query": query,
            "evidence_sentences": selected,
            "rank": rank,
            "ranking": ranking,
        }
        checkpoint.write_text(
            json.dumps(sorted(rows_by_id.values(), key=lambda row: int(row["id"].removeprefix("taa-"))), indent=2),
            encoding="utf-8",
        )

    rows = sorted(rows_by_id.values(), key=lambda row: int(row["id"].removeprefix("taa-")))
    candidate_coverage = sum(
        any(benchmark_alias_match(actor, row["gold"]) for actor in row["candidate_pool"])
        for row in rows
    ) / len(rows)
    summary = {
        "method": "multi-source ATT&CK union candidates -> established evidence-focused query and full actor-profile documents -> Qwen3 4B",
        "model": MODEL_NAME,
        "n": len(rows),
        "complete": len(rows) == 50,
        "candidate_generation": {
            "final_union_pool": {
                "Recall@pool": candidate_coverage,
                "mean_pool_size": sum(len(row["candidate_pool"]) for row in rows) / len(rows),
            },
            "ingestion": manifest,
        },
        "metrics": metrics(rows),
        "mean_selected_sentences": sum(len(row["evidence_sentences"]) for row in rows) / len(rows),
        "per_case_results": "checkpoint.json contains the exact candidate union, selected query evidence, and full Qwen ranking.",
    }
    (OUT / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
