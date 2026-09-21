import csv
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
BASE = ROOT / "eval_results/controlled_benchmark/full/taa_external_protocol/offline_diagnostics"
CTA = json.loads(
    (ROOT / "eval_results/controlled_benchmark/full/taa_external_protocol/ctibench_frozen_retrieval/ft_idf_rrf_summary.json").read_text()
)["rows"]
SHARED = json.loads((BASE / "passage_bm25_summary.json").read_text())["rows"]
PROFILES = json.loads(
    (ROOT / "eval_results/controlled_benchmark/taa20_20260918/actor_retrieval_study_v2/actor_profiles.json").read_text()
)
MODEL_NAME = os.environ.get("QWEN_RERANKER_MODEL", "Qwen/Qwen3-Reranker-0.6B")
OUT = ROOT / os.environ.get(
    "QWEN_RERANKER_OUTPUT",
    "eval_results/controlled_benchmark/full/taa_qwen3_union_audit",
)
BATCH_SIZE = int(os.environ.get("QWEN_RERANKER_BATCH_SIZE", "32"))
CTA_TOP_K = int(os.environ.get("QWEN_CTA_TOP_K", "20"))
BM25_TOP_K = int(os.environ.get("QWEN_BM25_TOP_K", "20"))
OUT.mkdir(parents=True, exist_ok=True)
REPORTS = {
    f"taa-{i}": row["Text"]
    for i, row in enumerate(
        csv.DictReader((ROOT / "data/cti-taa.tsv").open(encoding="utf-8"), delimiter="\t")
    )
}


def main():
    from sentence_transformers import CrossEncoder

    from eval.taa_protocol import benchmark_alias_match

    by_name = {profile["canonical_actor"]: profile for profile in PROFILES}
    model = CrossEncoder(
        MODEL_NAME,
        max_length=2048,
        device="cuda",
    )
    checkpoint = OUT / "checkpoint.json"
    rows = json.loads(checkpoint.read_text()) if checkpoint.exists() else []

    # A checkpoint made before detailed rankings were introduced is deliberately
    # recomputed. Interrupted detailed runs can still resume item by item.
    complete_ids = {
        row["id"]
        for row in rows
        if "candidate_pool" in row and "ranking" in row
    }

    for cta_row, bm25_row in zip(CTA, SHARED):
        item_id = cta_row["id"]
        if item_id in complete_ids:
            continue

        cta_candidates = cta_row["ranking"][:CTA_TOP_K]
        bm25_candidates = bm25_row["bm25"][:BM25_TOP_K]
        pool = list(dict.fromkeys(cta_candidates + bm25_candidates))
        passages = []
        for name in pool:
            profile = by_name.get(name, {})
            passages.append(
                "Actor: "
                + name
                + "\n"
                + profile.get("profile_text", "")
                + "\n"
                + "\n".join(
                    f"{field}: " + ", ".join(map(str, profile.get(field, [])))
                    for field in (
                        "aliases",
                        "malware",
                        "tools",
                        "techniques",
                        "campaigns",
                        "target_regions",
                        "target_sectors",
                        "infrastructure",
                    )
                )
            )

        scores = model.predict(
            [(REPORTS[item_id], passage) for passage in passages],
            show_progress_bar=False,
            batch_size=BATCH_SIZE,
        )
        ranked = sorted(
            ((float(score), name) for score, name in zip(scores, pool)),
            key=lambda pair: pair[0],
            reverse=True,
        )
        ranking = [
            {"actor": name, "score": score}
            for score, name in ranked
        ]
        rank = next(
            (
                position
                for position, entry in enumerate(ranking, 1)
                if benchmark_alias_match(entry["actor"], cta_row["gold"])
            ),
            None,
        )
        row = {
            "id": item_id,
            "gold": cta_row["gold"],
            "cta_candidates": cta_candidates,
            "bm25_candidates": bm25_candidates,
            "rank": rank,
            "candidate_pool": pool,
            "ranking": ranking,
        }
        rows = [existing for existing in rows if existing["id"] != item_id]
        rows.append(row)
        checkpoint.write_text(json.dumps(rows, indent=2))

    rows.sort(key=lambda row: int(row["id"].removeprefix("taa-")))
    checkpoint.write_text(json.dumps(rows, indent=2))
    ranks = [row["rank"] for row in rows]
    metrics = {
        f"Recall@{k}": sum(bool(rank and rank <= k) for rank in ranks) / len(ranks)
        for k in (1, 3, 5, 10, 20)
    }
    metrics["MRR@10"] = sum(1 / rank if rank and rank <= 10 else 0 for rank in ranks) / len(ranks)
    candidate_pool_coverage = sum(
        any(benchmark_alias_match(actor, row["gold"]) for actor in row["candidate_pool"])
        for row in rows
    ) / len(rows)
    summary = {
        "model": MODEL_NAME,
        "candidate_generation": {
            "cta_top_k_requested": CTA_TOP_K,
            "bm25_top_k": BM25_TOP_K,
            "candidate_pool_coverage": candidate_pool_coverage,
            "mean_candidate_pool_size": sum(len(row["candidate_pool"]) for row in rows) / len(rows),
        },
        "metrics": metrics,
        "n": len(rows),
        "complete": len(rows) == 50,
        "per_case_results": "checkpoint.json contains every candidate and reranker score.",
    }
    (OUT / "summary.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps(metrics, indent=2))


if __name__ == "__main__":
    main()
