"""Evaluate Jina Reranker v3.5 on the frozen CTA/BM25 union pool."""

import csv
import json
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
OUT = ROOT / "eval_results/controlled_benchmark/full/taa_jina_v35_union_audit"
OUT.mkdir(parents=True, exist_ok=True)
MODEL_NAME = "jinaai/jina-reranker-v3.5"
REPORTS = {
    f"taa-{i}": row["Text"]
    for i, row in enumerate(
        csv.DictReader((ROOT / "data/cti-taa.tsv").open(encoding="utf-8"), delimiter="\t")
    )
}


def passage_for(name: str, profiles: dict[str, dict]) -> str:
    profile = profiles.get(name, {})
    fields = (
        "aliases",
        "malware",
        "tools",
        "techniques",
        "campaigns",
        "target_regions",
        "target_sectors",
        "infrastructure",
    )
    return (
        "Actor: "
        + name
        + "\n"
        + profile.get("profile_text", "")
        + "\n"
        + "\n".join(
            f"{field}: " + ", ".join(map(str, profile.get(field, [])))
            for field in fields
        )
    )


def main() -> None:
    from transformers import AutoModel

    from eval.taa_protocol import benchmark_alias_match

    model = AutoModel.from_pretrained(
        MODEL_NAME,
        dtype="auto",
        trust_remote_code=True,
        device_map="auto",
    )
    model.eval()
    by_name = {profile["canonical_actor"]: profile for profile in PROFILES}
    checkpoint = OUT / "checkpoint.json"
    rows = json.loads(checkpoint.read_text()) if checkpoint.exists() else []
    complete_ids = {
        row["id"]
        for row in rows
        if "candidate_pool" in row and "ranking" in row
    }

    for cta_row, bm25_row in zip(CTA, SHARED):
        item_id = cta_row["id"]
        if item_id in complete_ids:
            continue

        pool = list(dict.fromkeys(cta_row["ranking"][:20] + bm25_row["bm25"][:20]))
        results = model.rerank(
            REPORTS[item_id],
            [passage_for(name, by_name) for name in pool],
        )
        ranking = [
            {
                "actor": pool[result["index"]],
                "score": float(result["relevance_score"]),
            }
            for result in results
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
        f"Recall@{cutoff}": sum(rank is not None and rank <= cutoff for rank in ranks) / len(ranks)
        for cutoff in (1, 3, 5, 10, 20)
    }
    metrics["MRR@10"] = sum(1 / rank if rank is not None and rank <= 10 else 0 for rank in ranks) / len(ranks)
    summary = {
        "model": MODEL_NAME,
        "metrics": metrics,
        "n": len(rows),
        "complete": len(rows) == 50,
        "per_case_results": "checkpoint.json contains every candidate and Jina relevance score.",
    }
    (OUT / "summary.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps(metrics, indent=2))


if __name__ == "__main__":
    main()
