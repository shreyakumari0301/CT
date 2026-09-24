import csv
import json
import math
import os
import re
import sys
from collections import Counter
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
    "eval_results/controlled_benchmark/full/taa_qwen3_normalized_cta15_bm2525_union_audit",
)
BATCH_SIZE = int(os.environ.get("QWEN_RERANKER_BATCH_SIZE", "32"))
CTA_TOP_K = int(os.environ.get("QWEN_CTA_TOP_K", "15"))
BM25_TOP_K = int(os.environ.get("QWEN_BM25_TOP_K", "25"))
OUT.mkdir(parents=True, exist_ok=True)
REPORTS = {
    f"taa-{i}": row["Text"]
    for i, row in enumerate(
        csv.DictReader((ROOT / "data/cti-taa.tsv").open(encoding="utf-8"), delimiter="\t")
    )
}


def contains(text, phrase):
    return bool(phrase) and re.search(r"(?<!\w)" + re.escape(phrase) + r"(?!\w)", text or "", re.I)


def sentences(text):
    return [part.strip() for part in re.split(r"(?<=[.!?])\s+|\n+", text or "") if part.strip()]


def profile_facts(profile):
    fields = {
        "alias_campaign": ("aliases", "campaigns"),
        "infrastructure": ("infrastructure",),
        "malware_tool": ("malware", "tools"),
        "targeting": ("target_regions", "target_sectors"),
        "behavior": ("techniques",),
    }
    return {channel: [value for field in names for value in profile.get(field, []) if value] for channel, names in fields.items()}


def build_fact_document_frequency(profiles):
    frequencies = Counter()
    for profile in profiles:
        for values in profile_facts(profile).values():
            frequencies.update(set(value.casefold() for value in values))
    return frequencies


def report_evidence(report, profile, fact_frequency):
    """Return gold-blind, corpus-rarity-weighted evidence channels."""
    facts = profile_facts(profile)
    channels = {}
    for channel, values in facts.items():
        matches = [value for value in values if contains(report, value)]
        channels[channel] = {
            "score": sum(1 / fact_frequency[value.casefold()] for value in set(matches)),
            "matches": sorted(set(matches)),
        }
    actor_names = [profile["canonical_actor"], *profile.get("aliases", [])]
    attribution = [
        sentence for sentence in sentences(report)
        if re.search(r"\b(?:attributed to|tracked as|identified as|associated with)\b", sentence, re.I)
        and any(contains(sentence, name) for name in actor_names)
    ]
    channels["explicit_attribution"] = {"score": float(bool(attribution)), "matches": attribution[:2]}
    return channels


def min_max(values):
    low, high = min(values), max(values)
    if math.isclose(low, high):
        return [0.0] * len(values)
    return [(value - low) / (high - low) for value in values]


def normalized_actor_ranking(report, pool, cta_candidates, bm25_candidates, profiles):
    by_name = {profile["canonical_actor"]: profile for profile in profiles}
    fact_frequency = build_fact_document_frequency(profiles)
    cta_rank = {actor: rank for rank, actor in enumerate(cta_candidates, 1)}
    bm25_rank = {actor: rank for rank, actor in enumerate(bm25_candidates, 1)}
    channels = ("alias_campaign", "infrastructure", "malware_tool", "targeting", "behavior", "explicit_attribution", "retrieval")
    raw = {channel: [] for channel in channels}
    evidence = {}
    for position, actor in enumerate(pool):
        profile = by_name.get(actor, {})
        actor_evidence = report_evidence(report, profile, fact_frequency)
        evidence[actor] = actor_evidence
        for channel in channels[:-1]:
            raw[channel].append(actor_evidence[channel]["score"])
        retrieval_scores = []
        if actor in cta_rank:
            retrieval_scores.append((len(cta_candidates) - cta_rank[actor] + 1) / len(cta_candidates))
        if actor in bm25_rank:
            retrieval_scores.append((len(bm25_candidates) - bm25_rank[actor] + 1) / len(bm25_candidates))
        raw["retrieval"].append(max(retrieval_scores, default=0.0))
    normalized = {channel: min_max(values) for channel, values in raw.items()}
    ranking = []
    for position, actor in enumerate(pool):
        score = sum(normalized[channel][position] for channel in channels) / len(channels)
        ranking.append({
            "actor": actor,
            "score": score,
            "original_pool_position": position,
            "channel_scores": {channel: normalized[channel][position] for channel in channels},
            "evidence": evidence[actor],
        })
    ranking.sort(key=lambda entry: (-entry["score"], entry["original_pool_position"], entry["actor"]))
    return ranking


def ranking_metrics(rows, key):
    from eval.taa_protocol import benchmark_alias_match

    ranks = [
        next((position for position, entry in enumerate(row[key], 1) if benchmark_alias_match(entry["actor"], row["gold"])), None)
        for row in rows
    ]
    result = {f"Recall@{cutoff}": sum(bool(rank and rank <= cutoff) for rank in ranks) / len(ranks) for cutoff in (1, 3, 5, 10, 20)}
    result["MRR@10"] = sum(1 / rank if rank and rank <= 10 else 0 for rank in ranks) / len(ranks)
    return result


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
        if "candidate_pool" in row and "normalized_ranking" in row and "ranking" in row
    }

    for cta_row, bm25_row in zip(CTA, SHARED):
        item_id = cta_row["id"]
        if item_id in complete_ids:
            continue

        cta_candidates = cta_row["ranking"][:CTA_TOP_K]
        bm25_candidates = bm25_row["bm25"][:BM25_TOP_K]
        pool = list(dict.fromkeys(cta_candidates + bm25_candidates))
        normalized_ranking = normalized_actor_ranking(
            REPORTS[item_id], pool, cta_candidates, bm25_candidates, PROFILES
        )
        frozen_pool = [entry["actor"] for entry in normalized_ranking[:20]]
        passages = []
        for name in frozen_pool:
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
            ((float(score), name) for score, name in zip(scores, frozen_pool)),
            key=lambda pair: (-pair[0], pair[1]),
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
            "candidate_pool": pool,
            "normalized_ranking": normalized_ranking,
            "frozen_candidate_pool": frozen_pool,
            "rank": rank,
            "ranking": ranking,
        }
        rows = [existing for existing in rows if existing["id"] != item_id]
        rows.append(row)
        checkpoint.write_text(json.dumps(rows, indent=2))

    rows.sort(key=lambda row: int(row["id"].removeprefix("taa-")))
    checkpoint.write_text(json.dumps(rows, indent=2))
    candidate_pool_coverage = sum(
        any(benchmark_alias_match(actor, row["gold"]) for actor in row["candidate_pool"])
        for row in rows
    ) / len(rows)
    normalized_metrics = ranking_metrics(rows, "normalized_ranking")
    qwen_metrics = ranking_metrics(rows, "ranking")
    summary = {
        "model": MODEL_NAME,
        "candidate_generation": {
            "cta_top_k_requested": CTA_TOP_K,
            "bm25_top_k": BM25_TOP_K,
            "candidate_pool_coverage": candidate_pool_coverage,
            "mean_candidate_pool_size": sum(len(row["candidate_pool"]) for row in rows) / len(rows),
            "frozen_pool_size": 20,
            "frozen_pool_coverage": sum(
                any(benchmark_alias_match(actor, row["gold"]) for actor in row["frozen_candidate_pool"])
                for row in rows
            ) / len(rows),
        },
        "normalized_retrieval_metrics": normalized_metrics,
        "qwen_fixed_pool_metrics": qwen_metrics,
        "metrics": qwen_metrics,
        "n": len(rows),
        "complete": len(rows) == 50,
        "per_case_results": "checkpoint.json contains the full union, normalized channel scores, frozen top-20 pool, and Qwen scores.",
    }
    (OUT / "summary.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps(qwen_metrics, indent=2))


if __name__ == "__main__":
    main()
