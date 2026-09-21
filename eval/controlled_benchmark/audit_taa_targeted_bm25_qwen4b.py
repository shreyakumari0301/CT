"""Gold-blind targeted multi-query BM25 candidates followed by Qwen3 4B.

Four report-derived sparse queries (indicators, targeting, behavior, and the
full report) retrieve against unprefixed frozen ATT&CK actor-profile fields.
Their actor rankings are fused with RRF, added to the established CTA/BM25
candidate sources, and reranked with the established complete profile text.
"""
from __future__ import annotations

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
OUT = ROOT / os.environ.get(
    "TARGETED_BM25_QWEN_OUTPUT",
    "eval_results/controlled_benchmark/full/taa_targeted_bm25_union_qwen4b_audit",
)
MODEL_NAME = os.environ.get("TARGETED_BM25_QWEN_MODEL", "Qwen/Qwen3-Reranker-4B")
BATCH_SIZE = int(os.environ.get("TARGETED_BM25_QWEN_BATCH_SIZE", "8"))
CTA_TOP_K = int(os.environ.get("TARGETED_BM25_CTA_TOP_K", "10"))
SHARED_BM25_TOP_K = int(os.environ.get("TARGETED_BM25_SHARED_TOP_K", "20"))
VIEW_TOP_K = int(os.environ.get("TARGETED_BM25_VIEW_TOP_K", "10"))
TARGETED_TOP_K = int(os.environ.get("TARGETED_BM25_TARGETED_TOP_K", "20"))
OUT.mkdir(parents=True, exist_ok=True)
REPORTS = {
    f"taa-{i}": row["Text"]
    for i, row in enumerate(csv.DictReader((ROOT / "data/cti-taa.tsv").open(encoding="utf-8"), delimiter="\t"))
}


def tokenize(text: str) -> list[str]:
    return re.findall(r"[a-z0-9]+(?:[._-][a-z0-9]+)*", text.lower())


class LocalBM25:
    """Deterministic BM25 over the frozen profile-field passages."""

    def __init__(self, texts: list[str], k1: float = 1.5, b: float = 0.75):
        self.k1, self.b = k1, b
        self.frequencies = [Counter(tokenize(text)) for text in texts]
        self.lengths = [sum(frequency.values()) for frequency in self.frequencies]
        self.average_length = sum(self.lengths) / max(len(self.lengths), 1)
        document_frequency: Counter = Counter()
        for frequency in self.frequencies:
            document_frequency.update(frequency)
        total = len(self.frequencies)
        self.idf = {
            token: math.log(1 + (total - frequency + 0.5) / (frequency + 0.5))
            for token, frequency in document_frequency.items()
        }

    def scores(self, query: str) -> list[float]:
        query_terms = Counter(tokenize(query))
        results: list[float] = []
        for frequency, length in zip(self.frequencies, self.lengths):
            normalization = self.k1 * (1 - self.b + self.b * length / max(self.average_length, 1))
            score = 0.0
            for token in query_terms:
                tf = frequency.get(token, 0)
                if tf:
                    score += self.idf.get(token, 0.0) * tf * (self.k1 + 1) / (tf + normalization)
            results.append(score)
        return results


def full_profile_passage(profile: dict) -> str:
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
        + profile["canonical_actor"]
        + "\n"
        + profile.get("profile_text", "")
        + "\n"
        + "\n".join(f"{field}: " + ", ".join(map(str, profile.get(field, []))) for field in fields)
    )


def build_field_documents(profiles: list[dict]) -> list[dict]:
    documents: list[dict] = []
    for actor_index, profile in enumerate(profiles):
        for field in ("profile_text", "malware_tools", "infrastructure", "targeting", "behavior", "aliases_campaigns"):
            text = profile.get("profile_text", "") if field == "profile_text" else profile.get("field_text", {}).get(field, "")
            if text.strip():
                documents.append({"actor_index": actor_index, "actor": profile["canonical_actor"], "field": field, "text": text})
    return documents


def actor_ranking(scores, documents: list[dict]) -> list[tuple[int, float]]:
    best: dict[int, float] = {}
    actor_names: dict[int, str] = {}
    for document, score in zip(documents, scores):
        actor_index = document["actor_index"]
        actor_names[actor_index] = document["actor"]
        best[actor_index] = max(best.get(actor_index, float("-inf")), float(score))
    return sorted(best.items(), key=lambda item: (-item[1], actor_names[item[0]]))


def unique(values: list[str]) -> list[str]:
    return list(dict.fromkeys(value for value in values if value))


def extract_views(report: str, profiles: list[dict]) -> tuple[dict[str, str], dict[str, list[str]]]:
    """Create short, report-only retrieval views with no labels or generation."""
    from utils.taa_actor_retrieval import BEHAVIORS, REGIONS, SECTORS, contains, entity_mention, sentences

    sentences_in_report = sentences(report)
    malware_tools = unique(
        value
        for profile in profiles
        for field in ("malware", "tools", "infrastructure")
        for value in profile.get(field, [])
        if entity_mention(report, value, "malware_tools" if field != "infrastructure" else "infrastructure")
    )
    campaigns = unique(
        value
        for profile in profiles
        for value in profile.get("campaigns", [])
        if len(value) >= 5 and contains(report, value)
    )
    indicators = unique(
        malware_tools
        + campaigns
        + re.findall(r"\bCVE-\d{4}-\d{4,}\b|\bT\d{4}(?:\.\d{3})?\b|\b(?:\d{1,3}\.){3}\d{1,3}\b", report, flags=re.I)
        + re.findall(r"\b[a-z0-9-]+(?:\[\.\]|\.)(?:com|net|org|info|biz)\b", report, flags=re.I)
    )
    targets = [term for term in (*REGIONS, *SECTORS) if contains(report, term)]
    target_sentences = [sentence for sentence in sentences_in_report if re.search(r"target|victim|government|sector|countr|military", sentence, re.I)][:3]
    behaviors = [term for term in BEHAVIORS if contains(report, term)] + re.findall(r"\bT\d{4}(?:\.\d{3})?\b", report)
    behavior_sentences = [sentence for sentence in sentences_in_report if re.search(r"phish|inject|persist|hijack|side.load|credential|execution|registry", sentence, re.I)][:3]
    terms = {
        "indicators": indicators,
        "targeting": unique(targets + target_sentences),
        "behavior": unique(behaviors + behavior_sentences),
        "full_report": [],
    }
    views = {
        "indicators": " ".join(indicators),
        "targeting": " ".join(terms["targeting"]),
        "behavior": " ".join(terms["behavior"]),
        "full_report": report,
    }
    # Sparse views must be non-empty even for a report without a recognized cue.
    for name, query in views.items():
        if not query.strip():
            views[name] = report
    return views, terms


def recall_at(rows: list[dict], key: str, cutoffs: tuple[int, ...]) -> dict[str, float]:
    from eval.taa_protocol import benchmark_alias_match

    return {
        f"Recall@{cutoff}": sum(
            any(benchmark_alias_match(actor, row["gold"]) for actor in row[key][:cutoff]) for row in rows
        )
        / len(rows)
        for cutoff in cutoffs
    }


def main() -> None:
    from sentence_transformers import CrossEncoder

    from eval.taa_protocol import benchmark_alias_match

    documents = build_field_documents(PROFILES)
    bm25 = LocalBM25([document["text"] for document in documents])
    by_name = {profile["canonical_actor"]: profile for profile in PROFILES}
    retrieval_rows: list[dict] = []
    for cta_row, shared_row in zip(CTA, SHARED):
        item_id = cta_row["id"]
        views, terms = extract_views(REPORTS[item_id], PROFILES)
        per_view_top: dict[str, list[str]] = {}
        rrf: Counter = Counter()
        for view_name, query in views.items():
            ranking = actor_ranking(bm25.scores(query), documents)
            names = [documents[next(i for i, d in enumerate(documents) if d["actor_index"] == actor_index)]["actor"] for actor_index, _ in ranking[:VIEW_TOP_K]]
            per_view_top[view_name] = names
            for rank, name in enumerate(names, 1):
                rrf[name] += 1 / (60 + rank)
        targeted = [name for name, _ in sorted(rrf.items(), key=lambda item: (-item[1], item[0]))[:TARGETED_TOP_K]]
        cta_candidates = cta_row["ranking"][:CTA_TOP_K]
        shared_candidates = shared_row["bm25"][:SHARED_BM25_TOP_K]
        pool = list(dict.fromkeys(cta_candidates + shared_candidates + targeted))
        retrieval_rows.append(
            {
                "id": item_id,
                "gold": cta_row["gold"],
                "targeted_query_terms": terms,
                "targeted_bm25_top_by_view": per_view_top,
                "targeted_bm25_rrf_top": targeted,
                "cta_candidates": cta_candidates,
                "shared_bm25_candidates": shared_candidates,
                "candidate_pool": pool,
            }
        )

    model = CrossEncoder(MODEL_NAME, max_length=2048, device="cuda")
    checkpoint = OUT / "checkpoint.json"
    completed = json.loads(checkpoint.read_text()) if checkpoint.exists() else []
    rows_by_id = {row["id"]: row for row in completed if "ranking" in row and "candidate_pool" in row}
    for row in retrieval_rows:
        item_id = row["id"]
        if item_id in rows_by_id:
            continue
        passages = [full_profile_passage(by_name[name]) for name in row["candidate_pool"]]
        scores = model.predict(
            [(REPORTS[item_id], passage) for passage in passages],
            show_progress_bar=False,
            batch_size=BATCH_SIZE,
        )
        ranking = [
            {"actor": name, "score": float(score)}
            for score, name in sorted(zip(scores, row["candidate_pool"]), key=lambda item: float(item[0]), reverse=True)
        ]
        rank = next(
            (position for position, entry in enumerate(ranking, 1) if benchmark_alias_match(entry["actor"], row["gold"])),
            None,
        )
        rows_by_id[item_id] = {**row, "rank": rank, "ranking": ranking}
        checkpoint.write_text(
            json.dumps(sorted(rows_by_id.values(), key=lambda item: int(item["id"].removeprefix("taa-"))), indent=2),
            encoding="utf-8",
        )

    rows = sorted(rows_by_id.values(), key=lambda row: int(row["id"].removeprefix("taa-")))
    checkpoint.write_text(json.dumps(rows, indent=2), encoding="utf-8")
    ranks = [row["rank"] for row in rows]
    reranked = {
        f"Recall@{cutoff}": sum(bool(rank and rank <= cutoff) for rank in ranks) / len(ranks)
        for cutoff in (1, 3, 5, 10, 20)
    }
    reranked["MRR@10"] = sum(1 / rank if rank and rank <= 10 else 0 for rank in ranks) / len(ranks)
    summary = {
        "method": "CTA top-10 + shared BM25 top-20 + targeted multi-query actor-field BM25 RRF top-20 -> Qwen3 4B",
        "queries": "report-only indicators, targeting, behavior, and full-report sparse views",
        "model": MODEL_NAME,
        "documents": len(documents),
        "n": len(rows),
        "complete": len(rows) == 50,
        "candidate_generation_metrics": {
            "targeted_bm25_rrf_top20": recall_at(rows, "targeted_bm25_rrf_top", (1, 3, 5, 10, 20)),
            "final_union_pool": {
                "Recall@pool": sum(
                    any(benchmark_alias_match(actor, row["gold"]) for actor in row["candidate_pool"]) for row in rows
                ) / len(rows),
                "mean_pool_size": sum(len(row["candidate_pool"]) for row in rows) / len(rows),
            },
        },
        "reranked_metrics": reranked,
        "per_case_results": "checkpoint.json contains report-derived query terms, each BM25 view, the fused candidates, and all Qwen scores.",
    }
    (OUT / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
