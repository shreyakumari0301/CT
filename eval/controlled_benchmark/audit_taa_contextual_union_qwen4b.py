"""Contextual dense/BM25 retrieval followed by Qwen3 4B reranking.

This is a gold-blind controlled benchmark.  It derives natural passages from
the frozen ATT&CK actor profiles, prepends each with short actor/evidence
context, indexes that contextualized text with both MiniLM and BM25, then
reranks the union of the two top-20 actor lists with Qwen3-Reranker-4B.
"""
from __future__ import annotations

import csv
import hashlib
import json
import math
import os
import re
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
PROFILE_PATH = (
    ROOT
    / "eval_results/controlled_benchmark/taa20_20260918/actor_retrieval_study_v2"
    / "actor_profiles.json"
)
MODEL_NAME = os.environ.get("CONTEXTUAL_QWEN_MODEL", "Qwen/Qwen3-Reranker-4B")
BATCH_SIZE = int(os.environ.get("CONTEXTUAL_QWEN_BATCH_SIZE", "8"))
PASSAGE_MODE = os.environ.get("CONTEXTUAL_QWEN_PASSAGE_MODE", "full_profile")
if PASSAGE_MODE not in {"full_profile", "contextual_retrieved_chunks"}:
    raise ValueError("CONTEXTUAL_QWEN_PASSAGE_MODE must be full_profile or contextual_retrieved_chunks")
OUT = ROOT / os.environ.get(
    "CONTEXTUAL_QWEN_OUTPUT",
    "eval_results/controlled_benchmark/full/taa_contextual_union_qwen4b_full_profile_audit",
)
TOP_K = 20
CHUNK_TOKENS = 180
OUT.mkdir(parents=True, exist_ok=True)


def tokenize(text: str) -> list[str]:
    """Stable lexical tokens for the local, dependency-free BM25 index."""
    return re.findall(r"[a-z0-9]+(?:[._-][a-z0-9]+)*", text.lower())


def natural_chunks(text: str, tokenizer, max_tokens: int = CHUNK_TOKENS) -> list[str]:
    """Group complete sentences, splitting only an overlong single sentence."""
    sentences = [
        sentence.strip()
        for sentence in re.split(r"(?<=[.!?])\s+|\n+", text)
        if sentence.strip()
    ]
    chunks: list[str] = []
    current: list[str] = []
    for sentence in sentences or [text.strip()]:
        candidate = " ".join([*current, sentence]).strip()
        if current and len(tokenizer.encode(candidate, add_special_tokens=False)) > max_tokens:
            chunks.append(" ".join(current))
            current = []
        token_ids = tokenizer.encode(sentence, add_special_tokens=False)
        if len(token_ids) > max_tokens:
            if current:
                chunks.append(" ".join(current))
                current = []
            for start in range(0, len(token_ids), max_tokens):
                chunks.append(tokenizer.decode(token_ids[start : start + max_tokens], skip_special_tokens=True))
        else:
            current.append(sentence)
    if current:
        chunks.append(" ".join(current))
    return [chunk for chunk in chunks if chunk.strip()]


def limited(values: list[str], count: int = 6) -> str:
    return ", ".join(values[:count]) if values else "none recorded"


def contextual_prefix(profile: dict, field: str) -> str:
    """A short structured document-level context added to every passage."""
    labels = {
        "profile_text": "actor background and operational history",
        "malware_tools": "malware and tooling associations",
        "infrastructure": "infrastructure associations",
        "targeting": "targeting and victimology",
        "behavior": "ATT&CK techniques and behavior",
        "aliases_campaigns": "aliases and campaign associations",
    }
    return (
        f"Actor: {profile['canonical_actor']}. "
        f"Evidence type: {labels[field]}. "
        f"Aliases: {limited(profile.get('aliases', []), 4)}. "
        f"Associated malware/tools: {limited(profile.get('malware', []) + profile.get('tools', []), 6)}. "
        f"Reported targets: {limited(profile.get('target_regions', []) + profile.get('target_sectors', []), 5)}."
    )


def build_documents(profiles: list[dict], tokenizer) -> list[dict]:
    documents: list[dict] = []
    fields = ("profile_text", "malware_tools", "infrastructure", "targeting", "behavior", "aliases_campaigns")
    for actor_index, profile in enumerate(profiles):
        for field in fields:
            source = profile.get(field, "") if field == "profile_text" else profile.get("field_text", {}).get(field, "")
            for chunk_index, passage in enumerate(natural_chunks(source.strip(), tokenizer)):
                documents.append(
                    {
                        "actor_index": actor_index,
                        "actor": profile["canonical_actor"],
                        "field": field,
                        "chunk_index": chunk_index,
                        "text": f"{contextual_prefix(profile, field)}\nPassage: {passage}",
                    }
                )
    return documents


def full_profile_passage(profile: dict) -> str:
    """Match the established Qwen audit evidence representation exactly."""
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


class LocalBM25:
    """Small deterministic BM25 implementation; avoids another runtime package."""

    def __init__(self, texts: list[str], k1: float = 1.5, b: float = 0.75):
        self.k1, self.b = k1, b
        self.term_frequencies = [Counter(tokenize(text)) for text in texts]
        self.lengths = [sum(freq.values()) for freq in self.term_frequencies]
        self.average_length = sum(self.lengths) / max(len(self.lengths), 1)
        document_frequency: Counter = Counter()
        for frequency in self.term_frequencies:
            document_frequency.update(frequency.keys())
        total = len(self.term_frequencies)
        self.idf = {
            term: math.log(1 + (total - freq + 0.5) / (freq + 0.5))
            for term, freq in document_frequency.items()
        }

    def scores(self, query: str) -> list[float]:
        query_terms = Counter(tokenize(query))
        scores: list[float] = []
        for frequency, length in zip(self.term_frequencies, self.lengths):
            normalization = self.k1 * (1 - self.b + self.b * length / max(self.average_length, 1))
            score = 0.0
            for term in query_terms:
                tf = frequency.get(term, 0)
                if tf:
                    score += self.idf.get(term, 0.0) * tf * (self.k1 + 1) / (tf + normalization)
            scores.append(score)
        return scores


def actor_ranking(scores, documents: list[dict]) -> tuple[list[tuple[int, float]], dict[int, int]]:
    """Max-pool passage scores to a deterministic actor ranking."""
    best_scores: dict[int, float] = {}
    best_doc: dict[int, int] = {}
    for doc_index, score in enumerate(scores):
        actor_index = documents[doc_index]["actor_index"]
        score = float(score)
        if score > best_scores.get(actor_index, float("-inf")):
            best_scores[actor_index], best_doc[actor_index] = score, doc_index
    ranked = sorted(best_scores.items(), key=lambda item: (-item[1], documents[best_doc[item[0]]]["actor"]))
    return ranked, best_doc


def retrieval_metrics(rows: list[dict], key: str) -> dict[str, float]:
    from eval.taa_protocol import benchmark_alias_match

    return {
        f"Recall@{cutoff}": sum(
            any(benchmark_alias_match(actor, row["gold"]) for actor in row[key][:cutoff]) for row in rows
        )
        / len(rows)
        for cutoff in (1, 3, 5, 10, 20)
    }


def pool_coverage(rows: list[dict]) -> dict[str, float]:
    from eval.taa_protocol import benchmark_alias_match

    return {
        "Recall@pool": sum(
            any(benchmark_alias_match(actor, row["gold"]) for actor in row["candidate_pool"])
            for row in rows
        )
        / len(rows),
        "mean_pool_size": sum(len(row["candidate_pool"]) for row in rows) / len(rows),
    }


def rank_metrics(rows: list[dict]) -> dict[str, float]:
    ranks = [row["rank"] for row in rows]
    result = {
        f"Recall@{cutoff}": sum(bool(rank and rank <= cutoff) for rank in ranks) / len(ranks)
        for cutoff in (1, 3, 5, 10, 20)
    }
    result["MRR@10"] = sum(1 / rank if rank and rank <= 10 else 0 for rank in ranks) / len(ranks)
    return result


def main() -> None:
    import numpy as np
    from sentence_transformers import CrossEncoder, SentenceTransformer

    from eval.taa_protocol import benchmark_alias_match

    profiles = json.loads(PROFILE_PATH.read_text(encoding="utf-8"))
    actor_indices = {profile["canonical_actor"]: index for index, profile in enumerate(profiles)}
    reports = list(csv.DictReader((ROOT / "data/cti-taa.tsv").open(encoding="utf-8"), delimiter="\t"))
    labels = list(
        csv.DictReader((ROOT / "data/ctibench_taa/cti-taa-responses.tsv").open(encoding="utf-8"), delimiter="\t")
    )
    if len(reports) != len(labels):
        raise ValueError(f"Expected aligned reports and labels, got {len(reports)} and {len(labels)}")

    # MiniLM runs on CPU so the one requested GPU remains dedicated to Qwen3 4B.
    dense_model = SentenceTransformer("all-MiniLM-L6-v2", device="cpu")
    dense_model.max_seq_length = 256
    documents = build_documents(profiles, dense_model.tokenizer)
    corpus_digest = hashlib.sha256(json.dumps(documents, sort_keys=True).encode()).hexdigest()
    cache_dir = Path(os.environ.get("CONTEXTUAL_EMBEDDING_CACHE", str(OUT / "embedding_cache")))
    cache_dir.mkdir(parents=True, exist_ok=True)
    embedding_path = cache_dir / f"{corpus_digest}.npy"
    if embedding_path.exists():
        embeddings = np.load(embedding_path)
    else:
        embeddings = dense_model.encode(
            [document["text"] for document in documents],
            batch_size=64,
            normalize_embeddings=True,
            show_progress_bar=False,
        )
        np.save(embedding_path, embeddings)
    bm25 = LocalBM25([document["text"] for document in documents])

    retrieval_rows: list[dict] = []
    candidate_inputs: dict[str, list[tuple[str, str]]] = {}
    for item_number, (report, label) in enumerate(zip(reports, labels)):
        item_id = f"taa-{item_number}"
        report_text = report["Text"]
        dense_scores = embeddings @ dense_model.encode([report_text], normalize_embeddings=True, show_progress_bar=False)[0]
        dense_ranked, dense_best_doc = actor_ranking(dense_scores, documents)
        bm25_ranked, bm25_best_doc = actor_ranking(bm25.scores(report_text), documents)
        dense_top = [documents[dense_best_doc[index]]["actor"] for index, _ in dense_ranked[:TOP_K]]
        bm25_top = [documents[bm25_best_doc[index]]["actor"] for index, _ in bm25_ranked[:TOP_K]]
        pool = list(dict.fromkeys(dense_top + bm25_top))
        passage_pairs: list[tuple[str, str]] = []
        candidate_documents: dict[str, list[dict]] = {}
        for actor in pool:
            actor_index = actor_indices[actor]
            selected = list(dict.fromkeys([dense_best_doc[actor_index], bm25_best_doc[actor_index]]))
            if PASSAGE_MODE == "full_profile":
                passage = full_profile_passage(profiles[actor_index])
            else:
                passage = "\n\n".join(documents[index]["text"] for index in selected)
            passage_pairs.append((actor, passage))
            candidate_documents[actor] = [
                {"field": documents[index]["field"], "chunk_index": documents[index]["chunk_index"]}
                for index in selected
            ]
        candidate_inputs[item_id] = passage_pairs
        retrieval_rows.append(
            {
                "id": item_id,
                "gold": label["GT"],
                "contextual_dense_top20": dense_top,
                "contextual_bm25_top20": bm25_top,
                "candidate_pool": pool,
                "candidate_documents": candidate_documents,
            }
        )

    model = CrossEncoder(MODEL_NAME, max_length=2048, device="cuda")
    checkpoint = OUT / "checkpoint.json"
    completed = json.loads(checkpoint.read_text()) if checkpoint.exists() else []
    rows_by_id = {
        row["id"]: row
        for row in completed
        if {"contextual_dense_top20", "contextual_bm25_top20", "candidate_pool", "ranking"}.issubset(row)
    }
    for retrieval_row in retrieval_rows:
        item_id = retrieval_row["id"]
        if item_id in rows_by_id:
            continue
        scores = model.predict(
            [(reports[int(item_id.removeprefix("taa-"))]["Text"], passage) for _, passage in candidate_inputs[item_id]],
            show_progress_bar=False,
            batch_size=BATCH_SIZE,
        )
        ranking = [
            {"actor": actor, "score": float(score)}
            for score, (actor, _) in sorted(zip(scores, candidate_inputs[item_id]), key=lambda item: float(item[0]), reverse=True)
        ]
        rank = next(
            (position for position, entry in enumerate(ranking, 1) if benchmark_alias_match(entry["actor"], retrieval_row["gold"])),
            None,
        )
        rows_by_id[item_id] = {**retrieval_row, "rank": rank, "ranking": ranking}
        rows = sorted(rows_by_id.values(), key=lambda row: int(row["id"].removeprefix("taa-")))
        checkpoint.write_text(json.dumps(rows, indent=2), encoding="utf-8")

    rows = sorted(rows_by_id.values(), key=lambda row: int(row["id"].removeprefix("taa-")))
    checkpoint.write_text(json.dumps(rows, indent=2), encoding="utf-8")
    summary = {
        "method": "contextual natural passages -> MiniLM/BM25 top-20 union -> Qwen3 4B",
        "retrieval_context": "Each indexed natural passage has deterministic actor, evidence-type, alias, malware/tool, and targeting context prepended.",
        "reranker_passage_mode": PASSAGE_MODE,
        "model": MODEL_NAME,
        "documents": len(documents),
        "n": len(rows),
        "complete": len(rows) == len(reports),
        "candidate_generation_metrics": {
            "contextual_dense_top20": retrieval_metrics(rows, "contextual_dense_top20"),
            "contextual_bm25_top20": retrieval_metrics(rows, "contextual_bm25_top20"),
            "contextual_union_pool": pool_coverage(rows),
        },
        "reranked_metrics": rank_metrics(rows),
        "per_case_results": "checkpoint.json contains contextual dense/BM25 candidates, selected passages, and all Qwen scores.",
    }
    (OUT / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
