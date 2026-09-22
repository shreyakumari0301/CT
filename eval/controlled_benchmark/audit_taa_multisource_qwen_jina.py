"""Compare Qwen3-4B and Jina on one gold-blind multi-source ATT&CK pool.

The candidate pool always retains the frozen CTA/BM25 candidates.  It adds
actor-linked ATT&CK group, campaign, and software passages retrieved by both
BM25 and MiniLM dense similarity.  CAPEC and Sigma are not silently fabricated:
the manifest records their absence from the local bundle.
"""
from __future__ import annotations

import csv
import gc
import json
import math
import os
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from utils.multisource_attack_ingestion import build_attack_multisource_corpus  # noqa: E402

CTA = json.loads((ROOT / "eval_results/controlled_benchmark/full/taa_external_protocol/ctibench_frozen_retrieval/ft_idf_rrf_summary.json").read_text())["rows"]
SHARED = json.loads((ROOT / "eval_results/controlled_benchmark/full/taa_external_protocol/offline_diagnostics/passage_bm25_summary.json").read_text())["rows"]
BUNDLE = ROOT / "data/ctibench_taa/enterprise-attack.json"
OUT = ROOT / os.environ.get("MULTISOURCE_OUTPUT", "eval_results/controlled_benchmark/full/taa_multisource_attack_qwen_jina_audit")
OUT.mkdir(parents=True, exist_ok=True)
MODELS = tuple(item.strip().lower() for item in os.environ.get("MULTISOURCE_RERANKERS", "qwen,jina").split(",") if item.strip())
DENSE_TOP_K = int(os.environ.get("MULTISOURCE_DENSE_TOP_K", "20"))
BM25_TOP_K = int(os.environ.get("MULTISOURCE_BM25_TOP_K", "20"))
CTA_TOP_K = int(os.environ.get("MULTISOURCE_CTA_TOP_K", "10"))
SHARED_TOP_K = int(os.environ.get("MULTISOURCE_SHARED_TOP_K", "20"))
QWEN_MODEL = os.environ.get("MULTISOURCE_QWEN_MODEL", "Qwen/Qwen3-Reranker-4B")
JINA_MODEL = os.environ.get("MULTISOURCE_JINA_MODEL", "jinaai/jina-reranker-v3.5")
REPORTS = {f"taa-{i}": row["Text"] for i, row in enumerate(csv.DictReader((ROOT / "data/cti-taa.tsv").open(encoding="utf-8"), delimiter="\t"))}


def tokenize(text: str) -> list[str]:
    return re.findall(r"[a-z0-9]+(?:[._-][a-z0-9]+)*", text.lower())


class LocalBM25:
    def __init__(self, texts: list[str], k1: float = 1.5, b: float = 0.75):
        self.k1, self.b = k1, b
        self.frequencies = [Counter(tokenize(text)) for text in texts]
        self.lengths = [sum(freq.values()) for freq in self.frequencies]
        self.average_length = sum(self.lengths) / max(len(self.lengths), 1)
        document_frequency: Counter = Counter()
        for frequency in self.frequencies:
            document_frequency.update(frequency)
        total = len(self.frequencies)
        self.idf = {token: math.log(1 + (total - count + 0.5) / (count + 0.5)) for token, count in document_frequency.items()}

    def scores(self, query: str) -> list[float]:
        terms = Counter(tokenize(query))
        scores = []
        for frequency, length in zip(self.frequencies, self.lengths):
            normalizer = self.k1 * (1 - self.b + self.b * length / max(self.average_length, 1))
            score = 0.0
            for token in terms:
                frequency_value = frequency.get(token, 0)
                if frequency_value:
                    score += self.idf.get(token, 0.0) * frequency_value * (self.k1 + 1) / (frequency_value + normalizer)
            scores.append(float(score))
        return scores


def actor_max(scores, passages: list[dict]) -> tuple[list[str], dict[str, float], dict[str, list[int]]]:
    best: dict[str, float] = {}
    documents: dict[str, list[int]] = defaultdict(list)
    for index, (score, passage) in enumerate(zip(scores, passages)):
        actor = passage["actor"]
        best[actor] = max(best.get(actor, float("-inf")), float(score))
        documents[actor].append(index)
    ranking = sorted(best, key=lambda actor: (-best[actor], actor.casefold()))
    return ranking, best, documents


def evidence_query(report: str, passages: list[dict], max_characters: int = 6000) -> tuple[str, list[dict]]:
    """Deterministically keep report sentences rich in source-corpus indicators."""
    from utils.taa_actor_retrieval import sentences

    df: Counter = Counter()
    terms: set[str] = set()
    for passage in passages:
        value = passage["source_name"].strip()
        # Generic one-word product names create noisy matches; phrase/ID/marked
        # names remain valid high-specificity attribution clues.
        if len(value) >= 4 and (" " in value or re.search(r"[0-9._-]", value) or re.search(r"[a-z][A-Z]", value)):
            terms.add(value)
    for term in terms:
        pattern = re.compile(r"(?<!\w)" + re.escape(term) + r"(?!\w)", re.I)
        df[term] = sum(bool(pattern.search(passage["text"])) for passage in passages)
    candidates = []
    for index, sentence in enumerate(sentences(report)):
        signals = []
        score = 0.0
        for term in terms:
            if re.search(r"(?<!\w)" + re.escape(term) + r"(?!\w)", sentence, re.I):
                signals.append(term)
                score += 8 / max(df[term], 1)
        cves = re.findall(r"\bCVE-\d{4}-\d{4,}\b", sentence, re.I)
        attack_ids = re.findall(r"\bT\d{4}(?:\.\d{3})?\b", sentence)
        iocs = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b|\b[a-z0-9-]+(?:\[\.\]|\.)(?:com|net|org|info|biz)\b", sentence, re.I)
        score += 4 * len(cves) + 3 * len(attack_ids) + 3 * len(iocs)
        signals.extend(cves + attack_ids + iocs)
        if re.search(r"\b(?:target|victim|attribut|campaign|malware|tool|backdoor|ransomware|phish|side.load|inject|persist)\b", sentence, re.I):
            score += 0.5
        if score:
            candidates.append({"index": index, "sentence": sentence, "score": score, "signals": list(dict.fromkeys(signals))[:12]})
    selected, used = [], len("Evidence-focused CTI report excerpts:\n")
    for item in sorted(candidates, key=lambda item: (-item["score"], item["index"])):
        if used + len(item["sentence"]) + 1 <= max_characters:
            selected.append(item)
            used += len(item["sentence"]) + 1
    if not selected:
        for index, sentence in enumerate(sentences(report)):
            if used + len(sentence) + 1 > max_characters:
                break
            selected.append({"index": index, "sentence": sentence, "score": 0.0, "signals": []})
            used += len(sentence) + 1
    selected.sort(key=lambda item: item["index"])
    return "Evidence-focused CTI report excerpts:\n" + "\n".join(item["sentence"] for item in selected), selected


def actor_document(actor: str, passage_indices: list[int], combined_scores: list[float], passages: list[dict]) -> tuple[str, list[dict]]:
    """Build a compact, auditable reranker document from natural source passages."""
    selected = sorted(passage_indices, key=lambda index: (-combined_scores[index], passages[index]["source_type"], passages[index]["source_name"]))[:4]
    evidence = []
    chunks = [f"Actor: {actor}"]
    for index in selected:
        passage = passages[index]
        source = re.sub(r"\s+", " ", passage["text"])
        # Preserve source title/evidence, fit all documents beneath the Qwen
        # cross-encoder budget once paired with the 6k-character query.
        source = source[:900]
        chunks.append(source)
        evidence.append({
            "source_type": passage["source_type"], "source_name": passage["source_name"],
            "source_stix_id": passage["source_stix_id"], "combined_retrieval_score": combined_scores[index],
        })
    return "\n\n".join(chunks)[:3700], evidence


def metrics(rows: list[dict], ranking_key: str) -> dict[str, float]:
    from eval.taa_protocol import benchmark_alias_match

    ranks = []
    for row in rows:
        rank = next((i for i, entry in enumerate(row[ranking_key], 1) if benchmark_alias_match(entry["actor"], row["gold"])), None)
        ranks.append(rank)
    value = {f"Recall@{cutoff}": sum(bool(rank and rank <= cutoff) for rank in ranks) / len(ranks) for cutoff in (1, 3, 5, 10, 20)}
    value["MRR@10"] = sum(1 / rank if rank and rank <= 10 else 0 for rank in ranks) / len(ranks)
    return value


def candidate_rows(passages: list[dict]) -> list[dict]:
    import numpy as np
    from sentence_transformers import SentenceTransformer

    bm25 = LocalBM25([passage["text"] for passage in passages])
    # Candidate embeddings are intentionally CPU-bound: the Slurm GPU is held
    # for the requested rerankers only, under the one-CPU allocation.
    encoder = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2", device="cpu")
    corpus_embeddings = encoder.encode([passage["text"] for passage in passages], normalize_embeddings=True, batch_size=32, show_progress_bar=False)
    records = []
    for cta_row, shared_row in zip(CTA, SHARED):
        query = REPORTS[cta_row["id"]]
        dense_scores = np.asarray(corpus_embeddings @ encoder.encode([query], normalize_embeddings=True, show_progress_bar=False)[0], dtype=float)
        bm25_scores = bm25.scores(query)
        dense_names, dense_actor_scores, actor_docs = actor_max(dense_scores, passages)
        bm25_names, bm25_actor_scores, _ = actor_max(bm25_scores, passages)
        dense_scale = max(max(abs(score) for score in dense_scores), 1e-9)
        bm25_scale = max(max(abs(score) for score in bm25_scores), 1e-9)
        combined = [float(dense / dense_scale + sparse / bm25_scale) for dense, sparse in zip(dense_scores, bm25_scores)]
        source_dense = dense_names[:DENSE_TOP_K]
        source_bm25 = bm25_names[:BM25_TOP_K]
        cta_candidates = cta_row["ranking"][:CTA_TOP_K]
        shared_candidates = shared_row["bm25"][:SHARED_TOP_K]
        pool = list(dict.fromkeys(cta_candidates + shared_candidates + source_dense + source_bm25))
        documents = {}
        source_evidence = {}
        for actor in pool:
            indices = actor_docs.get(actor, [])
            if indices:
                documents[actor], source_evidence[actor] = actor_document(actor, indices, combined, passages)
            else:
                documents[actor] = f"Actor: {actor}\nNo actor-linked multi-source ATT&CK passage was materialized."
                source_evidence[actor] = []
        rerank_query, selected = evidence_query(query, passages)
        records.append({
            "id": cta_row["id"], "gold": cta_row["gold"],
            "cta_candidates": cta_candidates, "shared_bm25_candidates": shared_candidates,
            "multisource_dense_top": source_dense, "multisource_bm25_top": source_bm25,
            "candidate_pool": pool, "evidence_query": rerank_query, "evidence_sentences": selected,
            "candidate_source_evidence": source_evidence,
            "candidate_source_scores": {
                "dense": {actor: dense_actor_scores[actor] for actor in source_dense},
                "bm25": {actor: bm25_actor_scores[actor] for actor in source_bm25},
            },
            "documents": documents,
        })
    del encoder
    gc.collect()
    return records


def save_checkpoint(rows: list[dict], path: Path) -> None:
    # Documents are useful for runtime but duplicate retained source evidence;
    # checkpoint keeps per-case rankings and precise provenance without bloat.
    serializable = [{key: value for key, value in row.items() if key != "documents"} for row in rows]
    path.write_text(json.dumps(serializable, indent=2), encoding="utf-8")


def run_qwen(rows: list[dict]) -> None:
    from sentence_transformers import CrossEncoder

    model = CrossEncoder(QWEN_MODEL, max_length=2048, device="cuda")
    for row in rows:
        if "qwen_ranking" in row:
            continue
        scores = model.predict([(row["evidence_query"], row["documents"][actor]) for actor in row["candidate_pool"]], batch_size=8, show_progress_bar=False)
        row["qwen_ranking"] = [{"actor": actor, "score": float(score)} for score, actor in sorted(zip(scores, row["candidate_pool"]), key=lambda pair: float(pair[0]), reverse=True)]
        save_checkpoint(rows, OUT / "checkpoint.json")
    del model
    gc.collect()
    import torch
    torch.cuda.empty_cache()


def run_jina(rows: list[dict]) -> None:
    from transformers import AutoModel

    model = AutoModel.from_pretrained(JINA_MODEL, dtype="auto", trust_remote_code=True, device_map="auto")
    model.eval()
    for row in rows:
        if "jina_ranking" in row:
            continue
        results = model.rerank(row["evidence_query"], [row["documents"][actor] for actor in row["candidate_pool"]])
        row["jina_ranking"] = [{"actor": row["candidate_pool"][item["index"]], "score": float(item["relevance_score"])} for item in results]
        save_checkpoint(rows, OUT / "checkpoint.json")
    del model
    gc.collect()
    import torch
    torch.cuda.empty_cache()


def main() -> None:
    passages, manifest = build_attack_multisource_corpus(BUNDLE)
    saved = json.loads((OUT / "checkpoint.json").read_text()) if (OUT / "checkpoint.json").exists() else []
    saved_by_id = {row["id"]: row for row in saved}
    rows = candidate_rows(passages)
    for row in rows:
        previous = saved_by_id.get(row["id"], {})
        for key in ("qwen_ranking", "jina_ranking"):
            if key in previous:
                row[key] = previous[key]
    (OUT / "ingestion_manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    save_checkpoint(rows, OUT / "checkpoint.json")
    if "qwen" in MODELS:
        run_qwen(rows)
    if "jina" in MODELS:
        run_jina(rows)
    from eval.taa_protocol import benchmark_alias_match
    summary = {
        "method": "frozen CTA/shared-BM25 union plus multi-source MITRE ATT&CK group/campaign/software dense+BM25 candidates; same source-evidence document and report-only evidence query for each reranker",
        "models_requested": MODELS, "models_completed": [model for model in ("qwen", "jina") if f"{model}_ranking" in rows[0]],
        "qwen_model": QWEN_MODEL, "jina_model": JINA_MODEL, "n": len(rows), "complete": len(rows) == 50,
        "ingestion": manifest,
        "candidate_generation_metrics": {
            "final_union_pool": {
                "Recall@pool": sum(any(benchmark_alias_match(actor, row["gold"]) for actor in row["candidate_pool"]) for row in rows) / len(rows),
                "mean_pool_size": sum(len(row["candidate_pool"]) for row in rows) / len(rows),
            }
        },
        "per_case_results": "checkpoint.json contains base and multi-source candidates, source-evidence provenance, exact reranker scores, and full rankings.",
    }
    if all("qwen_ranking" in row for row in rows):
        summary["qwen_metrics"] = metrics(rows, "qwen_ranking")
    if all("jina_ranking" in row for row in rows):
        summary["jina_metrics"] = metrics(rows, "jina_ranking")
    (OUT / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
