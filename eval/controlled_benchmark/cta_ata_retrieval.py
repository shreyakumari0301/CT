"""CTA-specific ATA candidate pool variants (tuning for recall@5)."""
from __future__ import annotations

import json
import re
from collections import defaultdict
from functools import lru_cache
from pathlib import Path
from typing import Callable

from eval.controlled_benchmark.attack_retrieval import (
    ANCHORS,
    ID_RE,
    _rank_entries,
    _tokens,
    extract_behavior_clauses,
    hybrid_candidate_pool,
    load_enterprise_attack,
    rank_enterprise_attack,
    rerank_candidates,
)
from eval.controlled_benchmark.ata_discriminative import expand_hierarchy_candidates

ROOT = Path(__file__).resolve().parents[2]
CHUNKS_PATH = ROOT / "vector_dbs/memorization_vdb/chunks.json"
TOKEN_RE = re.compile(r"[a-z0-9]{3,}")


@lru_cache(maxsize=1)
def _chunks() -> list[dict]:
    if not CHUNKS_PATH.exists():
        return []
    return json.loads(CHUNKS_PATH.read_text(encoding="utf-8"))


@lru_cache(maxsize=1)
def _chunk_token_index() -> dict[str, list[int]]:
    index: dict[str, list[int]] = defaultdict(list)
    for idx, row in enumerate(_chunks()):
        for token in list(_tokens((row.get("content") or "")[:2500]))[:80]:
            if len(index[token]) < 400:
                index[token].append(idx)
    return index


def memorization_lexical_context(query: str, *, top_chunks: int = 5) -> str:
    """CTA memorization corpus via lexical overlap (no FAISS)."""
    clauses = extract_behavior_clauses(query)
    q_tokens = _tokens(" ".join(clauses))
    if not q_tokens:
        return ""
    candidate_idxs: set[int] = set()
    for token in q_tokens:
        candidate_idxs.update(_chunk_token_index().get(token, []))
    if not candidate_idxs:
        return ""
    chunks = _chunks()
    scored: list[tuple[int, str]] = []
    for idx in candidate_idxs:
        row = chunks[idx]
        text = (row.get("content") or "")[:4000]
        overlap = len(q_tokens & _tokens(text))
        if overlap >= 3:
            scored.append((overlap, text))
    scored.sort(key=lambda pair: (-pair[0], pair[1][:40]))
    return "\n\n".join(text[:1200] for _, text in scored[:top_chunks])


def hybrid_pool_tuned(
    entries: list[dict],
    query: str,
    previous_text: str = "",
    *,
    limit: int = 10,
    procedure_k: int = 8,
    definition_k: int = 8,
    rrf_k: int = 60,
) -> list[dict]:
    definitions = [entry for entry in entries if entry.get("kind") == "definition"]
    by_id = {entry["id"]: entry for entry in definitions}
    lists = []
    previous_ids = list(dict.fromkeys(ID_RE.findall(previous_text or "")))
    lists.append([by_id[i.upper()] for i in previous_ids if i.upper() in by_id][:8])
    procedure_entries = [entry for entry in entries if entry.get("kind") == "procedure"]
    lists.append(_rank_entries(procedure_entries, query, procedure_k))
    lists.append(rank_enterprise_attack(definitions, query, limit=definition_k))
    anchor_entries = [
        by_id[identifier]
        for cue, identifier in ANCHORS.items()
        if cue in (query or "").lower() and identifier in by_id
    ]
    lists.append(anchor_entries)
    scores: dict[str, float] = defaultdict(float)
    for candidates in lists:
        for rank, entry in enumerate(candidates, 1):
            scores[entry["id"]] += 1.0 / (rrf_k + rank)
    ranked = sorted(scores, key=lambda identifier: (-scores[identifier], identifier))
    return [by_id[identifier] for identifier in ranked[:limit]]


def cta_candidate_pool(
    catalog: list[dict],
    query: str,
    *,
    variant: str,
    limit: int = 10,
) -> list[dict]:
    memo = memorization_lexical_context(query)
    base_prev = memo

    if variant == "hybrid_report":
        return hybrid_candidate_pool(catalog, query, "", limit=limit)

    if variant == "hybrid_memo":
        return hybrid_candidate_pool(catalog, query, memo, limit=limit)

    if variant == "hybrid_tuned":
        return hybrid_pool_tuned(catalog, query, memo, limit=limit)

    if variant == "hybrid_tuned_hierarchy":
        pool = hybrid_pool_tuned(catalog, query, memo, limit=limit + 6)
        ids = expand_hierarchy_candidates([e["id"] for e in pool])
        by_id = {e["id"]: e for e in catalog if e.get("kind") == "definition"}
        return [by_id[i] for i in ids if i in by_id][:limit]

    if variant == "hybrid_wide_rerank":
        wide = hybrid_pool_tuned(catalog, query, memo, limit=20)
        defs = [e for e in wide if e.get("kind") == "definition"] or wide
        reranked = rerank_candidates(defs, query, limit=limit)
        return reranked

    if variant == "hybrid_bootstrap_attack":
        first = hybrid_pool_tuned(catalog, query, memo, limit=8)
        from eval.controlled_benchmark.attack_retrieval import format_attack_entries

        attack_block = format_attack_entries(first[:5])
        return hybrid_pool_tuned(catalog, query, memo + "\n" + attack_block, limit=limit)

    if variant == "hybrid_memo_clauses":
        clause_prev = "\n".join(extract_behavior_clauses(query))
        return hybrid_pool_tuned(catalog, query, memo + "\n" + clause_prev, limit=limit)

    raise ValueError(f"unknown variant: {variant}")


VARIANTS = [
    "hybrid_report",
    "hybrid_memo",
    "hybrid_tuned",
    "hybrid_tuned_hierarchy",
    "hybrid_wide_rerank",
    "hybrid_bootstrap_attack",
    "hybrid_memo_clauses",
]
