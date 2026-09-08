"""Reliability gate: admit retrieval only when evidence is discriminative."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List

from tcar.contrast import CandidateScore
from tcar.config import TCARConfig


@dataclass
class GateDecision:
    admit_retrieval: bool
    reliability: float
    margin: float
    agreement: float
    evidence_coverage: float
    ambiguity: float
    reason: str


def _lexical_ranks(question: str, doc_ids: List[str], store_text: Dict[str, str]) -> Dict[str, int]:
    import re

    qtok = set(re.findall(r"[a-z0-9]{4,}", question.lower()))
    scores = []
    for did in doc_ids:
        blob = store_text.get(did, "").lower()
        dtok = set(re.findall(r"[a-z0-9]{4,}", blob))
        overlap = len(qtok & dtok) / max(1, len(qtok | dtok))
        scores.append((did, overlap))
    scores.sort(key=lambda x: x[1], reverse=True)
    return {did: i for i, (did, _) in enumerate(scores)}


def _rank_agreement(dense_order: List[str], lex_order: List[str]) -> float:
    if not dense_order or not lex_order:
        return 0.0
    top_d = dense_order[0]
    top_l = lex_order[0]
    if top_d == top_l:
        return 1.0
    if top_d in lex_order[:3] or top_l in dense_order[:3]:
        return 0.5
    return 0.0


def evaluate_gate(
    question: str,
    scored: List[CandidateScore],
    store_text: Dict[str, str],
    cfg: TCARConfig,
) -> GateDecision:
    if cfg.oracle_gate:
        return GateDecision(
            admit_retrieval=True,
            reliability=1.0,
            margin=1.0,
            agreement=1.0,
            evidence_coverage=1.0,
            ambiguity=0.0,
            reason="oracle_gate",
        )

    if not scored:
        return GateDecision(
            admit_retrieval=False,
            reliability=0.0,
            margin=0.0,
            agreement=0.0,
            evidence_coverage=0.0,
            ambiguity=1.0,
            reason="no_candidates",
        )

    margin = scored[0].total - (scored[1].total if len(scored) > 1 else 0.0)
    margin = max(0.0, margin)

    ids = [s.doc_id for s in scored]
    lex_rank = _lexical_ranks(question, ids, store_text)
    lex_sorted = sorted(ids, key=lambda x: lex_rank.get(x, 999))
    agreement = _rank_agreement(ids, lex_sorted)

    evidence = sum(1 for s in scored[:3] if s.support >= 0.25) / 3.0
    ambiguity = min(1.0, len(scored) / max(1, cfg.max_confusion))

    rel = (
        cfg.w_margin * min(margin / 0.25, 1.0)
        + cfg.w_agreement * agreement
        + cfg.w_evidence * evidence
        - cfg.w_ambiguity * ambiguity
    )

    admit = rel >= cfg.reliability_threshold
    if not cfg.use_reliability_gate:
        admit = True

    return GateDecision(
        admit_retrieval=admit,
        reliability=rel,
        margin=margin,
        agreement=agreement,
        evidence_coverage=evidence,
        ambiguity=ambiguity,
        reason="admit" if admit else "fallback_closed_book",
    )
