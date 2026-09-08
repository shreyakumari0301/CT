"""Constrained behavior-to-technique matching for ATA."""

from __future__ import annotations

from typing import Dict, List, Set

from tcar.attributes import extract_ata_behaviors
from tcar.contrast import CandidateScore, _BEHAVIOR_TO_TECHNIQUE
from tcar.corpus_store import CorpusStore


def constrained_ata_select(
    question: str,
    scored: List[CandidateScore],
    store: CorpusStore,
    *,
    min_edge: float = 0.35,
) -> List[str]:
    """
    Pick techniques linked to explicit behaviors; drop unsupported extras.
    Prefer sub-technique over parent when behavior maps to sub-ID.
    """
    beh = extract_ata_behaviors(question)
    if not beh.behaviors:
        # Fall back to top-1 contrastive if any support
        for cs in scored:
            if cs.support >= 0.25 or cs.similarity >= 0.3:
                return [cs.doc_id]
        return [scored[0].doc_id] if scored else []

    allowed: Set[str] = set()
    for b in beh.behaviors:
        for tid in _BEHAVIOR_TO_TECHNIQUE.get(b["label"], []):
            allowed.add(tid.upper())

    # Score edges behavior -> candidate
    picks: List[str] = []
    for cs in scored:
        tid = cs.doc_id.upper()
        if cs.total < min_edge and tid not in allowed:
            continue
        if allowed and tid not in allowed:
            parent = tid.split(".")[0]
            if parent not in allowed and tid not in allowed:
                continue
        picks.append(tid)

    # Parent/sub dedup: if sub picked, drop parent
    final: List[str] = []
    pick_set = set(picks)
    for tid in picks:
        parent = tid.split(".")[0]
        if parent != tid and parent in pick_set:
            continue
        if tid not in final:
            final.append(tid)

    if not final and scored:
        return [scored[0].doc_id]
    return final[:3]
