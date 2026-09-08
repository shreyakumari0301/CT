"""Gate candidate scoring for chunk-based tasks (MCQ, VSP) without taxonomy contrast."""

from __future__ import annotations

import re
from typing import List

from eval.cticonnect_kb import KBHit

from tcar.contrast import CandidateScore

_TOKEN_RE = re.compile(r"[a-z0-9]{4,}")


def _token_overlap(question: str, text: str) -> float:
    qtok = set(_TOKEN_RE.findall((question or "").lower()))
    dtok = set(_TOKEN_RE.findall((text or "").lower()))
    if not qtok or not dtok:
        return 0.0
    return len(qtok & dtok) / len(qtok | dtok)


def hits_to_scored(question: str, hits: List[KBHit]) -> List[CandidateScore]:
    """
    Score retrieved chunks for the reliability gate.

  Uses embedding similarity plus lexical query–chunk overlap as support
  (fixes the MCQ/VSP bug where support was always 0.0).
    """
    scored: List[CandidateScore] = []
    for h in hits:
        overlap = _token_overlap(question, h.text)
        support = min(1.0, overlap * 2.5)
        total = float(h.score) + 0.45 * support
        scored.append(
            CandidateScore(
                doc_id=h.doc_id,
                similarity=float(h.score),
                support=support,
                contradiction=0.0,
                abstraction_penalty=0.0,
                total=total,
                support_notes=[f"Lexical overlap {overlap:.2f}"] if overlap > 0.1 else [],
            )
        )
    scored.sort(key=lambda x: x.total, reverse=True)
    return scored
