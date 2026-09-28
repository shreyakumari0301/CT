"""Entity multi-query retrieval (graphrag_local) without importing run_controlled_smoke."""
from __future__ import annotations

import hashlib
import re
from typing import List, Tuple

EVIDENCE_TOKEN_BUDGET = 1800


def truncate_evidence(text: str, budget_tokens: int = EVIDENCE_TOKEN_BUDGET) -> str:
    max_chars = budget_tokens * 4
    t = (text or "").strip()
    if len(t) <= max_chars:
        return t
    return t[: max_chars - 20] + "\n…[truncated]"


def retrieve_graphrag_local(retriever, query: str, k: int = 5) -> Tuple[str, List[str]]:
    k_i = int(k)
    ents = re.findall(
        r"\b(?:CVE-\d{4}-\d+|CWE-\d+|T\d{4}(?:\.\d{3})?|[A-Z][a-zA-Z0-9+\-]{3,})\b",
        query,
    )
    ents = list(dict.fromkeys(ents))[:8]
    merged: dict[str, str] = {}
    for q in [query] + [str(e) for e in ents]:
        try:
            chunk = retriever.search(str(q), k=max(3, k_i))
        except Exception:  # noqa: BLE001
            continue
        if not isinstance(chunk, str):
            chunk = str(chunk or "")
        for block in chunk.split("\n\n"):
            if not block.strip():
                continue
            key = hashlib.md5(block[:200].encode()).hexdigest()
            merged[key] = block.strip()
    if not merged:
        chunk = retriever.search(query, k=k_i)
        return truncate_evidence(chunk if isinstance(chunk, str) else str(chunk or "")), ents
    return truncate_evidence("\n\n".join(list(merged.values())[:k_i])), ents
