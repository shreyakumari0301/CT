"""RCM mechanism-aware hybrid retrieval (dense + BM25 → RRF → taxonomy).

Enable with:
  RCM_GAD=off
  RCM_PIPELINE=hybrid
  RCM_RERANK=taxonomy
  RCM_PROMPT=soft
  RCM_DIVERSIFY=0
  RCM_TOP_K=3
"""

from __future__ import annotations

import json
import os
import re
import threading
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

from eval.cticonnect_kb import KBHit
from tcar.specialist_retrieval import (
    _norm_cwe,
    env_flag,
    format_cwe_hits_for_prompt,
    gold_in_top_n,
    rerank_cwe_taxonomy,
)

ROOT = Path(__file__).resolve().parent.parent
CHUNKS_PATH = ROOT / "vector_dbs" / "understanding_vdbs" / "faiss_cwe" / "chunks_cwe.json"
CONNECT_CWE = (
    ROOT / "CTICONNECT data" / "CTIConnect-main" / "corpus_kb" / "cwe.jsonl"
)

_PRODUCT_RE = re.compile(
    r"\b("
    r"windows|linux|macos|android|ios|chrome|firefox|safari|edge|"
    r"apache|nginx|iis|tomcat|wordpress|drupal|joomla|magento|"
    r"oracle|mysql|postgres|mongodb|redis|elasticsearch|"
    r"cisco|fortinet|palo\s*alto|juniper|vmware|citrix|"
    r"microsoft|google|apple|adobe|ibm|sap|samsung|"
    r"openssl|openssh|libxml|imagemagick|ffmpeg|"
    r"php|python|java|javascript|node\.?js|\.net|asp\.net|"
    r"cve-\d{4}-\d+|version\s+[\d.]+|v?\d+\.\d+(?:\.\d+)*"
    r")\b",
    re.I,
)
_CONSEQUENCE_LEAD = re.compile(
    r"\b(allow(?:s|ing)?|enabl(?:e|es|ing)|result(?:s|ing)? in|lead(?:s|ing)? to|"
    r"caus(?:e|es|ing)|can be used to|attacker(?:s)? can)\b",
    re.I,
)
_MECH_PATTERNS: Tuple[Tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"directory traversal|\.\./|pathname|path traversal", re.I),
     "Improper pathname restriction allowing directory traversal and arbitrary file access"),
    (re.compile(r"sql\s*injection|blind sql", re.I),
     "Improper neutralization of special elements in SQL commands (SQL injection)"),
    (re.compile(r"command\s*injection|os command|shell command", re.I),
     "Improper neutralization of special elements used in an OS command"),
    (re.compile(r"cross-?site\s*script|xss", re.I),
     "Improper neutralization of input during web page generation (XSS)"),
    (re.compile(r"xml\s*external|xxe", re.I),
     "Improper restriction of XML external entity reference"),
    (re.compile(r"server-?side\s*request|ssrf", re.I),
     "Server-side request forgery allowing attacker-controlled outbound requests"),
    (re.compile(r"buffer\s*overflow|stack\s*overflow|heap\s*overflow", re.I),
     "Buffer copy without checking size of input (buffer overflow)"),
    (re.compile(r"use\s*after\s*free", re.I),
     "Use after free memory corruption"),
    (re.compile(r"integer\s*overflow", re.I),
     "Integer overflow or wraparound"),
    (re.compile(r"deserializ", re.I),
     "Deserialization of untrusted data"),
    (re.compile(r"path\s*traversal|arbitrary\s*file\s*(read|write|access)", re.I),
     "Improper limitation of a pathname to a restricted directory"),
    (re.compile(r"missing\s*authenticat|no\s*authenticat|without\s*authenticat|unauthenticated", re.I),
     "Missing authentication for critical function"),
    (re.compile(r"missing\s*authoriz|improper\s*access\s*control|privilege\s*escalat", re.I),
     "Improper access control / authorization"),
    (re.compile(r"hardcoded?\s*(password|credential|secret|key)", re.I),
     "Use of hard-coded credentials"),
    (re.compile(r"open\s*redirect", re.I),
     "URL redirection to untrusted site (open redirect)"),
    (re.compile(r"csrf|cross-?site\s*request\s*forgery", re.I),
     "Cross-site request forgery"),
    (re.compile(r"race\s*condition", re.I),
     "Concurrent execution using shared resource with improper synchronization"),
    (re.compile(r"information\s*disclosure|sensitive\s*(data|information)\s*(leak|expos)", re.I),
     "Exposure of sensitive information to an unauthorized actor"),
)


def rcm_pipeline_mode() -> str:
    raw = env_flag("RCM_PIPELINE", "default")
    if raw in {"hybrid", "mechanism", "mech", "mech_hybrid", "mechanism_hybrid", "1"}:
        return "hybrid"
    if raw in {
        "vanilla_advisory",
        "advisory",
        "kb_advisory",
        "kb_primary",
        "verify",
    }:
        return "vanilla_advisory"
    return "default"


def normalize_rcm_mechanism_query(description: str) -> str:
    """Strip products/versions/consequence fluff; keep root weakness language."""
    text = (description or "").strip()
    if not text:
        return ""
    for pat, label in _MECH_PATTERNS:
        if pat.search(text):
            return label
    # Generic cleanup: drop product tokens and compress.
    cleaned = _PRODUCT_RE.sub(" ", text)
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    # Prefer clause after consequence lead if present.
    m = _CONSEQUENCE_LEAD.search(cleaned)
    if m and m.start() > 20:
        head = cleaned[: m.start()].strip(" .,;")
        if len(head.split()) >= 4:
            cleaned = head
    # Keep first ~40 tokens
    toks = cleaned.split()
    if len(toks) > 40:
        cleaned = " ".join(toks[:40])
    return cleaned or text[:240]


def _tokenize(text: str) -> List[str]:
    return re.findall(r"[a-z0-9]+", (text or "").lower())


class CweHybridRetriever:
    """BM25 over enriched CWE docs + dense FAISS fusion via RRF."""

    _lock = threading.Lock()
    _instance: Optional["CweHybridRetriever"] = None

    def __init__(self) -> None:
        self.rows: List[dict] = []
        self.docs: List[str] = []
        self.tokens: List[List[str]] = []
        self.by_id: Dict[str, dict] = {}
        self._bm25 = None
        self._load()

    @classmethod
    def get(cls) -> "CweHybridRetriever":
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance

    def _load_connect_enrichment(self) -> Dict[str, str]:
        out: Dict[str, str] = {}
        if not CONNECT_CWE.exists():
            return out
        for line in CONNECT_CWE.read_text(encoding="utf-8", errors="replace").splitlines():
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            cid = _norm_cwe(str(row.get("cwe_id") or row.get("id") or ""))
            if not cid:
                continue
            contents = row.get("contents")
            if isinstance(contents, str):
                try:
                    contents = json.loads(contents)
                except json.JSONDecodeError:
                    contents = {"raw": contents}
            parts: List[str] = []
            title = str(row.get("title") or "")
            if title:
                parts.append(title)
            if isinstance(contents, dict):
                for key in (
                    "Description",
                    "Extended_Description",
                    "Common_Consequences",
                    "Modes_Of_Introduction",
                    "Detection_Methods",
                    "Applicable_Platforms",
                    "Potential_Mitigations",
                    "raw",
                ):
                    val = contents.get(key)
                    if val:
                        parts.append(f"{key}: {val}" if key != "raw" else str(val))
            meta = row.get("metadata") or {}
            if isinstance(meta, dict):
                for key in ("parent", "parents", "children", "child", "related"):
                    if meta.get(key):
                        parts.append(f"{key}: {meta.get(key)}")
            out[cid] = "\n".join(parts)
        return out

    def _load(self) -> None:
        from rank_bm25 import BM25Okapi  # noqa: WPS433

        raw_rows = json.loads(CHUNKS_PATH.read_text(encoding="utf-8"))
        enrich = self._load_connect_enrichment()
        docs: List[str] = []
        rows: List[dict] = []
        for entry in raw_rows:
            cid = _norm_cwe(str(entry.get("cwe_id") or ""))
            if not cid:
                continue
            name = str(entry.get("name") or "")
            desc = str(entry.get("description") or "")
            ext = str(entry.get("extended_description") or "")
            text = str(entry.get("text") or "")
            body_parts = [
                f"CWE ID: {cid}",
                f"Name: {name}",
                f"Description: {desc}",
            ]
            if ext:
                body_parts.append(f"Extended: {ext}")
            if text and text not in desc:
                body_parts.append(f"Text: {text}")
            extra = enrich.get(cid)
            if extra:
                body_parts.append(f"Enrichment:\n{extra}")
            # Alternate terms: name tokens + common aliases from description first sentence
            body_parts.append(f"Alternate terms: {name}")
            doc = "\n".join(body_parts)
            rows.append(
                {
                    "cwe_id": cid,
                    "name": name,
                    "description": desc,
                    "extended_description": ext,
                    "text": text or desc,
                    "enriched": doc,
                }
            )
            docs.append(doc)
            self.by_id[cid] = rows[-1]
        self.rows = rows
        self.docs = docs
        self.tokens = [_tokenize(d) for d in docs]
        self._bm25 = BM25Okapi(self.tokens)

    def bm25_retrieve(self, query: str, k: int = 20) -> List[KBHit]:
        assert self._bm25 is not None
        q = _tokenize(query)
        if not q:
            return []
        scores = self._bm25.get_scores(q)
        order = sorted(range(len(scores)), key=lambda i: float(scores[i]), reverse=True)[:k]
        hits: List[KBHit] = []
        for i in order:
            row = self.rows[i]
            hits.append(
                KBHit(
                    doc_id=row["cwe_id"],
                    title=row["name"],
                    text=(row.get("text") or row.get("description") or "")[:700],
                    score=float(scores[i]),
                )
            )
        return hits

    def row_to_hit(self, cid: str, score: float) -> Optional[KBHit]:
        row = self.by_id.get(_norm_cwe(cid))
        if not row:
            return None
        return KBHit(
            doc_id=row["cwe_id"],
            title=row["name"],
            text=(row.get("text") or row.get("description") or "")[:700],
            score=score,
        )


def reciprocal_rank_fusion(
    rank_lists: Sequence[Sequence[str]],
    *,
    k: int = 60,
) -> List[Tuple[str, float]]:
    scores: Dict[str, float] = {}
    for ranks in rank_lists:
        for i, cid in enumerate(ranks, start=1):
            cid = _norm_cwe(cid)
            if not cid:
                continue
            scores[cid] = scores.get(cid, 0.0) + 1.0 / (k + i)
    return sorted(scores.items(), key=lambda x: (-x[1], x[0]))


def hybrid_retrieve_cwe(
    description: str,
    dense_retriever,
    *,
    pool_k: int = 20,
    rrf_k: int = 60,
) -> Tuple[List[KBHit], dict]:
    """Mechanism-normalized dense + BM25 → RRF pool."""
    mech = normalize_rcm_mechanism_query(description)
    hybrid = CweHybridRetriever.get()
    dense_q = mech or description
    dense_hits = dense_retriever.retrieve(dense_q, "cwe", k=pool_k)
    # Also retrieve with original description to avoid missing lexical product-specific CWEs
    dense_raw = dense_retriever.retrieve(description, "cwe", k=pool_k)
    bm25_hits = hybrid.bm25_retrieve(dense_q, k=pool_k)
    bm25_raw = hybrid.bm25_retrieve(description, k=max(10, pool_k // 2))

    dense_ids = list(
        dict.fromkeys([_norm_cwe(h.doc_id) for h in dense_hits + dense_raw if h.doc_id])
    )
    bm25_ids = list(
        dict.fromkeys([_norm_cwe(h.doc_id) for h in bm25_hits + bm25_raw if h.doc_id])
    )
    union_ids = list(dict.fromkeys(dense_ids + bm25_ids))

    lists = [
        [_norm_cwe(h.doc_id) for h in dense_hits],
        [_norm_cwe(h.doc_id) for h in dense_raw],
        [_norm_cwe(h.doc_id) for h in bm25_hits],
        [_norm_cwe(h.doc_id) for h in bm25_raw],
    ]
    fused = reciprocal_rank_fusion(lists, k=rrf_k)
    by_best: Dict[str, KBHit] = {}
    for group in (dense_hits, dense_raw, bm25_hits, bm25_raw):
        for h in group:
            cid = _norm_cwe(h.doc_id)
            prev = by_best.get(cid)
            if prev is None or float(h.score or 0) > float(prev.score or 0):
                by_best[cid] = h

    out: List[KBHit] = []
    for cid, score in fused[:pool_k]:
        hit = by_best.get(cid) or hybrid.row_to_hit(cid, score)
        if hit is None:
            continue
        out.append(KBHit(doc_id=hit.doc_id, title=hit.title, text=hit.text, score=float(score)))
    rrf_ids = [_norm_cwe(h.doc_id) for h in out]
    meta = {
        "rcm_pipeline": "mechanism_hybrid",
        "mechanism_query": mech,
        "n_dense_mech": len(dense_hits),
        "n_dense_raw": len(dense_raw),
        "n_bm25_mech": len(bm25_hits),
        "n_bm25_raw": len(bm25_raw),
        "dense_ids": dense_ids[:pool_k],
        "bm25_ids": bm25_ids[:pool_k],
        "union_ids": union_ids,
        "rrf_ids": rrf_ids,
        "pool_ids": rrf_ids,
        "n_union": len(union_ids),
        "n_rrf": len(rrf_ids),
        # Fraction of union members retained in RRF top-20 (fusion retention proxy)
        "rrf_retention_of_union": (
            len(set(rrf_ids) & set(union_ids)) / max(1, min(pool_k, len(union_ids)))
        ),
    }
    return out, meta


def format_rcm_contrast_candidates(hits: Sequence[KBHit], mechanism_query: str) -> str:
    """Top contrasting CWEs with mechanism-first decision rule."""
    if not hits:
        return "No CWE candidates available."
    lines = [
        "CONTRASTING CWE CANDIDATES (choose the most specific root weakness supported):",
        f'Observed mechanism: "{mechanism_query}"',
        "",
    ]
    for h in hits:
        cid = _norm_cwe(h.doc_id) or h.doc_id
        lines.append(f"{cid}: {h.title or ''}")
        lines.append(f"  {(h.text or '')[:420]}")
        lines.append("")
    lines.append(
        "Decision: return exactly one CWE that matches the observed mechanism. "
        "Prefer the most specific root weakness directly supported; do not pick a "
        "sibling or symptom variant merely because it appears in the list."
    )
    return "\n".join(lines)


def rcm_advisory_mode() -> str:
    """Advisory catalogue size/style for vanilla_advisory pipeline.

    top1 — densest taxonomy top-1 only (minimum distraction)
    contrast — top-3 with parent/sibling labels for abstraction errors
    """
    raw = env_flag("RCM_ADVISORY", "top1")
    if raw in {"contrast", "parent_sibling", "ps", "graph"}:
        return "contrast"
    return "top1"


def format_rcm_advisory_candidates(
    hits: Sequence[KBHit],
    *,
    mode: str = "top1",
    graph=None,
) -> str:
    """Taxonomy candidates as verification-only (not primary evidence)."""
    if not hits:
        return "No advisory CWE candidates."
    use = list(hits[:1] if mode == "top1" else hits[:3])
    lines = [
        "ADVISORY CWE CANDIDATES (verify only — do not override a KB-supported answer):",
        "",
    ]
    seed = _norm_cwe(use[0].doc_id) if use else ""
    for h in use:
        cid = _norm_cwe(h.doc_id) or h.doc_id
        rel = ""
        if graph is not None and seed and cid != seed:
            if graph.parent_of.get(cid) == seed:
                rel = " [child of top-1]"
            elif graph.parent_of.get(seed) == cid:
                rel = " [parent of top-1]"
            elif cid in graph.siblings(seed):
                rel = " [sibling of top-1]"
        lines.append(f"{cid}{rel}: {h.title or ''}")
        lines.append(f"  {(h.text or '')[:360]}")
        lines.append("")
    if mode == "contrast":
        lines.append(
            "If candidates are parent/child/sibling of each other, pick the abstraction "
            "level that matches the DESCRIPTION + KB mechanism — not a near-miss neighbour."
        )
    lines.append(
        "Verification rule: keep the KB/description CWE unless a candidate clearly "
        "matches the same root mechanism more precisely."
    )
    return "\n".join(lines)


def retrieve_rcm_mechanism_hybrid(
    description: str,
    dense_retriever,
    *,
    pool_k: int = 20,
    top_k: int = 3,
    gold_ids: Optional[Sequence[str]] = None,
) -> Tuple[List[KBHit], List[KBHit], dict]:
    """Full specialist pool: hybrid@20 → taxonomy rerank → top_k (no diversify)."""
    pool, meta = hybrid_retrieve_cwe(description, dense_retriever, pool_k=pool_k)
    mech = meta.get("mechanism_query") or normalize_rcm_mechanism_query(description)
    selected = rerank_cwe_taxonomy(
        mech or description,
        pool,
        top_k=top_k,
        diversify=False,
        lookup_docs=getattr(dense_retriever, "get_docs_cwe", None),
    )
    gold = list(gold_ids or [])
    meta["gold_at_pool"] = gold_in_top_n(pool, gold, n=len(pool) or pool_k)
    meta["gold_at_selected"] = gold_in_top_n(selected, gold, n=top_k)
    meta["selected_ids"] = [h.doc_id for h in selected]
    meta["top_k"] = top_k
    return pool, selected, meta
