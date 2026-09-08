"""
CTA-RAG on CTIConnect (Option B): task router + specialized modules on corpus_kb.

Owns graph-aware CWE/MITRE candidate diversification for CTIConnect RCM and ATA.
No EtR/DtR — same retrieval entry as vanilla_rag (raw question, top-k from task KB).
Only the post-retrieval module differs (understanding-style RCM, reasoning-style ATA).

Does not expose gold labels. Router uses task name only (rcm → understanding, ata → reasoning).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable, Dict, List, Tuple

from eval.cticonnect_kb import CTIConnectKBRetriever, format_candidates, KBHit
from eval.cticonnect_loader import QARecord
from eval.mitre_diversify import MitreDiversifyMeta, build_diversified_mitre_hits
from eval.rcm_diversify import DiversifyMeta, build_diversified_rcm_hits
from tcar.corpus_store import CorpusStore
from tcar.pipeline_prompts import (
    ATA_PROMPT_K,
    RCM_PROMPT_K,
    build_cticonnect_ata_prompt,
    build_cticonnect_rcm_prompt,
)
from tcar.taxonomy.cwe_graph import CWEGraph

_REPO_ROOT = Path(__file__).resolve().parent.parent
_CWE_GRAPH: CWEGraph | None = None


def cwe_graph() -> CWEGraph:
    global _CWE_GRAPH
    if _CWE_GRAPH is None:
        _CWE_GRAPH = CWEGraph(
            _REPO_ROOT
            / "CTICONNECT data"
            / "CTIConnect-main"
            / "construction"
            / "seeds"
            / "correlations"
            / "cwe_xrefs.jsonl"
        )
    return _CWE_GRAPH


def diversify_cwe_hits(
    dense_hits: List[KBHit],
    *,
    lookup_docs: Callable[[List[str]], List[KBHit]] | None = None,
    prompt_k: int = RCM_PROMPT_K,
    seed_n: int = 5,
    max_per_cluster: int = 3,
    audit_k: int = 20,
) -> Tuple[List[KBHit], DiversifyMeta]:
    """Shared graph-aware diversification (CTIConnect + CTIBench CWE catalogues)."""
    return build_diversified_rcm_hits(
        dense_hits,
        cwe_graph(),
        lookup_docs=lookup_docs,
        prompt_k=prompt_k,
        seed_n=seed_n,
        max_per_cluster=max_per_cluster,
        audit_k=audit_k,
    )


def retrieve_diversified_rcm_candidates(
    retriever: CTIConnectKBRetriever,
    question: str,
    *,
    k_retrieve: int = 5,
    prompt_k: int | None = None,
) -> Tuple[List[KBHit], List[KBHit], DiversifyMeta]:
    """
    CTIConnect RCM retrieval for the prompt.

    Returns (audit_hits top-20, prompt_hits diversified K, diversify meta).
    """
    pk = max(k_retrieve, prompt_k or RCM_PROMPT_K)
    hits = retriever.retrieve_for_task(question, "rcm", k=max(pk, 20))
    audit_hits = hits[:20]
    prompt_hits, meta = diversify_cwe_hits(
        hits,
        lookup_docs=lambda ids: retriever.get_docs("cwe", ids),
        prompt_k=pk,
        seed_n=5,
        max_per_cluster=3,
        audit_k=20,
    )
    return audit_hits, prompt_hits, meta


_MITRE_SUBS: Dict[str, set[str]] | None = None


def _mitre_subs_by_parent(corpus_dir: Path | None = None) -> Dict[str, set[str]]:
    """Parent → sub-technique IDs from corpus_kb/mitre.jsonl (same role as CWE graph edges)."""
    global _MITRE_SUBS
    if _MITRE_SUBS is not None:
        return _MITRE_SUBS
    root = corpus_dir or (
        _REPO_ROOT / "CTICONNECT data" / "CTIConnect-main" / "corpus_kb"
    )
    store = CorpusStore(root)
    store._load_mitre()
    _MITRE_SUBS = {k: set(v) for k, v in store._mitre_subs.items()}
    return _MITRE_SUBS


def diversify_mitre_hits(
    dense_hits: List[KBHit],
    *,
    lookup_docs: Callable[[List[str]], List[KBHit]] | None = None,
    prompt_k: int = ATA_PROMPT_K,
    seed_n: int = 5,
    max_per_cluster: int = 3,
    corpus_dir: Path | None = None,
) -> Tuple[List[KBHit], MitreDiversifyMeta]:
    """Shared MITRE graph-aware diversification (same shape as CWE diversify for RCM)."""
    return build_diversified_mitre_hits(
        dense_hits,
        lookup_docs=lookup_docs or (lambda _ids: []),
        subs_by_parent=_mitre_subs_by_parent(corpus_dir),
        prompt_k=prompt_k,
        seed_n=seed_n,
        max_per_cluster=max_per_cluster,
    )


def retrieve_diversified_ata_candidates(
    retriever: CTIConnectKBRetriever,
    question: str,
    *,
    k_retrieve: int = 5,
    prompt_k: int | None = None,
) -> Tuple[List[KBHit], List[KBHit], MitreDiversifyMeta]:
    """
    CTIConnect ATA / MITRE retrieval for the prompt — same GAD pipeline as RCM:
    dense top-20 → seed top-5 → parent/sub expand → diversify select K=12.
    """
    pk = max(k_retrieve, prompt_k or ATA_PROMPT_K)
    hits = retriever.retrieve_for_task(question, "ata", k=max(pk, 20))
    audit_hits = hits[:20]
    prompt_hits, meta = diversify_mitre_hits(
        hits,
        lookup_docs=lambda ids: retriever.get_docs("mitre", ids),
        prompt_k=pk,
        seed_n=5,
        max_per_cluster=3,
        corpus_dir=retriever.corpus_dir,
    )
    return audit_hits, prompt_hits, meta


def _route(task: str) -> str:
    if task == "rcm":
        return "understanding"
    if task == "ata":
        return "reasoning_ate"
    raise ValueError(f"cta_rag_port unsupported task: {task!r}")


def predict_rcm(qa: QARecord, ctx: Dict[str, Any], *, chat: Callable[..., str]) -> str:
    retriever: CTIConnectKBRetriever = ctx["cti_kb"]
    _, prompt_hits, _ = retrieve_diversified_rcm_candidates(
        retriever,
        qa.question,
        k_retrieve=int(ctx.get("k", 5)),
    )
    return chat(
        build_cticonnect_rcm_prompt(
            question=qa.question,
            candidates=format_candidates(prompt_hits),
        ),
        max_tokens=512,
    )


def predict_ata(qa: QARecord, ctx: Dict[str, Any], *, chat: Callable[..., str]) -> str:
    """CTIConnect ATA only (MITRE). Same GAD pipeline as RCM: diversify → K=12."""
    retriever: CTIConnectKBRetriever = ctx["cti_kb"]
    k = max(int(ctx.get("k", 5)), ATA_PROMPT_K)
    _, prompt_hits, _ = retrieve_diversified_ata_candidates(
        retriever, qa.question, k_retrieve=int(ctx.get("k", 5)), prompt_k=k
    )
    return chat(
        build_cticonnect_ata_prompt(
            question=qa.question,
            candidates=format_candidates(prompt_hits),
        ),
        max_tokens=800,
    )


def predict(qa: QARecord, ctx: Dict[str, Any], *, chat: Callable[..., str]) -> str:
    module = _route(qa.task)
    if module == "understanding":
        return predict_rcm(qa, ctx, chat=chat)
    if module == "reasoning_ate":
        return predict_ata(qa, ctx, chat=chat)
    raise ValueError(f"unknown module {module!r}")
