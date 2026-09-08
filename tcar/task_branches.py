"""Per-task counterfactual branches — each task uses its CTA-RAG pipeline prompt form."""

from __future__ import annotations

import os
import re
import threading
from dataclasses import asdict
from pathlib import Path
from typing import Any, Callable, Dict, List, Tuple, Union

from eval.cticonnect_kb import CTIConnectKBRetriever, format_candidates, KBHit
from eval.cta_rag_port import (
    retrieve_diversified_ata_candidates,
    retrieve_diversified_rcm_candidates,
)
from tcar.config import TCARConfig
from tcar.ctibench_kb import CTIBenchKBRetriever
from tcar.gate import GateDecision, evaluate_gate
from tcar.gate_scoring import hits_to_scored
from tcar.pipeline_prompts import (
    ATA_PROMPT_K,
    OTHER_GAD_K,
    RCM_PROMPT_K,
    build_ate_exploitation_prompt,
    build_ate_prompt,
    build_cticonnect_ata_behavior_prompt,
    build_cticonnect_ata_grounded_prompt,
    build_cticonnect_ata_prompt,
    build_cticonnect_rcm_prompt,
    build_mcq_prompt,
    build_understanding_rcm_prompt,
    build_vsp_prompt,
    empty_candidates,
    empty_mem_context,
    empty_rcm_cwe_context,
    empty_rcm_kb_context,
)
from tcar.specialist_retrieval import (
    apply_rcm_oracle_pin,
    ata_abstain_enabled,
    ate_prompt_mode,
    env_flag,
    filter_ata_to_evidence,
    format_cwe_hits_for_prompt,
    gold_in_top_n,
    mcq_abstain_enabled,
    mcq_option_queries,
    mcq_retrieval_mode,
    mcq_should_prefer_closed_book,
    merge_option_hits,
    rcm_oracle_mode,
    rcm_rerank_mode,
    rerank_cwe_learned,
    rerank_cwe_taxonomy,
    vsp_metric_case_block,
    vsp_retrieval_mode,
)

from utils.cve_sanitize import is_query_near_dup, sanitize_cve_store_passage

_REPO_ROOT = Path(__file__).resolve().parent.parent
_GAD_TL = threading.local()

Retriever = Union[CTIConnectKBRetriever, CTIBenchKBRetriever]

_BRANCH_RESULT = Tuple[str, str, GateDecision, List[KBHit], dict]

RCM_RETRIEVAL_CORPUS_KB = "corpus_kb"
RCM_RETRIEVAL_CTIBENCH = "ctibench"


def resolve_rcm_retrieval(explicit: str | None = None) -> str:
    """RCM retrieval backend for CTIConnect: corpus_kb (default) or ctibench."""
    raw = (explicit or os.getenv("RCM_RETRIEVAL") or RCM_RETRIEVAL_CORPUS_KB).strip().lower()
    if raw in {RCM_RETRIEVAL_CTIBENCH, "ctibench_kb", "memorization_vdb"}:
        return RCM_RETRIEVAL_CTIBENCH
    return RCM_RETRIEVAL_CORPUS_KB


def _store_text(hits: List[KBHit]) -> Dict[str, str]:
    return {h.doc_id: h.text for h in hits}


def gad_mode() -> str:
    """Force / Soft GAD for ATE, MCQ, VSP. Unset = original mem/case prompts."""
    raw = (os.getenv("GAD_MODE") or "off").strip().lower()
    if raw in {"force", "soft"}:
        return raw
    return "off"


def rcm_gad_mode() -> str:
    """CTIBench/Connect RCM catalogue mode: off = Forced RAG (no graph diversify); force = Force GAD."""
    raw = (os.getenv("RCM_GAD") or "force").strip().lower()
    if raw in {"off", "0", "false", "no", "forced_rag", "dense"}:
        return "off"
    return "force"


def ata_gad_mode() -> str:
    """CTIConnect ATA: off = Forced RAG (dense top-k); force = same Force GAD as RCM (K=12 diversify)."""
    raw = (os.getenv("ATA_GAD") or os.getenv("RCM_GAD") or "force").strip().lower()
    if raw in {"off", "0", "false", "no", "forced_rag", "dense"}:
        return "off"
    return "force"


def _connect_catalogue() -> CTIConnectKBRetriever:
    kb = getattr(_GAD_TL, "connect_kb", None)
    if kb is None:
        kb = CTIConnectKBRetriever(
            corpus_dir=_REPO_ROOT / "CTICONNECT data" / "CTIConnect-main" / "corpus_kb"
        )
        _GAD_TL.connect_kb = kb
    return kb


def _collapse_mitre_hits_to_main(hits: List[KBHit]) -> List[KBHit]:
    """Prefer main technique IDs in catalogue (ATE gold is main-only; subs tempt extras)."""
    out: List[KBHit] = []
    seen: set[str] = set()
    for h in hits:
        tid = (h.doc_id or "").upper().split(".")[0]
        if not tid.startswith("T") or tid in seen:
            continue
        seen.add(tid)
        title = h.title or tid
        if "." in (h.doc_id or ""):
            title = f"{tid} (parent of {h.doc_id})"
        out.append(KBHit(doc_id=tid, title=title, text=h.text, score=h.score))
    return out


def _mitre_gad_catalogue(
    query: str,
    *,
    prompt_k: int = OTHER_GAD_K,
    main_techniques_only: bool = False,
) -> Tuple[str, List[KBHit], dict]:
    """MITRE GAD catalogue — same pipeline as RCM CWE GAD (via retrieve_diversified_ata_candidates)."""
    kb = _connect_catalogue()
    _, hits, meta = retrieve_diversified_ata_candidates(
        kb, query, k_retrieve=5, prompt_k=prompt_k
    )
    if main_techniques_only:
        hits = _collapse_mitre_hits_to_main(hits)
        meta_d = asdict(meta)
        meta_d["main_techniques_only"] = True
        meta_d["selected_ids"] = [h.doc_id for h in hits]
        return format_candidates(hits), hits, meta_d
    return format_candidates(hits), hits, asdict(meta)


def _cwe_gad_catalogue(query: str, *, prompt_k: int = OTHER_GAD_K) -> Tuple[str, List[KBHit], dict]:
    kb = _connect_catalogue()
    _, prompt_hits, meta = retrieve_diversified_rcm_candidates(
        kb, query, k_retrieve=5, prompt_k=prompt_k
    )
    return format_candidates(prompt_hits), prompt_hits, asdict(meta)


def _format_mem_context(hits: List[KBHit], *, cta_style: bool = False) -> str:
    if not hits:
        return empty_mem_context()
    blocks: List[str] = []
    for h in hits:
        if cta_style:
            # Match reasoning_ate_pipeline: prefer title/url-like source string.
            source = h.title or h.doc_id or "Unknown"
        else:
            source = h.title if h.title and not str(h.title).startswith("T") else "Unknown"
        blocks.append(f"Source: {source}\nContent: {h.text}")
    return "\n\n".join(blocks)


def _run_rcm_ctibench_retrieval(
    question: str,
    retriever: CTIBenchKBRetriever,
    cfg: TCARConfig,
    *,
    prompt_style: str,
    gold_ids: List[str] | None = None,
) -> Tuple[str, str, GateDecision, List[KBHit], dict]:
    """CTIBench RCM: mem KB + optional CWE (Forced RAG) or Force GAD diversify.

    Specialist ranking (Forced RAG path only), via env:
      RCM_PIPELINE=hybrid — mechanism query + BM25/dense RRF → taxonomy top-k (no diversify)
      RCM_RERANK=taxonomy|learned — dense CWE top-20 → rerank → diversified top-5
      RCM_ORACLE=gold_pin  — pin gold if in/lookupable from top-20 (headroom bound)
      RCM_ORACLE=gold_at20_log — log gold@20 only
    """
    mode = rcm_gad_mode()
    gold_ids = gold_ids or []
    if mode == "off":
        from tcar.rcm_mechanism_hybrid import (  # noqa: WPS433
            format_rcm_contrast_candidates,
            normalize_rcm_mechanism_query,
            rcm_pipeline_mode,
            retrieve_rcm_mechanism_hybrid,
        )

        from tcar.rcm_mechanism_hybrid import (  # noqa: WPS433
            format_rcm_advisory_candidates,
            rcm_advisory_mode,
        )

        rerank = rcm_rerank_mode()
        oracle = rcm_oracle_mode()
        pipeline = rcm_pipeline_mode()
        use_pool = (
            rerank != "off"
            or oracle != "off"
            or pipeline in {"hybrid", "vanilla_advisory"}
        )
        pool_k = int(os.getenv("RCM_POOL") or "20")
        top_k = int(
            os.getenv("RCM_TOP_K")
            or (
                "3"
                if pipeline == "hybrid"
                else ("3" if pipeline == "vanilla_advisory" else str(max(cfg.k_retrieve, 5)))
            )
        )
        if use_pool:
            # Always pull a CWE pool for ranking experiments (even if CWE default off).
            kb_hits = retriever.retrieve_mem_chunks(question, k=cfg.k_retrieve)
            hybrid_meta: dict = {}
            if pipeline == "vanilla_advisory":
                # Vanilla KB primary; taxonomy candidates advisory only (top-1 or contrast).
                adv = rcm_advisory_mode()
                cwe_pool = retriever.retrieve(question, "cwe", k=pool_k)
                oracle_meta = gold_in_top_n(cwe_pool, gold_ids, n=pool_k)
                selected = rerank_cwe_taxonomy(
                    question,
                    list(cwe_pool),
                    top_k=max(top_k, 3 if adv == "contrast" else 1),
                    diversify=False,
                    lookup_docs=retriever.get_docs_cwe,
                )
                n_show = 1 if adv == "top1" else 3
                cwe_hits = selected[:n_show]
                graph = None
                try:
                    from tcar.taxonomy.cwe_graph import CWEGraph  # noqa: WPS433

                    graph = CWEGraph(cfg.cwe_xrefs)
                except Exception:
                    graph = None
                cwe_ctx = format_rcm_advisory_candidates(
                    cwe_hits, mode=adv, graph=graph
                )
                div_strategy = f"vanilla_advisory_{adv}"
                mech_q = ""
                hybrid_meta = {
                    "advisory_mode": adv,
                    "selected_ids": [h.doc_id for h in cwe_hits],
                    "top_k": n_show,
                }
                os.environ.setdefault("RCM_PROMPT", "advisory")
            elif pipeline == "hybrid":
                cwe_pool, selected, hybrid_meta = retrieve_rcm_mechanism_hybrid(
                    question,
                    retriever,
                    pool_k=pool_k,
                    top_k=top_k,
                    gold_ids=gold_ids,
                )
                mech_q = hybrid_meta.get("mechanism_query") or normalize_rcm_mechanism_query(question)
                oracle_meta = hybrid_meta.get("gold_at_pool") or gold_in_top_n(cwe_pool, gold_ids, n=pool_k)
                cwe_hits = selected
                cwe_ctx = format_rcm_contrast_candidates(cwe_hits, mech_q)
                div_strategy = "mechanism_hybrid_taxonomy"
                # Force description-first soft prompt for hybrid specialist
                os.environ.setdefault("RCM_PROMPT", "soft")
            else:
                cwe_pool = retriever.retrieve(question, "cwe", k=pool_k)
                oracle_meta = gold_in_top_n(cwe_pool, gold_ids, n=pool_k)
                selected = list(cwe_pool)
                if oracle == "gold_pin":
                    selected, pin_meta = apply_rcm_oracle_pin(
                        selected,
                        gold_ids,
                        lookup_docs=retriever.get_docs_cwe,
                        top_k=top_k,
                    )
                    oracle_meta.update(pin_meta)
                elif rerank == "learned":
                    selected = rerank_cwe_learned(
                        question,
                        selected,
                        top_k=top_k,
                        lookup_docs=retriever.get_docs_cwe,
                    )
                elif rerank == "taxonomy":
                    selected = rerank_cwe_taxonomy(
                        question,
                        selected,
                        top_k=top_k,
                        diversify=False if env_flag("RCM_DIVERSIFY", "0") in {"0", "false", "off", "no"} else None,
                        lookup_docs=retriever.get_docs_cwe,
                    )
                else:
                    selected = selected[:top_k]
                cwe_hits = selected
                cwe_ctx = format_cwe_hits_for_prompt(cwe_hits)
                div_strategy = None
                if rerank in {"taxonomy", "learned"}:
                    div_strategy = f"{rerank}_rerank"
                mech_q = ""
            if kb_hits:
                kb_ctx = "\n\n".join(
                    f"Source: {h.title or 'Unknown'}\nContent: {h.text}" for h in kb_hits
                )
            else:
                kb_ctx = empty_rcm_kb_context()
            gate_hits = kb_hits or cwe_hits
            scored = hits_to_scored(question, gate_hits)
            gate = evaluate_gate(question, scored, _store_text(gate_hits), cfg)
            # Hybrid / advisory: force the matching prompt style for this call
            if pipeline == "hybrid":
                prev_prompt = os.environ.get("RCM_PROMPT")
                os.environ["RCM_PROMPT"] = "soft"
                rag_prompt = build_understanding_rcm_prompt(
                    query=question, kb_context=kb_ctx, cwe_context=cwe_ctx
                )
                cb_prompt = build_understanding_rcm_prompt(
                    query=question,
                    kb_context=empty_rcm_kb_context(),
                    cwe_context=empty_rcm_cwe_context(),
                )
                if prev_prompt is None:
                    os.environ.pop("RCM_PROMPT", None)
                else:
                    os.environ["RCM_PROMPT"] = prev_prompt
            elif pipeline == "vanilla_advisory":
                prev_prompt = os.environ.get("RCM_PROMPT")
                os.environ["RCM_PROMPT"] = "advisory"
                rag_prompt = build_understanding_rcm_prompt(
                    query=question, kb_context=kb_ctx, cwe_context=cwe_ctx
                )
                cb_prompt = build_understanding_rcm_prompt(
                    query=question,
                    kb_context=empty_rcm_kb_context(),
                    cwe_context=empty_rcm_cwe_context(),
                )
                if prev_prompt is None:
                    os.environ.pop("RCM_PROMPT", None)
                else:
                    os.environ["RCM_PROMPT"] = prev_prompt
            else:
                rag_prompt = build_understanding_rcm_prompt(
                    query=question, kb_context=kb_ctx, cwe_context=cwe_ctx
                )
                cb_prompt = build_understanding_rcm_prompt(
                    query=question,
                    kb_context=empty_rcm_kb_context(),
                    cwe_context=empty_rcm_cwe_context(),
                )
            meta = {
                "prompt_style": (
                    "understanding_rcm_mechanism_hybrid"
                    if pipeline == "hybrid"
                    else (
                        "understanding_rcm_vanilla_advisory"
                        if pipeline == "vanilla_advisory"
                        else (prompt_style or "understanding_pipeline_forced_rag_ranked")
                    )
                ),
                "rcm_retrieval": RCM_RETRIEVAL_CTIBENCH,
                "rcm_gad": "off",
                "rcm_pipeline": pipeline,
                "rcm_rerank": (
                    "taxonomy"
                    if pipeline in {"hybrid", "vanilla_advisory"}
                    else rerank
                ),
                "rcm_oracle": oracle,
                "rcm_oracle_stats": oracle_meta,
                "rcm_hybrid": hybrid_meta,
                "mechanism_query": mech_q,
                "gate": gate.__dict__,
                "seed_ids": [h.doc_id for h in gate_hits],
                "kb_hit_count": len(kb_hits),
                "cwe_hit_count": len(cwe_hits),
                "cwe_pool_ids": [h.doc_id for h in cwe_pool],
                "prompt_k": len(cwe_hits),
                "diversify": {"strategy": div_strategy},
            }
            return cb_prompt, rag_prompt, gate, cwe_pool[:20] or kb_hits[:20], meta

        kb_ctx, cwe_ctx, kb_hits, cwe_hits = retriever.retrieve_rcm_context(
            question, k_kb=cfg.k_retrieve, k_cwe=cfg.k_retrieve
        )
        gate_hits = kb_hits or cwe_hits
        scored = hits_to_scored(question, gate_hits)
        gate = evaluate_gate(question, scored, _store_text(gate_hits), cfg)
        rag_prompt = build_understanding_rcm_prompt(
            query=question, kb_context=kb_ctx, cwe_context=cwe_ctx
        )
        cb_prompt = build_understanding_rcm_prompt(
            query=question,
            kb_context=empty_rcm_kb_context(),
            cwe_context=empty_rcm_cwe_context(),
        )
        audit_hits = kb_hits[:20] if kb_hits else (cwe_hits[:20] if cwe_hits else [])
        if not audit_hits:
            audit_hits = retriever.retrieve_mem_chunks(question, k=20)
        meta = {
            "prompt_style": prompt_style or "understanding_pipeline_forced_rag",
            "rcm_retrieval": RCM_RETRIEVAL_CTIBENCH,
            "rcm_gad": "off",
            "gate": gate.__dict__,
            "seed_ids": [h.doc_id for h in gate_hits],
            "kb_hit_count": len(kb_hits),
            "cwe_hit_count": len(cwe_hits),
            "prompt_k": cfg.k_retrieve,
            "diversify": {"strategy": None},
        }
        return cb_prompt, rag_prompt, gate, audit_hits, meta

    prompt_k = max(cfg.k_retrieve, RCM_PROMPT_K)
    kb_ctx, cwe_ctx, kb_hits, cwe_hits, div_meta = retriever.retrieve_rcm_context_diversified(
        question, k_kb=cfg.k_retrieve, k_cwe_audit=20, prompt_k=prompt_k
    )
    # Soft GAD + specialist rerank: rerank diversified prompt set (optional).
    if rcm_rerank_mode() == "taxonomy" and cwe_hits:
        cwe_hits = rerank_cwe_taxonomy(
            question,
            cwe_hits,
            top_k=prompt_k,
            lookup_docs=retriever.get_docs_cwe,
        )
        cwe_ctx = format_cwe_hits_for_prompt(cwe_hits)
    elif rcm_rerank_mode() == "learned" and cwe_hits:
        cwe_hits = rerank_cwe_learned(
            question,
            cwe_hits,
            top_k=prompt_k,
            lookup_docs=retriever.get_docs_cwe,
        )
        cwe_ctx = format_cwe_hits_for_prompt(cwe_hits)
    gate_hits = (cwe_hits[: cfg.k_retrieve] if cwe_hits else kb_hits)
    scored = hits_to_scored(question, gate_hits)
    gate = evaluate_gate(question, scored, _store_text(gate_hits), cfg)
    rag_prompt = build_understanding_rcm_prompt(
        query=question, kb_context=kb_ctx, cwe_context=cwe_ctx
    )
    cb_prompt = build_understanding_rcm_prompt(
        query=question,
        kb_context=empty_rcm_kb_context(),
        cwe_context=empty_rcm_cwe_context(),
    )
    audit_hits = cwe_hits[:20] if cwe_hits else kb_hits[:20]
    if not audit_hits:
        audit_hits = retriever.retrieve(question, "cwe", k=20)
    meta = {
        "prompt_style": prompt_style,
        "rcm_retrieval": RCM_RETRIEVAL_CTIBENCH,
        "rcm_gad": "force",
        "rcm_rerank": rcm_rerank_mode(),
        "gate": gate.__dict__,
        "seed_ids": [h.doc_id for h in gate_hits],
        "kb_hit_count": len(kb_hits),
        "cwe_hit_count": len(cwe_hits),
        "prompt_k": prompt_k,
        "diversify": {
            "strategy": div_meta.strategy if div_meta else None,
            "seed_ids": div_meta.seed_ids if div_meta else [],
            "selected_ids": div_meta.selected_ids if div_meta else [],
            "cluster_of": div_meta.cluster_of if div_meta else {},
            "cluster_sizes_selected": div_meta.cluster_sizes_selected if div_meta else {},
            "max_per_cluster": div_meta.max_per_cluster if div_meta else None,
        },
    }
    return cb_prompt, rag_prompt, gate, audit_hits, meta


def run_rcm_branches(
    question: str,
    retriever: Retriever,
    cfg: TCARConfig,
    chat_fn: Callable[..., str],
    *,
    benchmark: str,
    rcm_retrieval: str | None = None,
    max_tokens: int = 500,
    gold_ids: List[str] | None = None,
) -> _BRANCH_RESULT:
    """RCM: CTIConnect → cta_rag_port; CTIBench → understanding_pipeline + CWE diversify."""
    gold_ids = gold_ids or []
    # Hybrid / soft JSON answers need more than 500 tokens (sol failures were max_tokens).
    from tcar.rcm_mechanism_hybrid import rcm_pipeline_mode as _rcm_pipe  # noqa: WPS433

    if _rcm_pipe() in {"hybrid", "vanilla_advisory"} or (os.getenv("RCM_PROMPT") or "").strip().lower() in {
        "soft",
        "advisory",
        "vanilla_advisory",
        "kb_advisory",
    }:
        max_tokens = max(max_tokens, 900)

    if benchmark == "cticonnect" and resolve_rcm_retrieval(rcm_retrieval) == RCM_RETRIEVAL_CTIBENCH:
        assert isinstance(retriever, CTIBenchKBRetriever)
        style = (
            "understanding_pipeline_forced_rag"
            if rcm_gad_mode() == "off"
            else "understanding_pipeline_force_gad"
        )
        cb_prompt, rag_prompt, gate, audit_hits, meta = _run_rcm_ctibench_retrieval(
            question,
            retriever,
            cfg,
            prompt_style=style,
            gold_ids=gold_ids,
        )
    elif benchmark == "cticonnect":
        assert isinstance(retriever, CTIConnectKBRetriever)
        # Same Force GAD as CTIBench RCM: dense→seed→graph→K=12. RCM_GAD=off = Forced RAG dense.
        if rcm_gad_mode() == "off":
            dense = retriever.retrieve_for_task(question, "rcm", k=max(cfg.k_retrieve, 20))
            audit_hits = dense[:20]
            oracle_meta = gold_in_top_n(dense, gold_ids, n=20)
            prompt_hits = dense[: cfg.k_retrieve]
            if rcm_oracle_mode() == "gold_pin":
                prompt_hits, pin_meta = apply_rcm_oracle_pin(
                    dense,
                    gold_ids,
                    lookup_docs=lambda ids: retriever.get_docs("cwe", ids),
                    top_k=cfg.k_retrieve,
                )
                oracle_meta.update(pin_meta)
            elif rcm_rerank_mode() == "learned":
                prompt_hits = rerank_cwe_learned(
                    question,
                    dense,
                    top_k=cfg.k_retrieve,
                    lookup_docs=lambda ids: retriever.get_docs("cwe", ids),
                )
            elif rcm_rerank_mode() == "taxonomy":
                prompt_hits = rerank_cwe_taxonomy(
                    question,
                    dense,
                    top_k=cfg.k_retrieve,
                    lookup_docs=lambda ids: retriever.get_docs("cwe", ids),
                )
            gate_hits = prompt_hits
            scored = hits_to_scored(question, gate_hits)
            gate = evaluate_gate(question, scored, _store_text(gate_hits), cfg)
            candidates = format_candidates(prompt_hits)
            rag_prompt = build_cticonnect_rcm_prompt(question=question, candidates=candidates)
            cb_prompt = build_cticonnect_rcm_prompt(question=question, candidates=empty_candidates())
            rr = rcm_rerank_mode()
            meta = {
                "prompt_style": "cta_rag_port_rcm_forced_rag",
                "rcm_retrieval": RCM_RETRIEVAL_CORPUS_KB,
                "rcm_gad": "off",
                "rcm_rerank": rr,
                "rcm_oracle": rcm_oracle_mode(),
                "rcm_oracle_stats": oracle_meta,
                "gate": gate.__dict__,
                "seed_ids": [h.doc_id for h in gate_hits],
                "prompt_ids": [h.doc_id for h in prompt_hits],
                "prompt_k": cfg.k_retrieve,
                "diversify": {
                    "strategy": f"{rr}_rerank_diversify" if rr in {"taxonomy", "learned"} else None
                },
            }
        else:
            audit_hits, prompt_hits, div_meta = retrieve_diversified_rcm_candidates(
                retriever,
                question,
                k_retrieve=cfg.k_retrieve,
                prompt_k=max(cfg.k_retrieve, RCM_PROMPT_K),
            )
            if rcm_rerank_mode() == "taxonomy":
                prompt_hits = rerank_cwe_taxonomy(
                    question,
                    prompt_hits,
                    top_k=max(cfg.k_retrieve, RCM_PROMPT_K),
                    lookup_docs=lambda ids: retriever.get_docs("cwe", ids),
                )
            elif rcm_rerank_mode() == "learned":
                prompt_hits = rerank_cwe_learned(
                    question,
                    prompt_hits,
                    top_k=max(cfg.k_retrieve, RCM_PROMPT_K),
                    lookup_docs=lambda ids: retriever.get_docs("cwe", ids),
                )
            gate_hits = audit_hits[: cfg.k_retrieve]
            scored = hits_to_scored(question, gate_hits)
            gate = evaluate_gate(question, scored, _store_text(gate_hits), cfg)
            candidates = format_candidates(prompt_hits)
            rag_prompt = build_cticonnect_rcm_prompt(question=question, candidates=candidates)
            cb_prompt = build_cticonnect_rcm_prompt(question=question, candidates=empty_candidates())
            meta = {
                "prompt_style": "cta_rag_port_rcm_force_gad",
                "rcm_retrieval": RCM_RETRIEVAL_CORPUS_KB,
                "rcm_gad": "force",
                "rcm_rerank": rcm_rerank_mode(),
                "gate": gate.__dict__,
                "seed_ids": [h.doc_id for h in gate_hits],
                "prompt_ids": [h.doc_id for h in prompt_hits],
                "prompt_k": max(cfg.k_retrieve, RCM_PROMPT_K),
                "diversify": {
                    "strategy": div_meta.strategy,
                    "seed_ids": div_meta.seed_ids,
                    "selected_ids": div_meta.selected_ids,
                    "cluster_of": div_meta.cluster_of,
                    "cluster_sizes_selected": div_meta.cluster_sizes_selected,
                    "max_per_cluster": div_meta.max_per_cluster,
                },
            }
    else:
        assert isinstance(retriever, CTIBenchKBRetriever)
        style = (
            "understanding_pipeline_forced_rag"
            if rcm_gad_mode() == "off"
            else "understanding_pipeline_force_gad"
        )
        cb_prompt, rag_prompt, gate, audit_hits, meta = _run_rcm_ctibench_retrieval(
            question,
            retriever,
            cfg,
            prompt_style=style,
            gold_ids=gold_ids,
        )

    cb_raw = chat_fn(cb_prompt, max_tokens=max_tokens)
    rag_raw = chat_fn(rag_prompt, max_tokens=max_tokens)
    return cb_raw, rag_raw, gate, audit_hits, meta


def _chat_with_empty_retry(
    chat_fn: Callable[..., str],
    prompt: str,
    *,
    max_tokens: int,
    retries: int = 1,
) -> Tuple[str, int]:
    """Same retry policy for CB and RAG: retry empty responses a fixed number of times."""
    attempts = 0
    raw = ""
    for _ in range(retries + 1):
        attempts += 1
        raw = chat_fn(prompt, max_tokens=max_tokens) or ""
        if raw.strip():
            return raw, attempts
    return raw, attempts


def ata_retrieval_mode() -> str:
    """Forced RAG ATA retrieval: grounded | behavior (default) | dense (legacy)."""
    raw = (os.getenv("ATA_RETRIEVAL") or "behavior").strip().lower()
    if raw in {"dense", "whole", "report", "legacy"}:
        return "dense"
    if raw in {"grounded", "behavior_grounded", "bg", "rrf"}:
        return "grounded"
    return "behavior"


def _decompose_ata_behaviors(question: str, chat_fn: Callable[..., str]) -> List[str]:
    from eval.cticonnect_official_prompts import DTR_DECOMPOSE

    raw = chat_fn(DTR_DECOMPOSE.format(question=question), max_tokens=256)
    behaviors = [b.strip("-* \t") for b in (raw or "").splitlines() if b.strip()][:5]
    # Drop lines that look like answers / IDs rather than behaviors.
    cleaned: List[str] = []
    for b in behaviors:
        if b.upper().startswith("ANSWER"):
            continue
        if b.upper().startswith("T") and b[1:5].isdigit() and len(b) < 12:
            continue
        cleaned.append(b)
    return cleaned or [question]


def run_ata_branches(
    question: str,
    retriever: CTIConnectKBRetriever,
    cfg: TCARConfig,
    chat_fn: Callable[..., str],
    *,
    max_tokens: int = 800,
    gold_ids: List[str] | None = None,
) -> _BRANCH_RESULT:
    """ATA (CTIConnect only): Force GAD = diversify K=12; ATA_GAD=off = Forced RAG.

    Forced RAG retrieval modes (ATA_RETRIEVAL):
      grounded — rule-based behaviours → per-behaviour top-20 → RRF → soft evidence
      behavior — LLM DtR decompose → per-behaviour retrieve (default)
      dense — legacy whole-report top-k
    """
    import os

    from tcar.ata_behavior_grounded import (  # noqa: WPS433
        cleanup_ata_prediction,
        format_grounded_candidates,
        retrieve_grounded_ata,
        should_abstain_ata_v4,
    )

    prompt_k = max(cfg.k_retrieve, ATA_PROMPT_K)
    soft = (os.getenv("ATA_PROMPT", "soft") or "soft").strip().lower() != "strict"
    behaviors: List[str] = []
    behavior_blocks = ""
    grounded_meta: dict = {}
    grounded_cands = []

    if ata_gad_mode() == "off":
        mode = ata_retrieval_mode()
        if mode == "grounded":
            grounded_cands, behaviors, grounded_meta = retrieve_grounded_ata(
                question,
                retriever,
                per_behavior_k=int(os.getenv("ATA_PER_BEHAVIOR_K") or "20"),
                final_k=int(os.getenv("ATA_GROUNDED_K") or "20"),
                gold_ids=gold_ids,
            )
            prompt_hits = [g.hit for g in grounded_cands]
            audit_hits = list(prompt_hits)[:20]
            div_meta = None
            style = "cta_rag_port_ata_behavior_grounded_v4"
            rag_prompt = build_cticonnect_ata_grounded_prompt(
                question=question,
                grounded_block=format_grounded_candidates(grounded_cands),
            )
        elif mode == "behavior":
            behaviors = _decompose_ata_behaviors(question, chat_fn)
            blocks: List[str] = []
            merged: Dict[str, KBHit] = {}
            for b in behaviors:
                hits = retriever.retrieve_for_task(b, "ata", k=cfg.k_retrieve)
                blocks.append(
                    f"Behavior: {b}\nCandidates:\n{format_candidates(hits, max_chars=300)}"
                )
                for h in hits:
                    prev = merged.get(h.doc_id)
                    if prev is None or h.score > prev.score:
                        merged[h.doc_id] = h
            behavior_blocks = "\n\n---\n\n".join(blocks)
            prompt_hits = sorted(merged.values(), key=lambda h: h.score, reverse=True)[
                : max(cfg.k_retrieve * 2, 10)
            ]
            audit_hits = list(prompt_hits)[:20]
            div_meta = None
            style = "cta_rag_port_ata_forced_rag_behavior"
            rag_prompt = build_cticonnect_ata_behavior_prompt(
                question=question, behavior_blocks=behavior_blocks or "(no behaviors)"
            )
        else:
            dense = retriever.retrieve_for_task(question, "ata", k=max(cfg.k_retrieve, 20))
            audit_hits = dense[:20]
            prompt_hits = dense[: cfg.k_retrieve]
            div_meta = None
            style = "cta_rag_port_ata_forced_rag"
            candidates = format_candidates(prompt_hits)
            rag_prompt = build_cticonnect_ata_prompt(question=question, candidates=candidates)
        gad = "off"
        diversify = {"strategy": None, "retrieval": mode, **grounded_meta}
        seed_ids = [h.doc_id for h in prompt_hits]
        pk = cfg.k_retrieve
    else:
        audit_hits, prompt_hits, div_meta = retrieve_diversified_ata_candidates(
            retriever, question, k_retrieve=cfg.k_retrieve, prompt_k=prompt_k
        )
        candidates = format_candidates(prompt_hits)
        rag_prompt = build_cticonnect_ata_prompt(question=question, candidates=candidates)
        style = "cta_rag_port_ata_soft_gad" if soft else "cta_rag_port_ata_force_gad"
        diversify = {
            "strategy": div_meta.strategy,
            "seed_ids": div_meta.seed_ids,
            "selected_ids": div_meta.selected_ids,
            "cluster_of": div_meta.cluster_of,
            "cluster_sizes_selected": div_meta.cluster_sizes_selected,
            "max_per_cluster": div_meta.max_per_cluster,
        }
        seed_ids = list(div_meta.seed_ids)
        pk = prompt_k
        gad = "force"

    scored = hits_to_scored(question, prompt_hits[: cfg.k_retrieve] or prompt_hits)
    gate = evaluate_gate(question, scored, _store_text(prompt_hits), cfg)
    cb_prompt = build_cticonnect_ata_prompt(question=question, candidates=empty_candidates())
    cb_raw, cb_attempts = _chat_with_empty_retry(chat_fn, cb_prompt, max_tokens=max_tokens, retries=1)
    rag_raw, rag_attempts = _chat_with_empty_retry(
        chat_fn,
        rag_prompt,
        max_tokens=(200 if (gad == "off" and ata_retrieval_mode() == "grounded") else max(max_tokens, 900)),
        retries=1,
    )
    # Grounded path: cleanup → damage-aware v4 gate → empty/inconsistent → CB.
    abstain_meta: dict = {"ata_abstain": False}
    if gad == "off" and ata_retrieval_mode() == "grounded":
        allowed = [h.doc_id for h in prompt_hits]
        filtered_raw, kept, cmeta = cleanup_ata_prediction(rag_raw, allowed_ids=allowed)
        if cmeta.get("emptied") or not kept:
            if not kept:
                rag_raw2, extra = _chat_with_empty_retry(
                    chat_fn, rag_prompt, max_tokens=max(max_tokens, 900), retries=0
                )
                rag_attempts += extra
                filtered_raw, kept, cmeta = cleanup_ata_prediction(rag_raw2, allowed_ids=allowed)
        gate_on = (os.getenv("ATA_DAMAGE_GATE", "1") or "1").strip().lower() not in {
            "0",
            "false",
            "off",
            "no",
        }
        damage_reason = ""
        if kept and gate_on:
            abstain_gate, damage_reason = should_abstain_ata_v4(
                kept[0],
                question=question,
                behaviors=behaviors,
                grounded_ids=allowed,
                evidence_levels=(grounded_meta or {}).get("evidence_levels") or {},
                n_strong=int((grounded_meta or {}).get("n_strong") or 0),
            )
            if abstain_gate:
                kept = []
                cmeta = {**cmeta, "damage_gate": True, "damage_gate_reason": damage_reason}
        if not kept:
            rag_raw = cb_raw
            abstain_meta = {
                "ata_abstain": True,
                "ata_abstain_to_cb": True,
                "ata_kept_ids": [],
                "ata_cleanup": cmeta,
                "ata_damage_gate_reason": damage_reason or cmeta.get("damage_gate_reason"),
            }
        else:
            rag_raw = filtered_raw
            abstain_meta = {
                "ata_abstain": True,
                "ata_abstain_to_cb": False,
                "ata_kept_ids": kept,
                "ata_cleanup": cmeta,
                "ata_damage_gate_reason": "keep",
            }
    elif ata_abstain_enabled():
        allowed = [h.doc_id for h in prompt_hits]
        filtered_raw, kept, emptied = filter_ata_to_evidence(rag_raw, allowed)
        if emptied:
            rag_raw = cb_raw
            abstain_meta = {
                "ata_abstain": True,
                "ata_abstain_to_cb": True,
                "ata_kept_ids": [],
            }
        else:
            rag_raw = filtered_raw
            abstain_meta = {
                "ata_abstain": True,
                "ata_abstain_to_cb": False,
                "ata_kept_ids": kept,
            }
    meta = {
        "task": "ata",
        "benchmark": "cticonnect",
        "prompt_style": style,
        "ata_gad": gad,
        "ata_retrieval": ata_retrieval_mode() if gad == "off" else "gad",
        "behaviors": behaviors,
        "gate": gate.__dict__,
        "seed_ids": seed_ids,
        "prompt_k": pk,
        "ata_prompt": "soft" if soft else "strict",
        "diversify": diversify,
        "cb_attempts": cb_attempts,
        "rag_attempts": rag_attempts,
        "cb_empty": not bool((cb_raw or "").strip()),
        "rag_empty": not bool((rag_raw or "").strip()),
        **abstain_meta,
    }
    return cb_raw, rag_raw, gate, audit_hits, meta


def run_ate_branches(
    description: str,
    retriever: CTIBenchKBRetriever,
    cfg: TCARConfig,
    chat_fn: Callable[..., str],
    *,
    max_tokens: int = 800,
) -> _BRANCH_RESULT:
    """ATE (CTIBench only). Default = whole-description Forced-RAG / CTA prompt.

    Ablation (does not replace the strong baseline unless it beats ~0.905 F1):
      ATE_RETRIEVAL=exploitation — per-stage exploitation-chain retrieve + RRF
    Set ATE_PROMPT=cta for original CTA-RAG prompt/order on the dense path.
    """
    from tcar.ate_exploitation_stages import (  # noqa: WPS433
        ate_retrieval_mode,
        format_exploitation_context,
        retrieve_exploitation_ate,
        to_main_technique_ids,
    )
    from eval.scoring import parse_ate_ids

    mode = gad_mode()
    retrieval = ate_retrieval_mode() if mode == "off" else "dense"
    exploit_meta: dict = {}
    linked = []

    if retrieval == "exploitation":
        hits, stages, linked, exploit_meta = retrieve_exploitation_ate(
            description,
            retriever,
            per_stage_k=int(os.getenv("ATE_PER_STAGE_K") or "10"),
            final_k=int(os.getenv("ATE_STAGE_K") or str(max(cfg.k_retrieve, 8))),
        )
        cta = False
        rag_context = format_exploitation_context(linked, cta_style=False)
        style = "reasoning_ate_exploitation_stages"
    else:
        hits = retriever.retrieve_mem_chunks(description, k=cfg.k_retrieve)
        cta = ate_prompt_mode() == "cta" and mode == "off"
        rag_context = _format_mem_context(hits, cta_style=cta)
        style = "reasoning_ate_pipeline_cta" if cta else "reasoning_ate_pipeline"

    scored = hits_to_scored(description, hits)
    gate = evaluate_gate(description, scored, _store_text(hits), cfg)
    cb_context = empty_mem_context()
    catalogue = ""
    gad_meta: dict = {}
    if mode != "off":
        # Force/Soft ATE gold is main-technique F1=1; collapse catalogue subs → parents
        # so graph neighbours do not tempt subtechnique / sibling extras.
        catalogue, gad_hits, gad_meta = _mitre_gad_catalogue(
            description, prompt_k=OTHER_GAD_K, main_techniques_only=True
        )
        gad_meta["catalogue_ids"] = [h.doc_id for h in gad_hits]
    cb_prompt = build_ate_prompt(description=description, similar_context=cb_context, catalogue="")
    if retrieval == "exploitation":
        rag_prompt = build_ate_exploitation_prompt(
            description=description, stage_context=rag_context
        )
    else:
        rag_prompt = build_ate_prompt(
            description=description, similar_context=rag_context, catalogue=catalogue
        )
    cb_raw = chat_fn(cb_prompt, max_tokens=max_tokens)
    # Fair counterfactual: same generation budget for CB and RAG (evidence is the only difference).
    rag_raw = chat_fn(rag_prompt, max_tokens=max_tokens)
    # Exploitation path: normalize answer line to main technique IDs (evaluator contract).
    if retrieval == "exploitation" and rag_raw:
        mains = to_main_technique_ids(sorted(parse_ate_ids(rag_raw)))
        if mains:
            if re.search(r"(?im)^answer\s*:", rag_raw):
                rag_raw = re.sub(
                    r"(?im)^answer\s*:.*$",
                    "answer: " + ", ".join(mains),
                    rag_raw,
                    count=1,
                )
            else:
                rag_raw = rag_raw.rstrip() + "\nanswer: " + ", ".join(mains)
    audit_hits = (
        list(hits)[:20]
        if retrieval == "exploitation"
        else retriever.retrieve_mem_chunks(description, k=20)
    )
    if mode == "force":
        style = "reasoning_ate_gad_k12"
    elif mode == "soft":
        style = "reasoning_ate_soft_gad_k12"
    meta = {
        "task": "ate",
        "benchmark": "ctibench",
        "prompt_style": style,
        "ate_prompt": ate_prompt_mode(),
        "ate_retrieval": retrieval,
        "gad_mode": mode,
        "gate": gate.__dict__,
        "seed_ids": [h.doc_id for h in hits],
        "context_sources": [h.title for h in hits],
        "prompt_k": OTHER_GAD_K if mode != "off" else cfg.k_retrieve,
        "gad": gad_meta,
        **exploit_meta,
    }
    return cb_raw, rag_raw, gate, audit_hits, meta


def run_mcq_branches(
    question: str,
    retriever: CTIBenchKBRetriever,
    cfg: TCARConfig,
    chat_fn: Callable[..., str],
) -> _BRANCH_RESULT:
    """MCQ: memorization_pipeline.

    MCQ_RETRIEVAL=
      option_aware     — per-option retrieve (v2)
      relation_aware   — STIX typed-edge lookup first, then relation-specific semantic (v3)
    """
    mode = gad_mode()
    retrieval = mcq_retrieval_mode()
    relation_meta: dict = {}

    if retrieval == "relation_aware":
        from tcar.mcq_relation_aware import (  # noqa: WPS433
            AttackRelationIndex,
            build_mcq_relation_prompt,
            detect_relation_type,
            format_stix_evidence_block,
            lookup_relation_options,
            relation_semantic_queries,
        )
        from tcar.specialist_retrieval import parse_mcq_options

        index = AttackRelationIndex.get()
        opts = parse_mcq_options(question)
        rel, rel_conf = detect_relation_type(question)
        stix_res = lookup_relation_options(question, opts, index=index, relation=rel)
        stix_block = format_stix_evidence_block(stix_res)
        relation_meta = {
            "mcq_relation": rel,
            "mcq_relation_conf": rel_conf,
            "stix_method": stix_res.method,
            "stix_deterministic": stix_res.deterministic,
            "stix_unique": stix_res.unique_supported,
            "stix_supported": list(stix_res.supported_letters),
            "stix_anchors": stix_res.anchors,
            "attack_bundle": index.meta.to_dict() if hasattr(index.meta, "to_dict") else index.meta.__dict__,
        }

        # Deterministic short-circuit: unique structured support → skip LLM for RAG branch
        if stix_res.deterministic and stix_res.unique_supported:
            letter = stix_res.unique_supported
            rag_raw = (
                f"Structured ATT&CK {rel} edge uniquely supports option {letter}.\n"
                f"Final Answer: {letter}"
            )
            cb_prompt = build_mcq_prompt(question=question, context=empty_mem_context(), catalogue="")
            cb_raw = chat_fn(cb_prompt, max_tokens=600)
            hits: List[KBHit] = []
            scored = hits_to_scored(question, hits)
            gate = evaluate_gate(question, scored, "", cfg)
            audit_hits = retriever.retrieve_for_task(question, "mcq", k=20)
            meta = {
                "prompt_style": "relation_aware_stix_deterministic",
                "mcq_retrieval": "relation_aware",
                "decision_source": "STIX",
                "evidence_changed": True,
                "gad_mode": mode,
                "gate": gate.__dict__,
                "seed_ids": [],
                "prompt_k": 0,
                "gad": {},
                "mcq_abstain": False,
                **relation_meta,
            }
            return cb_raw, rag_raw, gate, audit_hits, meta

        has_edges = bool(stix_res.endpoint_ids or stix_res.endpoint_names)
        # Hybrid: unchanged evidence vs v2 option-aware → same retrieval path (answers reusable)
        if (not has_edges) and rel == "generic":
            labeled = []
            for lab, q in mcq_option_queries(question):
                labeled.append((lab, retriever.retrieve_for_task(q, "mcq", k=cfg.k_retrieve)))
            hits = merge_option_hits(labeled, top_k=cfg.k_retrieve)
            retrieval_tag = "relation_aware_fallback"
            rag_context = _format_mem_context(hits)
            relation_meta["decision_source"] = "fallback"
            relation_meta["evidence_changed"] = False
        else:
            labeled = []
            for lab, q in relation_semantic_queries(question, opts, rel):
                labeled.append((lab, retriever.retrieve_for_task(q, "mcq", k=cfg.k_retrieve)))
            hits = merge_option_hits(labeled, top_k=cfg.k_retrieve)
            retrieval_tag = "relation_aware"
            rag_context = (
                "=== STRUCTURED ATT&CK EDGES ===\n"
                + stix_block
                + "\n\n=== RELATION-SPECIFIC PASSAGES ===\n"
                + _format_mem_context(hits)
            )
            relation_meta["decision_source"] = "semantic"
            relation_meta["evidence_changed"] = True
    elif retrieval == "option_aware":
        labeled = []
        for lab, q in mcq_option_queries(question):
            labeled.append((lab, retriever.retrieve_for_task(q, "mcq", k=cfg.k_retrieve)))
        hits = merge_option_hits(labeled, top_k=cfg.k_retrieve)
        retrieval_tag = "option_aware"
        rag_context = _format_mem_context(hits)
    else:
        hits = retriever.retrieve_for_task(question, "mcq", k=cfg.k_retrieve)
        retrieval_tag = "default"
        rag_context = _format_mem_context(hits)

    scored = hits_to_scored(question, hits)
    gate = evaluate_gate(question, scored, _store_text(hits), cfg)
    cb_context = empty_mem_context()
    catalogue = ""
    gad_meta: dict = {}
    if mode != "off":
        mitre_txt, mitre_hits, mitre_meta = _mitre_gad_catalogue(question, prompt_k=OTHER_GAD_K)
        cwe_txt, cwe_hits, cwe_meta = _cwe_gad_catalogue(question, prompt_k=OTHER_GAD_K)
        catalogue = (
            "=== MITRE ATT&CK ===\n"
            + mitre_txt
            + "\n\n=== CWE ===\n"
            + cwe_txt
        )
        gad_meta = {
            "mitre_gad": mitre_meta,
            "cwe_gad": cwe_meta,
            "catalogue_ids": [h.doc_id for h in mitre_hits] + [h.doc_id for h in cwe_hits],
        }
    if retrieval_tag == "relation_aware":
        from tcar.mcq_relation_aware import build_mcq_relation_prompt  # noqa: WPS433

        rel = relation_meta.get("mcq_relation") or "generic"
        stix_block = ""
        if "=== STRUCTURED ATT&CK EDGES ===\n" in rag_context:
            stix_block = rag_context.split("=== RELATION-SPECIFIC PASSAGES ===\n", 1)[0]
            stix_block = stix_block.replace("=== STRUCTURED ATT&CK EDGES ===\n", "").strip()
            passages = rag_context.split("=== RELATION-SPECIFIC PASSAGES ===\n", 1)[-1]
        else:
            passages = rag_context
        rag_prompt = build_mcq_relation_prompt(
            question=question,
            context=passages,
            relation=rel,
            stix_block=stix_block,
            catalogue=catalogue,
        )
    else:
        rag_prompt = build_mcq_prompt(question=question, context=rag_context, catalogue=catalogue)
    cb_prompt = build_mcq_prompt(question=question, context=cb_context, catalogue="")
    cb_raw = chat_fn(cb_prompt, max_tokens=600)
    rag_raw = chat_fn(rag_prompt, max_tokens=600)
    abstain_meta: dict = {"mcq_abstain": False}
    if mcq_abstain_enabled() and mcq_should_prefer_closed_book(
        question, cb_raw=cb_raw, rag_raw=rag_raw, context=rag_context
    ):
        rag_raw = cb_raw
        abstain_meta = {"mcq_abstain": True, "mcq_abstain_to_cb": True}
    audit_hits = retriever.retrieve_for_task(question, "mcq", k=20)
    style = "memorization_pipeline"
    if mode == "force":
        style = "memorization_gad_k12"
    elif mode == "soft":
        style = "memorization_soft_gad_k12"
    if retrieval_tag == "option_aware":
        style = f"{style}_option_aware"
    elif retrieval_tag == "relation_aware":
        style = f"{style}_relation_aware"
    elif retrieval_tag == "relation_aware_fallback":
        style = f"{style}_option_aware_reuse"
    meta = {
        "prompt_style": style,
        "mcq_retrieval": retrieval_tag,
        "gad_mode": mode,
        "gate": gate.__dict__,
        "seed_ids": [h.doc_id for h in hits],
        "prompt_k": OTHER_GAD_K if mode != "off" else cfg.k_retrieve,
        "gad": gad_meta,
        **abstain_meta,
        **relation_meta,
    }
    return cb_raw, rag_raw, gate, audit_hits, meta


def run_vsp_branches(
    question: str,
    retriever: CTIBenchKBRetriever,
    cfg: TCARConfig,
    chat_fn: Callable[..., str],
) -> _BRANCH_RESULT:
    """VSP: problem_solving_pipeline. VSP_RETRIEVAL=metric_wise|structured."""
    mode = gad_mode()
    vsp_mode = vsp_retrieval_mode()

    # Structured fact → deterministic CVSS decoding specialist
    if vsp_mode == "structured":
        from tcar.vsp_structured_decoder import (  # noqa: WPS433
            build_vsp_metric_evidence_block,
            build_vsp_structured_prompt,
            decode_vsp_prediction,
            extract_vsp_facts_rulebased,
            facts_to_cvss_vector,
        )

        hits = retriever.retrieve_for_task(question, "vsp", k=max(cfg.k_retrieve, 8))
        filtered: List[KBHit] = []
        for h in hits:
            if is_query_near_dup(question, h.text):
                continue
            clean = sanitize_cve_store_passage(h.text)
            if not clean or is_query_near_dup(question, clean):
                continue
            filtered.append(KBHit(doc_id=h.doc_id, title=h.title, text=clean, score=h.score))
            if len(filtered) >= cfg.k_retrieve:
                break
        use_hits = filtered or hits[: cfg.k_retrieve]
        scored = hits_to_scored(question, use_hits)
        gate = evaluate_gate(question, scored, _store_text(use_hits), cfg)
        evidence = build_vsp_metric_evidence_block(use_hits[:5], question)
        cb_prompt = build_vsp_structured_prompt(query_description=question, evidence_block="")
        rag_prompt = build_vsp_structured_prompt(
            query_description=question, evidence_block=evidence
        )
        cb_raw_facts = chat_fn(cb_prompt, max_tokens=1200) or ""
        rag_raw_facts = chat_fn(rag_prompt, max_tokens=1200) or ""
        # Controlled comparison: same prompt schema + same decoder; only evidence differs.
        cb_vec, cb_dec = decode_vsp_prediction(cb_raw_facts, description=question)
        rag_vec, rag_dec = decode_vsp_prediction(rag_raw_facts, description=question)
        # Ensure scorer sees a vector string (exact-vector CF metric)
        cb_raw = cb_vec
        rag_raw = rag_vec
        audit_hits = retriever.retrieve_for_task(question, "vsp", k=20)
        rb = extract_vsp_facts_rulebased(question)
        from tcar.vsp_structured_decoder import apply_vsp_consistency_logged  # noqa: WPS433

        rb2, rb_log = apply_vsp_consistency_logged(rb, question)
        meta = {
            "prompt_style": "vsp_structured_fact_decoder",
            "vsp_retrieval": "structured",
            "vsp_consistency": (os.getenv("VSP_CONSISTENCY") or "high_precision"),
            "vsp_comparison": {
                "structured_cb": "fact prompt + no evidence + deterministic decoder",
                "structured_rag": "same fact prompt + retrieved evidence + same decoder",
            },
            "metrics_note": {
                "cf_correct": "exact 8-metric vector match (MAD8==0)",
                "mad8": "mean fraction of disagreeing metrics in {AV,AC,PR,UI,S,C,I,A}",
                "mad_base": "mean |base_score(pred)-base_score(gold)| on [0,10]",
                "paper_mad": "CTA-RAG headline uses mad_base (1.31→1.06), not mad8/exact",
            },
            "gad_mode": "off",
            "gate": gate.__dict__,
            "seed_ids": [h.doc_id for h in use_hits],
            "prompt_k": cfg.k_retrieve,
            "vsp_cases_shown": min(5, len(use_hits)),
            "vsp_cb_decoder": cb_dec,
            "vsp_rag_decoder": rag_dec,
            "vsp_cb_facts_raw": (cb_raw_facts or "")[:2000],
            "vsp_rag_facts_raw": (rag_raw_facts or "")[:2000],
            "vsp_rulebased_vector": facts_to_cvss_vector(rb2),
            "vsp_rulebased_consistency": rb_log,
        }
        return cb_raw, rag_raw, gate, audit_hits, meta

    hits = retriever.retrieve_for_task(question, "vsp", k=max(cfg.k_retrieve, 8))
    filtered = []
    for h in hits:
        if is_query_near_dup(question, h.text):
            continue
        clean = sanitize_cve_store_passage(h.text)
        if not clean or is_query_near_dup(question, clean):
            continue
        filtered.append(KBHit(doc_id=h.doc_id, title=h.title, text=clean, score=h.score))
        if len(filtered) >= cfg.k_retrieve:
            break

    use_hits = filtered or hits[: cfg.k_retrieve]
    scored = hits_to_scored(question, use_hits)
    gate = evaluate_gate(question, scored, _store_text(use_hits), cfg)

    show_n = 8 if mode != "off" else 3
    cb_case_block = "Below are descriptions of similar historical CVEs:\n\n(no distinct reference cases retrieved)\n"
    if vsp_mode == "metric_wise":
        rag_case_block = vsp_metric_case_block(use_hits[:show_n], question)
        shown = min(len(use_hits), show_n)
        vsp_tag = "metric_wise"
    else:
        rag_lines = ["Below are descriptions of similar historical CVEs:\n"]
        shown = 0
        for h in use_hits:
            if shown >= show_n:
                break
            rag_lines.append(f"Case {shown + 1}:")
            rag_lines.append(f"Description: {h.text}\n")
            shown += 1
        if shown == 0:
            rag_case_block = cb_case_block
        else:
            rag_case_block = "\n".join(rag_lines)
        vsp_tag = "default"

    catalogue = ""
    gad_meta: dict = {}
    if mode != "off":
        catalogue, gad_hits, gad_meta = _cwe_gad_catalogue(question, prompt_k=OTHER_GAD_K)
        gad_meta["catalogue_ids"] = [h.doc_id for h in gad_hits]

    cb_prompt = build_vsp_prompt(query_description=question, case_block=cb_case_block, catalogue="")
    rag_prompt = build_vsp_prompt(
        query_description=question, case_block=rag_case_block, catalogue=catalogue
    )
    cb_raw = chat_fn(cb_prompt, max_tokens=1500)
    rag_raw = chat_fn(rag_prompt, max_tokens=1500)
    audit_hits = retriever.retrieve_for_task(question, "vsp", k=20)
    style = "problem_solving_pipeline"
    if mode == "force":
        style = "problem_solving_gad_k12"
    elif mode == "soft":
        style = "problem_solving_soft_gad_k12"
    meta = {
        "prompt_style": style,
        "vsp_retrieval": vsp_tag,
        "gad_mode": mode,
        "gate": gate.__dict__,
        "seed_ids": [h.doc_id for h in use_hits],
        "prompt_k": OTHER_GAD_K if mode != "off" else cfg.k_retrieve,
        "vsp_cases_shown": shown,
        "gad": gad_meta,
    }
    return cb_raw, rag_raw, gate, audit_hits, meta


def audit_task_kind(task: str) -> str:
    if task in ("rcm", "rcm2021"):
        return "cwe"
    if task == "ata":
        return "mitre"
    if task in ("ate", "mcq"):
        return "mem"
    if task == "vsp":
        return "vsp"
    raise ValueError(f"unknown task {task!r}")


def run_task_branches(
    task: str,
    question: str,
    retriever: Retriever,
    cfg: TCARConfig,
    chat_fn: Callable[..., str],
    *,
    benchmark: str,
    rcm_retrieval: str | None = None,
    gold_ids: List[str] | None = None,
) -> _BRANCH_RESULT:
    """Dispatch by task name — not by benchmark family."""
    if task in ("rcm", "rcm2021"):
        return run_rcm_branches(
            question,
            retriever,
            cfg,
            chat_fn,
            benchmark=benchmark,
            rcm_retrieval=rcm_retrieval,
            max_tokens=500,
            gold_ids=gold_ids,
        )
    if task == "ata":
        if not isinstance(retriever, CTIConnectKBRetriever):
            raise TypeError("ATA (CTIConnect) branches require CTIConnectKBRetriever — not CTIBench ATE")
        return run_ata_branches(question, retriever, cfg, chat_fn, gold_ids=gold_ids)
    if task == "ate":
        if not isinstance(retriever, CTIBenchKBRetriever):
            raise TypeError("ATE (CTIBench) branches require CTIBenchKBRetriever — not CTIConnect ATA")
        return run_ate_branches(question, retriever, cfg, chat_fn)
    if task == "mcq":
        if not isinstance(retriever, CTIBenchKBRetriever):
            raise TypeError("MCQ branches require CTIBenchKBRetriever")
        return run_mcq_branches(question, retriever, cfg, chat_fn)
    if task == "vsp":
        if not isinstance(retriever, CTIBenchKBRetriever):
            raise TypeError("VSP branches require CTIBenchKBRetriever")
        return run_vsp_branches(question, retriever, cfg, chat_fn)
    raise ValueError(f"unsupported counterfactual task {task!r}")
