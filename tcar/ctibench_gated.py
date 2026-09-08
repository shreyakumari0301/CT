"""Confidence-gated inference for CTIBench tasks without TCAR specialists (MCQ, VSP)."""

from __future__ import annotations

import os
import re
from typing import Any, Callable, Dict, List, Optional, Tuple

from eval.cticonnect_kb import KBHit
from tcar.config import TCARConfig
from tcar.ctibench_kb import CTIBenchKBRetriever
from tcar.gate import evaluate_gate
from tcar.gate_scoring import hits_to_scored as _hits_to_scored
from tcar.pipeline_prompts import build_ate_prompt, empty_mem_context
from utils.cve_sanitize import is_query_near_dup, sanitize_cve_store_passage  # noqa: WPS433

_VSP_BASE = """
Analyze the following CVE description and calculate the CVSS v3.1 Base Score. Determine the values for each base metric: AV, AC, PR, UI, S, C, I, and A. Summarize each metric's value and provide the final CVSS v3.1 vector string. Valid options for each metric are as follows: - **Attack Vector (AV)**: Network (N), Adjacent (A), Local (L), Physical (P) - **Attack Complexity (AC)**: Low (L), High (H) - **Privileges Required (PR)**: None (N), Low (L), High (H) - **User Interaction (UI)**: None (N), Required (R) - **Scope (S)**: Unchanged (U), Changed (C) - **Confidentiality (C)**: None (N), Low (L), High (H) - **Integrity (I)**: None (N), Low (L), High (H) - **Availability (A)**: None (N), Low (L), High (H) Summarize each metric's value and provide the final CVSS v3.1 vector string. Ensure the final line of your response contains only the CVSS v3 Vector String in the following format: Example format: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H CVE
""".strip()


def _store_text(hits: List[KBHit]) -> Dict[str, str]:
    return {h.doc_id: h.text for h in hits}


def predict_mcq(
    question: str,
    retriever: CTIBenchKBRetriever,
    cfg: TCARConfig,
    chat: Callable[..., str],
) -> Tuple[str, Dict[str, Any]]:
    hits = retriever.retrieve_for_task(question, "mcq", k=cfg.k_retrieve)
    scored = _hits_to_scored(question, hits)
    gate = evaluate_gate(question, scored, _store_text(hits), cfg)
    meta: Dict[str, Any] = {"task": "mcq", "gate": gate.__dict__, "seed_ids": [h.doc_id for h in hits]}

    if gate.admit_retrieval and hits:
        context = "\n\n".join(
            f"[{h.doc_id}] {h.text[:500]}" for h in hits[: cfg.k_retrieve]
        )
        prompt = f"""You are a Cyber Threat Intelligence (CTI) assistant answering a multiple-choice question.

Use the RETRIEVED CONTEXT when it is relevant. If the context is incomplete or off-topic, still answer using reliable CTI knowledge.

RETRIEVED CONTEXT:
{context}

QUERY:
{question}

REQUIREMENTS:
- Choose exactly one option: A, B, C, or D.
- Give brief reasoning (a few sentences).
- The last line must be exactly: Final Answer: <A|B|C|D>
- Do not abstain."""
        meta["mode"] = "contrast_retrieval"
    else:
        prompt = f"""You are a Cyber Threat Intelligence (CTI) assistant answering a multiple-choice question.

Answer from reliable CTI knowledge (MITRE ATT&CK, CVE/CWE, security controls).

QUERY:
{question}

REQUIREMENTS:
- Choose exactly one option: A, B, C, or D.
- Give brief reasoning (a few sentences).
- The last line must be exactly: Final Answer: <A|B|C|D>
- Do not abstain."""
        meta["mode"] = "closed_book_fallback"

    raw = chat(prompt, max_tokens=600)
    meta["raw"] = raw[:2000]
    return raw, meta


def predict_vsp(
    question: str,
    retriever: CTIBenchKBRetriever,
    cfg: TCARConfig,
    chat: Callable[..., str],
) -> Tuple[str, Dict[str, Any]]:
    hits = retriever.retrieve_for_task(question, "vsp", k=max(cfg.k_retrieve, 8))
    # Drop near-duplicate neighbours (same as problem_solving_pipeline).
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

    scored = _hits_to_scored(question, filtered or hits[: cfg.k_retrieve])
    store = _store_text(filtered or hits)
    gate = evaluate_gate(question, scored, store, cfg)
    meta: Dict[str, Any] = {
        "task": "vsp",
        "gate": gate.__dict__,
        "seed_ids": [h.doc_id for h in (filtered or hits)],
    }

    if gate.admit_retrieval and filtered:
        lines = ["Below are descriptions of similar historical CVEs:\n"]
        for i, h in enumerate(filtered, 1):
            lines.append(f"Case {i}:")
            lines.append(f"Description: {h.text}\n")
        context = "\n".join(lines)
        prompt = (
            f"{context}\n{_VSP_BASE}\n\nCVE Description:\n{question}\n\n"
            "Provide the summary for each metric and ensure the final line ONLY "
            "contains the CVSS v3.1 vector string."
        )
        meta["mode"] = "contrast_retrieval"
    else:
        prompt = (
            f"{_VSP_BASE}\n\nCVE Description:\n{question}\n\n"
            "Provide the summary for each metric and ensure the final line ONLY "
            "contains the CVSS v3.1 vector string."
        )
        meta["mode"] = "closed_book_fallback"

    raw = chat(prompt, max_tokens=1500)
    meta["raw"] = raw[:2000]
    return raw, meta


def _format_mem_context(hits: List[KBHit]) -> str:
    if not hits:
        return empty_mem_context()
    blocks: List[str] = []
    for h in hits:
        source = h.title if h.title and not str(h.title).startswith("T") else "Unknown"
        blocks.append(f"Source: {source}\nContent: {h.text}")
    return "\n\n".join(blocks)


def predict_ate(
    description: str,
    retriever: CTIBenchKBRetriever,
    cfg: TCARConfig,
    chat: Callable[..., str],
) -> Tuple[str, Dict[str, Any]]:
    """ATE (CTIBench): reasoning_ate_pipeline with optional gated retrieval."""
    hits = retriever.retrieve_mem_chunks(description, k=cfg.k_retrieve)
    scored = _hits_to_scored(description, hits)
    gate = evaluate_gate(description, scored, _store_text(hits), cfg)
    meta: Dict[str, Any] = {
        "task": "ate",
        "prompt_style": "reasoning_ate_pipeline",
        "gate": gate.__dict__,
        "seed_ids": [h.doc_id for h in hits],
        "context_sources": [h.title for h in hits],
    }

    if gate.admit_retrieval and hits:
        context = _format_mem_context(hits)
        meta["mode"] = "contrast_retrieval"
    else:
        context = empty_mem_context()
        meta["mode"] = "closed_book_fallback"

    prompt = build_ate_prompt(description=description, similar_context=context)
    raw = chat(prompt, max_tokens=800)
    meta["raw"] = raw[:2000]
    return raw, meta


def predict_gated(
    task_key: str,
    question: str,
    *,
    retriever: CTIBenchKBRetriever,
    cfg: TCARConfig,
    chat: Callable[..., str],
) -> Tuple[str, Dict[str, Any]]:
    if task_key == "mcq":
        return predict_mcq(question, retriever, cfg, chat)
    if task_key == "vsp":
        return predict_vsp(question, retriever, cfg, chat)
    if task_key == "ate":
        return predict_ate(question, retriever, cfg, chat)
    raise ValueError(f"predict_gated does not handle {task_key!r}")
