"""Constrained TAA generation: LLM must pick among top-k retrieved actor candidates."""
from __future__ import annotations

import json
import os
from functools import lru_cache
from pathlib import Path
from typing import Any, Callable, Optional

ROOT = Path(__file__).resolve().parents[2]

TAA_PROMPT_VERSION = "taa-candidate-v1"
PROFILE_PATH = (
    ROOT
    / "eval_results/controlled_benchmark/taa20_20260918"
    / "actor_retrieval_study_v2/actor_profiles.json"
)
EMBED_CACHE = ROOT / "eval_results/controlled_benchmark/taa20_20260918/actor_retrieval_study/embedding_cache"
EMBED_MODEL = os.environ.get("TAA_ACTOR_EMBED_MODEL", "sentence-transformers/all-MiniLM-L6-v2")


def constrained_taa_enabled() -> bool:
    return (os.environ.get("TAA_CONSTRAINED_CANDIDATES") or "1").strip().lower() not in {
        "0",
        "false",
        "no",
        "off",
    }


def candidate_k() -> int:
    k = int(os.environ.get("TAA_CANDIDATE_K", "3"))
    if k not in (3, 5):
        raise ValueError("TAA_CANDIDATE_K must be 3 or 5")
    return k


@lru_cache(maxsize=1)
def _profiles_by_name() -> dict[str, dict]:
    profiles = json.loads(PROFILE_PATH.read_text(encoding="utf-8"))
    return {profile["canonical_actor"]: profile for profile in profiles}


@lru_cache(maxsize=1)
def _actor_retriever():
    from sentence_transformers import SentenceTransformer

    from utils.taa_actor_retrieval import ActorRetriever

    profiles = json.loads(PROFILE_PATH.read_text(encoding="utf-8"))
    model = SentenceTransformer(EMBED_MODEL)
    return ActorRetriever(model, profiles, EMBED_CACHE)


def actor_candidates(
    system: str,
    report: str,
    k: int,
    *,
    retrieval_used: bool = True,
) -> list[str]:
    if not retrieval_used:
        return []
    retriever = _actor_retriever()
    profiles = _profiles_by_name()
    if system == "graphrag_local":
        result = retriever.retrieve_graph_inclusion(report)
        pool = list(result.get("graph_pool") or result.get("multiquery_exact") or [])
    else:
        result = retriever.retrieve(report)
        pool = list(result.get("multiquery_exact") or result.get("top3") or [])
    names: list[str] = []
    for name in pool:
        if name in profiles and name not in names:
            names.append(name)
        if len(names) >= k:
            break
    return names


def overlap_score(evidence: str, profile: dict) -> tuple[int, list[str]]:
    """Gold-blind lexical overlap of aliases/malware/tools/campaigns with evidence."""
    from utils.taa_actor_retrieval import contains

    terms: list[str] = []
    for field in ("aliases", "malware", "tools", "campaigns"):
        terms.extend(str(value) for value in profile.get(field, []) or [])
    terms.append(str(profile.get("canonical_actor") or ""))
    hits: list[str] = []
    score = 0
    seen: set[str] = set()
    for term in sorted({t.strip() for t in terms if t.strip()}, key=len, reverse=True):
        key = term.casefold()
        if key in seen or len(term) < 4:
            continue
        seen.add(key)
        if contains(evidence, term):
            hits.append(term)
            score += len(term)
    return score, hits


def rerank_by_evidence_overlap(
    evidence: str,
    names: list[str],
    profiles: dict[str, dict],
) -> tuple[list[str], dict[str, dict[str, Any]]]:
    """Stable reorder of a fused shortlist. Ties keep CombSUM order. No gold labels."""
    ranked: list[tuple[int, int, str]] = []
    detail: dict[str, dict[str, Any]] = {}
    for index, name in enumerate(names):
        score, hits = overlap_score(evidence, profiles.get(name) or {})
        ranked.append((score, -index, name))
        detail[name] = {"overlap_score": score, "overlap_hits": hits}
    ranked.sort(reverse=True)
    return [name for _, _, name in ranked], detail


def candidate_card(rank: int, name: str, profile: dict) -> str:
    def join(field: str) -> str:
        values = [str(value) for value in profile.get(field, [])[:12]]
        return ", ".join(values) if values else "none listed"

    text = (profile.get("profile_text") or "")[:700]
    return (
        f"Candidate {rank}: {name}\n"
        f"Aliases: {join('aliases')}\n"
        f"Malware/tools: {join('malware')}; {join('tools')}\n"
        f"Campaigns: {join('campaigns')}\n"
        f"Targets: {join('target_regions')}; {join('target_sectors')}\n"
        f"Profile: {text}"
    )


def build_selection_prompt(report: str, cards: list[str], k: int) -> str:
    choices = ", ".join(str(i) for i in range(1, k + 1))
    return (
        "You are given an anonymised threat report and retrieved actor candidates.\n"
        "Candidates are already overlap-reranked against the report; rank 1 is not automatically correct.\n"
        "Score distinctive aliases, malware, tools, and campaigns. Prefer a specific child or alias "
        "over a related parent when both appear.\n"
        "If any candidate has distinctive lexical overlap with the report, you must pick that candidate. "
        "Do not answer NO_MATCH in that case.\n"
        "Use NO_MATCH only if every candidate has zero distinctive overlap.\n"
        "Do not name any actor outside the candidate list.\n\n"
        f"Return only JSON with keys selected_candidate ({choices}, or 0), confidence (0 to 1), "
        "reason (one sentence), and status (MATCH or NO_MATCH).\n\n"
        f"Report evidence:\n{report[:6000]}\n\n"
        + "\n\n".join(cards)
    )


def parse_choice(raw: str, k: int) -> dict[str, Any]:
    data = json.loads(raw)
    selected = int(data.get("selected_candidate") or 0)
    status = str(data.get("status") or "").upper()
    valid = set(range(1, k + 1))
    if status == "NO_MATCH" or selected not in valid:
        selected = 0
        status = "NO_MATCH"
    else:
        status = "MATCH"
    return {
        "selected_candidate": selected,
        "confidence": data.get("confidence"),
        "reason": str(data.get("reason") or "")[:500],
        "status": status,
    }


def resolve_prediction(names: list[str], choice: dict[str, Any]) -> Optional[str]:
    selected = int(choice.get("selected_candidate") or 0)
    if selected <= 0 or selected > len(names):
        return None
    return names[selected - 1]


def run_constrained_taa(
    *,
    system: str,
    report: str,
    call_llm: Callable[..., dict],
    model: str,
    retrieval_used: bool = True,
    k: Optional[int] = None,
) -> dict[str, Any]:
    k = k or candidate_k()
    profiles = _profiles_by_name()
    names = actor_candidates(system, report, k, retrieval_used=retrieval_used)
    if not names:
        return {
            "raw_response": json.dumps({"selected_candidate": 0, "status": "NO_MATCH", "reason": "no candidates"}),
            "parsed_prediction": None,
            "valid": False,
            "taa_candidates": [],
            "taa_selection": {"selected_candidate": 0, "status": "NO_MATCH"},
            "prompt": None,
            "api_calls": 0,
        }
    cards = [candidate_card(rank, name, profiles[name]) for rank, name in enumerate(names, 1)]
    prompt = build_selection_prompt(report, cards, k)
    gen = call_llm(prompt, model=model, max_tokens=180, response_format={"type": "json_object"})
    choice = parse_choice(gen["raw"], k)
    predicted = resolve_prediction(names, choice)
    return {
        "raw_response": gen["raw"],
        "parsed_prediction": predicted,
        "valid": predicted is not None,
        "taa_candidates": names,
        "taa_selection": choice,
        "prompt": prompt,
        "provider_meta": gen.get("meta") or {},
        "api_calls": 1,
    }
