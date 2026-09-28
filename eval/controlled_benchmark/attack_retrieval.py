"""Task-aware lexical retrieval over the Enterprise ATT&CK catalog.

This is an additional candidate source, not an evaluation-label lookup. It uses
the public technique names/descriptions shipped with the repository and applies
the same evidence budget as the shared retriever.
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterable

TOKEN_RE = re.compile(r"[a-z0-9]{3,}")
STOPWORDS = {
    "the", "and", "for", "that", "this", "with", "from", "into", "their",
    "which", "were", "have", "has", "are", "was", "been", "also", "using",
    "user", "users", "attack", "attacker", "threat", "actor", "report",
}
CLAUSE_RE = re.compile(r"(?<=[.!?])\s+|\s+(?:and|then|while|before|after)\s+", re.I)
ID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.I)
ANCHORS = {
    "powershell": "T1059.001", "pwsh": "T1059.001", "smtp": "T1071.003",
    "callback phishing": "T1566.004", "created an account": "T1136",
    "create an account": "T1136", "new user": "T1136", "public-facing": "T1190",
    "public facing": "T1190", "rdp": "T1021.001", "remote desktop": "T1021.001",
    "malicious web page": "T1189", "drive-by": "T1189", "keylogger": "T1056.001",
}


def _tokens(text: str) -> set[str]:
    return {token for token in TOKEN_RE.findall((text or "").lower()) if token not in STOPWORDS}


def extract_behavior_clauses(report: str, limit: int = 8) -> list[str]:
    """Split report prose into short action-bearing retrieval clauses."""
    cleaned = re.sub(r"\[[^]]+\]", " ", report or "")
    cleaned = re.sub(r"(?i)please\s+.*", " ", cleaned)
    clauses = []
    for clause in CLAUSE_RE.split(cleaned):
        clause = " ".join(clause.split()).strip(" \"'")
        tokens = _tokens(clause)
        if len(tokens) >= 4 and re.search(
            r"(?i)\b(use|used|using|exploit|exploited|exploit(?:s|ing)|create|created|send|sent|deploy|drop|execute|access|connect|target|compromise|phish|keylog|brute|transfer|open)\w*\b",
            clause,
        ):
            clauses.append(clause[:500])
    return list(dict.fromkeys(clauses))[:limit] or [cleaned[:700]]


def _iter_objects(payload: Any) -> Iterable[dict]:
    if isinstance(payload, dict):
        yield from payload.get("objects", [])
    elif isinstance(payload, list):
        yield from payload


def load_enterprise_attack(path: Path) -> list[dict]:
    if not path.exists():
        return []
    payload = json.loads(path.read_text(encoding="utf-8"))
    entries = []
    attack_by_ref = {}
    for obj in _iter_objects(payload):
        if obj.get("type") != "attack-pattern" or obj.get("x_mitre_deprecated"):
            continue
        identifier = next(
            (ref.get("external_id") for ref in obj.get("external_references", [])
             if str(ref.get("external_id", "")).startswith("T")),
            None,
        )
        if not identifier:
            continue
        description = re.sub(r"<[^>]+>", " ", obj.get("description", ""))
        entries.append({
            "kind": "definition",
            "id": identifier.upper(),
            "name": obj.get("name", ""),
            "description": " ".join(description.split()),
            "platforms": obj.get("x_mitre_platforms", []),
        })
        attack_by_ref[obj.get("id")] = entries[-1]
    for obj in _iter_objects(payload):
        if obj.get("type") != "relationship" or obj.get("relationship_type") != "uses":
            continue
        target = attack_by_ref.get(obj.get("target_ref"))
        description = re.sub(r"<[^>]+>", " ", obj.get("description", ""))
        if target and description.strip():
            entries.append({**target, "kind": "procedure", "description": " ".join(description.split())})
    return entries


def rank_enterprise_attack(entries: list[dict], query: str, limit: int = 10) -> list[dict]:
    clauses = extract_behavior_clauses(query)
    ranks = defaultdict(float)
    by_id = {entry["id"]: entry for entry in entries if entry.get("kind") == "definition"}
    for clause_rank, clause in enumerate(clauses):
        query_tokens = _tokens(clause)
        scored = []
        for entry in entries:
            name_tokens = _tokens(entry["name"])
            description_tokens = _tokens(entry["description"])
            name_overlap = len(query_tokens & name_tokens)
            description_overlap = len(query_tokens & description_tokens)
            if name_overlap or description_overlap:
                scored.append((name_overlap * 8 + min(description_overlap, 12), entry["id"]))
        scored.sort(key=lambda pair: (-pair[0], pair[1]))
        for rank, (_, identifier) in enumerate(scored[:limit], start=1):
            ranks[identifier] += 1.0 / (60 + rank)
    ranked = []
    query_tokens = _tokens(" ".join(clauses))
    for entry in entries:
        name_tokens = _tokens(entry["name"])
        description_tokens = _tokens(entry["description"])
        name_overlap = len(query_tokens & name_tokens)
        description_overlap = len(query_tokens & description_tokens)
        if name_overlap or description_overlap:
            score = name_overlap * 8 + min(description_overlap, 12)
            ranked.append((ranks[entry["id"]] + score / 1000.0, entry))
    ranked.sort(key=lambda pair: (-pair[0], pair[1]["id"]))
    return [entry for _, entry in ranked[:limit]]


def hybrid_candidate_pool(entries: list[dict], query: str, previous_text: str = "", limit: int = 10) -> list[dict]:
    """Union previous CTA, procedure, definition, and anchor candidates via RRF."""
    definitions = [entry for entry in entries if entry.get("kind") == "definition"]
    by_id = {entry["id"]: entry for entry in definitions}
    lists = []
    previous_ids = list(dict.fromkeys(ID_RE.findall(previous_text or "")))
    lists.append([by_id[identifier.upper()] for identifier in previous_ids if identifier.upper() in by_id][:5])
    procedure_entries = [entry for entry in entries if entry.get("kind") == "procedure"]
    lists.append(_rank_entries(procedure_entries, query, 5))
    lists.append(rank_enterprise_attack(definitions, query, limit=5))
    anchor_entries = [by_id[identifier] for cue, identifier in ANCHORS.items() if cue in (query or "").lower() and identifier in by_id]
    lists.append(anchor_entries)
    scores = defaultdict(float)
    for candidates in lists:
        for rank, entry in enumerate(candidates, 1):
            scores[entry["id"]] += 1.0 / (60 + rank)
    ranked = sorted(scores, key=lambda identifier: (-scores[identifier], identifier))
    return [by_id[identifier] for identifier in ranked[:limit]]


def _rank_entries(entries: list[dict], query: str, limit: int) -> list[dict]:
    clauses = extract_behavior_clauses(query)
    query_tokens = _tokens(" ".join(clauses))
    scored = []
    for entry in entries:
        overlap = len(query_tokens & _tokens(entry["name"] + " " + entry["description"]))
        if overlap:
            scored.append((overlap, entry))
    scored.sort(key=lambda pair: (-pair[0], pair[1]["id"]))
    return [entry for _, entry in scored[:limit]]


def rerank_candidates(entries: list[dict], query: str, limit: int = 5) -> list[dict]:
    """Rerank the retrieved pool; optionally use a local CrossEncoder."""
    clauses = extract_behavior_clauses(query)
    try:
        from sentence_transformers import CrossEncoder

        model = _cross_encoder()
        scores = model.predict([(clause, f"{entry['name']}. {entry['description']}") for clause in clauses for entry in entries])
        scored = []
        offset = 0
        for entry in entries:
            scored.append((max(scores[offset + i] for i in range(len(clauses))), entry))
            offset += len(clauses)
    except Exception:
        # Offline/uncached environments retain deterministic hybrid ranking.
        scored = []
        for entry in entries:
            query_tokens = _tokens(" ".join(clauses))
            candidate_tokens = _tokens(entry["name"] + " " + entry["description"])
            scored.append((len(query_tokens & candidate_tokens), entry))
    scored.sort(key=lambda pair: (-float(pair[0]), pair[1]["id"]))
    return [entry for _, entry in scored[:limit]]


@lru_cache(maxsize=1)
def _cross_encoder():
    from sentence_transformers import CrossEncoder

    return CrossEncoder("cross-encoder/ms-marco-MiniLM-L-6-v2")


def format_attack_entries(entries: list[dict]) -> str:
    return "\n\n".join(
        f"Source: ATT&CK Enterprise technique catalog\n"
        f"Technique: {entry['id']} — {entry['name']}\n"
        f"Platforms: {', '.join(entry['platforms']) or 'unspecified'}\n"
        f"Definition: {entry['description']}"
        for entry in entries
    )
