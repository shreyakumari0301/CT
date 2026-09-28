"""Shared alias-equivalence rules for the TAA controlled benchmarks.

Candidate rankings use the canonical actor names from ``actor_profiles.json``
while CTA labels may use a vendor-specific alias.  Metrics must therefore
compare actor identities rather than display strings.
"""

from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path


def _normalise(name: str) -> str:
    """Return a case- and punctuation-insensitive actor label."""
    return re.sub(r"[^a-z0-9]", "", (name or "").lower())


# These CTA gold-label aliases are absent from the locally frozen MITRE actor
# profiles.  The values are canonical names used by the retrieval pool.
_EXTRA_ALIASES = {
    "mummyspider": "FIN7",
    "chrysene": "OilRig",
    "lazarus": "Lazarus Group",
    "charmingcypress": "Magic Hound",
    "gamaredon": "Gamaredon Group",
    "bitterapt": "BITTER",
    # Kept for label completeness.  Sharp Dragon is not represented in the
    # frozen retrieval profiles, so this gold label cannot become a false hit.
    "sharppanda": "Sharp Dragon",
}


@lru_cache(maxsize=1)
def _actor_ids() -> dict[str, frozenset[str]]:
    """Map every local canonical name and alias to canonical actor IDs."""
    root = Path(__file__).resolve().parents[1]
    profile_path = (
        root
        / "eval_results/controlled_benchmark/taa20_20260918"
        / "actor_retrieval_study_v2/actor_profiles.json"
    )
    profiles = json.loads(profile_path.read_text(encoding="utf-8"))

    actor_ids: dict[str, set[str]] = {}
    for profile in profiles:
        canonical = _normalise(profile["canonical_actor"])
        for label in (profile["canonical_actor"], *profile.get("aliases", [])):
            actor_ids.setdefault(_normalise(label), set()).add(canonical)

    for alias, canonical in _EXTRA_ALIASES.items():
        actor_ids.setdefault(alias, set()).add(_normalise(canonical))

    return {label: frozenset(ids) for label, ids in actor_ids.items()}


def mitre_canonical(name: str) -> str | None:
    """Map a display name to the frozen MITRE canonical actor, if known.

    Mint Sandstorm, APT35, and CharmingCypress all resolve to Magic Hound.
    This is identity, not a string rewrite of the CTIBench gold label.
    """
    key = _normalise(name)
    if not key:
        return None
    ids = _actor_ids().get(key)
    if not ids or len(ids) != 1:
        extra = _EXTRA_ALIASES.get(key)
        return extra
    canonical_key = next(iter(ids))
    root = Path(__file__).resolve().parents[1]
    profile_path = (
        root
        / "eval_results/controlled_benchmark/taa20_20260918"
        / "actor_retrieval_study_v2/actor_profiles.json"
    )
    for profile in json.loads(profile_path.read_text(encoding="utf-8")):
        if _normalise(profile["canonical_actor"]) == canonical_key:
            return profile["canonical_actor"]
    return extra if (extra := _EXTRA_ALIASES.get(key)) else None


def rank1_decision(gold: str, ranking: list, related=None) -> dict:
    """Score the rank-1 actor. Never replace it with a gold hit at rank 2 or 3."""
    names = [entry["actor"] if isinstance(entry, dict) else entry for entry in ranking]
    predicted = names[0] if names else ""
    gold_position = next(
        (position for position, name in enumerate(names[:3], 1) if benchmark_alias_match(name, gold)),
        None,
    )
    correct = bool(predicted) and benchmark_alias_match(predicted, gold)
    if correct:
        reason = "literal_match" if predicted.strip().lower() == gold.strip().lower() else "alias_match"
    elif predicted and related is not None and related(predicted, gold):
        reason = "related_actor_only"
    else:
        reason = "no_match"
    return {
        "top3": names[:3],
        "gold_position_in_top3": gold_position,
        "predicted_actor": predicted,
        "correct": correct,
        "match_reason": reason,
    }


def ctibench_dicts() -> tuple[dict, dict]:
    """Official CTIBench alias and related-group maps (Alam et al., 2024)."""
    root = Path(__file__).resolve().parents[1]
    folder = root / "data/ctibench_taa"
    import pickle

    with (folder / "alias_dict.pickle").open("rb") as handle:
        alias_dict = pickle.load(handle)
    with (folder / "related_dict.pickle").open("rb") as handle:
        related_dict = pickle.load(handle)
    return alias_dict, related_dict


def _norm_group_dict(raw: dict) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for key, values in raw.items():
        actor = str(key).strip().lower()
        aliases = [str(value).strip().lower() for value in values]
        out.setdefault(actor, [])
        for alias in aliases:
            if alias not in out[actor]:
                out[actor].append(alias)
            out.setdefault(alias, [])
            if actor not in out[alias]:
                out[alias].append(actor)
    return out


def _bfs_connected(start: str, goal: str, *graphs: dict[str, list[str]]) -> bool:
    seen = {start}
    queue = [start]
    while queue:
        current = queue.pop(0)
        for graph in graphs:
            for neighbour in graph.get(current, []):
                if neighbour == goal:
                    return True
                if neighbour not in seen:
                    seen.add(neighbour)
                    queue.append(neighbour)
    return False


def ctibench_taa_split(predicted: str, gold: str) -> str:
    """CTIBench TAA bucket: exact, alias (Correct), related (Plausible), or miss.

    Matches evaluation/evaluation.ipynb: C = alias chain, P = related-group chain.
    Exact is reported separately before alias credit.
    """
    pred = (predicted or "").strip()
    gt = (gold or "").strip()
    if not pred:
        return "miss"
    if pred.lower() == gt.lower():
        return "exact"
    alias_dict, related_dict = ctibench_dicts()
    aliases = _norm_group_dict(alias_dict)
    related = _norm_group_dict(related_dict)
    a, b = pred.lower(), gt.lower()
    if _bfs_connected(a, b, aliases):
        return "alias"
    if _bfs_connected(a, b, aliases, related):
        return "related"
    if benchmark_alias_match(pred, gt):
        return "alias"
    return "miss"


def benchmark_alias_match(candidate: str, gold: str) -> bool:
    """Whether a ranked candidate denotes the same actor as the gold label."""
    candidate_key, gold_key = _normalise(candidate), _normalise(gold)
    if not candidate_key or not gold_key:
        return False

    actor_ids = _actor_ids()
    candidate_ids = actor_ids.get(candidate_key, frozenset((candidate_key,)))
    gold_ids = actor_ids.get(gold_key, frozenset((gold_key,)))
    return not candidate_ids.isdisjoint(gold_ids)
