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


def benchmark_alias_match(candidate: str, gold: str) -> bool:
    """Whether a ranked candidate denotes the same actor as the gold label."""
    candidate_key, gold_key = _normalise(candidate), _normalise(gold)
    if not candidate_key or not gold_key:
        return False

    actor_ids = _actor_ids()
    candidate_ids = actor_ids.get(candidate_key, frozenset((candidate_key,)))
    gold_ids = actor_ids.get(gold_key, frozenset((gold_key,)))
    return not candidate_ids.isdisjoint(gold_ids)
