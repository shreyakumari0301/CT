"""STIX-aligned entity ontology and open-vocabulary relation schema.

Design notes
------------
* Entity types are a curated subset of STIX 2.1 SDOs chosen to cover the
  vocabulary observed in vendor threat reports. Each type has a fixed set of
  properties (extracted at NER time) so downstream tools can rely on the shape.
* Relations are intentionally *open-vocabulary* — the extractor emits free-form
  predicate strings (e.g., ``"uses"``, ``"delivered_via"``, ``"targets"``).
  Predicates are normalised by ``canonical_predicate`` to a snake_case form so
  semantically identical surface variants collapse, but no closed set is
  enforced. This matches how HippoRAG / OpenIE work and is enough for our use
  case: only the entity vocabulary feeds the sparse retrieval index, the
  relation graph is auxiliary.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, asdict
from typing import Any


# ------------------------------ Entity types ------------------------------

#: The eight entity types we extract from CTI reports. Each maps to a STIX 2.1
#: SDO when one exists; ``weakness`` does not have a STIX SDO so we treat it
#: as a typed variant of ``vulnerability``.
ENTITY_TYPES: dict[str, dict[str, Any]] = {
    "threat_actor": {
        "stix_type": "threat-actor",
        "description": "A named adversary, group, or operator behind malicious activity.",
        "examples": ["APT29", "Lazarus Group", "Scattered Spider"],
        "properties": [
            "country", "primary_motivation",
            "sectors_targeted", "regions_targeted",
            "first_seen", "last_seen",
        ],
    },
    "campaign": {
        "stix_type": "campaign",
        "description": "A grouping of adversarial behaviour over a finite time window.",
        "examples": ["Operation Aurora", "EleKtra-Leak"],
        "properties": ["objective", "first_seen", "last_seen"],
    },
    "malware": {
        "stix_type": "malware",
        "description": "A malicious software family or instance used by adversaries.",
        "examples": ["LockBit", "QakBot", "Cobalt Strike (when used maliciously)"],
        "properties": ["family", "capabilities", "platforms", "first_seen"],
    },
    "tool": {
        "stix_type": "tool",
        "description": "A legitimate or dual-use tool repurposed for offensive operations.",
        "examples": ["PsExec", "Mimikatz", "AnyDesk"],
        "properties": ["capabilities", "platforms"],
    },
    "attack_pattern": {
        "stix_type": "attack-pattern",
        "description": "An offensive behaviour, typically aligned with a MITRE ATT&CK technique.",
        "examples": ["Spearphishing Attachment (T1566.001)", "Credential Dumping"],
        "properties": ["technique_id", "tactic"],
    },
    "vulnerability": {
        "stix_type": "vulnerability",
        "description": "A specific software flaw identified by a CVE.",
        "examples": ["CVE-2024-3400", "CVE-2023-23397"],
        "properties": ["cve_id", "cvss", "severity"],
    },
    "weakness": {
        "stix_type": None,  # not a STIX SDO; CWE class
        "description": "A weakness class (CWE) underlying one or more vulnerabilities.",
        "examples": ["CWE-79 (XSS)", "CWE-787 (Out-of-bounds Write)"],
        "properties": ["cwe_id"],
    },
    "indicator": {
        "stix_type": "indicator",
        "description": "An observable IoC: IP, domain, URL, file hash, email.",
        "examples": ["evil.example[.]com", "203.0.113.42", "deadbeef… (sha256)"],
        "properties": ["ioc_type", "value"],
    },
    "identity": {
        "stix_type": "identity",
        "description": "A victim entity: organisation, sector, or geographic region.",
        "examples": ["U.S. Department of Defense", "European energy sector", "Ukraine"],
        "properties": ["sector", "region"],
    },
}


def entity_type_names() -> list[str]:
    """Canonical entity-type identifiers, in declaration order."""
    return list(ENTITY_TYPES)


# ----------------------------- Data classes -----------------------------

@dataclass(frozen=True)
class Entity:
    """A single extracted entity.

    ``canonical_name`` is the surface form chosen as the head of an alias
    group; ``aliases`` lists alternative surface forms observed for the same
    real-world entity. ``properties`` carries type-specific attributes (see
    ``ENTITY_TYPES``).

    Two ``Entity`` records collide on equality iff their ``(entity_type,
    canonical_name)`` pair matches — which lets us merge mentions across
    chunks without losing alias breadth.
    """

    entity_type: str
    canonical_name: str
    aliases: tuple[str, ...] = ()
    properties: dict[str, Any] = field(default_factory=dict)
    source_chunks: tuple[str, ...] = ()  # chunk IDs where this entity was seen

    def __post_init__(self) -> None:
        if self.entity_type not in ENTITY_TYPES:
            raise ValueError(
                f"Unknown entity_type {self.entity_type!r}. "
                f"Valid: {entity_type_names()}"
            )
        if not self.canonical_name or not self.canonical_name.strip():
            raise ValueError("canonical_name must be a non-empty string")

    @property
    def vocab(self) -> list[str]:
        """All surface forms (canonical + aliases) for BM25 indexing."""
        return [self.canonical_name, *self.aliases]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Entity":
        return cls(
            entity_type=d["entity_type"],
            canonical_name=d["canonical_name"],
            aliases=tuple(d.get("aliases", []) or []),
            properties=d.get("properties", {}) or {},
            source_chunks=tuple(d.get("source_chunks", []) or []),
        )


@dataclass(frozen=True)
class Relationship:
    """An open-RE triple: source entity -- predicate --> target entity.

    Source and target are referenced by ``(entity_type, canonical_name)`` so
    we can resolve them against the entity store without keeping object
    identity. ``predicate`` is the normalised relation string (see
    ``canonical_predicate``).
    """

    src_type: str
    src_name: str
    predicate: str
    tgt_type: str
    tgt_name: str
    source_chunks: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Relationship":
        return cls(
            src_type=d["src_type"],
            src_name=d["src_name"],
            predicate=d["predicate"],
            tgt_type=d["tgt_type"],
            tgt_name=d["tgt_name"],
            source_chunks=tuple(d.get("source_chunks", []) or []),
        )


# --------------------------- Predicate canonicalisation ---------------------------

_PRED_NORMALISE_RE = re.compile(r"[^a-z0-9]+")


def canonical_predicate(raw: str) -> str:
    """Normalise a free-form predicate string to snake_case.

    Examples
    --------
    >>> canonical_predicate("Uses")
    'uses'
    >>> canonical_predicate("delivered via")
    'delivered_via'
    >>> canonical_predicate("ATTRIBUTED-TO")
    'attributed_to'
    """
    if not raw:
        return ""
    s = raw.strip().lower()
    s = _PRED_NORMALISE_RE.sub("_", s)
    return s.strip("_")
