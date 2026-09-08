"""In-memory property graph backed by :class:`networkx.MultiDiGraph`.

Nodes are entities keyed by ``(entity_type, canonical_name)``; edges are
relationships with a free-form ``predicate`` attribute. The graph supports:

* incremental merging (multiple extractions from different chunks accumulate
  aliases and properties on the same node),
* GraphML serialisation (for visualisation in Gephi / Cytoscape),
* JSONL serialisation (entities and relationships as separate files, suitable
  for storage in git).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable, Iterator

import networkx as nx

from baselines.ctinexus_lite.ontology import Entity, Relationship


# -------------------------- merge helpers (pure) --------------------------

def _node_key(entity_type: str, canonical_name: str) -> str:
    return f"{entity_type}::{canonical_name}"


def _merge_alias_lists(existing: tuple[str, ...], incoming: Iterable[str]) -> tuple[str, ...]:
    """Union of ``existing`` and ``incoming`` preserving first-seen order."""
    out = list(existing)
    seen = set(out)
    for x in incoming:
        if x and x not in seen:
            out.append(x)
            seen.add(x)
    return tuple(out)


def _merge_property_dicts(existing: dict, incoming: dict) -> dict:
    """Merge incoming properties into existing.

    Lists are concatenated and deduplicated; scalars from ``incoming`` override
    ``None``/empty values in ``existing`` but never overwrite a present value.
    """
    merged = dict(existing) if existing else {}
    for k, v in (incoming or {}).items():
        if isinstance(v, list):
            cur = merged.get(k) or []
            if not isinstance(cur, list):
                cur = [cur]
            for item in v:
                if item not in cur:
                    cur.append(item)
            merged[k] = cur
        else:
            if v in (None, "") or merged.get(k) in (None, "", [], {}):
                merged[k] = v if v not in (None, "") else merged.get(k)
            # else: keep existing
    return merged


# ------------------------------- main class -------------------------------

class PropertyGraph:
    """A typed property graph for CTI entities and open-RE relations."""

    def __init__(self) -> None:
        self._g: nx.MultiDiGraph = nx.MultiDiGraph()

    # ------------------- mutation -------------------

    def add_entity(self, ent: Entity) -> str:
        """Add ``ent`` to the graph, merging with any existing node keyed
        identically. Returns the node key.
        """
        key = _node_key(ent.entity_type, ent.canonical_name)
        if self._g.has_node(key):
            data = self._g.nodes[key]
            data["aliases"] = _merge_alias_lists(
                tuple(data.get("aliases", ())), ent.aliases
            )
            data["properties"] = _merge_property_dicts(
                data.get("properties", {}), ent.properties
            )
            data["source_chunks"] = _merge_alias_lists(
                tuple(data.get("source_chunks", ())), ent.source_chunks
            )
        else:
            self._g.add_node(
                key,
                entity_type=ent.entity_type,
                canonical_name=ent.canonical_name,
                aliases=tuple(ent.aliases),
                properties=dict(ent.properties),
                source_chunks=tuple(ent.source_chunks),
            )
        return key

    def add_relationship(self, rel: Relationship) -> None:
        src = _node_key(rel.src_type, rel.src_name)
        tgt = _node_key(rel.tgt_type, rel.tgt_name)
        # Auto-create stub nodes if missing — extractor sometimes emits a
        # relation involving an entity that did not survive NER filtering.
        if not self._g.has_node(src):
            self._g.add_node(src, entity_type=rel.src_type,
                             canonical_name=rel.src_name,
                             aliases=(), properties={}, source_chunks=())
        if not self._g.has_node(tgt):
            self._g.add_node(tgt, entity_type=rel.tgt_type,
                             canonical_name=rel.tgt_name,
                             aliases=(), properties={}, source_chunks=())
        self._g.add_edge(
            src, tgt,
            key=rel.predicate,
            predicate=rel.predicate,
            source_chunks=tuple(rel.source_chunks),
        )

    # ------------------- queries -------------------

    @property
    def n_entities(self) -> int:
        return self._g.number_of_nodes()

    @property
    def n_relationships(self) -> int:
        return self._g.number_of_edges()

    def entities(self) -> Iterator[Entity]:
        for _, data in self._g.nodes(data=True):
            yield Entity(
                entity_type=data["entity_type"],
                canonical_name=data["canonical_name"],
                aliases=tuple(data.get("aliases", ())),
                properties=dict(data.get("properties", {}) or {}),
                source_chunks=tuple(data.get("source_chunks", ())),
            )

    def relationships(self) -> Iterator[Relationship]:
        for src, tgt, data in self._g.edges(data=True):
            src_data = self._g.nodes[src]
            tgt_data = self._g.nodes[tgt]
            yield Relationship(
                src_type=src_data["entity_type"],
                src_name=src_data["canonical_name"],
                predicate=data["predicate"],
                tgt_type=tgt_data["entity_type"],
                tgt_name=tgt_data["canonical_name"],
                source_chunks=tuple(data.get("source_chunks", ())),
            )

    def entities_by_type(self, entity_type: str) -> list[Entity]:
        return [e for e in self.entities() if e.entity_type == entity_type]

    def entity_vocab(self) -> list[str]:
        """All entity surface forms across the graph, deduplicated."""
        seen: set[str] = set()
        out: list[str] = []
        for e in self.entities():
            for name in e.vocab:
                if name not in seen:
                    seen.add(name)
                    out.append(name)
        return out

    # ------------------- serialisation -------------------

    def to_jsonl(self, entities_path: str | Path, relations_path: str | Path) -> None:
        """Persist as two JSONL files: one entity per line, one triple per line."""
        ep = Path(entities_path); ep.parent.mkdir(parents=True, exist_ok=True)
        rp = Path(relations_path); rp.parent.mkdir(parents=True, exist_ok=True)
        with ep.open("w", encoding="utf-8") as f:
            for e in self.entities():
                d = e.to_dict()
                d["aliases"] = list(d.get("aliases", ()))
                d["source_chunks"] = list(d.get("source_chunks", ()))
                f.write(json.dumps(d, ensure_ascii=False) + "\n")
        with rp.open("w", encoding="utf-8") as f:
            for r in self.relationships():
                d = r.to_dict()
                d["source_chunks"] = list(d.get("source_chunks", ()))
                f.write(json.dumps(d, ensure_ascii=False) + "\n")

    @classmethod
    def from_jsonl(cls, entities_path: str | Path,
                   relations_path: str | Path) -> "PropertyGraph":
        g = cls()
        with Path(entities_path).open(encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    g.add_entity(Entity.from_dict(json.loads(line)))
        with Path(relations_path).open(encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    g.add_relationship(Relationship.from_dict(json.loads(line)))
        return g

    def to_graphml(self, path: str | Path) -> None:
        """Persist as GraphML (Gephi / Cytoscape compatible)."""
        # NetworkX GraphML can't serialise dict/tuple attributes — flatten.
        h = nx.MultiDiGraph()
        for n, d in self._g.nodes(data=True):
            h.add_node(
                n,
                entity_type=d["entity_type"],
                canonical_name=d["canonical_name"],
                aliases="|".join(d.get("aliases", ())),
                properties_json=json.dumps(d.get("properties", {}) or {}, ensure_ascii=False),
                n_source_chunks=len(d.get("source_chunks", ())),
            )
        for src, tgt, d in self._g.edges(data=True):
            h.add_edge(
                src, tgt,
                predicate=d["predicate"],
                n_source_chunks=len(d.get("source_chunks", ())),
            )
        p = Path(path); p.parent.mkdir(parents=True, exist_ok=True)
        nx.write_graphml(h, p)

    # ------------------- introspection -------------------

    def stats(self) -> dict[str, int | dict[str, int]]:
        per_type: dict[str, int] = {}
        for e in self.entities():
            per_type[e.entity_type] = per_type.get(e.entity_type, 0) + 1
        return {
            "n_entities": self.n_entities,
            "n_relationships": self.n_relationships,
            "entities_by_type": per_type,
        }

    def __repr__(self) -> str:
        return (f"PropertyGraph(n_entities={self.n_entities}, "
                f"n_relationships={self.n_relationships})")
