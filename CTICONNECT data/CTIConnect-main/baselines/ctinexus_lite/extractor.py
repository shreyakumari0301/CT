"""Two-step LLM-driven extractor: typed NER, then open-vocabulary RE.

The extractor consumes a list of :class:`Chunk` objects (typically from
:func:`chunk_document`) and produces a :class:`PropertyGraph`. It runs the
NER and RE passes per chunk and then merges results across chunks of the
same document via :meth:`PropertyGraph.add_entity` (which deduplicates
nodes keyed by ``(entity_type, canonical_name)``).

Design notes
------------
* The extractor is *stateless*: a single instance can process many documents
  concurrently. Concurrency is bounded with ``llm.gather_bounded``.
* Bad chunks (LLM JSON failure, schema violation) are *logged and skipped*
  rather than crashing the whole document — KG construction is best-effort.
* The OpenIE pass is anchored on the entity list from NER: only triples
  whose endpoints appear in that list are accepted. This prevents the
  model from inventing new entities at the RE stage.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path

from baselines.ctinexus_lite.alias_table import AliasTable
from baselines.ctinexus_lite.chunker import Chunk
from baselines.ctinexus_lite.graph import PropertyGraph
from baselines.ctinexus_lite.llm import LLMClient, gather_bounded
from baselines.ctinexus_lite.ontology import (
    ENTITY_TYPES, Entity, Relationship, canonical_predicate,
)


log = logging.getLogger("ctinexus_lite.extractor")

PROMPTS_DIR = Path(__file__).parent / "prompts"


@dataclass
class ExtractionStats:
    n_chunks: int = 0
    n_ner_success: int = 0
    n_ner_fail: int = 0
    n_re_success: int = 0
    n_re_fail: int = 0
    n_entities_raw: int = 0
    n_entities_filtered: int = 0
    n_triples_raw: int = 0
    n_triples_filtered: int = 0
    usage: dict[str, int] = field(default_factory=lambda: {
        "prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0,
    })


class Extractor:
    """Two-step ontology-aware extractor."""

    def __init__(
        self,
        llm: LLMClient | None = None,
        *,
        concurrency: int = 8,
        alias_table: AliasTable | None = None,
    ):
        self.llm = llm or LLMClient()
        self.concurrency = concurrency
        # Pass ``None`` instead of an AliasTable to disable resolution (useful
        # in unit tests). Default behaviour: use the bundled seed table.
        self.alias_table = AliasTable() if alias_table is None else alias_table
        self._ner_template = (PROMPTS_DIR / "ner.txt").read_text(encoding="utf-8")
        self._openie_template = (PROMPTS_DIR / "openie.txt").read_text(encoding="utf-8")

    # ------------------- single chunk -------------------

    async def extract_chunk(
        self, chunk: Chunk, stats: ExtractionStats,
    ) -> tuple[list[Entity], list[Relationship]]:
        """Run NER + RE on one chunk. Returns ``(entities, relationships)``."""
        entities = await self._extract_ner(chunk, stats)
        if not entities:
            return [], []
        triples = await self._extract_re(chunk, entities, stats)
        return entities, triples

    # ------------------- whole document -------------------

    async def extract_document(
        self,
        chunks: list[Chunk],
        *,
        graph: PropertyGraph | None = None,
        stats: ExtractionStats | None = None,
    ) -> tuple[PropertyGraph, ExtractionStats]:
        """Run extraction over every chunk in a document and merge into ``graph``."""
        graph = graph if graph is not None else PropertyGraph()
        stats = stats if stats is not None else ExtractionStats()
        stats.n_chunks += len(chunks)
        if not chunks:
            return graph, stats

        results = await gather_bounded(
            [self.extract_chunk(c, stats) for c in chunks],
            concurrency=self.concurrency,
        )
        for ents, rels in results:
            for e in ents:
                graph.add_entity(e)
            for r in rels:
                graph.add_relationship(r)
        return graph, stats

    # ------------------- internals -------------------

    async def _extract_ner(
        self, chunk: Chunk, stats: ExtractionStats,
    ) -> list[Entity]:
        prompt = self._ner_template.replace("{PASSAGE}", chunk.text)
        try:
            obj, result = await self.llm.aask_json(prompt, max_tokens=4000)
        except (ValueError, RuntimeError) as e:
            stats.n_ner_fail += 1
            log.warning("NER failed for %s: %s", chunk.chunk_id, e)
            return []
        stats.n_ner_success += 1
        _accumulate_usage(stats.usage, result.usage)

        raw = obj.get("entities") or []
        stats.n_entities_raw += len(raw)
        out = _coerce_entities(
            raw,
            chunk_id=chunk.chunk_id,
            alias_table=self.alias_table,
        )
        stats.n_entities_filtered += len(out)
        return out

    async def _extract_re(
        self,
        chunk: Chunk,
        entities: list[Entity],
        stats: ExtractionStats,
    ) -> list[Relationship]:
        entity_list_str = _format_entity_list_for_prompt(entities)
        prompt = (
            self._openie_template
            .replace("{ENTITIES}", entity_list_str)
            .replace("{PASSAGE}", chunk.text)
        )
        try:
            obj, result = await self.llm.aask_json(prompt, max_tokens=4000)
        except (ValueError, RuntimeError) as e:
            stats.n_re_fail += 1
            log.warning("RE failed for %s: %s", chunk.chunk_id, e)
            return []
        stats.n_re_success += 1
        _accumulate_usage(stats.usage, result.usage)

        raw = obj.get("triples") or []
        stats.n_triples_raw += len(raw)
        out = _coerce_triples(
            raw,
            entities=entities,
            chunk_id=chunk.chunk_id,
        )
        stats.n_triples_filtered += len(out)
        return out


# ------------------- coercion helpers -------------------

def _coerce_entities(
    raw: list[dict], *, chunk_id: str, alias_table: AliasTable | None = None,
) -> list[Entity]:
    """Validate and clean LLM-emitted entity records.

    When ``alias_table`` is supplied, known surface forms are rewritten to
    their canonical name and the seed table's full alias set is merged in.
    This collapses cross-report aliases at the earliest possible stage so
    that PropertyGraph node deduplication works as expected.
    """
    out: list[Entity] = []
    seen: set[tuple[str, str]] = set()
    for item in raw:
        if not isinstance(item, dict):
            continue
        etype = (item.get("entity_type") or "").strip()
        if etype not in ENTITY_TYPES:
            log.debug("dropping entity with unknown type %r", etype)
            continue
        name = (item.get("canonical_name") or "").strip()
        if not name:
            continue
        aliases_raw = item.get("aliases") or []
        if not isinstance(aliases_raw, list):
            aliases_raw = []
        aliases = tuple(_normalise_alias(a) for a in aliases_raw if _normalise_alias(a))

        # Resolve against the seed alias table: prefer the canonical form and
        # union the seed's known aliases with what the LLM already produced.
        if alias_table is not None:
            seed_match = alias_table.expand((name, *aliases), entity_type=etype)
            if seed_match is not None:
                seed_canonical, seed_aliases = seed_match
                # The original LLM-extracted name becomes an alias unless it
                # already matches the canonical form.
                merged_aliases: list[str] = []
                for surf in (name, *aliases, *seed_aliases):
                    if surf and surf != seed_canonical and surf not in merged_aliases:
                        merged_aliases.append(surf)
                name = seed_canonical
                aliases = tuple(merged_aliases)

        # Dedup any remaining aliases against the final canonical.
        aliases = tuple(a for a in aliases if a != name)

        properties = item.get("properties") or {}
        if not isinstance(properties, dict):
            properties = {}

        # IDs in name field should also surface as a property when applicable.
        properties = _enrich_id_properties(etype, name, properties)

        key = (etype, name)
        if key in seen:
            continue
        seen.add(key)

        try:
            out.append(Entity(
                entity_type=etype,
                canonical_name=name,
                aliases=aliases,
                properties=properties,
                source_chunks=(chunk_id,),
            ))
        except ValueError as e:
            log.debug("dropping malformed entity: %s", e)
    return out


def _coerce_triples(
    raw: list[dict], *, entities: list[Entity], chunk_id: str,
) -> list[Relationship]:
    """Keep only triples whose endpoints appear in the provided entity list."""
    by_key: dict[tuple[str, str], Entity] = {
        (e.entity_type, e.canonical_name): e for e in entities
    }
    # Also map any alias surface to its canonical so the LLM can be sloppy.
    alias_to_key: dict[str, tuple[str, str]] = {}
    for e in entities:
        for surf in (e.canonical_name, *e.aliases):
            alias_to_key.setdefault(surf, (e.entity_type, e.canonical_name))

    out: list[Relationship] = []
    seen: set[tuple[str, str, str, str, str]] = set()

    for t in raw:
        if not isinstance(t, dict):
            continue
        src_name = (t.get("src_name") or "").strip()
        tgt_name = (t.get("tgt_name") or "").strip()
        src_type = (t.get("src_type") or "").strip()
        tgt_type = (t.get("tgt_type") or "").strip()
        pred = canonical_predicate(t.get("predicate") or "")
        if not (src_name and tgt_name and pred):
            continue

        # Resolve via canonical, else alias.
        src_key = (src_type, src_name) if (src_type, src_name) in by_key \
            else alias_to_key.get(src_name)
        tgt_key = (tgt_type, tgt_name) if (tgt_type, tgt_name) in by_key \
            else alias_to_key.get(tgt_name)
        if not src_key or not tgt_key:
            continue
        if src_key == tgt_key:  # self-loop
            continue

        sig = (src_key[0], src_key[1], pred, tgt_key[0], tgt_key[1])
        if sig in seen:
            continue
        seen.add(sig)

        out.append(Relationship(
            src_type=src_key[0], src_name=src_key[1],
            predicate=pred,
            tgt_type=tgt_key[0], tgt_name=tgt_key[1],
            source_chunks=(chunk_id,),
        ))
    return out


def _normalise_alias(a: object) -> str:
    if not isinstance(a, str):
        return ""
    return a.strip()


def _enrich_id_properties(etype: str, name: str, properties: dict) -> dict:
    """If the canonical name itself is a CVE/CWE/T-ID, lift it into properties."""
    p = dict(properties or {})
    if etype == "vulnerability" and not p.get("cve_id"):
        if name.startswith("CVE-"):
            p["cve_id"] = name
    elif etype == "weakness" and not p.get("cwe_id"):
        if name.startswith("CWE-"):
            p["cwe_id"] = name
    elif etype == "attack_pattern" and not p.get("technique_id"):
        # T-IDs look like T1234 or T1234.001 — scan for the first such token.
        import re as _re
        m = _re.search(r"\bT\d{4}(?:\.\d{3})?\b", name)
        if m:
            p["technique_id"] = m.group(0)
    return p


def _format_entity_list_for_prompt(entities: list[Entity]) -> str:
    lines = []
    for e in entities:
        aliases = f" (aliases: {', '.join(e.aliases)})" if e.aliases else ""
        lines.append(f"- {e.entity_type}: {e.canonical_name}{aliases}")
    return "\n".join(lines)


def _accumulate_usage(target: dict[str, int], delta: dict[str, int]) -> None:
    for k in ("prompt_tokens", "completion_tokens", "total_tokens"):
        target[k] = target.get(k, 0) + (delta.get(k, 0) or 0)
