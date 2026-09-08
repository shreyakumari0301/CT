"""Unit tests for the two-step (NER + open-RE) LLM extractor.

The "offline" tests use a fake LLM client to verify the parser, schema
coercion, and stats accounting without touching the network. The "online"
test (marked ``slow``) runs one real extraction call against gpt-4o
against a fixed snippet — only run when ``OPENAI_API_KEY`` is set.
"""

from __future__ import annotations

import asyncio
import json
import os

import pytest

from baselines.ctinexus_lite import (
    Chunk, Entity, Extractor, ExtractionStats, parse_json_lenient,
)
from baselines.ctinexus_lite.extractor import _coerce_entities, _coerce_triples
from baselines.ctinexus_lite.tests._fake_llm import FakeLLM


# --------------------------- JSON parser ---------------------------

class TestJSONParser:
    def test_plain_json(self):
        assert parse_json_lenient('{"x": 1}') == {"x": 1}

    def test_fenced_json(self):
        text = '```json\n{"entities": []}\n```'
        assert parse_json_lenient(text) == {"entities": []}

    def test_json_with_preamble(self):
        text = 'Sure! Here is the JSON:\n{"k": "v"}\nThanks.'
        assert parse_json_lenient(text) == {"k": "v"}

    def test_invalid_raises(self):
        with pytest.raises(ValueError):
            parse_json_lenient("not json at all")
        with pytest.raises(ValueError):
            parse_json_lenient("")


# --------------------------- coercion ---------------------------

class TestCoercion:
    def test_drop_unknown_entity_type(self):
        raw = [{"entity_type": "alien", "canonical_name": "X"}]
        out = _coerce_entities(raw, chunk_id="c1")
        assert out == []

    def test_drop_empty_name(self):
        raw = [{"entity_type": "malware", "canonical_name": "   "}]
        assert _coerce_entities(raw, chunk_id="c1") == []

    def test_dedup_same_key(self):
        raw = [
            {"entity_type": "malware", "canonical_name": "LockBit"},
            {"entity_type": "malware", "canonical_name": "LockBit",
             "aliases": ["LockBit 3.0"]},
        ]
        out = _coerce_entities(raw, chunk_id="c1")
        assert len(out) == 1  # dedup at the (type, name) level
        assert out[0].canonical_name == "LockBit"

    def test_id_lifted_to_properties(self):
        raw = [
            {"entity_type": "vulnerability", "canonical_name": "CVE-2024-3400"},
            {"entity_type": "weakness", "canonical_name": "CWE-79"},
            {"entity_type": "attack_pattern",
             "canonical_name": "Spearphishing Attachment (T1566.001)"},
        ]
        out = _coerce_entities(raw, chunk_id="c1")
        props = {e.entity_type: e.properties for e in out}
        assert props["vulnerability"]["cve_id"] == "CVE-2024-3400"
        assert props["weakness"]["cwe_id"] == "CWE-79"
        assert props["attack_pattern"]["technique_id"] == "T1566.001"

    def test_alias_dedup_against_canonical(self):
        raw = [{
            "entity_type": "threat_actor",
            "canonical_name": "APT29",
            "aliases": ["Cozy Bear", "APT29"],  # alias same as canonical
        }]
        out = _coerce_entities(raw, chunk_id="c1")
        assert out[0].aliases == ("Cozy Bear",)

    def test_triple_drops_unknown_endpoints(self):
        ents = [
            Entity(entity_type="threat_actor", canonical_name="APT29"),
            Entity(entity_type="malware", canonical_name="WellMess"),
        ]
        triples = [
            # valid
            {"src_name": "APT29", "src_type": "threat_actor",
             "predicate": "uses",
             "tgt_name": "WellMess", "tgt_type": "malware"},
            # unknown endpoint
            {"src_name": "APT29", "src_type": "threat_actor",
             "predicate": "targets",
             "tgt_name": "DoD", "tgt_type": "identity"},
            # self-loop
            {"src_name": "APT29", "src_type": "threat_actor",
             "predicate": "uses",
             "tgt_name": "APT29", "tgt_type": "threat_actor"},
            # missing predicate
            {"src_name": "APT29", "src_type": "threat_actor",
             "predicate": "",
             "tgt_name": "WellMess", "tgt_type": "malware"},
        ]
        out = _coerce_triples(triples, entities=ents, chunk_id="c1")
        assert len(out) == 1
        assert out[0].predicate == "uses"

    def test_triple_resolves_via_alias(self):
        ents = [
            Entity(entity_type="threat_actor", canonical_name="APT29",
                   aliases=("Cozy Bear",)),
            Entity(entity_type="malware", canonical_name="WellMess"),
        ]
        triples = [{
            "src_name": "Cozy Bear", "src_type": "threat_actor",  # alias
            "predicate": "uses",
            "tgt_name": "WellMess", "tgt_type": "malware",
        }]
        out = _coerce_triples(triples, entities=ents, chunk_id="c1")
        assert len(out) == 1
        assert out[0].src_name == "APT29"  # resolved to canonical

    def test_predicate_normalisation(self):
        ents = [
            Entity(entity_type="threat_actor", canonical_name="A"),
            Entity(entity_type="malware", canonical_name="B"),
        ]
        triples = [{
            "src_name": "A", "src_type": "threat_actor",
            "predicate": "Attributed-To",
            "tgt_name": "B", "tgt_type": "malware",
        }]
        out = _coerce_triples(triples, entities=ents, chunk_id="c1")
        assert out[0].predicate == "attributed_to"


# --------------------------- extractor with fake LLM ---------------------------


class TestExtractorWithFakeLLM:
    def _run(self, coro):
        return asyncio.run(coro)

    def test_extract_chunk_happy_path(self):
        ner_resp = json.dumps({
            "entities": [
                {"entity_type": "threat_actor", "canonical_name": "APT29",
                 "aliases": ["Cozy Bear"], "properties": {"country": "Russia"}},
                {"entity_type": "malware", "canonical_name": "WellMess",
                 "aliases": [], "properties": {}},
            ]
        })
        re_resp = json.dumps({
            "triples": [
                {"src_name": "APT29", "src_type": "threat_actor",
                 "predicate": "uses",
                 "tgt_name": "WellMess", "tgt_type": "malware"}
            ]
        })
        llm = FakeLLM([ner_resp, re_resp])
        ext = Extractor(llm=llm, concurrency=1)
        chunk = Chunk(chunk_id="BLOG-1::ch0", doc_id="BLOG-1",
                      chunk_index=0, text="APT29 used WellMess.", token_count=5)
        stats = ExtractionStats()
        ents, rels = self._run(ext.extract_chunk(chunk, stats))
        assert len(ents) == 2
        assert ents[0].canonical_name == "APT29"
        assert len(rels) == 1
        assert rels[0].predicate == "uses"
        assert stats.n_ner_success == 1
        assert stats.n_re_success == 1
        assert stats.usage["total_tokens"] > 0

    def test_extract_chunk_skips_ner_failure(self):
        llm = FakeLLM(["not json at all"])  # NER fails, no RE attempt
        ext = Extractor(llm=llm, concurrency=1)
        chunk = Chunk(chunk_id="X::ch0", doc_id="X", chunk_index=0,
                      text="hello", token_count=1)
        stats = ExtractionStats()
        ents, rels = self._run(ext.extract_chunk(chunk, stats))
        assert ents == [] and rels == []
        assert stats.n_ner_fail == 1
        assert stats.n_re_success == 0
        assert stats.n_re_fail == 0  # we never called RE

    def test_extract_document_aggregates(self):
        # Two chunks, second mentions APT29 again with new alias.
        ner1 = json.dumps({"entities": [
            {"entity_type": "threat_actor", "canonical_name": "APT29",
             "aliases": ["Cozy Bear"]}
        ]})
        re1 = json.dumps({"triples": []})
        ner2 = json.dumps({"entities": [
            {"entity_type": "threat_actor", "canonical_name": "APT29",
             "aliases": ["Nobelium"]},
            {"entity_type": "malware", "canonical_name": "WellMess"},
        ]})
        re2 = json.dumps({"triples": [
            {"src_name": "APT29", "src_type": "threat_actor",
             "predicate": "uses",
             "tgt_name": "WellMess", "tgt_type": "malware"}
        ]})
        llm = FakeLLM([ner1, re1, ner2, re2])
        # Note: by default the extractor consults the seed AliasTable, which
        # injects the full set of known APT29 aliases (Cozy Bear, Nobelium,
        # Midnight Blizzard, etc.). We assert that the chunk-supplied aliases
        # are a SUBSET of the final alias set rather than equality.
        ext = Extractor(llm=llm, concurrency=1)
        chunks = [
            Chunk(chunk_id="D::ch0", doc_id="D", chunk_index=0,
                  text="APT29 active.", token_count=3),
            Chunk(chunk_id="D::ch1", doc_id="D", chunk_index=1,
                  text="APT29 used WellMess.", token_count=5),
        ]
        graph, stats = self._run(ext.extract_document(chunks))
        assert graph.n_entities == 2  # APT29 dedup, WellMess added
        apt29 = next(e for e in graph.entities() if e.canonical_name == "APT29")
        # Chunk-supplied aliases must survive the merge.
        assert "Cozy Bear" in apt29.aliases
        assert "Nobelium" in apt29.aliases
        # Source chunks accumulate.
        assert set(apt29.source_chunks) == {"D::ch0", "D::ch1"}
        assert graph.n_relationships == 1


# --------------------------- live smoke (slow) ---------------------------

@pytest.mark.skipif(
    not os.environ.get("OPENAI_API_KEY"),
    reason="needs OPENAI_API_KEY for live smoke test",
)
def test_live_extract_one_chunk():
    """One real GPT call on a short snippet. Asserts plausible extraction."""
    text = (
        "APT29 (also known as Cozy Bear and Nobelium) is a Russian "
        "state-sponsored group attributed to the SVR. In 2020, the group "
        "used the WellMess malware to target the U.S. healthcare sector. "
        "The campaign exploited CVE-2020-5902 in F5 BIG-IP devices."
    )
    chunk = Chunk(chunk_id="TEST::ch0", doc_id="TEST", chunk_index=0,
                  text=text, token_count=80)
    ext = Extractor()
    stats = ExtractionStats()
    ents, rels = asyncio.run(ext.extract_chunk(chunk, stats))
    canonical_names = {e.canonical_name for e in ents}
    # Plausibility: must have caught APT29 (or Cozy Bear / Nobelium) + CVE.
    actor_seen = any(name in canonical_names for name in {"APT29", "Cozy Bear", "Nobelium"})
    cve_seen = "CVE-2020-5902" in canonical_names
    assert actor_seen, f"actor not extracted: {canonical_names}"
    assert cve_seen, f"CVE not extracted: {canonical_names}"
    # Should have at least one relation
    assert len(rels) >= 1, f"no relations: {rels}"
    print(f"\n[live smoke] entities={len(ents)}, rels={len(rels)}, "
          f"tokens={stats.usage['total_tokens']}")
