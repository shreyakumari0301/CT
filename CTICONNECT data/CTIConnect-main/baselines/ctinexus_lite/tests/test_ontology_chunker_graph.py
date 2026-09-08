"""Unit tests for the ontology, chunker, and property graph — no LLM calls."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from baselines.ctinexus_lite import (
    ENTITY_TYPES, Entity, Relationship, PropertyGraph,
    chunk_document, canonical_predicate,
)
from baselines.ctinexus_lite.ontology import entity_type_names


# --------------------------- ontology tests ---------------------------

class TestOntology:
    def test_entity_types_complete(self):
        expected = {
            "threat_actor", "campaign", "malware", "tool",
            "attack_pattern", "vulnerability", "weakness",
            "indicator", "identity",
        }
        assert set(ENTITY_TYPES.keys()) == expected
        assert len(entity_type_names()) == 9

    def test_entity_type_metadata_shape(self):
        for name, meta in ENTITY_TYPES.items():
            assert "description" in meta
            assert "examples" in meta and isinstance(meta["examples"], list)
            assert "properties" in meta and isinstance(meta["properties"], list)

    def test_entity_construction_ok(self):
        e = Entity(
            entity_type="threat_actor",
            canonical_name="APT29",
            aliases=("Cozy Bear", "Nobelium"),
            properties={"country": "Russia", "primary_motivation": "espionage"},
            source_chunks=("BLOG-1::ch0",),
        )
        assert e.canonical_name == "APT29"
        assert e.vocab == ["APT29", "Cozy Bear", "Nobelium"]

    def test_entity_rejects_unknown_type(self):
        with pytest.raises(ValueError, match="Unknown entity_type"):
            Entity(entity_type="hackerman", canonical_name="anon")

    def test_entity_rejects_empty_name(self):
        with pytest.raises(ValueError, match="non-empty"):
            Entity(entity_type="malware", canonical_name="   ")

    def test_entity_roundtrip(self):
        e = Entity(
            entity_type="malware", canonical_name="LockBit",
            aliases=("LockBit 3.0",),
            properties={"family": "ransomware"},
        )
        e2 = Entity.from_dict(e.to_dict())
        assert e == e2

    def test_relationship_roundtrip(self):
        r = Relationship(
            src_type="threat_actor", src_name="APT29",
            predicate="uses",
            tgt_type="malware", tgt_name="WellMess",
            source_chunks=("BLOG-1::ch0",),
        )
        r2 = Relationship.from_dict(r.to_dict())
        assert r == r2

    def test_canonical_predicate(self):
        assert canonical_predicate("Uses") == "uses"
        assert canonical_predicate("delivered via") == "delivered_via"
        assert canonical_predicate("ATTRIBUTED-TO") == "attributed_to"
        assert canonical_predicate("  uses  ") == "uses"
        assert canonical_predicate("") == ""
        # Multi-symbol collapses to single underscore
        assert canonical_predicate("a -- b") == "a_b"


# --------------------------- chunker tests ---------------------------

class TestChunker:
    def test_empty_input(self):
        assert chunk_document("", doc_id="X") == []
        assert chunk_document("   \n  \n", doc_id="X") == []

    def test_short_doc_single_chunk(self):
        text = "APT29 used WellMess to target diplomats."
        chunks = chunk_document(text, doc_id="BLOG-1")
        assert len(chunks) == 1
        assert chunks[0].chunk_id == "BLOG-1::ch0"
        assert chunks[0].doc_id == "BLOG-1"
        assert chunks[0].chunk_index == 0
        assert chunks[0].token_count > 0
        assert chunks[0].text.startswith("APT29")

    def test_long_doc_splits(self):
        # Build a 4000-token-ish document with paragraph boundaries.
        para = ("LockBit ransomware uses double extortion. "
                "Operators deploy via PsExec. ") * 30
        text = "\n\n".join([para] * 8)
        chunks = chunk_document(text, doc_id="BLOG-99", chunk_size=512, overlap=64)
        assert len(chunks) > 1
        for c in chunks:
            assert c.token_count <= 512 + 64  # overlap may push slightly over
        # Chunks are correctly indexed
        for i, c in enumerate(chunks):
            assert c.chunk_index == i
            assert c.chunk_id == f"BLOG-99::ch{i}"

    def test_overlap_produces_shared_tokens(self):
        para = "Sentence one is here. Sentence two follows. Sentence three. " * 20
        chunks = chunk_document(para, doc_id="D", chunk_size=128, overlap=32)
        if len(chunks) >= 2:
            # The tail of chunk 0 should appear at the start of chunk 1.
            tail = chunks[0].text[-50:].strip()
            assert any(tok in chunks[1].text for tok in tail.split()
                       if len(tok) > 3), \
                "overlap chunk should share content with previous"

    def test_invalid_params(self):
        with pytest.raises(ValueError):
            chunk_document("hi", doc_id="X", chunk_size=0)
        with pytest.raises(ValueError):
            chunk_document("hi", doc_id="X", chunk_size=100, overlap=100)


# --------------------------- graph tests ---------------------------

class TestPropertyGraph:
    def test_empty_graph(self):
        g = PropertyGraph()
        assert g.n_entities == 0
        assert g.n_relationships == 0
        assert g.stats()["n_entities"] == 0

    def test_add_entity_dedup(self):
        g = PropertyGraph()
        g.add_entity(Entity(
            entity_type="threat_actor", canonical_name="APT29",
            aliases=("Cozy Bear",),
            properties={"country": "Russia"},
            source_chunks=("BLOG-1::ch0",),
        ))
        g.add_entity(Entity(
            entity_type="threat_actor", canonical_name="APT29",
            aliases=("Nobelium",),  # new alias
            properties={"primary_motivation": "espionage"},  # new property
            source_chunks=("BLOG-2::ch0",),
        ))
        assert g.n_entities == 1
        ents = list(g.entities())
        e = ents[0]
        assert e.canonical_name == "APT29"
        assert set(e.aliases) == {"Cozy Bear", "Nobelium"}
        assert e.properties["country"] == "Russia"
        assert e.properties["primary_motivation"] == "espionage"
        assert set(e.source_chunks) == {"BLOG-1::ch0", "BLOG-2::ch0"}

    def test_add_relationship_creates_stub_nodes(self):
        g = PropertyGraph()
        g.add_relationship(Relationship(
            src_type="threat_actor", src_name="APT29",
            predicate="uses",
            tgt_type="malware", tgt_name="WellMess",
        ))
        assert g.n_entities == 2
        assert g.n_relationships == 1

    def test_entities_by_type(self):
        g = PropertyGraph()
        g.add_entity(Entity(entity_type="threat_actor", canonical_name="APT29"))
        g.add_entity(Entity(entity_type="malware", canonical_name="WellMess"))
        g.add_entity(Entity(entity_type="malware", canonical_name="Sliver"))
        assert len(g.entities_by_type("malware")) == 2
        assert len(g.entities_by_type("threat_actor")) == 1
        assert len(g.entities_by_type("indicator")) == 0

    def test_entity_vocab_dedup(self):
        g = PropertyGraph()
        g.add_entity(Entity(
            entity_type="threat_actor", canonical_name="APT29",
            aliases=("Cozy Bear", "Nobelium"),
        ))
        g.add_entity(Entity(
            entity_type="malware", canonical_name="WellMess",
            aliases=("APT29",),  # collision across types: should still dedup at name level
        ))
        v = g.entity_vocab()
        # Each surface name appears at most once globally.
        assert len(v) == len(set(v))
        assert "APT29" in v
        assert "Cozy Bear" in v
        assert "WellMess" in v

    def test_jsonl_roundtrip(self, tmp_path):
        g = PropertyGraph()
        g.add_entity(Entity(
            entity_type="threat_actor", canonical_name="APT29",
            aliases=("Cozy Bear",),
            properties={"country": "Russia"},
            source_chunks=("BLOG-1::ch0",),
        ))
        g.add_entity(Entity(
            entity_type="malware", canonical_name="WellMess",
            properties={"family": "RAT"},
        ))
        g.add_relationship(Relationship(
            src_type="threat_actor", src_name="APT29",
            predicate="uses",
            tgt_type="malware", tgt_name="WellMess",
            source_chunks=("BLOG-1::ch0",),
        ))

        ep = tmp_path / "entities.jsonl"
        rp = tmp_path / "relations.jsonl"
        g.to_jsonl(ep, rp)
        assert ep.exists() and rp.exists()

        g2 = PropertyGraph.from_jsonl(ep, rp)
        assert g2.n_entities == g.n_entities
        assert g2.n_relationships == g.n_relationships

        # Spot-check content survives
        ents = sorted(g2.entities(), key=lambda e: e.canonical_name)
        assert ents[0].canonical_name == "APT29"
        assert "Cozy Bear" in ents[0].aliases
        assert ents[0].properties["country"] == "Russia"
        assert ents[1].canonical_name == "WellMess"

        rels = list(g2.relationships())
        assert rels[0].predicate == "uses"
        assert rels[0].src_name == "APT29"

    def test_graphml_writes(self, tmp_path):
        g = PropertyGraph()
        g.add_entity(Entity(entity_type="threat_actor", canonical_name="APT29",
                            aliases=("Cozy Bear",), properties={"country": "RU"}))
        g.add_entity(Entity(entity_type="malware", canonical_name="WellMess"))
        g.add_relationship(Relationship(
            src_type="threat_actor", src_name="APT29",
            predicate="uses",
            tgt_type="malware", tgt_name="WellMess",
        ))
        p = tmp_path / "g.graphml"
        g.to_graphml(p)
        assert p.exists()
        content = p.read_text()
        assert "APT29" in content
        assert "uses" in content

    def test_stats(self):
        g = PropertyGraph()
        g.add_entity(Entity(entity_type="threat_actor", canonical_name="A"))
        g.add_entity(Entity(entity_type="threat_actor", canonical_name="B"))
        g.add_entity(Entity(entity_type="malware", canonical_name="X"))
        stats = g.stats()
        assert stats["n_entities"] == 3
        assert stats["entities_by_type"]["threat_actor"] == 2
        assert stats["entities_by_type"]["malware"] == 1
