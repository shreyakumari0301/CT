"""Unit tests for the cross-vendor alias resolution table.

Covers:
* the static seed table API (case/punctuation tolerance, type filtering),
* integration with the extractor's entity coercion step,
* end-to-end: cross-report merging of two reports that mention the same
  threat actor under different surface forms.
"""

from __future__ import annotations

import asyncio
import json

import pytest

from baselines.ctinexus_lite import (
    AliasTable, ALIAS_SEED, Chunk, Extractor, PropertyGraph,
)
from baselines.ctinexus_lite.extractor import _coerce_entities
from baselines.ctinexus_lite.tests._fake_llm import FakeLLM


# --------------------------- seed table tests ---------------------------

class TestAliasTable:
    def setup_method(self):
        self.t = AliasTable()

    def test_seed_table_size(self):
        s = self.t.stats()
        assert s["n_canonical"] >= 60, f"expected >=60 canonicals, got {s}"
        assert s["by_type"].get("threat_actor", 0) >= 30
        assert s["by_type"].get("malware", 0) >= 20

    def test_lookup_canonical(self):
        m = self.t.lookup("APT29")
        assert m is not None
        assert m.canonical_name == "APT29"
        assert m.entity_type == "threat_actor"
        assert "Cozy Bear" in m.aliases
        assert "Nobelium" in m.aliases

    def test_lookup_alias(self):
        m = self.t.lookup("Cozy Bear")
        assert m is not None
        assert m.canonical_name == "APT29"
        assert "Midnight Blizzard" in m.aliases

    def test_lookup_case_and_punct_insensitive(self):
        for surf in ["apt-29", "APT 29", " APT29 ", "cozy_bear", "COZY  BEAR"]:
            m = self.t.lookup(surf)
            assert m is not None, surf
            assert m.canonical_name == "APT29"

    def test_lookup_type_filter(self):
        # If we ask for malware "APT29" we should get nothing.
        assert self.t.lookup("APT29", entity_type="malware") is None
        # But threat_actor should hit.
        assert self.t.lookup("APT29", entity_type="threat_actor") is not None

    def test_lookup_miss_returns_none(self):
        assert self.t.lookup("Unknown Group") is None
        assert self.t.lookup("") is None

    def test_canonicalize_fallback_to_input(self):
        # Unknown surface is returned unchanged.
        assert self.t.canonicalize("Quantum Threat XYZ") == "Quantum Threat XYZ"

    def test_known_malware_aliases(self):
        # BlackCat / ALPHV / Noberus are all the same.
        for surf in ["ALPHV", "Noberus", "ALPHV/BlackCat", "BlackCat"]:
            m = self.t.lookup(surf)
            assert m is not None and m.canonical_name == "BlackCat", surf

    def test_expand(self):
        # The extractor will use this: pass canonical + aliases and let the
        # table resolve to its seed entry.
        result = self.t.expand(["Sodinokibi", "REvil"], entity_type="malware")
        assert result is not None
        canonical, aliases = result
        assert canonical == "REvil"
        assert "Sodinokibi" in aliases

    def test_expand_none(self):
        assert self.t.expand(["MadeUpActor"], entity_type="threat_actor") is None


# --------------------------- extractor integration ---------------------------

class TestExtractorAliasResolution:
    def test_coerce_resolves_to_seed_canonical(self):
        # LLM emits "Cozy Bear" as the canonical_name; resolver should rewrite
        # it to "APT29" and union in the seed table's aliases.
        raw = [{
            "entity_type": "threat_actor",
            "canonical_name": "Cozy Bear",
            "aliases": ["Nobelium"],
            "properties": {"country": "Russia"},
        }]
        out = _coerce_entities(raw, chunk_id="c1", alias_table=AliasTable())
        assert len(out) == 1
        e = out[0]
        assert e.canonical_name == "APT29"
        # The original surface form is now an alias.
        assert "Cozy Bear" in e.aliases
        assert "Nobelium" in e.aliases
        # Seed-only aliases also show up.
        assert "Midnight Blizzard" in e.aliases
        # The user-provided property survives.
        assert e.properties["country"] == "Russia"

    def test_coerce_without_alias_table_unchanged(self):
        # When alias_table is None, the LLM's canonical name is preserved.
        raw = [{"entity_type": "threat_actor",
                "canonical_name": "Cozy Bear",
                "aliases": []}]
        out = _coerce_entities(raw, chunk_id="c1", alias_table=None)
        assert out[0].canonical_name == "Cozy Bear"

    def test_unknown_entity_unchanged(self):
        # Resolver does not invent canonicals for unknown surfaces.
        raw = [{"entity_type": "threat_actor",
                "canonical_name": "Brand New APT 999",
                "aliases": []}]
        out = _coerce_entities(raw, chunk_id="c1", alias_table=AliasTable())
        assert out[0].canonical_name == "Brand New APT 999"

    def test_e2e_cross_report_merge(self):
        """Two "reports" mention the same actor under different aliases —
        after extraction + alias resolution + graph merge, only ONE node
        should remain in the graph with both surface forms as aliases.
        """
        # Report 1 says "Cozy Bear"; report 2 says "Nobelium".
        ner1 = json.dumps({"entities": [
            {"entity_type": "threat_actor", "canonical_name": "Cozy Bear",
             "aliases": [], "properties": {"country": "Russia"}}
        ]})
        re1 = json.dumps({"triples": []})
        ner2 = json.dumps({"entities": [
            {"entity_type": "threat_actor", "canonical_name": "Nobelium",
             "aliases": [], "properties": {"primary_motivation": "espionage"}}
        ]})
        re2 = json.dumps({"triples": []})

        ext = Extractor(llm=FakeLLM([ner1, re1, ner2, re2]), concurrency=1)
        chunks1 = [Chunk(chunk_id="R1::ch0", doc_id="R1", chunk_index=0,
                         text="Cozy Bear active.", token_count=3)]
        chunks2 = [Chunk(chunk_id="R2::ch0", doc_id="R2", chunk_index=0,
                         text="Nobelium active.", token_count=3)]

        graph = PropertyGraph()
        asyncio.run(ext.extract_document(chunks1, graph=graph))
        asyncio.run(ext.extract_document(chunks2, graph=graph))

        # Despite different surface forms across reports, the graph should
        # have collapsed to a single APT29 node.
        threat_actors = graph.entities_by_type("threat_actor")
        assert len(threat_actors) == 1, [e.canonical_name for e in threat_actors]
        apt29 = threat_actors[0]
        assert apt29.canonical_name == "APT29"
        # Both report-specific aliases survive
        assert "Cozy Bear" in apt29.aliases
        assert "Nobelium" in apt29.aliases
        # Properties from both reports are merged
        assert apt29.properties.get("country") == "Russia"
        assert apt29.properties.get("primary_motivation") == "espionage"
        # source_chunks reflects both reports
        assert {"R1::ch0", "R2::ch0"}.issubset(set(apt29.source_chunks))
