"""End-to-end tests for the CSKG build pipeline + ``retrieve_related_reports``.

Verifies that the full online retrieval flow works against an artificial
4-document corpus, using a fake LLM to extract entities from the anchor at
query time. This is the function the cskg_guided ``run.py`` baseline will
call once per evaluation instance.
"""

from __future__ import annotations

import asyncio
import json

import pytest

from baselines.ctinexus_lite import (
    BM25EntityIndex, Extractor, retrieve_related_reports,
)
from baselines.ctinexus_lite.tests._fake_llm import FakeLLM


def _build_corpus_index() -> BM25EntityIndex:
    """Build a stand-in CSKG index with the canonical alias-shaped surface
    forms that the real pipeline would produce *after* alias resolution.
    """
    return BM25EntityIndex.build({
        # Two reports about the same actor under different aliases.
        # In the real pipeline alias resolution would canonicalise both to
        # ``APT29`` plus the seed alias set; we mirror that here directly.
        "BLOG-COZY":
            ["APT29", "Cozy Bear", "Nobelium", "The Dukes",
             "Midnight Blizzard", "WellMess", "U.S. healthcare sector"],
        "BLOG-NOBELIUM":
            ["APT29", "Cozy Bear", "Nobelium", "Midnight Blizzard",
             "SUNBURST", "SolarWinds", "U.S. federal agencies"],
        # Same APT, different malware. Should still rank highly for an
        # APT29-themed anchor.
        "BLOG-APT29-2024":
            ["APT29", "Cozy Bear", "Nobelium", "Midnight Blizzard",
             "European governments"],
        # Unrelated decoy.
        "BLOG-LOCKBIT":
            ["LockBit", "LockBit 3.0", "ALPHV", "ransomware-as-a-service"],
    })


def test_retrieve_related_reports_alias_aware():
    """Anchor mentions 'Midnight Blizzard' only — retrieval must still find
    the three APT29 reports thanks to seed-driven alias expansion at
    extraction time.
    """
    # Fake LLM returns NER that contains only 'Midnight Blizzard' as the
    # canonical_name. Because the Extractor has the alias_table on by
    # default, it will rewrite this to 'APT29' and union in the seed aliases.
    ner_resp = json.dumps({
        "entities": [{
            "entity_type": "threat_actor",
            "canonical_name": "Midnight Blizzard",
            "aliases": [],
            "properties": {},
        }]
    })
    re_resp = json.dumps({"triples": []})
    extractor = Extractor(llm=FakeLLM([ner_resp, re_resp]), concurrency=1)

    idx = _build_corpus_index()

    anchor_text = (
        "Researchers attribute the 2024 intrusion campaign to "
        "Midnight Blizzard, which has been observed targeting European "
        "ministries of foreign affairs."
    )
    result = asyncio.run(retrieve_related_reports(
        anchor_text,
        anchor_doc_id="ANCHOR-NEW",
        bm25_index=idx,
        extractor=extractor,
        k=4,
    ))

    # Anchor's resolved surfaces include APT29 plus the seed alias set,
    # not just 'Midnight Blizzard'.
    assert "APT29" in result.anchor_entities
    assert "Cozy Bear" in result.anchor_entities
    assert "Nobelium" in result.anchor_entities

    # All three APT29 corpus docs should be retrieved.
    retrieved = [h.doc_id for h in result.hits]
    assert "BLOG-COZY" in retrieved
    assert "BLOG-NOBELIUM" in retrieved
    assert "BLOG-APT29-2024" in retrieved


def test_retrieve_related_reports_excludes_anchor():
    """The anchor doc_id, if it exists in the index, must not appear in the
    retrieval result — otherwise the synthesis prompt would receive its own
    input twice.
    """
    ner_resp = json.dumps({
        "entities": [{
            "entity_type": "threat_actor",
            "canonical_name": "APT29",
            "aliases": [],
        }]
    })
    re_resp = json.dumps({"triples": []})
    extractor = Extractor(llm=FakeLLM([ner_resp, re_resp]), concurrency=1)

    idx = _build_corpus_index()
    result = asyncio.run(retrieve_related_reports(
        "APT29 update.",
        anchor_doc_id="BLOG-COZY",   # anchor is in the index
        bm25_index=idx,
        extractor=extractor,
        k=4,
    ))
    assert all(h.doc_id != "BLOG-COZY" for h in result.hits)


def test_retrieve_related_reports_decoy_ranks_low():
    """A query about APT29 should not rank a LockBit ransomware doc above
    the actor-themed reports, despite ``ALPHV`` appearing in both (because
    of how alias_table seeded BlackCat's alias set).
    """
    ner_resp = json.dumps({
        "entities": [{
            "entity_type": "threat_actor",
            "canonical_name": "APT29",
            "aliases": [],
        }]
    })
    re_resp = json.dumps({"triples": []})
    extractor = Extractor(llm=FakeLLM([ner_resp, re_resp]), concurrency=1)

    idx = _build_corpus_index()
    result = asyncio.run(retrieve_related_reports(
        "APT29 espionage report.",
        anchor_doc_id="ANCHOR",
        bm25_index=idx,
        extractor=extractor,
        k=4,
    ))
    scores = {h.doc_id: h.score for h in result.hits}
    apt29_docs = ["BLOG-COZY", "BLOG-NOBELIUM", "BLOG-APT29-2024"]
    # All three APT29-themed docs outscore the LockBit decoy if it appears.
    if "BLOG-LOCKBIT" in scores:
        lockbit_score = scores["BLOG-LOCKBIT"]
        for d in apt29_docs:
            if d in scores:
                assert scores[d] > lockbit_score, \
                    f"{d}={scores[d]} not > LockBit={lockbit_score}"
