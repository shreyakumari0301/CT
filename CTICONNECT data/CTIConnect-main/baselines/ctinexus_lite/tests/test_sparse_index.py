"""Unit tests for the BM25 sparse index over entity vocabularies."""

from __future__ import annotations

import pytest

from baselines.ctinexus_lite import (
    BM25EntityIndex, RetrievalHit, tokenize_entity_vocab,
)


# --------------------------- tokeniser ---------------------------

class TestTokenizer:
    def test_simple_words(self):
        assert tokenize_entity_vocab(["APT29"]) == ["apt29"]
        assert tokenize_entity_vocab(["Cozy Bear"]) == ["cozy", "bear"]

    def test_multiple_surfaces(self):
        toks = tokenize_entity_vocab(["APT29", "Cozy Bear", "Nobelium"])
        assert toks == ["apt29", "cozy", "bear", "nobelium"]

    def test_punctuation_split(self):
        # "ALPHV/BlackCat" splits, "CVE-2024-3400" splits too.
        toks = tokenize_entity_vocab(["ALPHV/BlackCat", "CVE-2024-3400"])
        assert toks == ["alphv", "blackcat", "cve", "2024", "3400"]

    def test_empty_inputs_dropped(self):
        assert tokenize_entity_vocab(["", None, "  "]) == []


# --------------------------- build + search ---------------------------

class TestBM25EntityIndex:
    def _build_sample(self) -> BM25EntityIndex:
        return BM25EntityIndex.build({
            "REPORT-1": ["APT29", "Cozy Bear", "WellMess", "CVE-2020-5902"],
            "REPORT-2": ["APT29", "Sliver", "CVE-2024-3400"],
            "REPORT-3": ["Lazarus Group", "TrickBot"],
            "REPORT-4": ["Windows", "Linux"],  # only generic — should rank low
            "REPORT-5": ["BlackCat", "ALPHV", "Noberus"],
        })

    def test_n_documents(self):
        idx = self._build_sample()
        assert idx.n_documents == 5

    def test_search_with_distinctive_entity_ranks_first(self):
        idx = self._build_sample()
        hits = idx.search(["WellMess"], k=3)
        assert len(hits) >= 1
        assert hits[0].doc_id == "REPORT-1"
        assert hits[0].score > 0

    def test_idf_downweights_generic_terms(self):
        # All 4 reports below have "Windows"; REPORT-4 is the only one
        # whose vocab is ALL generic — it should not be retrieved when the
        # query is a specific entity.
        idx = BM25EntityIndex.build({
            "DIST-1": ["APT29", "Windows"],
            "DIST-2": ["APT28", "Windows"],
            "DIST-3": ["FIN7", "Linux"],
            "GENERIC": ["Windows", "Linux"],
        })
        hits = idx.search(["APT29"], k=4)
        assert hits[0].doc_id == "DIST-1"
        retrieved = [h.doc_id for h in hits]
        assert "GENERIC" not in retrieved

    def test_exclude_anchor_doc(self):
        # Useful for MDS: the anchor report should not appear in retrieval.
        idx = self._build_sample()
        hits = idx.search(["APT29"], k=3, exclude_doc_ids={"REPORT-1"})
        # REPORT-1 has APT29 too but is the anchor.
        retrieved = [h.doc_id for h in hits]
        assert "REPORT-1" not in retrieved
        assert "REPORT-2" in retrieved  # REPORT-2 has APT29

    def test_query_with_alias_hits_canonical(self):
        # If we ship aliases in the indexed doc, a query for the alias hits.
        idx = self._build_sample()
        hits = idx.search(["Cozy Bear"], k=2)
        retrieved = [h.doc_id for h in hits]
        assert "REPORT-1" in retrieved

    def test_no_overlap_returns_empty(self):
        idx = self._build_sample()
        hits = idx.search(["Quantum Threat XYZ"], k=5)
        assert hits == []

    def test_empty_query_returns_empty(self):
        idx = self._build_sample()
        assert idx.search([], k=5) == []
        assert idx.search([""], k=5) == []

    def test_k_caps_results(self):
        idx = self._build_sample()
        hits = idx.search(["APT29", "Sliver"], k=1)
        assert len(hits) == 1

    def test_matched_tokens_recorded(self):
        idx = self._build_sample()
        hits = idx.search(["APT29", "WellMess"], k=1)
        # REPORT-1 has both APT29 and WellMess
        h = hits[0]
        assert h.doc_id == "REPORT-1"
        assert "apt29" in h.matched_tokens
        assert "wellmess" in h.matched_tokens

    def test_empty_doc_vocab_handled(self):
        # A doc with NO entities should not crash the index and must not
        # rank above docs with real entity matches. We use 3+ docs because
        # BM25Okapi IDF is undefined / zero when a term appears in ~half
        # the corpus (a known property of the formula, not a bug).
        idx = BM25EntityIndex.build({
            "WITH_ENT1": ["APT29", "WellMess"],
            "WITH_ENT2": ["LockBit"],
            "WITH_ENT3": ["TrickBot"],
            "EMPTY": [],
        })
        assert idx.n_documents == 4
        hits = idx.search(["APT29"], k=5)
        assert any(h.doc_id == "WITH_ENT1" for h in hits)
        assert all(h.doc_id != "EMPTY" for h in hits)

    def test_add_after_finalise_raises(self):
        idx = self._build_sample()
        with pytest.raises(RuntimeError, match="finalise"):
            idx.add("LATE", ["x"])

    def test_search_before_finalise_raises(self):
        idx = BM25EntityIndex()
        idx.add("X", ["a"])
        with pytest.raises(RuntimeError):
            idx.search(["a"], k=1)


# --------------------------- persistence ---------------------------

class TestPersistence:
    def test_save_load_roundtrip(self, tmp_path):
        original = BM25EntityIndex.build({
            "A": ["APT29", "Cozy Bear"],
            "B": ["Lazarus Group"],
            "C": ["BlackCat", "ALPHV"],
        })
        p = tmp_path / "bm25.pkl"
        original.save(p)
        assert p.exists()

        loaded = BM25EntityIndex.load(p)
        assert loaded.n_documents == original.n_documents
        # Scores should be byte-identical: same tokenisation, same BM25 params.
        h_orig = original.search(["APT29"], k=2)
        h_loaded = loaded.search(["APT29"], k=2)
        assert [h.doc_id for h in h_orig] == [h.doc_id for h in h_loaded]
        assert h_orig[0].score == pytest.approx(h_loaded[0].score)

    def test_surfaces_for_lookup(self, tmp_path):
        idx = BM25EntityIndex.build({
            "DOC-1": ["APT29", "Cozy Bear", "Nobelium"],
        })
        assert idx.surfaces_for("DOC-1") == ("APT29", "Cozy Bear", "Nobelium")
        assert idx.surfaces_for("MISSING") == ()

    def test_debug_jsonl_dump(self, tmp_path):
        idx = BM25EntityIndex.build({
            "A": ["APT29"],
            "B": ["LockBit"],
        })
        p = tmp_path / "debug.jsonl"
        idx.to_jsonl_for_debug(p)
        lines = [l for l in p.read_text().splitlines() if l.strip()]
        assert len(lines) == 2
        import json as _json
        ids = {_json.loads(l)["doc_id"] for l in lines}
        assert ids == {"A", "B"}


# --------------------------- realistic scenario ---------------------------

class TestMDSRealistic:
    """Simulate the actual CSKG-Guided RAG retrieval scenario:
    given an anchor report's entity vocab, retrieve related reports about
    the same campaign/actor across the corpus.
    """

    def test_cross_alias_retrieval(self):
        # Three reports about the same actor under different surface forms,
        # plus one decoy about a different actor.
        corpus = {
            "BLOG-CozyBear-2020": [
                "Cozy Bear", "WellMess", "U.S. healthcare sector", "CVE-2020-5902"
            ],
            "BLOG-Nobelium-2021": [
                "Nobelium", "SUNBURST", "SolarWinds", "U.S. federal agencies"
            ],
            "BLOG-APT29-2022": [
                "APT29", "WellMess", "European governments"
            ],
            "BLOG-LockBit-2023": [
                "LockBit", "Conti", "ransomware affiliate"
            ],
        }
        idx = BM25EntityIndex.build(corpus)

        # Anchor: a 2024 report that calls the same actor "Midnight Blizzard"
        # AND mentions WellMess. After alias canonicalisation the entity
        # vocabulary surfaced in the anchor would be the canonical "APT29"
        # plus all known aliases shipped by the seed table — so we exercise
        # that here directly.
        anchor_entities = ["APT29", "Cozy Bear", "Nobelium",
                           "Midnight Blizzard", "WellMess"]

        hits = idx.search(anchor_entities, k=4)
        retrieved = [h.doc_id for h in hits]

        # All three actor-related reports should be retrieved, decoy excluded
        # OR ranked last.
        assert "BLOG-CozyBear-2020" in retrieved
        assert "BLOG-Nobelium-2021" in retrieved
        assert "BLOG-APT29-2022" in retrieved
        # The decoy may or may not appear, but its score must be lowest.
        if "BLOG-LockBit-2023" in retrieved:
            scores = {h.doc_id: h.score for h in hits}
            assert scores["BLOG-LockBit-2023"] < min(
                scores[d] for d in retrieved if d != "BLOG-LockBit-2023"
            )
