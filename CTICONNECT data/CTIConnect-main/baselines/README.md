# CTIConnect Baselines

Reference implementations of the retrieval strategies evaluated in the paper.
Fork these and swap in your own answering model to produce a leaderboard entry.

## What's here

| Path | Strategy | Tasks | Status |
|---|---|---|---|
| `ctinexus_lite/` | STIX-aligned property-graph extraction library | (shared) | ✅ |
| `cskg_guided/` | **CSKG-Guided RAG** — entity-set retrieval over a cyber-knowledge graph | Multi-Doc Synthesis (CSC/TAP/MLA) | ✅ |
| `closed_book/` | LLM parametric knowledge only, no retrieval | Entity Linking + Entity Attribution | ✅ |
| `vanilla_rag/` | embed query → top-k → answer | Entity Linking + Entity Attribution | ✅ |
| `etr/` | **Extract-then-Retrieve** | Entity Linking | ✅ |
| `dtr/` | **Decompose-then-Retrieve** | Entity Attribution | ✅ |

## ctinexus-lite

A lean (~900 LOC, 4 dependencies) library for building a Cyber-Security
Knowledge Graph (CSKG) from threat reports, used by the CSKG-Guided RAG
baseline. It follows the two-step extraction pattern (typed NER → open
relation extraction) over a STIX-aligned ontology and indexes reports by their
entity vocabularies for sparse retrieval.

```
ctinexus_lite/
├── ontology.py      # 8 STIX-aligned entity types + open-vocabulary relations
├── chunker.py       # token-aware recursive splitter (1024 tok / 128 overlap)
├── llm.py           # async OpenAI client w/ retry + lenient JSON parsing
├── extractor.py     # two-step NER → open-RE, with alias canonicalization
├── alias_table.py   # ~75 curated APT/malware aliases (MITRE Groups + vendor rosetta)
├── graph.py         # NetworkX MultiDiGraph property graph + graphml/jsonl I/O
├── sparse_index.py  # BM25 over per-report entity vocabularies
├── pipeline.py      # corpus → property graph → BM25 index
└── prompts/         # ner.txt, openie.txt
```

Test it (no API key needed for the offline suite):

```bash
python -m pytest baselines/ctinexus_lite/tests/ -k "not live"   # 73 tests
```

## CSKG-Guided RAG

### Build the knowledge graph (offline, one-time)

```bash
export OPENAI_API_KEY=...        # required
export CTINEXUS_MODEL=gpt-4o # optional; default model

python -m baselines.cskg_guided.build_index \
    --corpus corpus_reports/preprocessed_reports.jsonl \
    --output cskg/ \
    --report-concurrency 8
```

This produces `entities.jsonl`, `relations.jsonl`, `graph.graphml`, and
`bm25_index.pkl`. A prebuilt CSKG is already shipped in `cskg/`, so you can
skip this step unless you want to rebuild from scratch or change the model.

### Retrieve + answer

At query time, the system extracts entities from the **anchor report**, queries
the BM25 entity index to retrieve related reports, then prompts an answering
LLM to synthesize the answer. See `cskg_guided/build_index.py` and
`ctinexus_lite/pipeline.py:retrieve_related_reports` for the API.

### Why entity-set retrieval

Multi-document synthesis questions are generic ("who is the threat actor?",
"how did the malware evolve?"). The retrieval signal comes from the anchor
report's entities (~23 per report on average), not the question. Different
vendors name the same actor differently (APT29 / Cozy Bear / Midnight
Blizzard) — embedding similarity breaks, but entity-set overlap (after alias
canonicalization) does not. Measured over the 137 multi-doc-synthesis
clusters, CSKG-Guided retrieval reaches **recall@10 = 0.84** (CSC 0.97,
TAP 0.84, MLA 0.67).

## Shared retrieval configuration (from the paper)

| Component | Setting |
|---|---|
| Embedding model | OpenAI `text-embedding-3-large` (3072-d, L2-normalized) |
| Vector store | FAISS `IndexFlatIP` (cosine) |
| Top-k | 5 (Entity Linking / Attribution), 10 (Multi-Doc Synthesis) |
| Report chunking | 1024 tokens, 128 overlap |
| Reranker (ablation) | BAAI/bge-reranker-v2-m3 |
