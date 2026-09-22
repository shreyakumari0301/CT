# TAA retrieval experiment plans

## MS-ATTACK-01 — multi-source ATT&CK candidate retrieval

**Status: selected and running.**

Test whether natural, actor-linked MITRE ATT&CK group, campaign, and software
passages improve the frozen CTA/shared-BM25 candidate pool and top-3 ranking.
The pipeline retains the frozen CTA top-10 and shared BM25 top-20 candidates,
then adds the top-20 actor results from multi-source MiniLM dense retrieval and
top-20 from multi-source local BM25. Qwen3-Reranker-4B and Jina Reranker v3.5
will rerank the exact same pool and source-evidence documents.

CAPEC and Sigma are explicitly out of scope for this run because they are not
present as actor-linked local inputs; the ingestion manifest will record that
rather than infer links. Acceptance criterion: improve Recall@3 beyond the
verified 70% evidence-focused Qwen baseline, while reporting candidate coverage
and all per-case rankings. Active run: see `progress.md` (MS-ATTACK-01).

## Deferred ideas

- Semantic boundary chunking, only if source-linked ATT&CK evidence does not
  improve the retained pool.
- Hierarchical actor/campaign summaries, after evaluating the simpler source
  passages; do not introduce generated summaries before this gold-blind test.
