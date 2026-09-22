# TAA retrieval experiment plans

## MS-ATTACK-01 — multi-source ATT&CK candidate retrieval

**Status: complete; did not meet the top-3 acceptance criterion.**

Test whether natural, actor-linked MITRE ATT&CK group, campaign, and software
passages improve the frozen CTA/shared-BM25 candidate pool and top-3 ranking.
The pipeline retains the frozen CTA top-10 and shared BM25 top-20 candidates,
then adds the top-20 actor results from multi-source MiniLM dense retrieval and
top-20 from multi-source local BM25. Qwen3-Reranker-4B and Jina Reranker v3.5
will rerank the exact same pool and source-evidence documents.

CAPEC and Sigma are explicitly out of scope for this run because they are not
present as actor-linked local inputs; the ingestion manifest records that
rather than inferring links. The run raised candidate-pool coverage from 82%
to 92%, but its changed compact source-evidence document reduced Qwen R@3 to
58%; see `progress.md` and `conclusions.md` for the completed result.

## MS-ATTACK-02 — multi-source pool with the proven Qwen evidence view

**Status: selected.**

Test the multi-source union without changing the successful Qwen3-4B
evidence-focused query selector or full actor-profile documents. This isolates
the candidate-pool effect that MS-ATTACK-01 confounded with a new compact
source-evidence document. The candidate pool, model revision, 50-report split,
and gold-blind protocol are fixed. Acceptance criterion: exceed the verified
70% Recall@3 evidence-focused baseline; candidate-pool coverage and all
per-case rankings are retained for diagnosis. Once it starts, the immutable
run ID and logs will be recorded in `progress.md`.

## Deferred ideas

- Semantic boundary chunking, only if source-linked ATT&CK evidence does not
  improve the retained pool.
- Hierarchical actor/campaign summaries, after evaluating the simpler source
  passages; do not introduce generated summaries before this gold-blind test.
