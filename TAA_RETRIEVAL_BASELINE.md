# TAA Retrieval Baseline for Qwen3

## Current System

The Qwen3 reranker now receives a fixed candidate pool built from frozen
CTA/IDF top-15 plus natural-passage BM25 top-25, deduplicated by actor name.
The pre-rerank ordering uses canonicalized actor matching, IDF-like rarity,
per-channel min-max normalization, and equal fusion. No final LLM calls are
used for these retrieval metrics.

IDF gives more signal to a clue that appears in fewer actor profiles. BM25
retrieves actors whose report terms match strongly while penalizing terms that
are common across the actor corpus.

## Retrieval-Only Results

| Variant | CTA top | BM25 top | R@1 | R@3 | R@5 | R@10 | R@20 | MRR@10 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Entity-relationship Graph-RAG baseline | - | - | 23/50 (46%) | 26/50 (52%) | 29/50 (58%) | 34/50 (68%) | 37/50 (74%) | 0.5157 |
| Initial CTA+BM25 strategic cosine | 20 | 20 | 6/50 (12%) | 13/50 (26%) | 19/50 (38%) | 28/50 (56%) | 39/50 (78%) | 0.2268 |
| CTA+BM25 manual relationship scorer | 15 | 25 | 23/50 (46%) | 29/50 (58%) | 30/50 (60%) | 35/50 (70%) | 39/50 (78%) | 0.5321 |
| **Normalized CTA+BM25 pre-Qwen baseline** | **15** | **25** | **24/50 (48%)** | **32/50 (64%)** | **32/50 (64%)** | **36/50 (72%)** | **41/50 (82%)** | **0.5601** |

## Qwen3 Evaluation

The Qwen3 audit uses the same CTA-15/BM25-25 pool and reranks complete actor
profiles. Its output directory is:

```text
eval_results/controlled_benchmark/full/taa_qwen3_normalized_cta15_bm2525_union_audit/
```

The comparison is valid only when the Qwen3 run is complete for all 50 items.
The retrieval baseline measures candidate ordering before Qwen3; the Qwen3
metrics measure ordering after the cross-encoder. No LLM final attribution
calls are included.

## Verified Evidence-Focused Qwen4B Audit

The verified evidence-focused Qwen4B run is a separate experiment from the
normalized CTA-15/BM25-25 baseline above. It uses frozen CTA top-10 plus shared
BM25 top-20, deduplicated by actor name, and reranks the complete candidate
pool with `Qwen/Qwen3-Reranker-4B`.

The query is built deterministically from high-specificity report sentences
under a fixed 1,100-token budget. Evidence signals select the report excerpts
provided to the reranker; they do not create a normalized pre-rerank actor
score or equal-weight channel fusion.

| Metric | Result |
| --- | ---: |
| Cases | 50/50 |
| Recall@1 | 24/50 (48%) |
| Recall@3 | 35/50 (70%) |
| Recall@5 | 36/50 (72%) |
| Recall@10 | 38/50 (76%) |
| Recall@20 | 41/50 (82%) |
| MRR@10 | 0.5865 |

Source files and artifact:

```text
eval/controlled_benchmark/audit_taa_qwen4b_evidence_query.py
scripts/run_taa_qwen4b_evidence_query.sbatch
eval_results/controlled_benchmark/full/taa_qwen4b_evidence_query_audit/summary.json
```

The reported Recall and MRR use the benchmark's alias-aware actor matching
policy (`benchmark_alias_match`), not literal string equality. For example,
an accepted actor alias is counted as the same actor as the gold label. These
metrics are ranked reranking metrics over the candidate pool; they are not
single-label generation accuracy and are not normalized CTA/BM25 retrieval
metrics.
