# CTA union-pool reranker comparison

## Evaluation setup

Each reranker evaluates the same fixed candidate pool for each of 50 TAA
reports: the union of CTA top-20 candidates and the shared BM25 top-20
candidates. Metrics use the benchmark's gold-actor matching protocol. Every
run stores its full per-case candidate ordering and model score in its
`checkpoint.json` file.

## Results

| Reranker | Recall@1 | Recall@3 | Recall@5 | Recall@10 | Recall@20 | MRR@10 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Qwen3-Reranker-0.6B | 46% | 58% | 62% | 70% | 80% | 0.533 |
| Qwen3-Reranker-4B | 48% | **68%** | 70% | 74% | 80% | 0.585 |
| Qwen3-Reranker-8B | 44% | 64% | 68% | 74% | 80% | 0.548 |
| Jina Reranker v3.5 | **50%** | 62% | **72%** | **80%** | 80% | **0.589** |
| Contextual MiniLM + BM25 -> Qwen3 4B | 20% | 42% | 52% | 64% | 74% | 0.335 |

## Interpretation

- **Qwen3 4B** is the best top-3 reranker (68% Recall@3), making it the
  preferred model when the product shows exactly three candidates.
- **Jina Reranker v3.5** is best overall: it has the highest Recall@1,
  Recall@5, Recall@10, and MRR@10. It is the preferred model when users can
  inspect five to ten candidates.
- **Qwen3 8B** does not improve on Qwen3 4B in this benchmark, so Qwen3 4B is
  the stronger Qwen choice.
- All four runs reach 80% Recall@20. The remaining 20% is therefore a
  candidate-retrieval coverage limitation rather than a reranking limitation.
- **Contextualized indexing did not help in this implementation.** It builds
  1,782 natural ATT&CK-profile passages, prepends deterministic actor/evidence
  context, retrieves the dense top-20 and BM25 top-20 actors, then reranks
  their 34.5-candidate average union with the same complete actor-profile
  evidence used by Qwen3 4B. Its union-pool coverage is 84%, but its 42%
  Recall@3 and 0.335 MRR@10 are far below the frozen CTA/BM25 plus Qwen3 4B
  baseline. Do not replace the established candidate generator with this
  contextual-profile variant.

## Result artifacts

| Reranker | Summary | Full per-case rankings |
| --- | --- | --- |
| Qwen3 0.6B | [summary](eval_results/controlled_benchmark/full/taa_qwen3_union_audit/summary.json) | [checkpoint](eval_results/controlled_benchmark/full/taa_qwen3_union_audit/checkpoint.json) |
| Qwen3 4B | [summary](eval_results/controlled_benchmark/full/taa_qwen3_4b_union_audit/summary.json) | [checkpoint](eval_results/controlled_benchmark/full/taa_qwen3_4b_union_audit/checkpoint.json) |
| Qwen3 8B | [summary](eval_results/controlled_benchmark/full/taa_qwen3_8b_union_audit/summary.json) | [checkpoint](eval_results/controlled_benchmark/full/taa_qwen3_8b_union_audit/checkpoint.json) |
| Jina v3.5 | [summary](eval_results/controlled_benchmark/full/taa_jina_v35_union_audit/summary.json) | [checkpoint](eval_results/controlled_benchmark/full/taa_jina_v35_union_audit/checkpoint.json) |
| Contextual MiniLM + BM25 -> Qwen3 4B | [summary](eval_results/controlled_benchmark/full/taa_contextual_union_qwen4b_full_profile_audit/summary.json) | [checkpoint](eval_results/controlled_benchmark/full/taa_contextual_union_qwen4b_full_profile_audit/checkpoint.json) |
