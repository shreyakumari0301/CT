# Fixed top-20 TAA retrieval fusion

Development-set offline retrieval. Fixed equal-weight RRF, no Qwen, no label-selected candidates. Local scorer; not directly comparable to remote 82% pool until parity is established.

| Method | R@1 | R@3 | R@5 | R@10 | R@20 | Correct / 50 | Strict R@20 |
|---|---:|---:|---:|---:|---:|---:|---:|
| existing_order_top20 | 44% | 56% | 60% | 64% | 78% | 39/50 | 72% |
| existing_rrf_top20 | 30% | 48% | 60% | 70% | 78% | 39/50 | 72% |
| procedure_rrf_top20 | 38% | 52% | 58% | 68% | 80% | 40/50 | 74% |
| enriched_rrf_top20 | 38% | 54% | 58% | 68% | 80% | 40/50 | 74% |

All methods return exactly 20 unique actors. RRF uses 1/(60+rank) with equal branch weights and actor-name tie breaking. No weight sweep or gold-based inclusion is performed.

The procedure and enriched branches already contain MiniLM/BM25 fusion; their evidence is correlated with the shared BM25 branch. This is a fixed branch-fusion experiment, not proof of independent evidence.
