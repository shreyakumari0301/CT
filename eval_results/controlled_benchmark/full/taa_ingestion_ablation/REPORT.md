# Offline TAA ingestion ablation results

50 reports; fixed actor inventory, cached off-the-shelf MiniLM, report-derived queries and retrieval scoring. No Qwen or GPT calls.

## MiniLM + BM25 rank fusion

| Ingestion variant | R@1 | R@3 | R@5 | R@10 | R@20 | MRR@10 |
|---|---:|---:|---:|---:|---:|---:|
| profile_lists | 22% | 38% | 48% | 62% | 70% | 0.3360 |
| procedures_fixed | 34% | 54% | 60% | 70% | 74% | 0.4602 |
| procedures_sentences | 30% | 54% | 62% | 66% | 70% | 0.4348 |
| source_enriched_sentences | 32% | 56% | 62% | 72% | 72% | 0.4610 |
| normalized_enriched_sentences | 34% | 54% | 62% | 72% | 72% | 0.4667 |

## Strict canonical identity sensitivity

| Variant | Strict R@3 | Strict R@10 |
|---|---:|---:|
| profile_lists | 32% | 50% |
| procedures_fixed | 42% | 58% |
| procedures_sentences | 48% | 54% |
| source_enriched_sentences | 48% | 60% |
| normalized_enriched_sentences | 46% | 60% |

## Separate candidate expansion diagnostic

The local frozen CTA top-10 + shared BM25 top-20 pool covers 42/50 under the local benchmark-compatible scorer. The supplied remote report records 41/50; input/scorer parity has not been established, so these coverage results are not directly comparable.

Each row below appends the new hybrid top-20 to that pool. Coverage alone does not establish better top-3 ranking.

| Added ingestion branch | Pool coverage | Newly covered reports | Mean candidates |
|---|---:|---:|---:|
| profile_lists | 90% | 3 | 34.50 |
| procedures_fixed | 92% | 4 | 37.06 |
| procedures_sentences | 90% | 3 | 36.90 |
| source_enriched_sentences | 90% | 3 | 37.70 |
| normalized_enriched_sentences | 90% | 3 | 37.62 |

## Scope

These experiments change ingestion within a fixed new retrieval harness. They do not reproduce the earlier fine-tuned MiniLM/IDF system and must not be read as changes from its headline metrics.

All rankings are development-set results. Expanded software descriptions are background context, not evidence that an actor used every listed capability. Source-linked additions and input hashes are saved beside the results. Strict canonical metrics are available in summary.json.
