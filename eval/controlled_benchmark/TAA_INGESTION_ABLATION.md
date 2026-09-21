# Offline TAA ingestion ablation

## Best fixed-top-20 variant from this experiment

`enriched_rrf_top20` combines the existing CTA top-10 and shared BM25 top-20
with the enriched-ingestion hybrid top-20. Equal reciprocal-rank fusion
(`1/(60+rank)`) selects exactly 20 unique actors. The enrichment retains
actor-specific procedure sentences and adds associated campaign/software
descriptions from the frozen local ATT&CK snapshot. Sentence boundaries are
preserved within the token budget. Targeting normalization is excluded.

| Configuration | R@3 | R@10 | R@20 | Strict R@20 |
|---|---:|---:|---:|---:|
| Existing ordering, truncated to 20 | 56% | 64% | 78% (39/50) | 72% |
| Procedure branch plus fixed fusion | 52% | 68% | 80% (40/50) | 74% |
| Enriched branch plus fixed fusion | 54% | 68% | 80% (40/50) | 74% |

The enriched variant is the better top-3 tie-breaker among the two new R@20
winners. It still falls below the existing ordering's R@3. Four reports enter
the top 20 and three leave, so the net gain is one report. This experimental
variant has not replaced the production pipeline. The 92% larger-pool
coverage result is not R@20.

### Replay the fixed-top-20 experiment

The saved rankings and local scorer inputs are included on the `eval` branch.
Replay requires only Python's standard library; no model download or GPU:

```bash
git clone --branch eval https://github.com/shreyakumari0301/CT.git
cd CT
python3 eval/controlled_benchmark/audit_taa_fixed_top20.py
```

Read `eval_results/controlled_benchmark/full/taa_fixed_top20_fusion/REPORT.md`.
Each prediction artifact includes the input branches, exact top-20 actors,
and fusion scores. Evaluation artifacts are separate. Labels are excluded
from the fusion inputs and consulted only after predictions have been saved.

### Rebuild the ingestion experiments

Requires `torch`, `sentence-transformers`, and `numpy`, plus a locally cached
`all-MiniLM-L6-v2` model. Model setup is separate from the offline run. The
script disables network model loading and limits CPU inference to four threads.

Run from the repository root with the cached MiniLM model:

```bash
python -u eval/controlled_benchmark/audit_taa_ingestion.py
```

This is retrieval only: no Qwen, GPT, external API, or network fetch. It uses
the saved 176-actor corpus, the local Enterprise ATT&CK snapshot and 50 TAA
reports. No benchmark report is added to the actor index. Source relationships
are materialized as text during ingestion; there is no graph traversal at query
time. Gold labels are used only for scoring completed rankings.

## Fixed protocol

- Off-the-shelf `all-MiniLM-L6-v2`, normalized embeddings, 256-token model limit.
- Existing report-only field queries, extracted once from the frozen vocabulary.
- Identical actor prefix and 180-token content limit for each passage.
- Dense retrieval: maximum passage cosine per actor per query; RRF (60) across
  field queries, with deterministic actor-name tie breaking.
- BM25: full report against one raw text document per actor, k1=1.5 and b=0.75.
  Chunk boundaries do not change BM25 documents or document frequency.
- Hybrid: equal RRF (60) over each branch's top 40 unique actors.
- Report R@1/3/5/10/20/40 and MRR@10. Benchmark-compatible and conservative
  canonical scoring are saved separately.

## Variants

1. `profile_lists`: description and field lists used by the earlier local Qwen
   passage builder; fixed-token chunks. This is a newly measured control.
2. `procedures_fixed`: add saved actor-specific procedure descriptions.
3. `procedures_sentences`: same content as variant 2, with sentence boundaries
   preserved where possible; only overlong sentences are token-split.
4. `source_enriched_sentences`: add associated software descriptions and campaign
   descriptions from the same local STIX snapshot. These are explicitly background
   evidence; software capabilities are not asserted as observed actor behavior.
5. `normalized_enriched_sentences`: same as 4 plus predefined lexical equivalents
   for region/sector spelling variants. Original evidence is retained.

## Outputs and interpretation

`eval_results/controlled_benchmark/full/taa_ingestion_ablation/` contains source
additions with references, fixed queries, passage manifests, complete per-item
rankings, strict and benchmark ranks, input hashes, and `summary.json` updated
after each variant. `complete: true` marks completion of all five variants.

These are development-set comparisons. The control uses the same new retrieval
harness as every treatment, not the remote fine-tuned MiniLM pipeline or Qwen
reranking. Its scores must not be substituted for those earlier experiments.
Candidate coverage is distinct from rank cutoff recall and answer accuracy.
Changing the corpus may help or harm; no result is assumed in advance.
