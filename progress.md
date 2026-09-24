# TAA retrieval and reranking experiment progress

This file is the tracked record of controlled, offline experiments on the 50
CTI-Bench TAA reports. Results are evaluated with the shared actor-alias
protocol and retain full per-case candidate rankings in their linked result
artifacts.

## Completed experiments

| Experiment | Candidate source / reranker | R@3 | R@10 | MRR@10 | Outcome |
| --- | --- | ---: | ---: | ---: | --- |
| Qwen3 0.6B | Frozen CTA + shared BM25 union | 58% | 70% | 0.533 | Baseline neural reranker |
| Qwen3 4B | Frozen CTA + shared BM25 union | 68% | 74% | 0.585 | Previous full-report Qwen baseline |
| Qwen3 4B, evidence-focused query | Frozen CTA + shared BM25 union | **70%** | 76% | 0.587 | Current verified top-3 result |
| Qwen3 8B | Frozen CTA + shared BM25 union | 64% | 74% | 0.548 | Worse than 4B |
| Jina v3.5 | Frozen CTA + shared BM25 union | 62% | **80%** | **0.589** | Best deeper ranking |
| Contextual profile retrieval + Qwen3 4B | Contextual MiniLM + BM25 union | 42% | 64% | 0.335 | Rejected: no ranking improvement |

The detailed comparison and links to all completed artifacts are in
[`RERANKER_COMPARISON.md`](RERANKER_COMPARISON.md).

## Experiment 6 — normalized CTA/BM25 retrieval baseline before Qwen3

**Status: complete (offline, no model calls).**

| Item | Value |
| --- | --- |
| Candidate pool | Frozen CTA/IDF top-15 + natural-passage BM25 top-25, deduplicated |
| Pre-rerank ranking | Canonicalized actor matching, IDF-like rarity, per-channel min-max normalization, equal fusion |
| Manual field weights | None in the normalized variant |
| R@1 / R@3 | 24/50 (48%) / 32/50 (64%) |
| R@5 / R@10 | 32/50 (64%) / 36/50 (72%) |
| R@20 / MRR@10 | 41/50 (82%) / 0.5601 |
| Artifact | `eval_results/controlled_benchmark/full/taa_frozen_cta_bm25_normalized_cta15_bm2525/summary.json` |

The Qwen3 union audit now defaults to this same CTA-15/BM25-25 candidate
pool and writes to `taa_qwen3_normalized_cta15_bm2525_union_audit/`. This keeps
the pre-rerank baseline and the Qwen3 reranker comparison on the same pool;
Qwen3 changes ordering only and does not generate new candidates.

## Experiment 1 — expanded BM25 candidate pool

**Status: complete (Slurm job `272076`).**

| Item | Value |
| --- | --- |
| Hypothesis | The existing Qwen3 4B can improve if more gold actors enter its candidate pool. |
| Candidate pool | Available CTA top-10 plus shared BM25 top-40, deduplicated. |
| Reranker | `Qwen/Qwen3-Reranker-4B` over the established complete actor-profile passage. |
| Measured coverage before reranking | 45/50 (90%) gold actors, versus 41/50 (82%) for CTA top-10 plus shared BM25 top-20. |
| Evaluation output | `eval_results/controlled_benchmark/full/taa_qwen3_4b_bm25_40_union_audit/` |
| Slurm resources | One A100 GPU and one CPU. |
| Result | R@1 50%, R@3 66%, R@5 70%, R@10 76%, R@20 84%, MRR@10 0.591. |

The expanded pool improved candidate coverage (82% to 90%), R@10 (74% to
76%), R@20 (80% to 84%), and MRR@10 (0.585 to 0.591). It did **not** improve
the top-3 target: R@3 fell from 68% to 66%. It is therefore a useful deeper
ranking variant, not a replacement for the existing top-3 Qwen3 4B pipeline.

The run records the CTA candidates, BM25 candidates, deduplicated pool, full
Qwen score ordering, final rank, candidate coverage, and ranking metrics.

## Experiment 2 — targeted multi-query BM25 candidate generation

**Status: complete (Slurm job `272090`).**

| Item | Planned method |
| --- | --- |
| Goal | Reduce long-report noise before sparse retrieval without using gold labels. |
| Queries | Four report-derived views: high-specificity indicators (malware/tool/CVE/IOC), targeting, ATT&CK behavior, and full report. |
| Candidate generation | Run local BM25 over unprefixed frozen actor-profile fields for each view, RRF their top actors, union with CTA top-10 and shared BM25 top-20, then Qwen3 4B reranks complete actor profiles. |
| Primary comparison | Experiment 1 and the existing Qwen3 4B baseline. |
| Acceptance criterion | Improve R@3 without lowering candidate-pool coverage. |

**Result:** candidate-pool coverage 86%, R@1 50%, R@3 66%, R@5 68%, R@10
72%, R@20 80%, MRR@10 0.586. The targeted queries improved pool coverage over
the original 82% pool and tied the expanded-pool R@1, but they failed the
acceptance criterion: R@3 is below the 68% Qwen3 4B baseline. This experiment
is retained as a fully recorded negative result and should not replace the
top-3 baseline.

## Experiment 3 — leakage-aware reranker ensemble

**Status: complete as one-CPU Slurm job `272112`.** The superseded GPU job
`272108` was canceled before it ran because this score-only analysis does not
need a GPU.

| Item | Planned method |
| --- | --- |
| Hypothesis | Qwen3 4B, Jina v3.5, and the other saved Qwen variants may correctly rank different cases in the same frozen candidate pool. |
| Inputs | Existing detailed scores from Qwen3 0.6B, 4B, 8B, and Jina v3.5; no new labels, candidates, or model inference. |
| Fusions | Per-report score min-max normalization and rank-percentile normalization; four-model convex weight sweep. |
| Anti-overfitting check | Five-fold out-of-fold selection: weights for each held-out fold are selected using only the other four folds. |
| Acceptance criterion | Five-fold OOF R@3 exceeds 68%; exploratory full-set metrics are explicitly not treated as unbiased. |

**Result:** the rank-normalized exploratory sweep reached 70% R@3, but five-
fold OOF R@3 was only 64%; score-normalized OOF R@3 was 60%. The apparent gain
does not generalize under the predeclared leakage check, so no ensemble is
promoted to the system.

## Experiment 4 — evidence-focused Qwen query

**Status: complete as one-GPU/one-CPU Slurm job `272119`.**

| Item | Planned method |
| --- | --- |
| Hypothesis | Long CTI reports can exceed Qwen's 2,048-token cross-encoder budget, hiding late attribution clues; a deterministic evidence-focused report view may improve Qwen's top-3 ordering. |
| Query construction | Select report sentences containing high-specificity malware/tool/campaign/infrastructure matches, CVEs/IOCs/ATT&CK IDs, targeting cues, and behavior cues. Fit the selected evidence to a fixed query-token budget. |
| Candidate pool | The original frozen CTA top-10 plus shared BM25 top-20 union, unchanged from the 68% Qwen3 4B baseline. |
| Anti-leakage rule | Uses only the report and frozen profiles; it never reads gold labels or other model rankings. |
| Acceptance criterion | R@3 exceeds 68% with the same candidate-pool coverage as the baseline. |

**Result:** R@1 48%, R@3 **70%**, R@5 72%, R@10 76%, R@20 82%, MRR@10
0.5865; mean selected report sentences 20.32. The candidate pool is unchanged,
and the result exceeds the predeclared top-3 criterion by two points. Results:
`eval_results/controlled_benchmark/full/taa_qwen4b_evidence_query_audit/`.

## Experiment 5 — multi-source ATT&CK ingestion, Qwen3-4B and Jina v3.5

**Status: complete; Slurm job `273485` (MS-ATTACK-01).**

| Item | Value |
| --- | --- |
| Question | Can source-linked ATT&CK group, campaign, and software passages improve the retained frozen candidate pool and top-3 ordering? |
| Ingestion | Normalize STIX/ATT&CK group identifiers and aliases; materialize only group passages, attributed campaign passages, and direct/group-or-attributed-campaign software `uses` passages. |
| Candidate pool | Frozen CTA top-10 + shared BM25 top-20 + multi-source MiniLM dense top-20 + multi-source BM25 top-20, deduplicated. The actual baseline candidate coverage is measured in the result; it is not assumed from Recall@20. |
| Reranking | Qwen3-Reranker-4B and Jina Reranker v3.5 receive exactly the same pool, deterministic report-only evidence query, and compact source-evidence document. |
| Excluded sources | CAPEC and Sigma: no local actor-linked inputs found, so neither is inferred or added. |
| Resources | One A100 GPU, one CPU, one sequential Slurm job; Qwen is released before Jina loads. |
| Artifacts | `eval_results/controlled_benchmark/full/taa_multisource_attack_qwen_jina_audit/{ingestion_manifest,checkpoint,summary}.json`; logs `logs/taa-ms-qwen-jina_273485.{out,err}`. |

**Result:** the multi-source union increased gold-blind candidate-pool coverage
from 41/50 (82%) to 46/50 (92%) and increased its mean size from 26.52 to
46.72. It did not improve the end-to-end ranking: Qwen3-4B reached R@3 58%
(R@1 44%, R@10 72%, MRR@10 0.532) and Jina v3.5 reached R@3 54% (R@1 34%,
R@10 72%, MRR@10 0.448). The compact multi-source evidence document is
therefore not a replacement for the established Qwen evidence-focused view.

## Experiment 6 — multi-source candidates + established Qwen evidence view

**Status: submitted as one-GPU/one-CPU Slurm job `273648` (MS-ATTACK-02).**

| Item | Value |
| --- | --- |
| Plan | MS-ATTACK-02 |
| Question | Does the 92%-coverage multi-source candidate pool improve Qwen R@3 when the proven evidence-focused query and full actor-profile documents are unchanged? |
| Controlled change | Candidate pool only; the Qwen model, 1,100-token evidence-query selector, profile documents, 50-report split, and alias scoring protocol remain the established configuration. |
| Output | `eval_results/controlled_benchmark/full/taa_multisource_evidence_profiles_qwen4b_audit/` |
| Runtime logs | `logs/taa-ms-evidence-q4b_273648.{out,err}` |

## Reproducibility

- All GPU runs use Slurm `cscc-gpu-p`, exactly one GPU, and exactly one CPU.
- `gpu-05` is excluded because it exposes no CUDA device. `gpu-54` is excluded
  because it lacked the shared `/l` mount during a submitted job.
- Generated result directories are ignored by default but their verified
  `summary.json` and `checkpoint.json` artifacts are force-added to the
  `qwen3-union-results` branch after completion.
