# TAA retrieval and reranking experiment progress

This file is the tracked record of controlled, offline experiments on the 50
CTI-Bench TAA reports. Results are evaluated with the shared actor-alias
protocol and retain full per-case candidate rankings in their linked result
artifacts.

## Completed experiments

| Experiment | Candidate source / reranker | R@3 | R@10 | MRR@10 | Outcome |
| --- | --- | ---: | ---: | ---: | --- |
| Qwen3 0.6B | Frozen CTA + shared BM25 union | 58% | 70% | 0.533 | Baseline neural reranker |
| Qwen3 4B | Frozen CTA + shared BM25 union | **68%** | 74% | 0.585 | Best top-3 result |
| Qwen3 8B | Frozen CTA + shared BM25 union | 64% | 74% | 0.548 | Worse than 4B |
| Jina v3.5 | Frozen CTA + shared BM25 union | 62% | **80%** | **0.589** | Best deeper ranking |
| Contextual profile retrieval + Qwen3 4B | Contextual MiniLM + BM25 union | 42% | 64% | 0.335 | Rejected: no ranking improvement |

The detailed comparison and links to all completed artifacts are in
[`RERANKER_COMPARISON.md`](RERANKER_COMPARISON.md).

## Experiment 1 — expanded BM25 candidate pool

**Status: submitted as Slurm job `272076`; it runs separately from later experiments.**

| Item | Value |
| --- | --- |
| Hypothesis | The existing Qwen3 4B can improve if more gold actors enter its candidate pool. |
| Candidate pool | Available CTA top-10 plus shared BM25 top-40, deduplicated. |
| Reranker | `Qwen/Qwen3-Reranker-4B` over the established complete actor-profile passage. |
| Measured coverage before reranking | 45/50 (90%) gold actors, versus 41/50 (82%) for CTA top-10 plus shared BM25 top-20. |
| Evaluation output | `eval_results/controlled_benchmark/full/taa_qwen3_4b_bm25_40_union_audit/` |
| Slurm resources | One A100 GPU and one CPU. |

The run records the CTA candidates, BM25 candidates, deduplicated pool, full
Qwen score ordering, final rank, candidate coverage, and ranking metrics.

## Experiment 2 — targeted multi-query BM25 candidate generation

**Status: queued; do not submit until Experiment 1 completes and is recorded.**

| Item | Planned method |
| --- | --- |
| Goal | Reduce long-report noise before sparse retrieval without using gold labels. |
| Queries | Four report-derived views: high-specificity indicators (malware/tool/CVE/IOC), targeting, ATT&CK behavior, and full report. |
| Candidate generation | Run BM25 for each view, union/RRF their top actors with CTA candidates, then Qwen3 4B reranks complete actor profiles. |
| Primary comparison | Experiment 1 and the existing Qwen3 4B baseline. |
| Acceptance criterion | Improve R@3 without lowering candidate-pool coverage. |

## Reproducibility

- All GPU runs use Slurm `cscc-gpu-p`, exactly one GPU, and exactly one CPU.
- `gpu-05` is excluded because it exposes no CUDA device. `gpu-54` is excluded
  because it lacked the shared `/l` mount during a submitted job.
- Generated result directories are ignored by default but their verified
  `summary.json` and `checkpoint.json` artifacts are force-added to the
  `qwen3-union-results` branch after completion.
