# TAA retrieval experiment conclusions

## EQ-QWEN4-01 — evidence-focused Qwen3-4B query

**Decision: current top-3 baseline.** Slurm run `272119` evaluates a
deterministic, report-only evidence sentence selector with the unchanged frozen
CTA top-10 plus shared BM25 top-20 candidate pool. It reached Recall@1 48%,
Recall@3 **70%**, Recall@5 72%, Recall@10 76%, Recall@20 82%, and MRR@10
0.5865 on all 50 CTI-Bench TAA reports. This is a two-point Recall@3 increase
over the prior Qwen3-4B frozen-pool result (68%).

Evidence: Slurm job `272119`; result artifacts
`eval_results/controlled_benchmark/full/taa_qwen4b_evidence_query_audit/summary.json`
and `checkpoint.json`. The checkpoint contains every selected report sentence,
candidate score, final rank, and candidate pool. The selector is gold-blind but
the result is still one fixed 50-report benchmark, so it should not be treated
as an independently tuned external-test result.

## Previously rejected replacements

- Contextual profile retrieval plus Qwen3-4B: Recall@3 42%; it should not
  replace the frozen pool.
- Expanded and targeted BM25 pools: each reached Recall@3 66%, below the 68%
  original Qwen3-4B baseline despite better candidate coverage/deeper recall.
- Four-reranker score/rank fusion: an exploratory 70% Recall@3 result fell to
  64% rank-normalized and 60% score-normalized five-fold OOF Recall@3; it is
  not promoted.

The detailed completed-model comparison remains in `RERANKER_COMPARISON.md`.
