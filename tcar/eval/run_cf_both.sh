#!/usr/bin/env bash
# Paired counterfactual on CTIConnect + CTIBench with per-task CTA-RAG prompts (parallel).
set -euo pipefail
cd /mnt/c/Users/SK/CTI-Chatbot
source .venv/bin/activate
export TMPDIR=/mnt/c/Users/SK/CTI-Chatbot/.tmp
mkdir -p tcar/eval_results/logs "$TMPDIR"
STAMP="${1:-20260902Tcf_both}"

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] Recall sweep (k up to 200)"
python -m tcar.eval.recall_sweep \
  --benchmark all \
  --tasks rcm,ata,ate,mcq,vsp \
  --max-k 200 \
  --target 0.90 \
  --stamp "${STAMP}_recall" \
  2>&1 | tee "tcar/eval_results/logs/recall_sweep_${STAMP}.log"

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] CTIConnect counterfactual (gpt-4o)"
python -m tcar.eval.run_counterfactual \
  --benchmark cticonnect \
  --tasks rcm,ata \
  --limit 0 \
  --workers 3 \
  --model gpt-4o \
  --variant no_confusion \
  --stamp "${STAMP}_cc" \
  --no-resume \
  2>&1 | tee "tcar/eval_results/logs/cf_cticonnect_${STAMP}.log" &

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] CTIBench counterfactual (gpt-4-turbo)"
python -m tcar.eval.run_counterfactual \
  --benchmark ctibench \
  --tasks rcm,ate,mcq,vsp \
  --limit 0 \
  --workers 3 \
  --model gpt-4-turbo \
  --variant no_confusion \
  --stamp "${STAMP}_cb" \
  --no-resume \
  2>&1 | tee "tcar/eval_results/logs/cf_ctibench_${STAMP}.log" &

wait
echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] Done. Summaries:"
python -m tcar.eval.gate_audit --summarize \
  tcar/eval_results/counterfactual_*_${STAMP}_cc.jsonl \
  tcar/eval_results/counterfactual_*_${STAMP}_cb.jsonl 2>/dev/null || true
