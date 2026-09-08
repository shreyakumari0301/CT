#!/usr/bin/env bash
# Re-run counterfactual eval with per-task CTA-RAG pipeline prompts (not TCAR contrast).
set -euo pipefail
cd /mnt/c/Users/SK/CTI-Chatbot
source .venv/bin/activate
export TMPDIR=/mnt/c/Users/SK/CTI-Chatbot/.tmp
export PIP_CACHE_DIR=/mnt/c/Users/SK/CTI-Chatbot/.pip-cache
mkdir -p tcar/eval_results/logs "$TMPDIR" "$PIP_CACHE_DIR"
STAMP="${1:-20260902Ttask_prompts}"

pip install --no-cache-dir -q sentence-transformers 2>>"tcar/eval_results/logs/pip_${STAMP}.log" || true

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] CTIConnect counterfactual start (gpt-4o, task prompts)"
python -m tcar.eval.run_counterfactual \
  --benchmark cticonnect \
  --tasks rcm,ata \
  --limit 0 \
  --workers 3 \
  --model gpt-4o \
  --variant no_confusion \
  --stamp "${STAMP}_cc" \
  --no-resume \
  2>&1 | tee "tcar/eval_results/logs/cf_cticonnect_${STAMP}.log"

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] CTIBench counterfactual start (gpt-4-turbo, task prompts)"
python -m tcar.eval.run_counterfactual \
  --benchmark ctibench \
  --tasks rcm,ate,mcq,vsp \
  --limit 0 \
  --workers 3 \
  --model gpt-4-turbo \
  --variant no_confusion \
  --stamp "${STAMP}_cb" \
  --no-resume \
  2>&1 | tee "tcar/eval_results/logs/cf_ctibench_${STAMP}.log"

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] All counterfactual reruns done (${STAMP})"
