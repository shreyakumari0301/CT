#!/usr/bin/env bash
# CTIBench RCM with gpt-5.4 (CTIFoundry Table 1 best operator):
#   1) Counterfactual Forced RAG (no GAD, CWE catalogue off) → CB + Forced RAG
#   2) Counterfactual Force GAD (graph diversify K=12)
#   3) CTA-RAG end-to-end oracle (understanding, catalogue off)
set -euo pipefail
cd /mnt/c/Users/SK/CTI-Chatbot
source .venv/bin/activate
export TMPDIR=/mnt/c/Users/SK/CTI-Chatbot/.tmp
mkdir -p tcar/eval_results/logs eval_results/logs "$TMPDIR"

MODEL="${MODEL:-gpt-5.4}"
export GENERATION_MODEL="$MODEL"
export RCM_PROMPT=soft

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] === RCM Forced RAG (no GAD) model=${MODEL} ==="
export RCM_GAD=off
export RCM_CWE_RETRIEVAL=off
unset GAD_MODE || true
python -m tcar.eval.run_counterfactual \
  --benchmark ctibench \
  --tasks rcm \
  --limit 0 \
  --workers 2 \
  --model "$MODEL" \
  --variant no_confusion \
  --stamp 20260904Tgpt54_forced_rag_rcm \
  --no-resume

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] === RCM Force GAD model=${MODEL} ==="
export RCM_GAD=force
unset RCM_CWE_RETRIEVAL || true
python -m tcar.eval.run_counterfactual \
  --benchmark ctibench \
  --tasks rcm \
  --limit 0 \
  --workers 2 \
  --model "$MODEL" \
  --variant no_confusion \
  --stamp 20260904Tgpt54_force_gad_rcm \
  --no-resume

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] === RCM CTA-RAG e2e oracle model=${MODEL} ==="
export RCM_CWE_RETRIEVAL=off
python -u -m eval.run_ctibench \
  --task rcm \
  --limit 0 \
  --route_mode oracle \
  --workers 2 \
  --out-dir eval_results

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] gpt-5.4 RCM suite done"
