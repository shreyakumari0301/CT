#!/usr/bin/env bash
# CTIBench RCM with OpenRouter openai/gpt-5.6-sol + reasoning:
#   1) Counterfactual Forced RAG (no GAD, CWE catalogue off) → CB + Forced RAG
#   2) Counterfactual Force GAD (graph diversify K=12)
#   3) CTA-RAG end-to-end oracle (understanding, catalogue off)
set -euo pipefail
cd /mnt/c/Users/SK/CTI-Chatbot
source .venv/bin/activate
set -a
# shellcheck disable=SC1091
source .env
set +a

export TMPDIR=/mnt/c/Users/SK/CTI-Chatbot/.tmp
mkdir -p tcar/eval_results/logs eval_results/logs "$TMPDIR"

MODEL="${MODEL:-openai/gpt-5.6-sol}"
export GENERATION_MODEL="$MODEL"
export OPENAI_BASE_URL="${OPENAI_BASE_URL:-https://openrouter.ai/api/v1}"
export USE_OPENROUTER=1
# Prefer OpenRouter key for the OpenAI SDK when present.
if [[ -n "${OPENROUTER_API_KEY:-}" ]]; then
  export OPENAI_API_KEY="$OPENROUTER_API_KEY"
fi
export OPENROUTER_REASONING_EFFORT="${OPENROUTER_REASONING_EFFORT:-medium}"
export OPENROUTER_REASONING=1
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
  --stamp 20260904Tgpt56sol_forced_rag_rcm \
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
  --stamp 20260904Tgpt56sol_force_gad_rcm \
  --no-resume

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] === RCM CTA-RAG e2e oracle model=${MODEL} ==="
export RCM_CWE_RETRIEVAL=off
python -u -m eval.run_ctibench \
  --task rcm \
  --limit 0 \
  --route_mode oracle \
  --workers 2 \
  --out-dir eval_results

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] gpt-5.6-sol RCM suite done"
