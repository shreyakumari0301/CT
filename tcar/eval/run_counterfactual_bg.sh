#!/usr/bin/env bash
# Counterfactual utility evaluation — background launcher (WSL).
# Usage: bash tcar/eval/run_counterfactual_bg.sh [stamp]
set -euo pipefail
cd "$(dirname "$0")/../.."
STAMP="${1:-$(date -u +%Y%m%dTcf)}"
LOGDIR="tcar/eval_results/logs"
mkdir -p "$LOGDIR"

if [[ -f .venv/bin/activate ]]; then
  # shellcheck disable=SC1091
  source .venv/bin/activate
fi

pip install -q -r requirements.txt 2>"$LOGDIR/pip_${STAMP}.log" || true

echo "Stamp=$STAMP"

# CTIConnect: gpt-4o (matches prior TCAR runs), 450 items × 2 calls
nohup python -m tcar.eval.run_counterfactual \
  --benchmark cticonnect \
  --tasks rcm,ata \
  --limit 0 \
  --workers 3 \
  --model gpt-4o \
  --variant no_confusion \
  --stamp "${STAMP}_cc" \
  >"$LOGDIR/counterfactual_cticonnect_${STAMP}.log" 2>&1 &
echo "CTIConnect PID=$!"

# CTIBench: gpt-4-turbo (matches CTA-RAG baselines), ~4560 items × 2 calls
nohup python -m tcar.eval.run_counterfactual \
  --benchmark ctibench \
  --tasks rcm,ata,ate,mcq \
  --limit 0 \
  --workers 3 \
  --model gpt-4-turbo \
  --variant no_confusion \
  --stamp "${STAMP}_cb" \
  >"$LOGDIR/counterfactual_ctibench_${STAMP}.log" 2>&1 &
echo "CTIBench PID=$!"

echo "Logs: $LOGDIR/counterfactual_*_${STAMP}.log"
echo "When done: python -m tcar.eval.gate_audit --summarize tcar/eval_results/counterfactual_*_${STAMP}*.jsonl"
