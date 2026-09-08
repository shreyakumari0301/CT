#!/usr/bin/env bash
set -euo pipefail
cd /mnt/c/Users/SK/CTI-Chatbot
source .venv/bin/activate
export TMPDIR=/mnt/c/Users/SK/CTI-Chatbot/.tmp
mkdir -p tcar/eval_results/logs "$TMPDIR"
STAMP="${1:-20260901Tcf}"

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] Starting CTIConnect counterfactual (gpt-4o)"
python -m tcar.eval.run_counterfactual \
  --benchmark cticonnect \
  --tasks rcm,ata \
  --limit 0 \
  --workers 3 \
  --model gpt-4o \
  --variant no_confusion \
  --stamp "${STAMP}_cc"

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] CTIConnect done"
