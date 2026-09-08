#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
mkdir -p tcar/eval_results/logs
STAMP="${1:-20260903Tctibench_kb_cc}"
LOG="tcar/eval_results/logs/cf_cticonnect_${STAMP}_nohup.log"
exec .venv/bin/python -m tcar.eval.run_counterfactual \
  --benchmark cticonnect \
  --tasks rcm \
  --limit 0 \
  --workers 3 \
  --model gpt-4o \
  --variant no_confusion \
  --k 5 \
  --rcm-retrieval ctibench \
  --stamp "$STAMP" \
  --no-resume \
  >"$LOG" 2>&1
