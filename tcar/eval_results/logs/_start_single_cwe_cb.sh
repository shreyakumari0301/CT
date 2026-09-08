#!/usr/bin/env bash
set -euo pipefail
cd /mnt/c/Users/SK/CTI-Chatbot
mkdir -p tcar/eval_results/logs
export PYTHONPATH=/mnt/c/Users/SK/CTI-Chatbot
# Match prior CTIBench counterfactual stack (gpt-4-turbo).
nohup .venv/bin/python -m tcar.eval.run_counterfactual \
  --benchmark ctibench \
  --tasks rcm \
  --limit 0 \
  --workers 2 \
  --model gpt-4-turbo \
  --variant no_confusion \
  --stamp 20260903Tsingle_cwe_cb \
  --no-resume \
  > tcar/eval_results/logs/cf_ctibench_20260903Tsingle_cwe_cb.log 2>&1 &
echo "PID=$!"
sleep 3
wc -l tcar/eval_results/logs/cf_ctibench_20260903Tsingle_cwe_cb.log || true
