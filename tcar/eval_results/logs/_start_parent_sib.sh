#!/usr/bin/env bash
set -euo pipefail
cd /mnt/c/Users/SK/CTI-Chatbot
mkdir -p tcar/eval_results/logs
export PYTHONPATH=/mnt/c/Users/SK/CTI-Chatbot
export PYTHONUNBUFFERED=1

setsid .venv/bin/python -m tcar.eval.run_counterfactual \
  --benchmark cticonnect --tasks rcm --limit 0 --workers 3 \
  --model gpt-4o --variant no_confusion \
  --stamp 20260903Tparent_sib_cc --no-resume \
  >> tcar/eval_results/logs/cf_cticonnect_20260903Tparent_sib_cc.log 2>&1 < /dev/null &
echo "CC_PID=$!"

setsid .venv/bin/python -m tcar.eval.run_counterfactual \
  --benchmark ctibench --tasks rcm --limit 0 --workers 2 \
  --model gpt-4-turbo --variant no_confusion \
  --stamp 20260903Tparent_sib_cb --no-resume \
  >> tcar/eval_results/logs/cf_ctibench_20260903Tparent_sib_cb.log 2>&1 < /dev/null &
echo "CB_PID=$!"
sleep 4
pgrep -af parent_sib || true
