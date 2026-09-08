#!/usr/bin/env bash
set -euo pipefail
cd /mnt/c/Users/SK/CTI-Chatbot
source .venv/bin/activate
PYTHONPATH=. python tcar/eval/run_vsp_per_metric_audit.py \
  2>&1 | tee tcar/eval_results/logs/vsp_per_metric_audit.log
