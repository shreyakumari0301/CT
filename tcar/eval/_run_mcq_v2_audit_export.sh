#!/usr/bin/env bash
set -euo pipefail
cd /mnt/c/Users/SK/CTI-Chatbot
source .venv/bin/activate
mkdir -p tcar/eval_results/logs
PYTHONPATH=. python tcar/eval/export_mcq_v2_audit.py \
  2>&1 | tee tcar/eval_results/logs/mcq_v2_audit_export.log
