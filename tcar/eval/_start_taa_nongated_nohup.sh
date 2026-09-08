#!/usr/bin/env bash
set -euo pipefail
cd /mnt/c/Users/SK/CTI-Chatbot
mkdir -p tcar/eval_results/logs eval_results
LOG=tcar/eval_results/logs/soft_gad_taa_nongated.log

nohup bash /mnt/c/Users/SK/CTI-Chatbot/tcar/eval/_taa_nongated_worker.sh >>"$LOG" 2>&1 &
echo "taa_nohup_pid=$!"
disown || true
sleep 4
pgrep -af "eval.run_taa|_taa_nongated_worker" || echo "WARNING: TAA worker not visible"
tail -30 "$LOG" || true
