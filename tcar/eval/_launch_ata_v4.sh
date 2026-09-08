#!/usr/bin/env bash
# Launch ATA v4 in background; do NOT touch MCQ.
set -euo pipefail
cd /mnt/c/Users/SK/CTI-Chatbot
mkdir -p tcar/eval_results/logs
chmod +x tcar/eval/run_ata_grounded_v4_turbo_full.sh

nohup bash tcar/eval/run_ata_grounded_v4_turbo_full.sh \
  > tcar/eval_results/logs/ata_grounded_v4_turbo_full.nohup.out 2>&1 &
echo "PID=$!"
sleep 3
pgrep -af 'ata_grounded_v4|mcq_option_aware_v2|run_counterfactual' | head -10
echo '---'
tail -n 40 tcar/eval_results/logs/ata_grounded_v4_turbo_full.nohup.out 2>/dev/null || true
