#!/usr/bin/env bash
cd /mnt/c/Users/SK/CTI-Chatbot
# Keep MCQ; start ATA v3
nohup bash tcar/eval/run_ata_grounded_v3_turbo_full.sh \
  > tcar/eval_results/logs/ata_grounded_v3_turbo_full.nohup.out 2>&1 &
echo ATA_V3_PID=$!
sleep 25
pgrep -af 'ata_grounded_v3|run_counterfactual' | head -8
echo '---'
tail -n 40 tcar/eval_results/logs/ata_grounded_v3_turbo_full.nohup.out 2>/dev/null || true
