#!/usr/bin/env bash
cd /mnt/c/Users/SK/CTI-Chatbot
# Do NOT kill MCQ — launch ATA alongside
nohup bash tcar/eval/run_ata_grounded_v2_turbo_n50.sh \
  > tcar/eval_results/logs/ata_grounded_v2_turbo_n50.nohup.out 2>&1 &
echo ATA_V2_PID=$!
sleep 20
pgrep -af 'ata_grounded_v2|turbo_ata_grounded_v2|run_counterfactual' | head -10
echo '---'
tail -n 40 tcar/eval_results/logs/ata_grounded_v2_turbo_n50.nohup.out 2>/dev/null || true
