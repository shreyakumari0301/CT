#!/usr/bin/env bash
# Restart ATA v3 with stronger soft-ground (keep MCQ).
cd /mnt/c/Users/SK/CTI-Chatbot
pkill -f 'stamp 20260908Tturbo_ata_grounded_v3_full' 2>/dev/null || true
pkill -f 'run_ata_grounded_v3_turbo_full' 2>/dev/null || true
sleep 2
rm -f tcar/eval_results/counterfactual_cticonnect_ata_20260908Tturbo_ata_grounded_v3_full.jsonl
# Quick recall check then full gen
source .venv/bin/activate
export ATA_GROUNDED_K=12
nohup bash tcar/eval/run_ata_grounded_v3_turbo_full.sh \
  > tcar/eval_results/logs/ata_grounded_v3_turbo_full.nohup.out 2>&1 &
echo RESTARTED=$!
sleep 20
pgrep -af 'ata_grounded_v3|mcq_option_aware_v2' | head -6
tail -n 25 tcar/eval_results/logs/ata_grounded_v3_turbo_full.nohup.out
