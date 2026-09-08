#!/usr/bin/env bash
# Restart ATA v2 only (keep MCQ). Pick up segmentation fix.
cd /mnt/c/Users/SK/CTI-Chatbot
pkill -f 'stamp 20260908Tturbo_ata_grounded_v2_n50' 2>/dev/null || true
pkill -f 'run_ata_grounded_v2_turbo_n50' 2>/dev/null || true
sleep 2
# wipe partial so we get clean v2 with fixed split
rm -f tcar/eval_results/counterfactual_cticonnect_ata_20260908Tturbo_ata_grounded_v2_n50.jsonl
nohup bash tcar/eval/run_ata_grounded_v2_turbo_n50.sh \
  > tcar/eval_results/logs/ata_grounded_v2_turbo_n50.nohup.out 2>&1 &
echo RESTARTED=$!
sleep 15
pgrep -af 'ata_grounded_v2|mcq_option_aware_v2|run_counterfactual' | head -8
tail -n 25 tcar/eval_results/logs/ata_grounded_v2_turbo_n50.nohup.out
