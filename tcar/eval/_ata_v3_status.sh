#!/usr/bin/env bash
cd /mnt/c/Users/SK/CTI-Chatbot
pgrep -af 'ata_grounded_v3|run_counterfactual' | head -8
echo '--- nohup ---'
tail -n 60 tcar/eval_results/logs/ata_grounded_v3_turbo_full.nohup.out 2>/dev/null || true
echo '--- log ---'
tail -n 40 tcar/eval_results/logs/ata_grounded_v3_turbo_full.log 2>/dev/null || true
