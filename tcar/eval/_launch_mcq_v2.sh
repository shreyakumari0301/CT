#!/usr/bin/env bash
set -euo pipefail
cd /mnt/c/Users/SK/CTI-Chatbot
# kill stuck helpers / old mcq
pkill -f '_restart_mcq_v2' 2>/dev/null || true
pkill -f 'turbo_mcq_option_aware_full' 2>/dev/null || true
pkill -f 'run_mcq_option_aware_turbo_full' 2>/dev/null || true
sleep 1
nohup bash tcar/eval/run_mcq_option_aware_turbo_v2.sh \
  > tcar/eval_results/logs/mcq_option_aware_turbo_v2.nohup.out 2>&1 &
echo LAUNCHED=$!
sleep 15
pgrep -af 'option_aware_v2|turbo_mcq_option_aware_v2|run_mcq_option_aware_turbo_v2' || true
echo '--- nohup ---'
tail -n 40 tcar/eval_results/logs/mcq_option_aware_turbo_v2.nohup.out || true
echo '--- log ---'
tail -n 20 tcar/eval_results/logs/mcq_option_aware_turbo_v2.log || true
