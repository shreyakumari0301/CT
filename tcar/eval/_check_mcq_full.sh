#!/usr/bin/env bash
set -euo pipefail
cd /mnt/c/Users/SK/CTI-Chatbot
echo "=== procs ==="
pgrep -af 'run_mcq_option_aware_turbo_full|turbo_mcq_option_aware_full|run_counterfactual' || true
echo "=== full log ==="
ls -la tcar/eval_results/logs/mcq_option_aware_turbo_full* 2>/dev/null || true
echo "=== head log ==="
head -n 50 tcar/eval_results/logs/mcq_option_aware_turbo_full.log 2>/dev/null || true
echo "=== head nohup ==="
head -n 50 tcar/eval_results/logs/mcq_option_aware_turbo_full.nohup.out 2>/dev/null || true
echo "=== dst lines ==="
wc -l tcar/eval_results/counterfactual_ctibench_mcq_20260907Tturbo_mcq_option_aware_full.jsonl 2>/dev/null || true
