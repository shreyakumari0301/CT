#!/usr/bin/env bash
cd /mnt/c/Users/SK/CTI-Chatbot
echo "pid 1975:"; ps -p 1975 -o pid,etime,pcpu,pmem,cmd 2>/dev/null || echo dead
echo "--- log size/mtime ---"
ls -la tcar/eval_results/logs/mcq_option_aware_turbo_v2.log
echo "--- full log ---"
cat tcar/eval_results/logs/mcq_option_aware_turbo_v2.log
echo "--- jsonl ---"
ls -la tcar/eval_results/counterfactual_ctibench_mcq_20260907Tturbo_mcq_option_aware_v2.jsonl 2>/dev/null || echo none
# children
pstree -p 1975 2>/dev/null || ps --ppid 1975 -o pid,cmd 2>/dev/null || true
