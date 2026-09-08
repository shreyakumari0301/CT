#!/usr/bin/env bash
cd /mnt/c/Users/SK/CTI-Chatbot
echo PROCS:
pgrep -af 'run_counterfactual|mcq_option_aware' || echo none
echo FILES:
ls -la tcar/eval_results/logs/mcq_option_aware_turbo_v2* 2>/dev/null || echo nofiles
echo NOHUP:
tail -n 50 tcar/eval_results/logs/mcq_option_aware_turbo_v2.nohup.out 2>/dev/null || echo empty
echo LOG:
tail -n 30 tcar/eval_results/logs/mcq_option_aware_turbo_v2.log 2>/dev/null || echo nolog
echo JSONL:
wc -l tcar/eval_results/counterfactual_ctibench_mcq_20260907Tturbo_mcq_option_aware_v2.jsonl 2>/dev/null || echo 0
