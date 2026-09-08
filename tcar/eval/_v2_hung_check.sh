#!/usr/bin/env bash
cd /mnt/c/Users/SK/CTI-Chatbot
ps -p 1975 -o pid,etime,pcpu,pmem,wchan,cmd 2>/dev/null || echo '1975 dead'
ls -la tcar/eval_results/counterfactual_ctibench_mcq_20260907Tturbo_mcq_option_aware_v2.jsonl 2>/dev/null || echo 'no jsonl'
# open files / strace snippet hard; check log mtime
stat tcar/eval_results/logs/mcq_option_aware_turbo_v2.log 2>/dev/null | grep -E 'Modify|Size'
# any python errors in nohup?
wc -c tcar/eval_results/logs/mcq_option_aware_turbo_v2.log tcar/eval_results/logs/mcq_option_aware_turbo_v2.nohup.out 2>/dev/null
# broken full last progress
if [[ -f tcar/eval_results/logs/mcq_option_aware_turbo_full.log ]]; then
  echo '--- broken full last ---'
  tail -c 500 tcar/eval_results/logs/mcq_option_aware_turbo_full.log | tr '\r' '\n' | tail -6
fi
