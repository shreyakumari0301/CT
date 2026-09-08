#!/usr/bin/env bash
pgrep -af '20260906Tgpt56sol_soft_gad|run_taa --mode gated' || true
echo ---
tail -25 /mnt/c/Users/SK/CTI-Chatbot/tcar/eval_results/logs/gpt56sol_soft_gad_priority.log || true
echo ---
ls -l /mnt/c/Users/SK/CTI-Chatbot/tcar/eval_results/counterfactual_*20260906Tgpt56sol_soft_gad* 2>/dev/null || true
ls -l /mnt/c/Users/SK/CTI-Chatbot/eval_results/taa_*soft_gad* 2>/dev/null || true
tail -5 /mnt/c/Users/SK/CTI-Chatbot/tcar/eval_results/logs/soft_gad_taa.log 2>/dev/null || true
tail -5 /mnt/c/Users/SK/CTI-Chatbot/tcar/eval_results/logs/soft_gad_ctibench_vsp.log 2>/dev/null || true
