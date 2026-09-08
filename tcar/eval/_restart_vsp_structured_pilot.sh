#!/usr/bin/env bash
# Restart VSP structured pilot with consistency logging; leave RCM/MCQ alone.
set -euo pipefail
cd /mnt/c/Users/SK/CTI-Chatbot
pkill -f 'run_vsp_structured_on_ids|stamp 20260908Tturbo_vsp_structured_n75' 2>/dev/null || true
sleep 1
rm -f tcar/eval_results/counterfactual_ctibench_vsp_20260908Tturbo_vsp_structured_n75.jsonl
rm -f tcar/eval_results/counterfactual_summary_20260908Tturbo_vsp_structured_n75.json
nohup bash tcar/eval/_job_vsp_structured_pilot.sh \
  > tcar/eval_results/logs/vsp_structured_n75.nohup.out 2>&1 &
echo "VSP_RESTART_PID=$!"
sleep 2
pgrep -af 'run_vsp_structured|vsp_structured_n75|run_rcm_hybrid|mcq_option' | head -10
