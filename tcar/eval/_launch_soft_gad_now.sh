#!/usr/bin/env bash
# Launch Soft GAD priority: VSP + ATA + TAA (+ optional expand).
set -euo pipefail
cd /mnt/c/Users/SK/CTI-Chatbot
chmod +x tcar/eval/run_gpt56sol_soft_gad_priority.sh

# Stop completed Forced RAG MCQ/VSP workers that are past full-n (free API slots for Soft GAD).
# Keep CTA E2E and baselines running.
for pat in \
  "run_counterfactual --benchmark ctibench --tasks mcq .*stamp 20260904Tgpt56sol_forced_rag_cb" \
  "run_counterfactual --benchmark ctibench --tasks vsp .*stamp 20260904Tgpt56sol_forced_rag_cb" \
  "run_counterfactual --benchmark ctibench --tasks mcq .*stamp 20260906Tgpt56sol_forced_rag_v3" \
  "run_counterfactual --benchmark ctibench --tasks vsp .*stamp 20260906Tgpt56sol_forced_rag_v3"
do
  pids=$(pgrep -f "$pat" || true)
  if [[ -n "${pids}" ]]; then
    echo "Stopping completed/extra Forced RAG: $pat -> $pids"
    kill $pids || true
  fi
done

sleep 2

nohup env \
  WORKERS=1 \
  TASKS_CB=vsp \
  TASKS_CC=ata \
  RUN_TAA=1 \
  STAMP_CB=20260906Tgpt56sol_soft_gad_cb \
  STAMP_CC=20260906Tgpt56sol_soft_gad_cc \
  STAMP_TAA=20260906Tgpt56sol_soft_gad_taa \
  bash tcar/eval/run_gpt56sol_soft_gad_priority.sh \
  > tcar/eval_results/logs/soft_gad_priority_nohup.out 2>&1 &
echo "phase1_pid=$!"

sleep 3

# Second wave: Soft GAD MCQ + Connect RCM (+ resume ATE/RCM soft if incomplete)
nohup env \
  WORKERS=1 \
  TASKS_CB=mcq,ate,rcm \
  TASKS_CC=rcm \
  RUN_TAA=0 \
  STAMP_CB=20260906Tgpt56sol_soft_gad_cb \
  STAMP_CC=20260906Tgpt56sol_soft_gad_cc \
  bash tcar/eval/run_gpt56sol_soft_gad_priority.sh \
  > tcar/eval_results/logs/soft_gad_wave2_nohup.out 2>&1 &
echo "phase2_pid=$!"

sleep 4
pgrep -af 'soft_gad|GAD_MODE=soft|run_taa|run_counterfactual --benchmark' | head -40 || true
tail -30 tcar/eval_results/logs/gpt56sol_soft_gad_priority.log || true
