#!/usr/bin/env bash
# Stop all CTI eval jobs (Soft GAD, CTA E2E, baselines, CF).
set -u
cd /mnt/c/Users/SK/CTI-Chatbot

patterns=(
  'tcar.eval.run_counterfactual'
  'eval.run_ctibench'
  'eval.run_cticonnect'
  'eval.run_taa'
  'eval.run_strong_rag'
  'eval.run_adaptive'
  'eval.run_graphrag'
  'eval.run_unified'
  'run_gpt56sol_soft_gad'
  'run_gpt56sol_cta_e2e'
  'run_gpt56sol_baselines'
  'run_gpt56sol_parallel'
  'run_gpt56sol_forced'
  'soft_gad_priority'
  'cta_e2e_relaunch'
  'baselines_queue'
  'run_specialist'
  'specialist_priority'
  'specialist_remaining'
  'rcm_learned_rerank'
  'ate_cta_fidelity'
  'train_rcm_specialist'
)

echo "BEFORE:"
pgrep -af 'run_counterfactual|run_ctibench|run_cticonnect|run_taa|run_strong|run_adaptive|run_graphrag|run_unified|soft_gad|cta_e2e|gpt56sol' || echo "(none)"

for pat in "${patterns[@]}"; do
  pkill -f "$pat" 2>/dev/null || true
done
sleep 2
# second pass SIGKILL leftovers
for pat in "${patterns[@]}"; do
  pkill -9 -f "$pat" 2>/dev/null || true
done
sleep 1

echo "AFTER:"
left=$(pgrep -af 'run_counterfactual|run_ctibench|run_cticonnect|run_taa|run_strong|run_adaptive|run_graphrag|run_unified|soft_gad|cta_e2e|gpt56sol' || true)
if [[ -z "${left}" ]]; then
  echo "all_stopped"
else
  echo "$left"
fi
