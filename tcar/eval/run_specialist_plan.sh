#!/usr/bin/env bash
# Specialist improvement experiments (generator stays gpt-5.6-sol).
# Priority: ATE CTA fidelity → RCM oracle top-20 stats → ATE/RCM CF runs.
set -euo pipefail
cd /mnt/c/Users/SK/CTI-Chatbot
source .venv/bin/activate
mkdir -p tcar/eval_results/logs

eval "$(PYTHONPATH=. python - <<'PY'
from pathlib import Path
from dotenv import dotenv_values
vals = dotenv_values(Path(".env"))
for k in ["OPENAI_API_KEY", "GENERATION_MODEL", "USE_OPENROUTER"]:
    v = vals.get(k)
    if v is None or str(v).strip() == "":
        continue
    v = str(v).strip().replace("\\", "\\\\").replace('"', '\\"')
    print(f'export {k}="{v}"')
PY
)"

export GENERATION_MODEL="${GENERATION_MODEL:-gpt-5.6-sol}"
export MODEL="$GENERATION_MODEL"
unset OPENAI_BASE_URL OPENROUTER_API_KEY || true
export USE_OPENROUTER=0
export RCM_PROMPT=soft ATA_PROMPT=soft
WORKERS="${WORKERS:-1}"
LOG=tcar/eval_results/logs/specialist_plan.log

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] specialist plan model=${MODEL}" | tee -a "$LOG"

# 1) RCM top-20 oracle headroom (retrieval only — cheap)
echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] RCM oracle top-20 stats" | tee -a "$LOG"
PYTHONPATH=. python -m tcar.eval.run_rcm_oracle_top20 --limit 0 --mode stats \
  2>&1 | tee -a tcar/eval_results/logs/rcm_oracle_top20_stats.log

# 1b) Train lightweight pairwise specialist reranker (no LLM)
echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] train RCM specialist reranker" | tee -a "$LOG"
PYTHONPATH=. python -m tcar.eval.train_rcm_specialist_reranker --limit 0 \
  2>&1 | tee -a tcar/eval_results/logs/rcm_train_reranker.log

# 2) ATE CTA fidelity Forced RAG (align prompt with paper CTA)
(
  export RCM_GAD=off ATA_GAD=off GAD_MODE=off RCM_CWE_RETRIEVAL=off
  export ATE_PROMPT=cta
  echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] ATE CTA-fidelity CF" | tee -a "$LOG"
  PYTHONPATH=. python -m tcar.eval.run_counterfactual \
    --benchmark ctibench --tasks ate --limit 0 --workers "$WORKERS" \
    --model "$MODEL" --variant no_confusion \
    --stamp 20260907Tsol_ate_cta_fidelity \
    2>&1 | tee -a tcar/eval_results/logs/ate_cta_fidelity.log
) &

# 3) RCM taxonomy rerank Forced RAG
(
  export RCM_GAD=off ATA_GAD=off GAD_MODE=off
  export RCM_CWE_RETRIEVAL=on RCM_RERANK=taxonomy RCM_ORACLE=off
  echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] RCM taxonomy rerank CF" | tee -a "$LOG"
  PYTHONPATH=. python -m tcar.eval.run_counterfactual \
    --benchmark ctibench --tasks rcm --limit 0 --workers "$WORKERS" \
    --model "$MODEL" --variant no_confusion \
    --stamp 20260907Tsol_rcm_taxonomy_rerank \
    2>&1 | tee -a tcar/eval_results/logs/rcm_taxonomy_rerank.log
) &

# 3b) RCM specialist learned rerank (requires prior train step)
(
  export RCM_GAD=off ATA_GAD=off GAD_MODE=off
  export RCM_CWE_RETRIEVAL=on RCM_RERANK=learned RCM_ORACLE=off
  echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] RCM learned rerank CF" | tee -a "$LOG"
  PYTHONPATH=. python -m tcar.eval.run_counterfactual \
    --benchmark ctibench --tasks rcm --limit 0 --workers "$WORKERS" \
    --model "$MODEL" --variant no_confusion \
    --stamp 20260907Tsol_rcm_learned_rerank \
    2>&1 | tee -a tcar/eval_results/logs/rcm_learned_rerank.log
) &

# 3c) Soft GAD + taxonomy rerank
(
  export RCM_GAD=force ATA_GAD=off GAD_MODE=soft
  export RCM_CWE_RETRIEVAL=on RCM_RERANK=taxonomy RCM_ORACLE=off
  echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] RCM Soft GAD + taxonomy CF" | tee -a "$LOG"
  PYTHONPATH=. python -m tcar.eval.run_counterfactual \
    --benchmark ctibench --tasks rcm --limit 0 --workers "$WORKERS" \
    --model "$MODEL" --variant no_confusion \
    --stamp 20260907Tsol_rcm_soft_gad_taxonomy \
    2>&1 | tee -a tcar/eval_results/logs/rcm_soft_gad_taxonomy.log
) &

# 4) RCM oracle gold_pin upper bound
(
  export RCM_GAD=off ATA_GAD=off GAD_MODE=off
  export RCM_CWE_RETRIEVAL=on RCM_RERANK=off RCM_ORACLE=gold_pin
  echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] RCM gold_pin oracle CF" | tee -a "$LOG"
  PYTHONPATH=. python -m tcar.eval.run_counterfactual \
    --benchmark ctibench --tasks rcm --limit 0 --workers "$WORKERS" \
    --model "$MODEL" --variant no_confusion \
    --stamp 20260907Tsol_rcm_gold_pin \
    2>&1 | tee -a tcar/eval_results/logs/rcm_gold_pin.log
) &

# 5) ATA behavior + abstain
(
  export RCM_GAD=off ATA_GAD=off GAD_MODE=off
  export ATA_RETRIEVAL=behavior ATA_ABSTAIN=1 ATA_PROMPT=soft
  echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] ATA behavior+abstain CF" | tee -a "$LOG"
  PYTHONPATH=. python -m tcar.eval.run_counterfactual \
    --benchmark cticonnect --tasks ata --limit 0 --workers "$WORKERS" \
    --model "$MODEL" --variant no_confusion \
    --stamp 20260907Tsol_ata_behavior_abstain \
    2>&1 | tee -a tcar/eval_results/logs/ata_behavior_abstain.log
) &

# 6) MCQ option-aware
(
  export RCM_GAD=off ATA_GAD=off GAD_MODE=off
  export MCQ_RETRIEVAL=option_aware
  echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] MCQ option-aware CF" | tee -a "$LOG"
  PYTHONPATH=. python -m tcar.eval.run_counterfactual \
    --benchmark ctibench --tasks mcq --limit 0 --workers "$WORKERS" \
    --model "$MODEL" --variant no_confusion \
    --stamp 20260907Tsol_mcq_option_aware \
    2>&1 | tee -a tcar/eval_results/logs/mcq_option_aware.log
) &

# 7) VSP metric-wise
(
  export RCM_GAD=off ATA_GAD=off GAD_MODE=off
  export VSP_RETRIEVAL=metric_wise
  echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] VSP metric-wise CF" | tee -a "$LOG"
  PYTHONPATH=. python -m tcar.eval.run_counterfactual \
    --benchmark ctibench --tasks vsp --limit 0 --workers "$WORKERS" \
    --model "$MODEL" --variant no_confusion \
    --stamp 20260907Tsol_vsp_metric_wise \
    2>&1 | tee -a tcar/eval_results/logs/vsp_metric_wise.log
) &

wait || true
echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] specialist plan batch finished" | tee -a "$LOG"
