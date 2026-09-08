#!/usr/bin/env bash
# Soft GAD on CTIBench + CTIConnect with gpt-5.6-sol (OpenAI direct).
# Priority: VSP, ATA, TAA — then MCQ / Connect RCM / remaining Soft GAD resumes.
#
# Soft GAD env (matches prior suite):
#   RCM_GAD=force ATA_GAD=force GAD_MODE=soft
#   RCM_PROMPT=soft ATA_PROMPT=soft
#
# TAA is not in run_counterfactual; Soft GAD uses non-gated closed_book + cta (always retrieve).
# Never use --mode gated / candidate_first gate.
set -euo pipefail
cd /mnt/c/Users/SK/CTI-Chatbot
source .venv/bin/activate

export TMPDIR=/mnt/c/Users/SK/CTI-Chatbot/.tmp
mkdir -p tcar/eval_results/logs eval_results/logs "$TMPDIR"

eval "$(PYTHONPATH=. python - <<'PY'
from pathlib import Path
from dotenv import dotenv_values
vals = dotenv_values(Path(".env"))
keep = ["OPENAI_API_KEY", "OPENAI_BASE_URL", "GENERATION_MODEL", "USE_OPENROUTER"]
for k in keep:
    v = vals.get(k)
    if v is None or str(v).strip() == "":
        continue
    v = str(v).strip().replace("\\", "\\\\").replace('"', '\\"')
    print(f'export {k}="{v}"')
PY
)"

export GENERATION_MODEL="${GENERATION_MODEL:-gpt-5.6-sol}"
export MODEL="${GENERATION_MODEL}"
unset OPENAI_BASE_URL OPENROUTER_API_KEY OPENROUTER_REASONING OPENROUTER_REASONING_EFFORT || true
export USE_OPENROUTER=0

export RCM_PROMPT=soft
export ATA_PROMPT=soft
export RCM_GAD=force
export ATA_GAD=force
export GAD_MODE=soft
unset RCM_CWE_RETRIEVAL || true

WORKERS="${WORKERS:-1}"
STAMP_CB="${STAMP_CB:-20260906Tgpt56sol_soft_gad_cb}"
STAMP_CC="${STAMP_CC:-20260906Tgpt56sol_soft_gad_cc}"
STAMP_TAA="${STAMP_TAA:-20260906Tgpt56sol_soft_gad_taa}"
# Priority tasks; override e.g. TASKS_CB=vsp,mcq TASKS_CC=ata
TASKS_CB="${TASKS_CB:-vsp,mcq,ate,rcm}"
TASKS_CC="${TASKS_CC:-ata,rcm}"
RUN_TAA="${RUN_TAA:-1}"
LOG="tcar/eval_results/logs/gpt56sol_soft_gad_priority.log"

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] Soft GAD sol model=${MODEL} workers=${WORKERS} CB=${STAMP_CB} CC=${STAMP_CC}" | tee -a "$LOG"

already_cf() {
  local bench="$1" task="$2" stamp="$3"
  ps aux | grep -E "run_counterfactual --benchmark ${bench} --tasks ${task} .*--stamp ${stamp}" | grep -v grep >/dev/null
}

launch_cf() {
  local bench="$1" task="$2" stamp="$3"
  if already_cf "$bench" "$task" "$stamp"; then
    echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] SKIP ${bench}/${task} soft_gad (running)" | tee -a "$LOG"
    return 0
  fi
  local logfile="tcar/eval_results/logs/soft_gad_${bench}_${task}.log"
  echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] RUN soft_gad ${bench}/${task} stamp=${stamp}" | tee -a "$LOG" "$logfile"
  (
    export RCM_GAD=force ATA_GAD=force GAD_MODE=soft RCM_PROMPT=soft ATA_PROMPT=soft
    unset RCM_CWE_RETRIEVAL || true
    python -m tcar.eval.run_counterfactual \
      --benchmark "$bench" \
      --tasks "$task" \
      --limit 0 \
      --workers "$WORKERS" \
      --model "$MODEL" \
      --variant no_confusion \
      --stamp "$stamp" \
      2>&1 | tee -a "$logfile"
    echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] DONE soft_gad ${bench}/${task}" | tee -a "$LOG" "$logfile"
  ) &
  echo "launched soft_gad ${bench}/${task} pid=$!" | tee -a "$LOG"
}

IFS=',' read -r -a CB_ARR <<< "$TASKS_CB"
IFS=',' read -r -a CC_ARR <<< "$TASKS_CC"

# Priority order: VSP first among CTIBench
for task in "${CB_ARR[@]}"; do
  launch_cf ctibench "$task" "$STAMP_CB"
done

for task in "${CC_ARR[@]}"; do
  launch_cf cticonnect "$task" "$STAMP_CC"
done

if [[ "$RUN_TAA" == "1" ]]; then
  if ps aux | grep -E "eval.run_taa --mode (closed_book|cta) .*${STAMP_TAA}" | grep -v grep >/dev/null; then
    echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] SKIP TAA (already running)" | tee -a "$LOG"
  else
    logfile="tcar/eval_results/logs/soft_gad_taa.log"
    echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] RUN TAA Soft GAD NON-GATED (closed_book + cta) stamp=${STAMP_TAA}" | tee -a "$LOG" "$logfile"
    (
      export RCM_GAD=force ATA_GAD=force GAD_MODE=soft RCM_PROMPT=soft ATA_PROMPT=soft
      unset RCM_CWE_RETRIEVAL || true
      for mode in closed_book cta; do
        echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] RUN TAA mode=${mode}" | tee -a "$logfile"
        PYTHONPATH=. python -u -m eval.run_taa \
          --mode "$mode" \
          --limit 0 \
          --workers "$WORKERS" \
          --out-dir eval_results \
          --stamp "${STAMP_TAA}_${mode}" \
          2>&1 | tee -a "$logfile"
        echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] DONE TAA mode=${mode}" | tee -a "$logfile"
      done
    ) &
    echo "launched TAA non-gated pid=$!" | tee -a "$LOG"
  fi
fi

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] Soft GAD priority batch launched. Monitor: $LOG" | tee -a "$LOG"
wait || true
echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] Soft GAD priority batch finished" | tee -a "$LOG"
