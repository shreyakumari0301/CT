#!/usr/bin/env bash
# Score-lift v3 Forced RAG (gpt-5.6-sol): anti-harm prompts + empty-RAG→CB fallback.
# Fresh stamp so old harm rows are not mixed with new prompts.
set -euo pipefail
cd /mnt/c/Users/SK/CTI-Chatbot
source .venv/bin/activate

export TMPDIR=/mnt/c/Users/SK/CTI-Chatbot/.tmp
mkdir -p tcar/eval_results/logs "$TMPDIR"
LOG="tcar/eval_results/logs/gpt56sol_forced_rag_v3.log"
MODEL="${MODEL:-gpt-5.6-sol}"
WORKERS="${WORKERS:-2}"
CB_STAMP="${CB_STAMP:-20260906Tgpt56sol_forced_rag_v3}"
CC_STAMP="${CC_STAMP:-20260906Tgpt56sol_forced_rag_v3_cc}"

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

export GENERATION_MODEL="${GENERATION_MODEL:-$MODEL}"
export MODEL="${GENERATION_MODEL}"
unset OPENAI_BASE_URL OPENROUTER_API_KEY OPENROUTER_REASONING OPENROUTER_REASONING_EFFORT || true
export USE_OPENROUTER=0
export RCM_PROMPT=soft
export ATA_PROMPT=soft
export RCM_GAD=off ATA_GAD=off GAD_MODE=off RCM_CWE_RETRIEVAL=off

run_one () {
  local bench="$1" task="$2" stamp="$3"
  local logfile="tcar/eval_results/logs/forced_rag_v3_${bench}_${task}.log"
  echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] RUN ${bench} ${task} stamp=${stamp}" | tee -a "$LOG" "$logfile"
  (
    python -m tcar.eval.run_counterfactual \
      --benchmark "$bench" \
      --tasks "$task" \
      --limit 0 \
      --workers "$WORKERS" \
      --model "$MODEL" \
      --variant no_confusion \
      --stamp "$stamp" \
      2>&1 | tee -a "$logfile"
    echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] DONE ${bench} ${task}" | tee -a "$LOG" "$logfile"
  ) &
  echo "launched ${bench}/${task} pid=$!" | tee -a "$LOG"
}

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] Score-lift v3 model=${MODEL}" | tee -a "$LOG"

# Highest-harm tasks (full remeasure under anti-harm prompts)
for t in mcq vsp; do
  run_one ctibench "$t" "$CB_STAMP"
done
for t in ata rcm; do
  run_one cticonnect "$t" "$CC_STAMP"
done

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] All v3 launches issued; waiting..." | tee -a "$LOG"
wait || true
echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] Score-lift v3 finish" | tee -a "$LOG"
