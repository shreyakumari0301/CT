#!/usr/bin/env bash
# CTIConnect counterfactual: closed-book + Vanilla/Forced RAG (GAD off).
# Same retrieval strategy as CTIBench Vanilla RAG; generator = gpt-5.6-sol (OpenAI direct).
# Tasks: RCM + ATA (overlap tasks). Both run simultaneously.
set -euo pipefail
cd /mnt/c/Users/SK/CTI-Chatbot
source .venv/bin/activate

export TMPDIR=/mnt/c/Users/SK/CTI-Chatbot/.tmp
mkdir -p tcar/eval_results/logs "$TMPDIR"
LOG="tcar/eval_results/logs/gpt56sol_forced_rag_cticonnect.log"
MODEL="${MODEL:-gpt-5.6-sol}"
WORKERS="${WORKERS:-2}"
STAMP="${STAMP:-20260906Tgpt56sol_forced_rag_cc}"

eval "$(PYTHONPATH=. python - <<'PY'
from pathlib import Path
from dotenv import dotenv_values
vals = dotenv_values(Path(".env"))
keep = [
    "OPENAI_API_KEY", "OPENAI_BASE_URL", "GENERATION_MODEL", "USE_OPENROUTER",
]
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
export ATA_RETRIEVAL=behavior
# Vanilla / Forced RAG — no GAD change
export RCM_GAD=off ATA_GAD=off GAD_MODE=off RCM_CWE_RETRIEVAL=off

run_task () {
  local task="$1"
  local logfile="tcar/eval_results/logs/forced_rag_cticonnect_${task}.log"
  echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] RUN cticonnect vanilla_rag ${task} stamp=${STAMP}" | tee -a "$LOG" "$logfile"
  python -m tcar.eval.run_counterfactual \
    --benchmark cticonnect \
    --tasks "$task" \
    --limit 0 \
    --workers "$WORKERS" \
    --model "$MODEL" \
    --variant no_confusion \
    --stamp "$STAMP" \
    2>&1 | tee -a "$logfile"
  echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] DONE cticonnect vanilla_rag ${task}" | tee -a "$LOG" "$logfile"
}

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] CTIConnect CB+Forced RAG workers=${WORKERS} stamp=${STAMP} model=${MODEL}" | tee -a "$LOG"

# RCM + ATA simultaneously
run_task rcm &
pid_rcm=$!
run_task ata &
pid_ata=$!
wait "$pid_rcm" || true
wait "$pid_ata" || true

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] CTIConnect CB+Forced RAG finish" | tee -a "$LOG"
