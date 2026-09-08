#!/usr/bin/env bash
# Launch remaining CTIBench Vanilla RAG tasks + CTIConnect CB/Forced RAG in parallel.
# Assumes ATE/RCM may already be running on stamp 20260904Tgpt56sol_forced_rag_cb.
set -euo pipefail
cd /mnt/c/Users/SK/CTI-Chatbot
source .venv/bin/activate

export TMPDIR=/mnt/c/Users/SK/CTI-Chatbot/.tmp
mkdir -p tcar/eval_results/logs "$TMPDIR"

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
export ATA_RETRIEVAL=behavior
export RCM_GAD=off ATA_GAD=off GAD_MODE=off RCM_CWE_RETRIEVAL=off

WORKERS="${WORKERS:-2}"
CB_STAMP="${CB_STAMP:-20260904Tgpt56sol_forced_rag_cb}"
CC_STAMP="${CC_STAMP:-20260906Tgpt56sol_forced_rag_cc}"
LOG="tcar/eval_results/logs/gpt56sol_parallel_all.log"

already_running() {
  local bench="$1" task="$2"
  ps aux | grep -E "run_counterfactual --benchmark ${bench} --tasks ${task}( |$)" | grep -v grep >/dev/null
}

launch_ctibench() {
  local task="$1"
  if already_running ctibench "$task"; then
    echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] SKIP ctibench ${task} (already running)" | tee -a "$LOG"
    return 0
  fi
  local logfile="tcar/eval_results/logs/forced_rag_v2_${task}.log"
  echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] RUN ctibench vanilla_rag ${task}" | tee -a "$LOG" "$logfile"
  (
    python -m tcar.eval.run_counterfactual \
      --benchmark ctibench \
      --tasks "$task" \
      --limit 0 \
      --workers "$WORKERS" \
      --model "$MODEL" \
      --variant no_confusion \
      --stamp "$CB_STAMP" \
      2>&1 | tee -a "$logfile"
    echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] DONE ctibench ${task}" | tee -a "$LOG" "$logfile"
  ) &
  echo "launched ctibench ${task} pid=$!" | tee -a "$LOG"
}

launch_cticonnect() {
  local task="$1"
  if already_running cticonnect "$task"; then
    echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] SKIP cticonnect ${task} (already running)" | tee -a "$LOG"
    return 0
  fi
  local logfile="tcar/eval_results/logs/forced_rag_cticonnect_${task}.log"
  echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] RUN cticonnect vanilla_rag ${task}" | tee -a "$LOG" "$logfile"
  (
    python -m tcar.eval.run_counterfactual \
      --benchmark cticonnect \
      --tasks "$task" \
      --limit 0 \
      --workers "$WORKERS" \
      --model "$MODEL" \
      --variant no_confusion \
      --stamp "$CC_STAMP" \
      2>&1 | tee -a "$logfile"
    echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] DONE cticonnect ${task}" | tee -a "$LOG" "$logfile"
  ) &
  echo "launched cticonnect ${task} pid=$!" | tee -a "$LOG"
}

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] Parallel all model=${MODEL} cb=${CB_STAMP} cc=${CC_STAMP}" | tee -a "$LOG"

# CTIBench: all four simultaneously (skip if already up)
for t in ate rcm mcq vsp; do
  launch_ctibench "$t"
done

# CTIConnect: RCM + ATA simultaneously, same Forced RAG / CB setup
for t in rcm ata; do
  launch_cticonnect "$t"
done

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] All launches issued; waiting..." | tee -a "$LOG"
wait || true
echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] Parallel all finish" | tee -a "$LOG"
