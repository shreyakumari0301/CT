#!/usr/bin/env bash
# CTA-RAG end-to-end on gpt-5.6-sol (OpenAI direct).
#
# Forced RAG (run_counterfactual, GAD off) is a retrieval ablation inside known
# specialist prompts — NOT the full system. This script runs the real CTA-RAG:
#   CTIBench oracle  = gold task → specialist pipeline  (fair peer to Forced RAG;
#                      both skip the router)
#   CTIBench router  = classify_query → specialist pipeline  (true E2E)
#   CTIConnect       = cta_rag_port (task→module + graph diversify)
#
# Usage:
#   bash tcar/eval/run_gpt56sol_cta_e2e.sh
#   MODE=oracle WORKERS=1 TASKS=ate,rcm bash tcar/eval/run_gpt56sol_cta_e2e.sh
#   SKIP_CONNECT=1 MODE=router bash tcar/eval/run_gpt56sol_cta_e2e.sh
set -euo pipefail
cd /mnt/c/Users/SK/CTI-Chatbot
source .venv/bin/activate

export TMPDIR=/mnt/c/Users/SK/CTI-Chatbot/.tmp
mkdir -p tcar/eval_results/logs eval_results/logs "CTICONNECT benchmark/eval_results" "$TMPDIR"

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
export CTICONNECT_MODEL="${CTICONNECT_MODEL:-$GENERATION_MODEL}"
unset OPENAI_BASE_URL OPENROUTER_API_KEY OPENROUTER_REASONING OPENROUTER_REASONING_EFFORT || true
export USE_OPENROUTER=0

# Paper-defended RCM: CWE catalogue off (same as Forced RAG CF default)
export RCM_CWE_RETRIEVAL=off
export RCM_PROMPT=soft

WORKERS="${WORKERS:-1}"
# Modes: oracle | router | both
MODE="${MODE:-both}"
TASKS="${TASKS:-ate,rcm,mcq,vsp}"
SKIP_CONNECT="${SKIP_CONNECT:-0}"
CONNECT_STAMP="${CONNECT_STAMP:-20260906Tgpt56sol_cta_port}"
LOG="tcar/eval_results/logs/gpt56sol_cta_e2e.log"

IFS=',' read -r -a TASK_ARR <<< "$TASKS"

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] CTA-RAG E2E model=${GENERATION_MODEL} mode=${MODE} workers=${WORKERS} tasks=${TASKS}" | tee -a "$LOG"

already_running_ctibench() {
  local task="$1" route="$2"
  ps aux | grep -E "eval.run_ctibench --task ${task} .*--route_mode ${route}" | grep -v grep >/dev/null
}

launch_ctibench() {
  local task="$1" route="$2"
  if already_running_ctibench "$task" "$route"; then
    echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] SKIP ctibench ${task} ${route} (already running)" | tee -a "$LOG"
    return 0
  fi
  local logfile="tcar/eval_results/logs/cta_e2e_${route}_${task}.log"
  echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] RUN ctibench ${route} ${task}" | tee -a "$LOG" "$logfile"
  (
    PYTHONPATH=. python -u -m eval.run_ctibench \
      --task "$task" \
      --limit 0 \
      --route_mode "$route" \
      --workers "$WORKERS" \
      --out-dir eval_results \
      2>&1 | tee -a "$logfile"
    echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] DONE ctibench ${route} ${task}" | tee -a "$LOG" "$logfile"
  ) &
  echo "launched ctibench ${route} ${task} pid=$!" | tee -a "$LOG"
}

for task in "${TASK_ARR[@]}"; do
  case "$MODE" in
    oracle) launch_ctibench "$task" oracle ;;
    router) launch_ctibench "$task" router ;;
    both)
      launch_ctibench "$task" oracle
      launch_ctibench "$task" router
      ;;
    *)
      echo "Unknown MODE=$MODE (use oracle|router|both)" >&2
      exit 1
      ;;
  esac
done

if [[ "$SKIP_CONNECT" != "1" ]]; then
  if ps aux | grep -E "eval.run_cticonnect .*cta_rag_port" | grep -v grep >/dev/null; then
    echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] SKIP cticonnect cta_rag_port (already running)" | tee -a "$LOG"
  else
    logfile="tcar/eval_results/logs/cta_e2e_cticonnect_port.log"
    echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] RUN cticonnect cta_rag_port stamp=${CONNECT_STAMP}" | tee -a "$LOG" "$logfile"
    (
      PYTHONPATH=. python -u -m eval.run_cticonnect \
        --systems cta_rag_port \
        --tasks rcm,ata \
        --limit 0 \
        --workers "$WORKERS" \
        --k 5 \
        --stamp "$CONNECT_STAMP" \
        --out-dir "CTICONNECT benchmark/eval_results" \
        2>&1 | tee -a "$logfile"
      echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] DONE cticonnect cta_rag_port" | tee -a "$LOG" "$logfile"
    ) &
    echo "launched cticonnect cta_rag_port pid=$!" | tee -a "$LOG"
  fi
fi

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] All CTA-RAG E2E jobs launched (background). Monitor: $LOG" | tee -a "$LOG"
wait || true
echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] CTA-RAG E2E batch finished" | tee -a "$LOG"
