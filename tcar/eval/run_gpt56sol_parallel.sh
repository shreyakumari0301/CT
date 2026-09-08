#!/usr/bin/env bash
# Run Forced RAG + Force GAD for each CTIBench task in parallel (gpt-5.6-sol).
set -euo pipefail
cd /mnt/c/Users/SK/CTI-Chatbot
source .venv/bin/activate

export TMPDIR=/mnt/c/Users/SK/CTI-Chatbot/.tmp
mkdir -p tcar/eval_results/logs "$TMPDIR"
LOGDIR=tcar/eval_results/logs
MODEL="${MODEL:-openai/gpt-5.6-sol}"
WORKERS="${WORKERS:-4}"

eval "$(PYTHONPATH=. python - <<'PY'
from pathlib import Path
from dotenv import dotenv_values
vals = dotenv_values(Path(".env"))
keep = [
    "OPENROUTER_API_KEY", "OPENAI_API_KEY", "OPENAI_BASE_URL",
    "GENERATION_MODEL", "OPENROUTER_HTTP_REFERER", "OPENROUTER_APP_TITLE",
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
export OPENAI_BASE_URL="${OPENAI_BASE_URL:-https://openrouter.ai/api/v1}"
export USE_OPENROUTER=1
if [[ -n "${OPENROUTER_API_KEY:-}" ]]; then
  export OPENAI_API_KEY="$OPENROUTER_API_KEY"
fi
export OPENROUTER_REASONING_EFFORT="${EFFORT:-low}"
export OPENROUTER_REASONING=1
export RCM_PROMPT=soft

run_one () {
  local mode="$1"   # forced_rag | force_gad
  local task="$2"
  local stamp="$3"
  local logfile="$LOGDIR/gpt56sol_${mode}_${task}.log"
  (
    if [[ "$mode" == "forced_rag" ]]; then
      export RCM_GAD=off ATA_GAD=off GAD_MODE=off RCM_CWE_RETRIEVAL=off
    else
      export RCM_GAD=force ATA_GAD=force GAD_MODE=force
      unset RCM_CWE_RETRIEVAL || true
    fi
    echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] START ${mode} task=${task} workers=${WORKERS}" | tee -a "$logfile"
    python -m tcar.eval.run_counterfactual \
      --benchmark ctibench \
      --tasks "$task" \
      --limit 0 \
      --workers "$WORKERS" \
      --model "$MODEL" \
      --variant no_confusion \
      --stamp "$stamp" \
      2>&1 | tee -a "$logfile"
    echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] DONE ${mode} task=${task}" | tee -a "$logfile"
  ) &
  echo "launched pid=$! mode=${mode} task=${task}"
}

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] Parallel launch workers/task=${WORKERS}"

# Forced RAG (CB + Forced CTA-RAG) — all tasks
run_one forced_rag rcm 20260904Tgpt56sol_forced_rag_cb
run_one forced_rag ate 20260904Tgpt56sol_forced_rag_cb
run_one forced_rag mcq 20260904Tgpt56sol_forced_rag_cb
run_one forced_rag vsp 20260904Tgpt56sol_forced_rag_cb

# Force GAD — all tasks
run_one force_gad rcm 20260904Tgpt56sol_force_gad_cb
run_one force_gad ate 20260904Tgpt56sol_force_gad_cb
run_one force_gad mcq 20260904Tgpt56sol_force_gad_cb
run_one force_gad vsp 20260904Tgpt56sol_force_gad_cb

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] All 8 jobs launched; waiting..."
wait
echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] All parallel gpt-5.6-sol jobs finished"
