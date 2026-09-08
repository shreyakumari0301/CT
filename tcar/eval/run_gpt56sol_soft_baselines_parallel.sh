#!/usr/bin/env bash
# Soft GAD (all tasks) + paper baselines in parallel on openai/gpt-5.6-sol.
set -euo pipefail
cd /mnt/c/Users/SK/CTI-Chatbot
source .venv/bin/activate

export TMPDIR=/mnt/c/Users/SK/CTI-Chatbot/.tmp
mkdir -p tcar/eval_results/logs eval_results/logs "$TMPDIR"
LOGDIR=tcar/eval_results/logs
MODEL="${MODEL:-openai/gpt-5.6-sol}"
CF_WORKERS="${CF_WORKERS:-4}"
BASE_WORKERS="${BASE_WORKERS:-3}"
STAMP_SOFT="${STAMP_SOFT:-20260904Tgpt56sol_soft_gad_cb}"
STAMP_BASE="${STAMP_BASE:-20260904Tgpt56sol_baselines}"

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

run_soft () {
  local task="$1"
  local logfile="$LOGDIR/gpt56sol_soft_gad_${task}.log"
  (
    export RCM_GAD=force ATA_GAD=force GAD_MODE=soft
    unset RCM_CWE_RETRIEVAL || true
    echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] START soft_gad task=${task}" | tee -a "$logfile"
    python -m tcar.eval.run_counterfactual \
      --benchmark ctibench \
      --tasks "$task" \
      --limit 0 \
      --workers "$CF_WORKERS" \
      --model "$MODEL" \
      --variant no_confusion \
      --stamp "$STAMP_SOFT" \
      2>&1 | tee -a "$logfile"
    echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] DONE soft_gad task=${task}" | tee -a "$logfile"
  ) &
  echo "launched soft_gad task=${task} pid=$!"
}

run_base () {
  local name="$1"
  local cmd="$2"
  local logfile="eval_results/logs/gpt56sol_${name}.log"
  mkdir -p eval_results/logs
  (
    echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] START baseline ${name}" | tee -a "$logfile"
    eval "$cmd" 2>&1 | tee -a "$logfile"
    echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] DONE baseline ${name}" | tee -a "$logfile"
  ) &
  echo "launched baseline ${name} pid=$!"
}

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] Parallel Soft GAD + baselines model=${MODEL}"

# Soft GAD — same diversify K=12, advisory catalogue prompts
for t in rcm ate mcq vsp; do
  run_soft "$t"
done

# Paper baselines (GENERATION_MODEL overrides hard-coded gpt-4-turbo via resolve_model)
TASKS_ALL=mcq,rcm,vsp,ate

run_base unified_rag \
  "python -m eval.run_unified_rag --limit 0 --tasks ${TASKS_ALL} --workers ${BASE_WORKERS} --out-dir eval_results --prompt-mode zero_shot --retrieval on"

run_base selfrag \
  "python -m eval.run_strong_rag_baselines --limit 0 --tasks ${TASKS_ALL} --systems selfrag --workers ${BASE_WORKERS} --out-dir eval_results --pred-name selfrag_${STAMP_BASE}.jsonl"

run_base graphrag \
  "python -m eval.run_strong_rag_baselines --limit 0 --tasks ${TASKS_ALL} --systems graphrag --workers ${BASE_WORKERS} --out-dir eval_results --pred-name graphrag_${STAMP_BASE}.jsonl"

run_base adaptive_rag \
  "python -m eval.run_adaptive_baselines --limit 0 --tasks ${TASKS_ALL} --systems adaptive_rag --workers ${BASE_WORKERS} --out-dir eval_results --pred-name adaptive_rag_${STAMP_BASE}.jsonl"

run_base tadarag \
  "python -m eval.run_adaptive_baselines --limit 0 --tasks ${TASKS_ALL} --systems tadarag --workers ${BASE_WORKERS} --out-dir eval_results --pred-name tadarag_${STAMP_BASE}.jsonl"

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] All Soft GAD + baseline jobs launched; waiting..."
wait
echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] Soft GAD + baselines finished"
