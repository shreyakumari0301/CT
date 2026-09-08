#!/usr/bin/env bash
# Finish CTIBench CB / Forced RAG / Force GAD on openai/gpt-5.6-sol (no poll).
set -euo pipefail
cd /mnt/c/Users/SK/CTI-Chatbot
source .venv/bin/activate

export TMPDIR=/mnt/c/Users/SK/CTI-Chatbot/.tmp
mkdir -p tcar/eval_results/logs "$TMPDIR"
LOG="tcar/eval_results/logs/gpt56sol_run.log"
MODEL="${MODEL:-openai/gpt-5.6-sol}"
TASKS="${TASKS:-rcm,ate,mcq,vsp}"
WORKERS="${WORKERS:-12}"

eval "$(PYTHONPATH=. python - <<'PY'
from pathlib import Path
from dotenv import dotenv_values
vals = dotenv_values(Path(".env"))
keep = [
    "OPENROUTER_API_KEY", "OPENAI_API_KEY", "OPENAI_BASE_URL",
    "GENERATION_MODEL", "OPENROUTER_REASONING_EFFORT", "OPENROUTER_REASONING",
    "OPENROUTER_HTTP_REFERER", "OPENROUTER_APP_TITLE",
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
# low effort = faster/cheaper so the $50 budget can finish; still sol reasoning
export OPENROUTER_REASONING_EFFORT="${EFFORT:-low}"
export OPENROUTER_REASONING=1
export RCM_PROMPT=soft

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] START model=${MODEL} tasks=${TASKS} workers=${WORKERS} effort=${OPENROUTER_REASONING_EFFORT}" | tee -a "$LOG"

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] === Forced RAG (CB + Forced CTA-RAG) ===" | tee -a "$LOG"
export RCM_GAD=off
export ATA_GAD=off
export RCM_CWE_RETRIEVAL=off
export GAD_MODE=off
python -m tcar.eval.run_counterfactual \
  --benchmark ctibench \
  --tasks "$TASKS" \
  --limit 0 \
  --workers "$WORKERS" \
  --model "$MODEL" \
  --variant no_confusion \
  --stamp 20260904Tgpt56sol_forced_rag_cb \
  2>&1 | tee -a "$LOG"

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] === Force GAD ===" | tee -a "$LOG"
export RCM_GAD=force
export ATA_GAD=force
export GAD_MODE=force
unset RCM_CWE_RETRIEVAL || true
python -m tcar.eval.run_counterfactual \
  --benchmark ctibench \
  --tasks "$TASKS" \
  --limit 0 \
  --workers "$WORKERS" \
  --model "$MODEL" \
  --variant no_confusion \
  --stamp 20260904Tgpt56sol_force_gad_cb \
  2>&1 | tee -a "$LOG"

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] DONE gpt-5.6-sol Forced RAG + Force GAD" | tee -a "$LOG"
