#!/usr/bin/env bash
# CTIConnect ATA Forced RAG with behavior-level retrieval (plan item 4).
set -euo pipefail
cd /mnt/c/Users/SK/CTI-Chatbot
source .venv/bin/activate

export TMPDIR=/mnt/c/Users/SK/CTI-Chatbot/.tmp
mkdir -p tcar/eval_results/logs "$TMPDIR"
LOG="tcar/eval_results/logs/gpt56sol_ata_behavior.log"
MODEL="${MODEL:-gpt-5.6-sol}"
WORKERS="${WORKERS:-2}"
STAMP="${STAMP:-20260906Tgpt56sol_ata_behavior_cc}"

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
export ATA_RETRIEVAL=behavior
export RCM_GAD=off ATA_GAD=off GAD_MODE=off RCM_CWE_RETRIEVAL=off

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] ATA behavior Forced RAG stamp=${STAMP} model=${MODEL}" | tee -a "$LOG"
python -m tcar.eval.run_counterfactual \
  --benchmark cticonnect \
  --tasks ata \
  --limit 0 \
  --workers "$WORKERS" \
  --model "$MODEL" \
  --variant no_confusion \
  --stamp "$STAMP" \
  2>&1 | tee -a "$LOG"
echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] ATA behavior done" | tee -a "$LOG"
