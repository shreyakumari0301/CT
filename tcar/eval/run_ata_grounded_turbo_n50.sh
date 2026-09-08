#!/usr/bin/env bash
# CTIConnect ATA behaviour-grounded pilot (turbo, n=50) — CB vs grounded Forced-RAG.
set -euo pipefail
cd /mnt/c/Users/SK/CTI-Chatbot
source .venv/bin/activate
mkdir -p tcar/eval_results/logs

eval "$(PYTHONPATH=. python - <<'PY'
from pathlib import Path
from dotenv import dotenv_values
vals = dotenv_values(Path(".env"))
for k in ["OPENAI_API_KEY", "USE_OPENROUTER"]:
    v = vals.get(k)
    if v is None or str(v).strip() == "":
        continue
    v = str(v).strip().replace("\\", "\\\\").replace('"', '\\"')
    print(f'export {k}="{v}"')
print('export GENERATION_MODEL="gpt-4-turbo"')
PY
)"

unset OPENAI_BASE_URL OPENROUTER_API_KEY || true
export USE_OPENROUTER=0
export GENERATION_MODEL=gpt-4-turbo
export MODEL=gpt-4-turbo
export RCM_GAD=off ATA_GAD=off GAD_MODE=off
export ATA_RETRIEVAL=grounded
export ATA_PER_BEHAVIOR_K=20
export ATA_GROUNDED_K=5
export ATA_PROMPT=soft
LIMIT="${LIMIT:-50}"
STAMP="${STAMP:-20260907Tturbo_ata_grounded_n${LIMIT}}"
LOG=tcar/eval_results/logs/ata_grounded_turbo_n${LIMIT}.log

PYTHONPATH=. python - <<'PY'
from tcar.ata_behavior_grounded import segment_behaviors_rulebased, reciprocal_rank_fusion
s = segment_behaviors_rulebased(
    'The malware used PowerShell to download a payload and later created a scheduled task for persistence.'
)
assert len(s) >= 1, s
assert reciprocal_rank_fusion([["T1","T2"],["T2","T3"]])[0][0] == "T2"
print("grounded_unit_ok", s)
from utils.llm_client import resolve_model
import os
assert resolve_model("gpt-4-turbo") == "gpt-4-turbo"
print("model_ok", (os.getenv("OPENAI_API_KEY") or "")[:12])
PY

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] ATA grounded turbo limit=$LIMIT" | tee "$LOG"
PYTHONPATH=. python -m tcar.eval.run_counterfactual \
  --benchmark cticonnect --tasks ata --limit "$LIMIT" --workers 1 \
  --model gpt-4-turbo --variant no_confusion \
  --stamp "$STAMP" \
  2>&1 | tee -a "$LOG"
echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] done" | tee -a "$LOG"
