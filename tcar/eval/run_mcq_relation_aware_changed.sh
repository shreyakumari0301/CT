#!/usr/bin/env bash
# MCQ v3 relation-aware: regenerate ONLY changed + control IDs (not full 2500).
# Requires: tcar/eval_results/mcq_v3_changed/regen_ids.txt
set -euo pipefail
cd /mnt/c/Users/SK/CTI-Chatbot
source .venv/bin/activate
mkdir -p tcar/eval_results/logs

IDS="${IDS:-tcar/eval_results/mcq_v3_changed/regen_ids.txt}"
if [[ ! -f "$IDS" ]]; then
  echo "missing $IDS — run: PYTHONPATH=. python tcar/eval/build_mcq_v3_changed_ids.py"
  exit 1
fi

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
print('export MODEL="gpt-4-turbo"')
PY
)"

unset OPENAI_BASE_URL OPENROUTER_API_KEY || true
export USE_OPENROUTER=0
export GENERATION_MODEL=gpt-4-turbo
export MODEL=gpt-4-turbo
export RCM_GAD=off ATA_GAD=off GAD_MODE=off
export MCQ_RETRIEVAL=relation_aware
export MCQ_ABSTAIN=1
export RCM_PROMPT=soft ATA_PROMPT=soft
WORKERS="${WORKERS:-1}"
LIMIT="${LIMIT:-0}"
STAMP="${STAMP:-20260908Tturbo_mcq_relation_aware_changed}"
LOG=tcar/eval_results/logs/mcq_relation_aware_changed.log

N=$(grep -cve '^[[:space:]]*$' "$IDS" || true)
echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] start MCQ relation_aware CHANGED regen n=$N stamp=$STAMP" | tee "$LOG"
PYTHONPATH=. python - <<'PY'
from utils.llm_client import resolve_model
import os
assert (os.getenv("OPENAI_API_KEY") or "").startswith("sk-proj-")
assert resolve_model("gpt-4-turbo") == "gpt-4-turbo"
print("model_ok")
from tcar.mcq_relation_aware import AttackRelationIndex
AttackRelationIndex.reset()
idx = AttackRelationIndex.get()
print("attack_bundles", [(b.domain, b.matrix_version, b.modified if hasattr(b,'modified') else b.matrix_modified) for b in idx.meta.bundles])
PY

PYTHONPATH=. python -m tcar.eval.run_counterfactual \
  --benchmark ctibench --tasks mcq --limit "$LIMIT" --workers "$WORKERS" \
  --model gpt-4-turbo --variant no_confusion \
  --stamp "$STAMP" \
  --ids-file "$IDS" \
  2>&1 | tee -a "$LOG"
echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] done" | tee -a "$LOG"
