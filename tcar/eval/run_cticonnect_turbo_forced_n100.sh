#!/usr/bin/env bash
# CTIConnect turbo Forced RAG pilot n=100 (RCM+ATA) — parallel to CTIBench MCQ option-aware.
# Note: CTIConnect has no MCQ; option_aware does not apply here.
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
print('export MODEL="gpt-4-turbo"')
PY
)"

unset OPENAI_BASE_URL OPENROUTER_API_KEY || true
export USE_OPENROUTER=0
export GENERATION_MODEL=gpt-4-turbo
export MODEL=gpt-4-turbo
export RCM_GAD=off ATA_GAD=off GAD_MODE=off
export RCM_PROMPT=soft ATA_PROMPT=soft
# Connect default behavior retrieve for ATA; keep Forced (no Soft GAD)
export ATA_RETRIEVAL=behavior
export ATA_ABSTAIN=0
WORKERS="${WORKERS:-1}"
STAMP=20260907Tturbo_forced_cc_n100
LOG=tcar/eval_results/logs/cticonnect_turbo_forced_n100.log

PYTHONPATH=. python - <<'PY'
from utils.llm_client import resolve_model
import os
print("key_prefix=", (os.getenv("OPENAI_API_KEY") or "")[:12])
print("resolve=", resolve_model("gpt-4-turbo"))
assert (os.getenv("OPENAI_API_KEY") or "").startswith("sk-proj-")
assert resolve_model("gpt-4-turbo") == "gpt-4-turbo"
print("model_ok")
PY

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] start CTIConnect turbo Forced n=100 rcm,ata" | tee "$LOG"
PYTHONPATH=. python -m tcar.eval.run_counterfactual \
  --benchmark cticonnect --tasks rcm,ata --limit 100 --workers "$WORKERS" \
  --model gpt-4-turbo --variant no_confusion \
  --stamp "$STAMP" \
  2>&1 | tee -a "$LOG"

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] done" | tee -a "$LOG"
