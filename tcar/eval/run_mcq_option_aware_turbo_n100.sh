#!/usr/bin/env bash
# MCQ option-aware pilot: gpt-4-turbo, n=100 (real turbo — do not use sol override).
set -euo pipefail
cd /mnt/c/Users/SK/CTI-Chatbot
source .venv/bin/activate
mkdir -p tcar/eval_results/logs

eval "$(PYTHONPATH=. python - <<'PY'
from pathlib import Path
from dotenv import dotenv_values
vals = dotenv_values(Path(".env"))
# API key + force turbo (do not leave sol override).
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
export MCQ_RETRIEVAL=option_aware
export RCM_PROMPT=soft ATA_PROMPT=soft
WORKERS="${WORKERS:-1}"
STAMP=20260907Tturbo_mcq_option_aware_n100
LOG=tcar/eval_results/logs/mcq_option_aware_turbo_n100.log

# Sanity: resolve_model must stay turbo; key must be sk-proj
PYTHONPATH=. python - <<'PY'
from utils.llm_client import resolve_model
import os
k = (os.getenv("OPENAI_API_KEY") or "")[:12]
print("key_prefix=", k)
print("GENERATION_MODEL=", os.getenv("GENERATION_MODEL"))
print("resolve=", resolve_model("gpt-4-turbo"))
assert (os.getenv("OPENAI_API_KEY") or "").startswith("sk-proj-"), "expected sk-proj key"
assert resolve_model("gpt-4-turbo") == "gpt-4-turbo", resolve_model("gpt-4-turbo")
print("model_ok")
PY

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] start MCQ option_aware turbo n=100" | tee "$LOG"
PYTHONPATH=. python -m tcar.eval.run_counterfactual \
  --benchmark ctibench --tasks mcq --limit 100 --workers "$WORKERS" \
  --model gpt-4-turbo --variant no_confusion \
  --stamp "$STAMP" \
  2>&1 | tee -a "$LOG"

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] done" | tee -a "$LOG"
