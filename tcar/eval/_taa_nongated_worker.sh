#!/usr/bin/env bash
set -euo pipefail
cd /mnt/c/Users/SK/CTI-Chatbot
source .venv/bin/activate

eval "$(PYTHONPATH=. python - <<'PY'
from pathlib import Path
from dotenv import dotenv_values
vals = dotenv_values(Path(".env"))
for k in ["OPENAI_API_KEY", "GENERATION_MODEL"]:
    v = vals.get(k)
    if v is None or str(v).strip() == "":
        continue
    v = str(v).strip().replace("\\", "\\\\").replace('"', '\\"')
    print(f'export {k}="{v}"')
PY
)"

unset OPENAI_BASE_URL OPENROUTER_API_KEY OPENROUTER_REASONING OPENROUTER_REASONING_EFFORT || true
export USE_OPENROUTER=0
export GENERATION_MODEL="${GENERATION_MODEL:-gpt-5.6-sol}"
export RCM_GAD=force ATA_GAD=force GAD_MODE=soft
export RCM_PROMPT=soft ATA_PROMPT=soft
unset RCM_CWE_RETRIEVAL || true

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] START TAA closed_book model=${GENERATION_MODEL}"
PYTHONPATH=. python -u -m eval.run_taa \
  --mode closed_book \
  --limit 0 \
  --workers 1 \
  --out-dir eval_results \
  --stamp 20260906Tgpt56sol_soft_gad_taa_closed_book

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] START TAA cta"
PYTHONPATH=. python -u -m eval.run_taa \
  --mode cta \
  --limit 0 \
  --workers 1 \
  --out-dir eval_results \
  --stamp 20260906Tgpt56sol_soft_gad_taa_cta

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] DONE TAA non-gated"
