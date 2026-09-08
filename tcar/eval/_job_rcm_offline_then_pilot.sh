#!/usr/bin/env bash
set -euo pipefail
cd /mnt/c/Users/SK/CTI-Chatbot
source .venv/bin/activate
export USE_OPENROUTER=0 GENERATION_MODEL=gpt-4-turbo MODEL=gpt-4-turbo
eval "$(PYTHONPATH=. python - <<'PY'
from pathlib import Path
from dotenv import dotenv_values
vals = dotenv_values(Path('.env'))
for k in ['OPENAI_API_KEY']:
    v = vals.get(k)
    if v:
        v = str(v).strip().replace('\\', '\\\\').replace('"', '\\"')
        print(f'export {k}="{v}"')
PY
)"
PYTHONPATH=. python tcar/eval/run_rcm_hybrid_offline_audit.py \
  2>&1 | tee tcar/eval_results/logs/rcm_hybrid_offline_audit.log
PYTHONPATH=. python tcar/eval/_maybe_start_rcm_hybrid_pilot.py
