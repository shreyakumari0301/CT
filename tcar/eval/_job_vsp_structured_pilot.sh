#!/usr/bin/env bash
set -euo pipefail
cd /mnt/c/Users/SK/CTI-Chatbot
source .venv/bin/activate
export GAD_MODE=off VSP_RETRIEVAL=structured
export GENERATION_MODEL=gpt-4-turbo MODEL=gpt-4-turbo USE_OPENROUTER=0
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
PYTHONPATH=. python tcar/eval/run_vsp_structured_on_ids.py \
  2>&1 | tee tcar/eval_results/logs/vsp_structured_n75.log
