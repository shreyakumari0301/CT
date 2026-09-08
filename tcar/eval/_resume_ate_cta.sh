#!/usr/bin/env bash
set -euo pipefail
cd /mnt/c/Users/SK/CTI-Chatbot
source .venv/bin/activate
eval "$(PYTHONPATH=. python - <<'PY'
from pathlib import Path
from dotenv import dotenv_values
vals = dotenv_values(Path(".env"))
for k in ["OPENAI_API_KEY", "GENERATION_MODEL", "USE_OPENROUTER"]:
    v = vals.get(k)
    if v is None or str(v).strip() == "":
        continue
    v = str(v).strip().replace("\\", "\\\\").replace('"', '\\"')
    print(f'export {k}="{v}"')
PY
)"
export GENERATION_MODEL="${GENERATION_MODEL:-gpt-5.6-sol}"
export MODEL="$GENERATION_MODEL"
unset OPENAI_BASE_URL OPENROUTER_API_KEY || true
export USE_OPENROUTER=0 RCM_GAD=off ATA_GAD=off GAD_MODE=off ATE_PROMPT=cta
# Resume retries empty_ate_prediction rows for same stamp
nohup env PYTHONPATH=. python -m tcar.eval.run_counterfactual \
  --benchmark ctibench --tasks ate --limit 0 --workers 1 \
  --model "$MODEL" --variant no_confusion \
  --stamp 20260907Tsol_ate_cta_fidelity \
  > tcar/eval_results/logs/ate_cta_fidelity_resume.log 2>&1 &
echo "ate_resume_pid=$!"
