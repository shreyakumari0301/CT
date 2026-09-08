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
export USE_OPENROUTER=0
export RCM_PROMPT=soft
export RCM_GAD=off ATA_GAD=off GAD_MODE=off
export RCM_CWE_RETRIEVAL=on RCM_RERANK=learned RCM_ORACLE=off RCM_DIVERSIFY=0

PYTHONPATH=. python - <<'PY'
from tcar.specialist_retrieval import load_learned_rcm_reranker
m = load_learned_rcm_reranker()
print("unpickle_ok", type(m).__module__, type(m).__name__)
PY

nohup env PYTHONPATH=. python -m tcar.eval.run_counterfactual \
  --benchmark ctibench --tasks rcm --limit 0 --workers 1 \
  --model "$MODEL" --variant no_confusion \
  --stamp 20260907Tsol_rcm_learned_rerank \
  > tcar/eval_results/logs/rcm_learned_rerank.log 2>&1 &
echo "restarted_pid=$!"
sleep 3
pgrep -af '20260907Tsol_rcm_learned_rerank' || echo "NOT_RUNNING"
