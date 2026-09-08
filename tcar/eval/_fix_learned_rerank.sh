#!/usr/bin/env bash
# Fix learned RCM reranker pickle + restart that CF job only.
set -euo pipefail
cd /mnt/c/Users/SK/CTI-Chatbot
source .venv/bin/activate

# Kill only the broken learned-rerank CF
pkill -f 'stamp 20260907Tsol_rcm_learned_rerank' || true
sleep 1

rm -f tcar/eval_results/counterfactual_ctibench_rcm_20260907Tsol_rcm_learned_rerank.jsonl
rm -f tcar/eval_results/counterfactual_ctibench_rcm_20260907Tsol_rcm_learned_rerank.summary.json

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] retrain reranker"
PYTHONPATH=. python -m tcar.eval.train_rcm_specialist_reranker --limit 0 \
  2>&1 | tee -a tcar/eval_results/logs/rcm_train_reranker.log

# smoke unpickle
PYTHONPATH=. python - <<'PY'
from tcar.specialist_retrieval import load_learned_rcm_reranker
m = load_learned_rcm_reranker()
print("unpickle_ok", type(m).__module__, type(m).__name__, m.weights[:2])
PY

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

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] restart learned RCM CF"
nohup env PYTHONPATH=. python -m tcar.eval.run_counterfactual \
  --benchmark ctibench --tasks rcm --limit 0 --workers 1 \
  --model "$MODEL" --variant no_confusion \
  --stamp 20260907Tsol_rcm_learned_rerank \
  > tcar/eval_results/logs/rcm_learned_rerank.log 2>&1 &
echo "pid=$!"
