#!/usr/bin/env bash
# Smoke + RCM oracle top-20 stats (no LLM). Then ATE CTA fidelity CF only.
set -euo pipefail
cd /mnt/c/Users/SK/CTI-Chatbot
source .venv/bin/activate
mkdir -p tcar/eval_results/logs

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
export RCM_PROMPT=soft ATA_PROMPT=soft
WORKERS="${WORKERS:-1}"
LOG=tcar/eval_results/logs/specialist_priority.log

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] smoke" | tee -a "$LOG"
PYTHONPATH=. python -m tcar.eval._smoke_specialist 2>&1 | tee -a "$LOG"

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] RCM oracle top-20 stats" | tee -a "$LOG"
PYTHONPATH=. python -m tcar.eval.run_rcm_oracle_top20 --limit 0 --mode stats \
  2>&1 | tee -a tcar/eval_results/logs/rcm_oracle_top20_stats.log

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] train RCM specialist reranker" | tee -a "$LOG"
PYTHONPATH=. python -m tcar.eval.train_rcm_specialist_reranker --limit 0 \
  2>&1 | tee -a tcar/eval_results/logs/rcm_train_reranker.log

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] ATE CTA-fidelity CF" | tee -a "$LOG"
(
  export RCM_GAD=off ATA_GAD=off GAD_MODE=off RCM_CWE_RETRIEVAL=off
  export ATE_PROMPT=cta
  PYTHONPATH=. python -m tcar.eval.run_counterfactual \
    --benchmark ctibench --tasks ate --limit 0 --workers "$WORKERS" \
    --model "$MODEL" --variant no_confusion \
    --stamp 20260907Tsol_ate_cta_fidelity \
    2>&1 | tee -a tcar/eval_results/logs/ate_cta_fidelity.log
)

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] priority batch done" | tee -a "$LOG"
