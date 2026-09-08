#!/usr/bin/env bash
set -euo pipefail
cd /mnt/c/Users/SK/CTI-Chatbot
pkill -f 'run_mcq_option_aware_turbo_v2' 2>/dev/null || true
pkill -f 'turbo_mcq_option_aware_v2' 2>/dev/null || true
sleep 2
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
export MCQ_RETRIEVAL=option_aware
export MCQ_ABSTAIN=1
STAMP=20260907Tturbo_mcq_option_aware_v2
LOG=tcar/eval_results/logs/mcq_option_aware_turbo_v2.log

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] direct start v2" | tee "$LOG"
echo "key=$(echo $OPENAI_API_KEY | cut -c1-12) model=$GENERATION_MODEL" | tee -a "$LOG"

# Fast smoke (no heavy imports of counterfactual)
PYTHONPATH=. python tcar/eval/_check_mcq_parse_fixed.py | tee -a "$LOG"

nohup env PYTHONPATH=. \
  USE_OPENROUTER=0 GENERATION_MODEL=gpt-4-turbo MODEL=gpt-4-turbo \
  RCM_GAD=off ATA_GAD=off GAD_MODE=off \
  MCQ_RETRIEVAL=option_aware MCQ_ABSTAIN=1 \
  OPENAI_API_KEY="$OPENAI_API_KEY" \
  python -m tcar.eval.run_counterfactual \
    --benchmark ctibench --tasks mcq --limit 0 --workers 1 \
    --model gpt-4-turbo --variant no_confusion \
    --stamp "$STAMP" \
  >> "$LOG" 2>&1 &
echo CF_PID=$!
sleep 25
pgrep -af 'run_counterfactual' || echo 'no cf'
tail -n 40 "$LOG"
