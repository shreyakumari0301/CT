#!/usr/bin/env bash
# ATA grounded v4 full: v3 retrieval + neighbour contrast + damage-aware abstain→CB.
set -euo pipefail
cd /mnt/c/Users/SK/CTI-Chatbot
source .venv/bin/activate
mkdir -p tcar/eval_results/logs

eval "$(PYTHONPATH=. python - <<'PY'
from pathlib import Path
from dotenv import dotenv_values
vals = dotenv_values(Path('.env'))
for k in ['OPENAI_API_KEY', 'USE_OPENROUTER']:
    v = vals.get(k)
    if v is None or str(v).strip() == '':
        continue
    v = str(v).strip().replace('\\', '\\\\').replace('"', '\\"')
    print(f'export {k}="{v}"')
print('export GENERATION_MODEL="gpt-4-turbo"')
PY
)"

unset OPENAI_BASE_URL OPENROUTER_API_KEY || true
export USE_OPENROUTER=0 GENERATION_MODEL=gpt-4-turbo MODEL=gpt-4-turbo
export RCM_GAD=off ATA_GAD=off GAD_MODE=off
export ATA_RETRIEVAL=grounded
export ATA_PER_BEHAVIOR_K=20
export ATA_GROUNDED_K=20
export ATA_PROMPT=soft
export ATA_DAMAGE_GATE=1
STAMP="${STAMP:-20260908Tturbo_ata_grounded_v4_full}"
LOG=tcar/eval_results/logs/ata_grounded_v4_turbo_full.log

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] start ATA grounded v4 FULL (damage gate on)" | tee "$LOG"
PYTHONPATH=. python -m tcar.eval.run_counterfactual \
  --benchmark cticonnect --tasks ata --limit 0 --workers 1 \
  --model gpt-4-turbo --variant no_confusion \
  --stamp "$STAMP" \
  2>&1 | tee -a "$LOG"
echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] done" | tee -a "$LOG"
