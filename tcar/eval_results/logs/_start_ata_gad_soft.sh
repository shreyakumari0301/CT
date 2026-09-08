#!/usr/bin/env bash
# CTIConnect ATA only (not CTIBench ATE). Two stamps: gad k=12, then soft advisory.
set -euo pipefail
cd /mnt/c/Users/SK/CTI-Chatbot
mkdir -p tcar/eval_results/logs
set -a
[ -f .env ] && . ./.env
set +a
export PYTHONPATH=/mnt/c/Users/SK/CTI-Chatbot
export PYTHONUNBUFFERED=1

# 1) GAD-style: MITRE catalogue k=12, default ATA prompt
unset ATA_PROMPT || true
setsid .venv/bin/python -m tcar.eval.run_counterfactual \
  --benchmark cticonnect --tasks ata --limit 0 --workers 3 \
  --model gpt-4o --variant no_confusion \
  --stamp 20260903Tgad_ata_cc --no-resume \
  >> tcar/eval_results/logs/cf_cticonnect_20260903Tgad_ata_cc.log 2>&1 < /dev/null &
echo "GAD_ATA_PID=$!"

# 2) Soft GAD-style: same k=12 + text-first advisory prompt
export ATA_PROMPT=soft
setsid .venv/bin/python -m tcar.eval.run_counterfactual \
  --benchmark cticonnect --tasks ata --limit 0 --workers 3 \
  --model gpt-4o --variant no_confusion \
  --stamp 20260903Tsoft_gad_ata_cc --no-resume \
  >> tcar/eval_results/logs/cf_cticonnect_20260903Tsoft_gad_ata_cc.log 2>&1 < /dev/null &
echo "SOFT_ATA_PID=$!"

sleep 3
pgrep -af 'gad_ata_cc|soft_gad_ata|other_tasks' || true
