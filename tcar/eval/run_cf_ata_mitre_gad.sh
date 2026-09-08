#!/usr/bin/env bash
set -euo pipefail
cd /mnt/c/Users/SK/CTI-Chatbot
source .venv/bin/activate
export TMPDIR=/mnt/c/Users/SK/CTI-Chatbot/.tmp
mkdir -p tcar/eval_results/logs "$TMPDIR"

# Force GAD only (Soft GAD cancelled). Same diversify as RCM: dense→seed→graph→K=12.
unset ATA_PROMPT || true
export ATA_GAD=force
export RCM_GAD=force
echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] ATA Force GAD (RCM-style diversify) 20260904Tmitre_gad_ata_cc"
python -m tcar.eval.run_counterfactual \
  --benchmark cticonnect \
  --tasks ata \
  --limit 0 \
  --workers 3 \
  --model gpt-4o \
  --variant no_confusion \
  --stamp 20260904Tmitre_gad_ata_cc

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] ATA Force GAD done (Soft skipped)"
