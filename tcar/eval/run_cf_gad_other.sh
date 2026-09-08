#!/usr/bin/env bash
set -euo pipefail
cd /mnt/c/Users/SK/CTI-Chatbot
source .venv/bin/activate
export TMPDIR=/mnt/c/Users/SK/CTI-Chatbot/.tmp
mkdir -p tcar/eval_results/logs "$TMPDIR"

# Force GAD only (Soft GAD cancelled).
export GAD_MODE=force
echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] Starting CTIBench ATE/MCQ/VSP Force GAD stamp=20260904Tgad_other_cb"
python -m tcar.eval.run_counterfactual \
  --benchmark ctibench \
  --tasks ate,mcq,vsp \
  --limit 0 \
  --workers 3 \
  --model gpt-4-turbo \
  --variant no_confusion \
  --stamp 20260904Tgad_other_cb
echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] Done Force GAD (Soft skipped)"
