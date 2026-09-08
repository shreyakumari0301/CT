#!/usr/bin/env bash
cd /mnt/c/Users/SK/CTI-Chatbot
# Keep MCQ; start ATA full
nohup bash tcar/eval/run_ata_grounded_v2_turbo_full.sh \
  > tcar/eval_results/logs/ata_grounded_v2_turbo_full.nohup.out 2>&1 &
echo ATA_FULL_PID=$!
sleep 18
pgrep -af 'run_counterfactual|ata_grounded_v2_turbo_full' | head -10
echo '---'
tail -n 30 tcar/eval_results/logs/ata_grounded_v2_turbo_full.nohup.out 2>/dev/null || true
# dataset size
PYTHONPATH=. python - <<'PY'
from pathlib import Path
p = Path("CTICONNECT data/data/entity_attribution/ata.jsonl")
print("ata_dataset_n", sum(1 for _ in p.open(encoding="utf-8") if _.strip()))
PY
