#!/usr/bin/env bash
cd /mnt/c/Users/SK/CTI-Chatbot
source .venv/bin/activate
echo PROCS:
pgrep -af 'run_counterfactual' || true
echo
PYTHONPATH=. python - <<'PY'
from pathlib import Path
p = Path("CTICONNECT data/data/entity_attribution/ata.jsonl")
n = sum(1 for _ in p.open(encoding="utf-8") if _.strip())
print("ata_full_dataset_n", n)
print("remaining_approx", n - 50)
PY
echo
tail -c 400 tcar/eval_results/logs/ata_grounded_v2_turbo_full.log 2>/dev/null | tr '\r' '\n' | tail -8
wc -l tcar/eval_results/counterfactual_cticonnect_ata_20260908Tturbo_ata_grounded_v2_full.jsonl 2>/dev/null
