#!/usr/bin/env bash
# Full CTIConnect ATA grounded v2 — resume from n=50 completed IDs.
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
print('export MODEL="gpt-4-turbo"')
PY
)"

unset OPENAI_BASE_URL OPENROUTER_API_KEY || true
export USE_OPENROUTER=0
export GENERATION_MODEL=gpt-4-turbo
export MODEL=gpt-4-turbo
export RCM_GAD=off ATA_GAD=off GAD_MODE=off
export ATA_RETRIEVAL=grounded
export ATA_PER_BEHAVIOR_K=20
export ATA_GROUNDED_K=8
export ATA_PROMPT=soft

STAMP="${STAMP:-20260908Tturbo_ata_grounded_v2_full}"
SRC=tcar/eval_results/counterfactual_cticonnect_ata_20260908Tturbo_ata_grounded_v2_n50.jsonl
DST=tcar/eval_results/counterfactual_cticonnect_ata_${STAMP}.jsonl
LOG=tcar/eval_results/logs/ata_grounded_v2_turbo_full.log

PYTHONPATH=. python - <<PY
import json
from pathlib import Path
src, dst = Path("$SRC"), Path("$DST")
assert src.exists(), src
best = {}
for line in src.read_text(encoding="utf-8").splitlines():
    if not line.strip():
        continue
    row = json.loads(line)
    rid = str(row.get("id") or "")
    if rid:
        best[rid] = row
existing = {}
if dst.exists():
    for line in dst.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        rid = str(row.get("id") or "")
        if rid:
            existing[rid] = row
merged = {**best, **existing}
if not dst.exists() or len(existing) < len(best):
    with dst.open("w", encoding="utf-8") as f:
        for rid in sorted(merged, key=lambda x: (0, int(x.split("-")[1])) if x.startswith("ata-") and x.split("-")[-1].isdigit() else (1, x)):
            f.write(json.dumps(merged[rid], ensure_ascii=False) + "\n")
    print(f"seeded {dst.name} with {len(merged)} rows (n50={len(best)}, prior={len(existing)})")
else:
    print(f"resume {dst.name} already has {len(existing)} rows")
PY

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] start ATA grounded v2 FULL" | tee -a "$LOG"
PYTHONPATH=. python -m tcar.eval.run_counterfactual \
  --benchmark cticonnect --tasks ata --limit 0 --workers 1 \
  --model gpt-4-turbo --variant no_confusion \
  --stamp "$STAMP" \
  2>&1 | tee -a "$LOG"
echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] done" | tee -a "$LOG"
