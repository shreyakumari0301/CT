#!/usr/bin/env bash
# Resume MCQ option-aware turbo for the REST of CTIBench (after n=100).
# Copies completed mcq-0..99 into the full stamp, then --limit 0 with resume.
set -euo pipefail
cd /mnt/c/Users/SK/CTI-Chatbot
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
export RCM_PROMPT=soft ATA_PROMPT=soft
WORKERS="${WORKERS:-1}"
STAMP="${STAMP:-20260907Tturbo_mcq_option_aware_full}"
SRC=tcar/eval_results/counterfactual_ctibench_mcq_20260907Tturbo_mcq_option_aware_n100.jsonl
DST=tcar/eval_results/counterfactual_ctibench_mcq_${STAMP}.jsonl
LOG=tcar/eval_results/logs/mcq_option_aware_turbo_full.log

PYTHONPATH=. python - <<PY
import json
from pathlib import Path
src = Path("$SRC")
dst = Path("$DST")
assert src.exists(), src
# Dedupe by id (n100 file had 200 lines / 100 unique)
best = {}
for line in src.read_text(encoding="utf-8").splitlines():
    if not line.strip():
        continue
    row = json.loads(line)
    rid = str(row.get("id") or "")
    if not rid:
        continue
    if rid not in best or (best[rid].get("error") and not row.get("error")):
        best[rid] = row
# Seed full stamp if missing or smaller
existing = {}
if dst.exists():
    for line in dst.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        rid = str(row.get("id") or "")
        if rid:
            existing[rid] = row
merged = {**best, **existing}  # prefer any newer full-run rows
# Keep seed order: write best then any extra
out_ids = sorted(merged.keys(), key=lambda x: (0, int(x.split("-")[1])) if x.startswith("mcq-") and x.split("-")[1].isdigit() else (1, x))
if not dst.exists() or len(existing) < len(best):
    with dst.open("w", encoding="utf-8") as f:
        for rid in out_ids:
            f.write(json.dumps(merged[rid], ensure_ascii=False) + "\n")
    print(f"seeded {dst} with {len(out_ids)} rows (from n100={len(best)}, prior_full={len(existing)})")
else:
    print(f"resume file already has {len(existing)} rows; n100 unique={len(best)}")
PY

PYTHONPATH=. python - <<'PY'
from utils.llm_client import resolve_model
import os
assert (os.getenv("OPENAI_API_KEY") or "").startswith("sk-proj-"), "expected sk-proj key"
assert resolve_model("gpt-4-turbo") == "gpt-4-turbo", resolve_model("gpt-4-turbo")
print("model_ok", resolve_model("gpt-4-turbo"))
PY

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] resume MCQ option_aware turbo FULL (skip done ids)" | tee -a "$LOG"
PYTHONPATH=. python -m tcar.eval.run_counterfactual \
  --benchmark ctibench --tasks mcq --limit 0 --workers "$WORKERS" \
  --model gpt-4-turbo --variant no_confusion \
  --stamp "$STAMP" \
  2>&1 | tee -a "$LOG"
echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] done" | tee -a "$LOG"
