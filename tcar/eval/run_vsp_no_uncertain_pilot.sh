#!/usr/bin/env bash
# VSP structured re-pilot on the same 75 IDs (no uncertain defaults).
# Variants: off / high_precision consistency. Do not expand to 200+ until near Vanilla.
set -euo pipefail
cd "$(dirname "$0")/../.."
source .venv/bin/activate
set -a; [ -f .env ] && source .env; set +a
export PYTHONPATH=.
export GENERATION_MODEL="${GENERATION_MODEL:-gpt-4-turbo}"
export MODEL="$GENERATION_MODEL"
export USE_OPENROUTER=0
export GAD_MODE=off
export VSP_RETRIEVAL=structured

IDS=tcar/eval_results/_vsp_structured_pilot_ids.txt
mkdir -p tcar/eval_results/logs

# Rebuild ID list from prior structured run if present
python - <<'PY'
import json
from pathlib import Path
root = Path("tcar/eval_results")
src = root / "counterfactual_ctibench_vsp_20260908Tturbo_vsp_structured_n75.jsonl"
alt = root / "counterfactual_ctibench_vsp_20260907Tsol_vsp_metric_wise.jsonl"
ids = []
for p in (src, alt):
    if not p.exists():
        continue
    for line in p.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        r = json.loads(line)
        if r.get("error"):
            continue
        ids.append(r["id"])
    if ids:
        break
out = root / "_vsp_structured_pilot_ids.txt"
out.write_text("\n".join(dict.fromkeys(ids)) + ("\n" if ids else ""), encoding="utf-8")
print(f"ids={len(ids)} -> {out}")
PY

# Offline ablation on stored raw facts (no LLM)
python tcar/eval/run_vsp_consistency_ablation.py || true

run_one() {
  local stamp="$1"
  local cons="$2"
  echo "=== $stamp (VSP_CONSISTENCY=$cons) ==="
  VSP_CONSISTENCY="$cons" python -m tcar.eval.run_counterfactual \
    --benchmark ctibench --tasks vsp --workers 1 \
    --model "$GENERATION_MODEL" --variant no_confusion \
    --stamp "$stamp" --ids-file "$IDS" --limit 0 \
    2>&1 | tee "tcar/eval_results/logs/${stamp}.log"
}

# New schema: always-commit value + confidence; no uncertain→defaults
run_one "20260908Tturbo_vsp_struct_no_unc_hp_n75" "high_precision"
run_one "20260908Tturbo_vsp_struct_no_unc_off_n75" "off"

echo "Compare vs Vanilla Exact 25.3% / MAD_base 0.93 on same 75. Scale only if near that."
