#!/usr/bin/env bash
# Cheap RCM v2 pilot: confusion + rescues + damages + 50 neutrals.
# Variants: vanilla (baseline) | top1 advisory | parent/sibling contrast.
set -euo pipefail
cd "$(dirname "$0")/../.."
source .venv/bin/activate
set -a; [ -f .env ] && source .env; set +a
export PYTHONPATH=.
export GENERATION_MODEL="${GENERATION_MODEL:-gpt-4-turbo}"
export MODEL="$GENERATION_MODEL"
export USE_OPENROUTER=0
export GAD_MODE=off
export RCM_GAD=off

DIAG=tcar/eval_results/rcm_prompt_diagnostic
IDS="$DIAG/pilot_ids.txt"
mkdir -p "$DIAG" tcar/eval_results/logs

python tcar/eval/run_rcm_gold_prompt_diagnostic.py

if [[ ! -f "$IDS" ]]; then
  echo "missing $IDS"; exit 1
fi

run_one() {
  local stamp="$1"
  shift
  echo "=== $stamp ==="
  env "$@" python -m tcar.eval.run_counterfactual \
    --benchmark ctibench --tasks rcm --workers 1 \
    --model "$GENERATION_MODEL" --variant no_confusion \
    --stamp "$stamp" --ids-file "$IDS" --limit 0 \
    2>&1 | tee "tcar/eval_results/logs/${stamp}.log"
}

# 1) Vanilla matched baseline on pilot IDs (no catalogue override path)
run_one "20260908Tturbo_rcm_vanilla_pilot" \
  RCM_PIPELINE=default RCM_PROMPT=strict

# 2) Vanilla KB + taxonomy top-1 advisory
run_one "20260908Tturbo_rcm_advisory_top1_pilot" \
  RCM_PIPELINE=vanilla_advisory RCM_ADVISORY=top1 RCM_PROMPT=advisory

# 3) Vanilla KB + parent/sibling contrast
run_one "20260908Tturbo_rcm_advisory_contrast_pilot" \
  RCM_PIPELINE=vanilla_advisory RCM_ADVISORY=contrast RCM_PROMPT=advisory

echo "Done. Compare Acc on identical pilot IDs; scale only if advisory beats vanilla without losing corrects."
