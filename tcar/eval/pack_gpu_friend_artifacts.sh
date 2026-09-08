#!/usr/bin/env bash
# Pack only the artifacts a GPU friend needs for RCM/VSP pilots + MCQ merge.
# Run from repo root before push / rsync. Does NOT include .env.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"
OUT="${1:-tcar/eval_results/_gpu_friend_bundle}"
mkdir -p "$OUT"

copy_one() {
  local src="$1"
  [[ -f "$src" ]] || { echo "SKIP missing: $src"; return; }
  local dest="$OUT/$(basename "$src")"
  # keep relative path structure for known dirs
  if [[ "$src" == tcar/eval_results/* ]]; then
    dest="$OUT/${src#tcar/eval_results/}"
    mkdir -p "$(dirname "$dest")"
  fi
  cp -a "$src" "$dest"
  echo "  + $src"
}

echo "Bundling essential eval jsonl → $OUT"
copy_one tcar/eval_results/counterfactual_ctibench_rcm_20260908Tturbo_rcm_hybrid_n200.jsonl
copy_one tcar/eval_results/counterfactual_ctibench_rcm_20260902Ttask_prompts_cb.jsonl
copy_one tcar/eval_results/counterfactual_ctibench_vsp_20260908Tturbo_vsp_structured_n75.jsonl
copy_one tcar/eval_results/counterfactual_ctibench_vsp_20260907Tsol_vsp_metric_wise.jsonl
copy_one tcar/eval_results/counterfactual_ctibench_mcq_20260907Tturbo_mcq_option_aware_v2.jsonl
# MCQ v3 in-progress / final regen (optional)
copy_one tcar/eval_results/counterfactual_ctibench_mcq_20260908Tturbo_mcq_relation_aware_changed.jsonl
if [[ -d tcar/eval_results/mcq_v3_changed ]]; then
  mkdir -p "$OUT/mcq_v3_changed"
  cp -a tcar/eval_results/mcq_v3_changed/manifest.csv "$OUT/mcq_v3_changed/" 2>/dev/null || true
  cp -a tcar/eval_results/mcq_v3_changed/regen_ids.txt "$OUT/mcq_v3_changed/" 2>/dev/null || true
  cp -a tcar/eval_results/mcq_v3_changed/*.json "$OUT/mcq_v3_changed/" 2>/dev/null || true
  echo "  + mcq_v3_changed/{manifest,regen_ids,json}"
fi

du -sh "$OUT"
echo "Friend can place these under tcar/eval_results/ after clone if not in git."
