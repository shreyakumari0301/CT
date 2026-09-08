#!/usr/bin/env bash
# CTIBench RCM evidence-source ablation (plan: CB / memory / CWE / combined).
# Uses Forced RAG counterfactual harness; only RCM_CWE_RETRIEVAL + stamp differ.
set -euo pipefail
cd /mnt/c/Users/SK/CTI-Chatbot
source .venv/bin/activate

export TMPDIR=/mnt/c/Users/SK/CTI-Chatbot/.tmp
mkdir -p tcar/eval_results/logs "$TMPDIR"
LOG="tcar/eval_results/logs/gpt56sol_rcm_source_ablation.log"
MODEL="${MODEL:-gpt-5.6-sol}"
WORKERS="${WORKERS:-2}"
BASE_STAMP="${BASE_STAMP:-20260906Tgpt56sol_rcm_src}"

eval "$(PYTHONPATH=. python - <<'PY'
from pathlib import Path
from dotenv import dotenv_values
vals = dotenv_values(Path(".env"))
keep = ["OPENAI_API_KEY", "OPENAI_BASE_URL", "GENERATION_MODEL", "USE_OPENROUTER"]
for k in keep:
    v = vals.get(k)
    if v is None or str(v).strip() == "":
        continue
    v = str(v).strip().replace("\\", "\\\\").replace('"', '\\"')
    print(f'export {k}="{v}"')
PY
)"

export GENERATION_MODEL="${GENERATION_MODEL:-$MODEL}"
export MODEL="${GENERATION_MODEL}"
unset OPENAI_BASE_URL OPENROUTER_API_KEY OPENROUTER_REASONING OPENROUTER_REASONING_EFFORT || true
export USE_OPENROUTER=0
export RCM_PROMPT=soft
export RCM_GAD=off ATA_GAD=off GAD_MODE=off

run_variant () {
  local name="$1"
  local cwe="$2"
  local stamp="${BASE_STAMP}_${name}"
  local logfile="tcar/eval_results/logs/rcm_src_${name}.log"
  echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] RCM source=${name} CWE=${cwe} stamp=${stamp}" | tee -a "$LOG" "$logfile"
  (
    export RCM_CWE_RETRIEVAL="$cwe"
    # memory always on via retrieve_rcm_context; cwe toggled by env
    python -m tcar.eval.run_counterfactual \
      --benchmark ctibench \
      --tasks rcm \
      --limit 0 \
      --workers "$WORKERS" \
      --model "$MODEL" \
      --variant no_confusion \
      --stamp "$stamp" \
      2>&1 | tee -a "$logfile"
    echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] DONE ${name}" | tee -a "$LOG" "$logfile"
  ) &
  echo "launched ${name} pid=$!" | tee -a "$LOG"
}

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] RCM evidence-source ablation model=${MODEL}" | tee -a "$LOG"

# Memory-only (current Forced RAG default)
run_variant mem_only off

# Memory + CWE catalogue
run_variant mem_plus_cwe on

# Note: CWE-only would need a code path that skips mem KB; not launched until implemented.
# CB is already the closed-book branch inside each counterfactual run.

wait || true
echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] RCM source ablation finish" | tee -a "$LOG"
echo "Compare CB vs RAG Acc within each stamp; then oracle max(CB,RAG) and mem vs mem+cwe RAG." | tee -a "$LOG"
