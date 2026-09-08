#!/usr/bin/env bash
# Kill gated TAA; restart Soft GAD TAA without any gate (closed_book + cta RAG).
set -euo pipefail
cd /mnt/c/Users/SK/CTI-Chatbot
source .venv/bin/activate

LOGDIR=tcar/eval_results/logs
mkdir -p "$LOGDIR" eval_results

# Stop gated TAA only
pkill -f 'eval.run_taa --mode gated' 2>/dev/null || true
pkill -f 'run_taa --mode gated' 2>/dev/null || true
sleep 2

eval "$(PYTHONPATH=. python - <<'PY'
from pathlib import Path
from dotenv import dotenv_values
vals = dotenv_values(Path(".env"))
for k in ["OPENAI_API_KEY", "GENERATION_MODEL", "USE_OPENROUTER"]:
    v = vals.get(k)
    if v is None or str(v).strip() == "":
        continue
    v = str(v).strip().replace("\\", "\\\\").replace('"', '\\"')
    print(f'export {k}="{v}"')
PY
)"

export GENERATION_MODEL="${GENERATION_MODEL:-gpt-5.6-sol}"
unset OPENAI_BASE_URL OPENROUTER_API_KEY OPENROUTER_REASONING OPENROUTER_REASONING_EFFORT || true
export USE_OPENROUTER=0
export RCM_GAD=force ATA_GAD=force GAD_MODE=soft
export RCM_PROMPT=soft ATA_PROMPT=soft
unset RCM_CWE_RETRIEVAL || true

WORKERS="${WORKERS:-1}"
STAMP="${STAMP_TAA:-20260906Tgpt56sol_soft_gad_taa}"
LOG="$LOGDIR/soft_gad_taa_nongated.log"

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] TAA Soft GAD NON-GATED stamp=${STAMP} modes=closed_book,cta" | tee -a "$LOG"

# closed_book then cta (always-retrieve / Soft-GAD-style), no gated / candidate_first gate
(
  for mode in closed_book cta; do
    echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] RUN TAA mode=${mode}" | tee -a "$LOG"
    PYTHONPATH=. python -u -m eval.run_taa \
      --mode "$mode" \
      --limit 0 \
      --workers "$WORKERS" \
      --out-dir eval_results \
      --stamp "${STAMP}_${mode}" \
      2>&1 | tee -a "$LOG"
    echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] DONE TAA mode=${mode}" | tee -a "$LOG"
  done
) &
echo "launched TAA non-gated pid=$!"
pgrep -af 'eval.run_taa' || true
