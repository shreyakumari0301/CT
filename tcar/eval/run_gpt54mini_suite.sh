#!/usr/bin/env bash
# Launch Soft GAD + Forced RAG CF + CTA E2E on gpt-5.4-mini (cheap generator).
set -euo pipefail
cd /mnt/c/Users/SK/CTI-Chatbot
source .venv/bin/activate
mkdir -p tcar/eval_results/logs eval_results "CTICONNECT benchmark/eval_results" .tmp
export TMPDIR=/mnt/c/Users/SK/CTI-Chatbot/.tmp

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

export GENERATION_MODEL="${GENERATION_MODEL:-gpt-5.4-mini}"
export MODEL="$GENERATION_MODEL"
export CTICONNECT_MODEL="$GENERATION_MODEL"
unset OPENAI_BASE_URL OPENROUTER_API_KEY OPENROUTER_REASONING OPENROUTER_REASONING_EFFORT || true
export USE_OPENROUTER=0
export RCM_PROMPT=soft ATA_PROMPT=soft
export ATA_RETRIEVAL=behavior

WORKERS="${WORKERS:-1}"
STAMP_SOFT="${STAMP_SOFT:-20260907Tgpt54mini_soft_gad_cb}"
STAMP_SOFT_CC="${STAMP_SOFT_CC:-20260907Tgpt54mini_soft_gad_cc}"
STAMP_FORCED="${STAMP_FORCED:-20260907Tgpt54mini_forced_rag_cb}"
STAMP_FORCED_CC="${STAMP_FORCED_CC:-20260907Tgpt54mini_forced_rag_cc}"
STAMP_CTA_CC="${STAMP_CTA_CC:-20260907Tgpt54mini_cta_port}"
LOG="tcar/eval_results/logs/gpt54mini_launch.log"

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] LAUNCH model=${MODEL} workers=${WORKERS}" | tee -a "$LOG"

# Smoke one completion
PYTHONPATH=. python - <<'PY' | tee -a "$LOG"
from utils.llm_client import get_openai_client, chat_completion_kwargs
import os
client = get_openai_client()
model = os.getenv("GENERATION_MODEL", "gpt-5.4-mini")
r = client.chat.completions.create(
    messages=[{"role": "user", "content": "Reply with exactly: OK"}],
    **chat_completion_kwargs(model, max_tokens=16, temperature=0.0),
)
print("SMOKE", model, repr((r.choices[0].message.content or "")[:40]))
PY

launch_cf() {
  local mode="$1" bench="$2" task="$3" stamp="$4"
  local logfile="tcar/eval_results/logs/${mode}_${bench}_${task}.log"
  (
    if [[ "$mode" == "soft_gad" ]]; then
      export RCM_GAD=force ATA_GAD=force GAD_MODE=soft
      unset RCM_CWE_RETRIEVAL || true
    else
      export RCM_GAD=off ATA_GAD=off GAD_MODE=off RCM_CWE_RETRIEVAL=off
    fi
    echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] RUN ${mode} ${bench}/${task}" | tee -a "$LOG" "$logfile"
    PYTHONPATH=. python -m tcar.eval.run_counterfactual \
      --benchmark "$bench" \
      --tasks "$task" \
      --limit 0 \
      --workers "$WORKERS" \
      --model "$MODEL" \
      --variant no_confusion \
      --stamp "$stamp" \
      2>&1 | tee -a "$logfile"
    echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] DONE ${mode} ${bench}/${task}" | tee -a "$LOG" "$logfile"
  ) &
  echo "launched ${mode} ${bench}/${task} pid=$!" | tee -a "$LOG"
}

# Soft GAD — priority VSP/ATA + full CTIBench/Connect
for t in vsp mcq rcm ate; do
  launch_cf soft_gad ctibench "$t" "$STAMP_SOFT"
done
for t in ata rcm; do
  launch_cf soft_gad cticonnect "$t" "$STAMP_SOFT_CC"
done

# Forced RAG ablation (for CB vs Forced vs Soft on same mini generator)
for t in vsp mcq rcm ate; do
  launch_cf forced_rag ctibench "$t" "$STAMP_FORCED"
done
for t in ata rcm; do
  launch_cf forced_rag cticonnect "$t" "$STAMP_FORCED_CC"
done

# CTA-RAG E2E (full system, not CF)
nohup env \
  GENERATION_MODEL="$MODEL" \
  CTICONNECT_MODEL="$MODEL" \
  USE_OPENROUTER=0 \
  MODE=both \
  TASKS=ate,rcm,mcq,vsp \
  WORKERS=1 \
  SKIP_CONNECT=0 \
  CONNECT_STAMP="$STAMP_CTA_CC" \
  bash tcar/eval/run_gpt56sol_cta_e2e.sh \
  > tcar/eval_results/logs/cta_e2e_gpt54mini_nohup.out 2>&1 &
echo "launched CTA E2E pid=$!" | tee -a "$LOG"

# TAA non-gated closed_book + cta (no gated)
(
  export RCM_GAD=force ATA_GAD=force GAD_MODE=soft RCM_PROMPT=soft ATA_PROMPT=soft
  unset RCM_CWE_RETRIEVAL || true
  echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] TAA closed_book mini" | tee -a "$LOG"
  PYTHONPATH=. python -u -m eval.run_taa --mode closed_book --limit 0 --workers 1 \
    --out-dir eval_results --stamp 20260907Tgpt54mini_taa_closed_book
  echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] TAA cta mini" | tee -a "$LOG"
  PYTHONPATH=. python -u -m eval.run_taa --mode cta --limit 0 --workers 1 \
    --out-dir eval_results --stamp 20260907Tgpt54mini_taa_cta
  echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] DONE TAA mini" | tee -a "$LOG"
) > tcar/eval_results/logs/taa_gpt54mini_nongated.log 2>&1 &
echo "launched TAA pid=$!" | tee -a "$LOG"

sleep 4
pgrep -af "gpt-5.4-mini|gpt54mini|20260907Tgpt54mini|run_ctibench|run_counterfactual|run_taa" | head -40 | tee -a "$LOG"
echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] All gpt-5.4-mini jobs launched" | tee -a "$LOG"
