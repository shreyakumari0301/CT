#!/usr/bin/env bash
# Resume gpt-5.6-sol CF + Soft GAD + baselines with low concurrency (avoid 402 in-flight).
# At most MAX_JOBS run at once; each job uses WORKERS threads.
set -euo pipefail
cd /mnt/c/Users/SK/CTI-Chatbot
source .venv/bin/activate

export TMPDIR=/mnt/c/Users/SK/CTI-Chatbot/.tmp
mkdir -p tcar/eval_results/logs eval_results/logs "$TMPDIR"
LOG="tcar/eval_results/logs/gpt56sol_resume_low.log"
MODEL="${MODEL:-openai/gpt-5.6-sol}"
WORKERS="${WORKERS:-2}"
MAX_JOBS="${MAX_JOBS:-2}"
STAMP_SOFT="${STAMP_SOFT:-20260904Tgpt56sol_soft_gad_cb}"
STAMP_BASE="${STAMP_BASE:-20260904Tgpt56sol_baselines}"

eval "$(PYTHONPATH=. python - <<'PY'
from pathlib import Path
from dotenv import dotenv_values
vals = dotenv_values(Path(".env"))
keep = [
    "OPENROUTER_API_KEY", "OPENAI_API_KEY", "OPENAI_BASE_URL",
    "GENERATION_MODEL", "OPENROUTER_HTTP_REFERER", "OPENROUTER_APP_TITLE",
]
for k in keep:
    v = vals.get(k)
    if v is None or str(v).strip() == "":
        continue
    v = str(v).strip().replace("\\", "\\\\").replace('"', '\\"')
    print(f'export {k}="{v}"')
PY
)"

export GENERATION_MODEL="${GENERATION_MODEL:-$MODEL}"
export OPENAI_BASE_URL="${OPENAI_BASE_URL:-https://openrouter.ai/api/v1}"
export USE_OPENROUTER=1
if [[ -n "${OPENROUTER_API_KEY:-}" ]]; then
  export OPENAI_API_KEY="$OPENROUTER_API_KEY"
fi
export OPENROUTER_REASONING_EFFORT="${EFFORT:-low}"
export OPENROUTER_REASONING=1
export RCM_PROMPT=soft

# Compact CF jsonl: one row per id (prefer non-error).
echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] Compacting CF jsonl files..." | tee -a "$LOG"
PYTHONPATH=. python - <<'PY'
import json
from pathlib import Path
base = Path("tcar/eval_results")
for p in sorted(base.glob("counterfactual_ctibench_*_20260904Tgpt56sol_*.jsonl")):
    by = {}
    for line in p.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            r = json.loads(line)
        except Exception:
            continue
        rid = r.get("id")
        if not rid:
            continue
        prev = by.get(rid)
        if prev is None:
            by[rid] = r
        elif prev.get("error") and not r.get("error"):
            by[rid] = r
        elif bool(prev.get("error")) == bool(r.get("error")):
            by[rid] = r  # keep latest
    rows = list(by.values())
    tmp = p.with_suffix(".jsonl.tmp")
    with tmp.open("w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    tmp.replace(p)
    ok = sum(1 for r in rows if not r.get("error"))
    print(f"  {p.name}: {len(rows)} unique, {ok} ok, {len(rows)-ok} err")
PY

run_with_slot () {
  # wait until fewer than MAX_JOBS background jobs
  while true; do
    local n
    n=$(jobs -rp | wc -l)
    if [[ "$n" -lt "$MAX_JOBS" ]]; then
      break
    fi
    sleep 5
  done
  "$@" &
}

cf_job () {
  local mode="$1" task="$2" stamp="$3"
  local logfile="tcar/eval_results/logs/resume_${mode}_${task}.log"
  (
    if [[ "$mode" == "forced_rag" ]]; then
      export RCM_GAD=off ATA_GAD=off GAD_MODE=off RCM_CWE_RETRIEVAL=off
    elif [[ "$mode" == "force_gad" ]]; then
      export RCM_GAD=force ATA_GAD=force GAD_MODE=force
      unset RCM_CWE_RETRIEVAL || true
    else
      export RCM_GAD=force ATA_GAD=force GAD_MODE=soft
      unset RCM_CWE_RETRIEVAL || true
    fi
    echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] RESUME ${mode} ${task} workers=${WORKERS}" | tee -a "$LOG" "$logfile"
    python -m tcar.eval.run_counterfactual \
      --benchmark ctibench \
      --tasks "$task" \
      --limit 0 \
      --workers "$WORKERS" \
      --model "$MODEL" \
      --variant no_confusion \
      --stamp "$stamp" \
      2>&1 | tee -a "$logfile"
    echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] DONE ${mode} ${task}" | tee -a "$LOG" "$logfile"
  )
}

base_job () {
  local name="$1" cmd="$2"
  local logfile="eval_results/logs/resume_${name}.log"
  (
    echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] RESUME baseline ${name} workers=${WORKERS}" | tee -a "$LOG" "$logfile"
    eval "$cmd" 2>&1 | tee -a "$logfile"
    echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] DONE baseline ${name}" | tee -a "$LOG" "$logfile"
  )
}

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] Resume low-concurrency workers=${WORKERS} max_jobs=${MAX_JOBS}" | tee -a "$LOG"

# CF: Forced RAG / Force GAD / Soft GAD — retry errors via resume
for task in rcm ate mcq vsp; do
  run_with_slot cf_job forced_rag "$task" 20260904Tgpt56sol_forced_rag_cb
  run_with_slot cf_job force_gad "$task" 20260904Tgpt56sol_force_gad_cb
  run_with_slot cf_job soft_gad "$task" "$STAMP_SOFT"
done

TASKS_ALL=mcq,rcm,vsp,ate
run_with_slot base_job unified_rag \
  "python -m eval.run_unified_rag --limit 0 --tasks ${TASKS_ALL} --workers ${WORKERS} --out-dir eval_results --prompt-mode zero_shot --retrieval on"
run_with_slot base_job selfrag \
  "python -m eval.run_strong_rag_baselines --limit 0 --tasks ${TASKS_ALL} --systems selfrag --workers ${WORKERS} --out-dir eval_results --pred-name selfrag_${STAMP_BASE}.jsonl"
run_with_slot base_job graphrag \
  "python -m eval.run_strong_rag_baselines --limit 0 --tasks ${TASKS_ALL} --systems graphrag --workers ${WORKERS} --out-dir eval_results --pred-name graphrag_${STAMP_BASE}.jsonl"
run_with_slot base_job adaptive_rag \
  "python -m eval.run_adaptive_baselines --limit 0 --tasks ${TASKS_ALL} --systems adaptive_rag --workers ${WORKERS} --out-dir eval_results --pred-name adaptive_rag_${STAMP_BASE}.jsonl"
run_with_slot base_job tadarag \
  "python -m eval.run_adaptive_baselines --limit 0 --tasks ${TASKS_ALL} --systems tadarag --workers ${WORKERS} --out-dir eval_results --pred-name tadarag_${STAMP_BASE}.jsonl"

wait
echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] All resume jobs finished" | tee -a "$LOG"
