#!/usr/bin/env bash
# Vanilla RAG (always-retrieve, GAD off) on gpt-5.6-sol via OpenAI direct.
# Default stamp resumes the partial 20260904 run (skips ok rows, retries errors).
set -euo pipefail
cd /mnt/c/Users/SK/CTI-Chatbot
source .venv/bin/activate

export TMPDIR=/mnt/c/Users/SK/CTI-Chatbot/.tmp
mkdir -p tcar/eval_results/logs "$TMPDIR"
LOG="tcar/eval_results/logs/gpt56sol_forced_rag_resume.log"
MODEL="${MODEL:-gpt-5.6-sol}"
WORKERS="${WORKERS:-2}"
MAX_JOBS="${MAX_JOBS:-4}"
STAMP="${STAMP:-20260904Tgpt56sol_forced_rag_cb}"

eval "$(PYTHONPATH=. python - <<'PY'
from pathlib import Path
from dotenv import dotenv_values
vals = dotenv_values(Path(".env"))
keep = [
    "OPENAI_API_KEY", "OPENAI_BASE_URL", "GENERATION_MODEL", "USE_OPENROUTER",
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
export MODEL="${GENERATION_MODEL}"
# OpenAI direct (sk-proj). Do not force OpenRouter.
unset OPENAI_BASE_URL OPENROUTER_API_KEY OPENROUTER_REASONING OPENROUTER_REASONING_EFFORT || true
export USE_OPENROUTER=0
export RCM_PROMPT=soft
export ATA_PROMPT=soft
# Vanilla / Forced RAG — no GAD change
export RCM_GAD=off ATA_GAD=off GAD_MODE=off RCM_CWE_RETRIEVAL=off

compact () {
  PYTHONPATH=. python - <<PY
import json
from pathlib import Path
base = Path("tcar/eval_results")
stamp = "${STAMP}"
for task in ("rcm", "ate", "mcq", "vsp"):
    p = base / f"counterfactual_ctibench_{task}_{stamp}.jsonl"
    if not p.exists():
        continue
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
        # Treat empty ATE preds as retryable errors
        if task == "ate" and not (r.get("retrieval_prediction") or "").strip():
            r["error"] = r.get("error") or "empty_ate_prediction"
        prev = by.get(rid)
        if prev is None or (prev.get("error") and not r.get("error")):
            by[rid] = r
        elif bool(prev.get("error")) == bool(r.get("error")):
            by[rid] = r
    rows = list(by.values())
    tmp = p.with_suffix(".jsonl.tmp")
    with tmp.open("w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    tmp.replace(p)
    ok = sum(1 for r in rows if not r.get("error"))
    print(f"  {p.name}: {ok}/{len(rows)} ok")
PY
}

incomplete () {
  local task="$1" nexp="$2"
  PYTHONPATH=. python - <<PY
import json
from pathlib import Path
p = Path("tcar/eval_results/counterfactual_ctibench_${task}_${STAMP}.jsonl")
nexp = ${nexp}
if not p.exists():
    raise SystemExit(1)
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
    if "${task}" == "ate" and not (r.get("retrieval_prediction") or "").strip():
        r["error"] = r.get("error") or "empty_ate_prediction"
    prev = by.get(rid)
    if prev is None or (prev.get("error") and not r.get("error")):
        by[rid] = r
    elif bool(prev.get("error")) == bool(r.get("error")):
        by[rid] = r
ok = sum(1 for r in by.values() if not r.get("error"))
raise SystemExit(0 if ok >= nexp else 1)
PY
}

run_task () {
  local task="$1"
  local logfile="tcar/eval_results/logs/forced_rag_v2_${task}.log"
  echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] RUN vanilla_rag ${task} stamp=${STAMP}" | tee -a "$LOG" "$logfile"
  python -m tcar.eval.run_counterfactual \
    --benchmark ctibench \
    --tasks "$task" \
    --limit 0 \
    --workers "$WORKERS" \
    --model "$MODEL" \
    --variant no_confusion \
    --stamp "$STAMP" \
    2>&1 | tee -a "$logfile"
  echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] DONE vanilla_rag ${task}" | tee -a "$LOG" "$logfile"
}

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] Vanilla RAG v2 workers=${WORKERS} stamp=${STAMP} model=${MODEL}" | tee -a "$LOG"
compact | tee -a "$LOG"

declare -a QUEUE=()
for task_n in "ate:60" "rcm:1000" "mcq:2500" "vsp:1000"; do
  task="${task_n%%:*}"
  nexp="${task_n##*:}"
  if ! incomplete "$task" "$nexp"; then
    QUEUE+=("$task")
  fi
done

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] Queue: ${QUEUE[*]:-empty}" | tee -a "$LOG"

idx=0
pids=()
tasks=()
while [[ $idx -lt ${#QUEUE[@]} ]] || [[ ${#pids[@]} -gt 0 ]]; do
  new_pids=(); new_tasks=()
  for i in "${!pids[@]}"; do
    if kill -0 "${pids[$i]}" 2>/dev/null; then
      new_pids+=("${pids[$i]}")
      new_tasks+=("${tasks[$i]}")
    else
      wait "${pids[$i]}" || true
      echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] slot freed ${tasks[$i]}" | tee -a "$LOG"
    fi
  done
  pids=("${new_pids[@]+"${new_pids[@]}"}")
  tasks=("${new_tasks[@]+"${new_tasks[@]}"}")

  while [[ ${#pids[@]} -lt $MAX_JOBS && $idx -lt ${#QUEUE[@]} ]]; do
    task="${QUEUE[$idx]}"
    idx=$((idx + 1))
    nexp=1000
    [[ "$task" == "ate" ]] && nexp=60
    [[ "$task" == "mcq" ]] && nexp=2500
    if incomplete "$task" "$nexp"; then
      continue
    fi
    run_task "$task" &
    pids+=($!)
    tasks+=("$task")
  done

  if [[ ${#pids[@]} -eq 0 && $idx -ge ${#QUEUE[@]} ]]; then
    break
  fi
  sleep 5
  compact >/dev/null || true
done

compact | tee -a "$LOG"
echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] Vanilla RAG v2 finish exit" | tee -a "$LOG"
