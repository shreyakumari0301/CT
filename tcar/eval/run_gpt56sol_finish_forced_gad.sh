#!/usr/bin/env bash
# Finish ONLY Forced RAG + Force GAD on gpt-5.6-sol (retry 402s until full).
set -euo pipefail
cd /mnt/c/Users/SK/CTI-Chatbot
source .venv/bin/activate

export TMPDIR=/mnt/c/Users/SK/CTI-Chatbot/.tmp
mkdir -p tcar/eval_results/logs "$TMPDIR"
LOG="tcar/eval_results/logs/gpt56sol_finish_forced_gad.log"
MODEL="${MODEL:-openai/gpt-5.6-sol}"
WORKERS="${WORKERS:-2}"
MAX_JOBS="${MAX_JOBS:-2}"

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

compact () {
  PYTHONPATH=. python - <<'PY'
import json
from pathlib import Path
base = Path("tcar/eval_results")
for stamp in ("20260904Tgpt56sol_forced_rag_cb", "20260904Tgpt56sol_force_gad_cb"):
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
  local stamp="$1" task="$2" nexp="$3"
  PYTHONPATH=. python - <<PY
import json
from pathlib import Path
p = Path("tcar/eval_results/counterfactual_ctibench_${task}_${stamp}.jsonl")
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
    prev = by.get(rid)
    if prev is None or (prev.get("error") and not r.get("error")):
        by[rid] = r
    elif bool(prev.get("error")) == bool(r.get("error")):
        by[rid] = r
ok = sum(1 for r in by.values() if not r.get("error"))
raise SystemExit(0 if ok >= nexp else 1)
PY
}

run_cf () {
  local mode="$1" task="$2" stamp="$3"
  local logfile="tcar/eval_results/logs/finish_${mode}_${task}.log"
  if [[ "$mode" == "forced_rag" ]]; then
    export RCM_GAD=off ATA_GAD=off GAD_MODE=off RCM_CWE_RETRIEVAL=off
  else
    export RCM_GAD=force ATA_GAD=force GAD_MODE=force
    unset RCM_CWE_RETRIEVAL || true
  fi
  echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] RUN ${mode} ${task}" | tee -a "$LOG" "$logfile"
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
}

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] Finish Forced RAG + Force GAD only workers=${WORKERS}" | tee -a "$LOG"
compact | tee -a "$LOG"

# Round-robin until both stamps are full (or credits die).
declare -a QUEUE=()
for task_n in "rcm:1000" "mcq:2500" "vsp:1000" "ate:60"; do
  task="${task_n%%:*}"
  nexp="${task_n##*:}"
  if ! incomplete 20260904Tgpt56sol_forced_rag_cb "$task" "$nexp"; then
    QUEUE+=("forced_rag:$task:20260904Tgpt56sol_forced_rag_cb")
  fi
  if ! incomplete 20260904Tgpt56sol_force_gad_cb "$task" "$nexp"; then
    QUEUE+=("force_gad:$task:20260904Tgpt56sol_force_gad_cb")
  fi
done

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] Queue: ${QUEUE[*]:-empty}" | tee -a "$LOG"

# Process with at most MAX_JOBS concurrent.
idx=0
pids=()
modes=()
tasks=()
while [[ $idx -lt ${#QUEUE[@]} ]] || [[ ${#pids[@]} -gt 0 ]]; do
  # reap finished
  new_pids=(); new_modes=(); new_tasks=()
  for i in "${!pids[@]}"; do
    if kill -0 "${pids[$i]}" 2>/dev/null; then
      new_pids+=("${pids[$i]}")
      new_modes+=("${modes[$i]}")
      new_tasks+=("${tasks[$i]}")
    else
      wait "${pids[$i]}" || true
      echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] slot freed ${modes[$i]} ${tasks[$i]}" | tee -a "$LOG"
    fi
  done
  pids=("${new_pids[@]+"${new_pids[@]}"}")
  modes=("${new_modes[@]+"${new_modes[@]}"}")
  tasks=("${new_tasks[@]+"${new_tasks[@]}"}")

  while [[ ${#pids[@]} -lt $MAX_JOBS && $idx -lt ${#QUEUE[@]} ]]; do
    entry="${QUEUE[$idx]}"
    idx=$((idx + 1))
    mode="${entry%%:*}"
    rest="${entry#*:}"
    task="${rest%%:*}"
    stamp="${rest#*:}"
    # skip if somehow completed meanwhile
    nexp=1000
    [[ "$task" == "ate" ]] && nexp=60
    [[ "$task" == "mcq" ]] && nexp=2500
    if incomplete "$stamp" "$task" "$nexp"; then
      echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] skip complete ${mode} ${task}" | tee -a "$LOG"
      continue
    fi
    run_cf "$mode" "$task" "$stamp" &
    pids+=("$!")
    modes+=("$mode")
    tasks+=("$task")
  done
  sleep 10
done

compact | tee -a "$LOG"
echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] Forced RAG + Force GAD finish pass done" | tee -a "$LOG"
PYTHONPATH=. python - <<'PY'
import json
from pathlib import Path
base = Path("tcar/eval_results")
for label, stamp in [("Forced RAG", "20260904Tgpt56sol_forced_rag_cb"), ("Force GAD", "20260904Tgpt56sol_force_gad_cb")]:
    print("==", label, "==")
    for task, nexp in [("rcm", 1000), ("ate", 60), ("mcq", 2500), ("vsp", 1000)]:
        p = base / f"counterfactual_ctibench_{task}_{stamp}.jsonl"
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
            if prev is None or (prev.get("error") and not r.get("error")):
                by[rid] = r
            elif bool(prev.get("error")) == bool(r.get("error")):
                by[rid] = r
        ok = [r for r in by.values() if not r.get("error")]
        status = "FULL" if len(ok) >= nexp else f"INCOMPLETE {len(ok)}/{nexp}"
        if ok:
            cb = sum(1 for r in ok if r.get("closed_book_correct")) / len(ok)
            rag = sum(1 for r in ok if r.get("retrieval_correct")) / len(ok)
            print(f"  {task}: {status} CB={cb:.1%} RAG={rag:.1%}")
        else:
            print(f"  {task}: {status}")
PY
