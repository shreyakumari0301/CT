#!/usr/bin/env bash
# Queue paper baselines on gpt-5.6-sol (OpenAI direct), after Forced/Vanilla RAG finishes.
# Replicates published ladder: Unified ZS, Self-RAG-style, Edge GraphRAG, Adaptive, TAdaRAG
# (CTIBench) + CTIConnect paper systems. Same k=5 / MiniLM chunk stores as paper baselines;
# Forced RAG task-KB differences are intentional (paper design) — see comparison table.
set -euo pipefail
cd /mnt/c/Users/SK/CTI-Chatbot
source .venv/bin/activate

export TMPDIR=/mnt/c/Users/SK/CTI-Chatbot/.tmp
mkdir -p tcar/eval_results/logs eval_results/logs "$TMPDIR" "CTICONNECT data/eval_results"
LOG="tcar/eval_results/logs/gpt56sol_baselines_queue.log"
MODEL="${MODEL:-gpt-5.6-sol}"
BASE_WORKERS="${BASE_WORKERS:-3}"
STAMP="${STAMP:-20260906Tgpt56sol_baselines}"
POLL_SEC="${POLL_SEC:-60}"
WAIT_FORCED="${WAIT_FORCED:-1}"

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
export CTICONNECT_MODEL="${CTICONNECT_MODEL:-$MODEL}"
unset OPENAI_BASE_URL OPENROUTER_API_KEY OPENROUTER_REASONING OPENROUTER_REASONING_EFFORT || true
export USE_OPENROUTER=0

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] Baseline queue armed model=${MODEL} stamp=${STAMP}" | tee -a "$LOG"

if [[ "$WAIT_FORCED" == "1" ]]; then
  echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] Waiting for Forced RAG counterfactual jobs to finish..." | tee -a "$LOG"
  while ps aux | grep -E 'run_counterfactual --benchmark (ctibench|cticonnect)' | grep -v grep >/dev/null; do
    echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] Forced RAG still running; sleep ${POLL_SEC}s" | tee -a "$LOG"
    sleep "$POLL_SEC"
  done
  echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] Forced RAG clear; starting baselines" | tee -a "$LOG"
fi

TASKS_ALL=mcq,rcm,vsp,ate

run_base () {
  local name="$1"
  local cmd="$2"
  local logfile="eval_results/logs/gpt56sol_${name}_${STAMP}.log"
  (
    echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] START baseline ${name}" | tee -a "$LOG" "$logfile"
    eval "$cmd" 2>&1 | tee -a "$logfile"
    echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] DONE baseline ${name}" | tee -a "$LOG" "$logfile"
  ) &
  echo "launched ${name} pid=$!" | tee -a "$LOG"
}

# CTIBench paper ladder (matched generator via GENERATION_MODEL)
run_base unified_rag \
  "python -m eval.run_unified_rag --limit 0 --tasks ${TASKS_ALL} --k 5 --workers ${BASE_WORKERS} --out-dir eval_results --prompt-mode zero_shot --retrieval on"

run_base selfrag \
  "python -m eval.run_strong_rag_baselines --limit 0 --tasks ${TASKS_ALL} --systems selfrag --k 5 --workers ${BASE_WORKERS} --out-dir eval_results --pred-name selfrag_${STAMP}.jsonl"

# Paper GraphRAG numbers match Edge local search (not multi-query style)
run_base graphrag_edge \
  "python -m eval.run_graphrag_edge --limit 0 --tasks ${TASKS_ALL} --workers ${BASE_WORKERS} --out-dir eval_results --pred-name graphrag_edge_${STAMP}.jsonl"

run_base adaptive_rag \
  "python -m eval.run_adaptive_baselines --limit 0 --tasks ${TASKS_ALL} --systems adaptive_rag --k 5 --workers ${BASE_WORKERS} --out-dir eval_results --pred-name adaptive_rag_${STAMP}.jsonl"

run_base tadarag \
  "python -m eval.run_adaptive_baselines --limit 0 --tasks ${TASKS_ALL} --systems tadarag --k 5 --workers ${BASE_WORKERS} --out-dir eval_results --pred-name tadarag_${STAMP}.jsonl"

# CTIConnect: same paper baseline systems (corpus_kb / te3-large as published CTIConnect setup)
run_base cticonnect_baselines \
  "python -m eval.run_cticonnect --systems unified_rag,selfrag,graphrag,tadarag --tasks rcm,ata --limit 0 --k 5 --workers ${BASE_WORKERS} --stamp ${STAMP}"

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] All baseline jobs launched; waiting..." | tee -a "$LOG"
wait || true
echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] Baseline queue finished" | tee -a "$LOG"
