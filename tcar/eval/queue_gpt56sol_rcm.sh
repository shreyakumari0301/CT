#!/usr/bin/env bash
# Poll OpenRouter until gpt-5.6-sol accepts a tiny request (no 402), then run CTIBench:
#   1) Forced RAG (RCM_GAD=off, GAD_MODE=off) → Closed book + Forced CTA-RAG
#      tasks: rcm, ate, mcq, vsp
#   2) Force GAD (same pipeline on every task: dense→seed→graph→K=12, ≤3/cluster)
#      RCM_GAD=force + GAD_MODE=force
set -euo pipefail
cd /mnt/c/Users/SK/CTI-Chatbot
source .venv/bin/activate

export TMPDIR=/mnt/c/Users/SK/CTI-Chatbot/.tmp
mkdir -p tcar/eval_results/logs "$TMPDIR"

MODEL="${MODEL:-openai/gpt-5.6-sol}"
POLL_SEC="${POLL_SEC:-120}"
LOG="tcar/eval_results/logs/gpt56sol_queue.log"
TASKS="${TASKS:-rcm,ate,mcq,vsp}"
WORKERS="${WORKERS:-2}"

# Load .env via Python (handles Windows CRLF); never source .env in bash.
load_env() {
  eval "$(PYTHONPATH=. python - <<'PY'
from pathlib import Path
from dotenv import dotenv_values
vals = dotenv_values(Path(".env"))
keep = [
    "OPENROUTER_API_KEY", "OPENAI_API_KEY", "OPENAI_BASE_URL",
    "GENERATION_MODEL", "OPENROUTER_REASONING_EFFORT", "OPENROUTER_REASONING",
    "OPENROUTER_HTTP_REFERER", "OPENROUTER_APP_TITLE",
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
  export OPENROUTER_REASONING_EFFORT="${OPENROUTER_REASONING_EFFORT:-medium}"
  export OPENROUTER_REASONING=1
  export RCM_PROMPT=soft
}

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] Queue armed for ${MODEL}; tasks=${TASKS}; polling every ${POLL_SEC}s" | tee -a "$LOG"

while true; do
  load_env
  set +e
  OUT=$(PYTHONPATH=. python - <<'PY' 2>&1
import os
from pathlib import Path
from dotenv import load_dotenv
load_dotenv(Path("/mnt/c/Users/SK/CTI-Chatbot/.env"), override=True)
os.environ["OPENAI_BASE_URL"] = (os.getenv("OPENAI_BASE_URL") or "https://openrouter.ai/api/v1").strip()
os.environ["USE_OPENROUTER"] = "1"
ork = (os.getenv("OPENROUTER_API_KEY") or "").strip()
if ork:
    os.environ["OPENAI_API_KEY"] = ork
from utils.llm_client import clear_client_cache, get_openai_client, chat_completion_kwargs, reasoning_body
clear_client_cache()
client = get_openai_client()
try:
    resp = client.chat.completions.create(
        messages=[{"role": "user", "content": "Reply OK"}],
        **chat_completion_kwargs(
            "openai/gpt-5.6-sol",
            max_tokens=16,
            temperature=None,
            reasoning=reasoning_body(effort="low", exclude=True),
        ),
    )
    print("READY", (resp.choices[0].message.content or "").strip()[:40])
except Exception as e:
    msg = str(e).replace("\n", " ")[:240]
    print("WAIT", type(e).__name__, msg)
    raise SystemExit(1)
PY
)
  RC=$?
  set -e
  echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] probe rc=${RC} ${OUT}" | tee -a "$LOG"
  if [[ $RC -eq 0 ]]; then
    break
  fi
  sleep "$POLL_SEC"
done

load_env
echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] Credits OK — starting CB / Forced RAG / Force GAD for ${TASKS}" | tee -a "$LOG"

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] === Forced RAG (CB + Forced CTA-RAG) ===" | tee -a "$LOG"
export RCM_GAD=off
export ATA_GAD=off
export RCM_CWE_RETRIEVAL=off
export GAD_MODE=off
python -m tcar.eval.run_counterfactual \
  --benchmark ctibench \
  --tasks "$TASKS" \
  --limit 0 \
  --workers "$WORKERS" \
  --model "$MODEL" \
  --variant no_confusion \
  --stamp 20260904Tgpt56sol_forced_rag_cb \
  --no-resume 2>&1 | tee -a "$LOG"

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] === Force GAD (same diversify K=12 on all tasks) ===" | tee -a "$LOG"
export RCM_GAD=force
export ATA_GAD=force
export GAD_MODE=force
unset RCM_CWE_RETRIEVAL || true
python -m tcar.eval.run_counterfactual \
  --benchmark ctibench \
  --tasks "$TASKS" \
  --limit 0 \
  --workers "$WORKERS" \
  --model "$MODEL" \
  --variant no_confusion \
  --stamp 20260904Tgpt56sol_force_gad_cb \
  --no-resume 2>&1 | tee -a "$LOG"

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] gpt-5.6-sol CTIBench CB/ForcedRAG/ForceGAD queue finished" | tee -a "$LOG"
