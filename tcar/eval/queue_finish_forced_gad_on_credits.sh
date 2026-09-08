#!/usr/bin/env bash
# Poll OpenRouter until enough credits remain, then finish Forced RAG + Force GAD only.
set -euo pipefail
cd /mnt/c/Users/SK/CTI-Chatbot
source .venv/bin/activate

export TMPDIR=/mnt/c/Users/SK/CTI-Chatbot/.tmp
mkdir -p tcar/eval_results/logs "$TMPDIR"
LOG="tcar/eval_results/logs/gpt56sol_credit_queue.log"
POLL_SEC="${POLL_SEC:-120}"
MIN_CREDIT_REMAIN="${MIN_CREDIT_REMAIN:-10}"
MODEL="${MODEL:-openai/gpt-5.6-sol}"

load_env() {
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
  export MIN_CREDIT_REMAIN="${MIN_CREDIT_REMAIN}"
}

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] Credit queue armed; poll=${POLL_SEC}s min_remain=${MIN_CREDIT_REMAIN}; auto-start Forced RAG v2 only" | tee -a "$LOG"

while true; do
  load_env
  set +e
  OUT=$(MIN_CREDIT_REMAIN="$MIN_CREDIT_REMAIN" PYTHONPATH=. python - <<'PY' 2>&1
import os
from pathlib import Path
import httpx
from dotenv import load_dotenv

load_dotenv(Path("/mnt/c/Users/SK/CTI-Chatbot/.env"), override=True)
ork = (os.getenv("OPENROUTER_API_KEY") or "").strip()
if not ork:
    print("WAIT missing_key")
    raise SystemExit(1)

headers = {"Authorization": f"Bearer {ork}"}
min_remain = float(os.getenv("MIN_CREDIT_REMAIN") or "10")
with httpx.Client(timeout=45.0) as client:
    cr = client.get("https://openrouter.ai/api/v1/credits", headers=headers)
    data = (cr.json() or {}).get("data") or {}
    total = float(data.get("total_credits") or 0)
    used = float(data.get("total_usage") or 0)
    remain = total - used
    if remain < min_remain:
        print(f"WAIT remain={remain:.2f} total={total:.2f} used={used:.2f} need>={min_remain:.0f}")
        raise SystemExit(1)

    os.environ["OPENAI_BASE_URL"] = (os.getenv("OPENAI_BASE_URL") or "https://openrouter.ai/api/v1").strip()
    os.environ["USE_OPENROUTER"] = "1"
    os.environ["OPENAI_API_KEY"] = ork
    from utils.llm_client import (
        clear_client_cache,
        get_openai_client,
        chat_completion_kwargs,
        reasoning_body,
    )
    clear_client_cache()
    client_oai = get_openai_client()
    try:
        resp = client_oai.chat.completions.create(
            messages=[{"role": "user", "content": "Reply OK"}],
            **chat_completion_kwargs(
                "openai/gpt-5.6-sol",
                max_tokens=16,
                temperature=None,
                reasoning=reasoning_body(effort="low", exclude=True),
            ),
        )
        reply = (resp.choices[0].message.content or "")[:20]
        print(f"READY remain={remain:.2f} total={total:.2f} used={used:.2f} reply={reply!r}")
    except Exception as e:
        msg = str(e).replace("\n", " ")[:200]
        print(f"WAIT remain={remain:.2f} total={total:.2f} used={used:.2f} err={type(e).__name__} {msg}")
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
echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] Credits OK — starting Forced RAG v2 only (Force GAD aside)" | tee -a "$LOG"
WORKERS="${WORKERS:-2}" MAX_JOBS="${MAX_JOBS:-2}" EFFORT="${EFFORT:-low}" \
  bash /mnt/c/Users/SK/CTI-Chatbot/tcar/eval/run_gpt56sol_forced_rag_v2.sh 2>&1 | tee -a "$LOG"
echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] Credit queue finished" | tee -a "$LOG"
