#!/usr/bin/env bash
cd /mnt/c/Users/SK/CTI-Chatbot
source .venv/bin/activate
echo "elapsed:"; ps -p 1975 -o etime,pcpu,wchan 2>/dev/null || { echo dead; exit 0; }
# Quick API smoke (should not hang >30s)
eval "$(PYTHONPATH=. python - <<'PY'
from pathlib import Path
from dotenv import dotenv_values
vals = dotenv_values(Path('.env'))
k = (vals.get('OPENAI_API_KEY') or '').strip()
print(f'export OPENAI_API_KEY="{k}"')
print('export GENERATION_MODEL=gpt-4-turbo USE_OPENROUTER=0')
PY
)"
timeout 45 env PYTHONPATH=. USE_OPENROUTER=0 GENERATION_MODEL=gpt-4-turbo OPENAI_API_KEY="$OPENAI_API_KEY" \
  python - <<'PY' || echo "API_SMOKE_FAIL:$?"
from utils.llm_client import chat, resolve_model
print("resolve", resolve_model("gpt-4-turbo"))
print("chat", (chat("Reply with OK only.", max_tokens=5) or "")[:40])
PY
echo "jsonl:"; ls -la tcar/eval_results/counterfactual_ctibench_mcq_20260907Tturbo_mcq_option_aware_v2.jsonl 2>/dev/null || echo none
