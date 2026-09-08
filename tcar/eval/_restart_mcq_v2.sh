#!/usr/bin/env bash
set -euo pipefail
cd /mnt/c/Users/SK/CTI-Chatbot
source .venv/bin/activate

# Stop broken option-aware full run (parser was a no-op).
pkill -f 'stamp 20260907Tturbo_mcq_option_aware_full' 2>/dev/null || true
pkill -f 'run_mcq_option_aware_turbo_full' 2>/dev/null || true
sleep 2
echo "=== after stop ==="
pgrep -af 'mcq_option_aware|run_counterfactual' || echo "(no mcq/cf)"

PYTHONPATH=. python tcar/eval/_check_mcq_parse_fixed.py
PYTHONPATH=. python - <<'PY'
import json
from pathlib import Path
from tcar.specialist_retrieval import parse_mcq_options
p = Path("tcar/eval_results/counterfactual_ctibench_mcq_20260907Tturbo_mcq_option_aware_full.jsonl")
ok = n = 0
for line in p.read_text(encoding="utf-8").splitlines()[:200]:
    if not line.strip():
        continue
    n += 1
    if len(parse_mcq_options(json.loads(line)["question"])) == 4:
        ok += 1
print(f"real_prompts parse_ok {ok}/{n}")
PY

nohup bash tcar/eval/run_mcq_option_aware_turbo_v2.sh > tcar/eval_results/logs/mcq_option_aware_turbo_v2.nohup.out 2>&1 &
echo "launched PID=$!"
sleep 12
pgrep -af 'mcq_option_aware_turbo_v2|turbo_mcq_option_aware_v2' || true
tail -n 30 tcar/eval_results/logs/mcq_option_aware_turbo_v2.nohup.out 2>/dev/null || true
tail -n 20 tcar/eval_results/logs/mcq_option_aware_turbo_v2.log 2>/dev/null || true
