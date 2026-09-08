#!/usr/bin/env bash
set -euo pipefail
cd /mnt/c/Users/SK/CTI-Chatbot
source .venv/bin/activate
PYTHONPATH=. python - <<'PY'
import json
from pathlib import Path
p = Path("tcar/eval_results/counterfactual_ctibench_mcq_20260907Tturbo_mcq_option_aware_n100.jsonl")
ids = []
for line in p.read_text(encoding="utf-8").splitlines():
    if line.strip():
        ids.append(json.loads(line)["id"])
print("n_rows", len(ids), "unique", len(set(ids)))
print("first", ids[0], "last", ids[-1])
PY
# dataset size
PYTHONPATH=. python - <<'PY'
from tcar.eval.run_counterfactual import load_rows
# find how load works
import inspect
print("skip")
PY
