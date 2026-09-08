#!/usr/bin/env bash
cd /mnt/c/Users/SK/CTI-Chatbot
source .venv/bin/activate
PYTHONPATH=. python tcar/eval/_tmp_status_snapshot.py
echo ====
pgrep -af 'eval.run_ctibench|systems cta_rag_port' || true
echo ====
python - <<'PY'
from pathlib import Path
p = Path('CTICONNECT benchmark/eval_results/cticonnect_cta_rag_port_20260906Tgpt56sol_cta_port.jsonl')
print('connect lines', sum(1 for _ in p.open()) if p.exists() else 0, 'mtime', p.stat().st_mtime if p.exists() else None)
PY
