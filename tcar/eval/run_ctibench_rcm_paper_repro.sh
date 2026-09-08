#!/usr/bin/env bash
set -euo pipefail
cd /mnt/c/Users/SK/CTI-Chatbot
source .venv/bin/activate
export TMPDIR=/mnt/c/Users/SK/CTI-Chatbot/.tmp
mkdir -p eval_results/logs "$TMPDIR"

# Paper primary RCM path: understanding pipeline, CWE catalogue OFF → claimed Acc 78.1%
export RCM_CWE_RETRIEVAL=off
unset RCM_PROMPT || true

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] CTIBench RCM oracle reproduce (catalogue off) → paper Acc 78.1%"
python -m eval.run_ctibench \
  --task rcm \
  --limit 0 \
  --route_mode oracle \
  --workers 3 \
  --out-dir eval_results

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] RCM reproduce done"
