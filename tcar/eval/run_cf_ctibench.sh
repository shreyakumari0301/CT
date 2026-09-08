#!/usr/bin/env bash
set -euo pipefail
cd /mnt/c/Users/SK/CTI-Chatbot
source .venv/bin/activate
export TMPDIR=/mnt/c/Users/SK/CTI-Chatbot/.tmp
export PIP_CACHE_DIR=/mnt/c/Users/SK/CTI-Chatbot/.pip-cache
mkdir -p tcar/eval_results/logs "$TMPDIR" "$PIP_CACHE_DIR"
STAMP="${1:-20260901Tcf}"

# CTIBench retriever needs sentence-transformers (or langchain-huggingface)
pip install --no-cache-dir -q sentence-transformers 2>>tcar/eval_results/logs/pip_ctibench_${STAMP}.log || true

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] Starting CTIBench counterfactual (gpt-4-turbo)"
python -m tcar.eval.run_counterfactual \
  --benchmark ctibench \
  --tasks rcm,ate,mcq,vsp \
  --limit 0 \
  --workers 3 \
  --model gpt-4-turbo \
  --variant no_confusion \
  --stamp "${STAMP}_cb"

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] CTIBench done"
