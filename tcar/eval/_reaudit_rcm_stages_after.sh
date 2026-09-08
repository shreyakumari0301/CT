#!/usr/bin/env bash
# After current RCM audit finishes, re-run with full stage table (union/RRF loss).
# Does not block the gated pilot if the first audit already passed.
set -euo pipefail
cd /mnt/c/Users/SK/CTI-Chatbot
source .venv/bin/activate
# Wait until the in-flight audit process exits
while pgrep -f 'run_rcm_hybrid_offline_audit.py' >/dev/null 2>&1; do
  sleep 30
done
echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] first audit done; writing stage-complete audit"
PYTHONPATH=. python tcar/eval/run_rcm_hybrid_offline_audit.py \
  2>&1 | tee tcar/eval_results/logs/rcm_hybrid_offline_audit_stages.log
# Re-evaluate gate (idempotent if pilot already started)
PYTHONPATH=. python tcar/eval/_maybe_start_rcm_hybrid_pilot.py
