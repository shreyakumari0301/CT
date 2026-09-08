#!/usr/bin/env bash
set -euo pipefail
cd /mnt/c/Users/SK/CTI-Chatbot
echo "=== result files ==="
ls -la tcar/eval_results/*20260907Tsol* 2>/dev/null | head -40 || true
echo "=== ATE log tail ==="
tail -n 40 tcar/eval_results/logs/ate_cta_fidelity.log 2>/dev/null || true
echo "=== RCM taxonomy tail ==="
tail -n 25 tcar/eval_results/logs/rcm_taxonomy_rerank.log 2>/dev/null || true
echo "=== RCM learned tail ==="
tail -n 25 tcar/eval_results/logs/rcm_learned_rerank.log 2>/dev/null || true
echo "=== ATA tail ==="
tail -n 25 tcar/eval_results/logs/ata_behavior_abstain.log 2>/dev/null || true
echo "=== processes ==="
pgrep -af run_counterfactual || true
pgrep -af run_specialist || true
