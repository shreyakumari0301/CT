#!/usr/bin/env bash
set -euo pipefail
echo '=== processes ==='
pgrep -af 'run_counterfactual' || true
echo '=== CC jsonl ==='
wc -l /mnt/c/Users/SK/CTI-Chatbot/tcar/eval_results/counterfactual_cticonnect_rcm_20260903Tparent_sib_cc.jsonl 2>/dev/null || echo nojsonl
echo '=== CB jsonl ==='
wc -l /mnt/c/Users/SK/CTI-Chatbot/tcar/eval_results/counterfactual_ctibench_rcm_20260903Tparent_sib_cb.jsonl 2>/dev/null || echo nojsonl
echo '=== CC log tail ==='
tr '\r' '\n' < /mnt/c/Users/SK/CTI-Chatbot/tcar/eval_results/logs/cf_cticonnect_20260903Tparent_sib_cc.log | tail -8
echo '=== CB log tail ==='
tr '\r' '\n' < /mnt/c/Users/SK/CTI-Chatbot/tcar/eval_results/logs/cf_ctibench_20260903Tparent_sib_cb.log | tail -8
