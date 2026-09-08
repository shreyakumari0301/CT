#!/usr/bin/env bash
set -euo pipefail
echo "=== processes ==="
pgrep -af 'mcq|run_counterfactual|option_aware' || true
echo "=== mcq logs ==="
ls -lt /mnt/c/Users/SK/CTI-Chatbot/tcar/eval_results/logs/*mcq* 2>/dev/null | head -10 || true
echo "=== n100 log tail ==="
if [[ -f /mnt/c/Users/SK/CTI-Chatbot/tcar/eval_results/logs/mcq_option_aware_turbo_n100.log ]]; then
  tail -c 800 /mnt/c/Users/SK/CTI-Chatbot/tcar/eval_results/logs/mcq_option_aware_turbo_n100.log | tr '\r' '\n' | tail -20
fi
echo "=== jsonl lines ==="
wc -l /mnt/c/Users/SK/CTI-Chatbot/tcar/eval_results/counterfactual_ctibench_mcq_20260907Tturbo_mcq_option_aware_n100.jsonl 2>/dev/null || true
echo "=== summary exists ==="
ls -la /mnt/c/Users/SK/CTI-Chatbot/tcar/eval_results/counterfactual_summary_20260907Tturbo_mcq_option_aware_n100.json 2>/dev/null || true
echo "=== ata still running? ==="
pgrep -af 'ata_grounded|turbo_ata_grounded' || true
