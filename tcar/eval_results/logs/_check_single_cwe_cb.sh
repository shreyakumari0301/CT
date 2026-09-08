#!/usr/bin/env bash
set -euo pipefail
pgrep -af 20260903Tsingle_cwe_cb || echo DEAD
if [[ -f /mnt/c/Users/SK/CTI-Chatbot/tcar/eval_results/counterfactual_ctibench_rcm_20260903Tsingle_cwe_cb.jsonl ]]; then
  wc -l /mnt/c/Users/SK/CTI-Chatbot/tcar/eval_results/counterfactual_ctibench_rcm_20260903Tsingle_cwe_cb.jsonl
else
  echo nojsonl
fi
tr '\r' '\n' < /mnt/c/Users/SK/CTI-Chatbot/tcar/eval_results/logs/cf_ctibench_20260903Tsingle_cwe_cb.log | tail -20
