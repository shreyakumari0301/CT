#!/usr/bin/env bash
cd /mnt/c/Users/SK/CTI-Chatbot
echo '=== PROCS ==='
pgrep -af 'rcm_hybrid|vsp_structured|mcq_option|run_counterfactual' | grep -v status | head -15
echo '=== RCM AUDIT JSON ==='
python3 -c 'import json;print(json.dumps(json.load(open("tcar/eval_results/rcm_hybrid_offline_audit.json")),indent=2)[:800])' 2>/dev/null || true
echo '=== RCM PILOT ==='
tail -c 400 tcar/eval_results/logs/rcm_hybrid_turbo_n200.log 2>/dev/null | tr '\r' '\n' | tail -8
echo '=== VSP PILOT ==='
tail -c 400 tcar/eval_results/logs/vsp_structured_n75.log 2>/dev/null | tr '\r' '\n' | tail -8
