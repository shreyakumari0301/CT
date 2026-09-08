#!/usr/bin/env bash
cd /mnt/c/Users/SK/CTI-Chatbot
pgrep -af 'run_rcm_hybrid|run_vsp_|rcm_hybrid_turbo|mcq_option_aware' | head -12 || true
echo ===
ls -la tcar/eval_results/rcm_hybrid_offline_audit.json tcar/eval_results/vsp_per_metric_audit.json 2>/dev/null || true
echo '=== VSP AUDIT ==='
tail -n 50 tcar/eval_results/logs/vsp_per_metric_audit.log 2>/dev/null || true
echo '=== RCM OFFLINE ==='
tail -n 25 tcar/eval_results/logs/rcm_hybrid_offline_audit.log 2>/dev/null || true
echo '=== VSP PILOT ==='
tail -c 800 tcar/eval_results/logs/vsp_structured_n75.log 2>/dev/null | tr '\r' '\n' | tail -12 || true
echo '=== RCM GATE OUT ==='
tail -n 20 tcar/eval_results/logs/rcm_hybrid_offline_and_gate.nohup.out 2>/dev/null || true
