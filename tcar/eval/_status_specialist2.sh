#!/usr/bin/env bash
cd /mnt/c/Users/SK/CTI-Chatbot
echo "=== jsonl lines ==="
for f in tcar/eval_results/counterfactual_*20260907Tsol*; do
  [ -e "$f" ] || continue
  echo "$f $(wc -l < "$f")"
done
echo "=== open files / strace sample ==="
ls -la tcar/eval_results/logs/ | grep -E 'ate_cta|rcm_tax|rcm_learn|ata_beh|mcq_opt|vsp_met|rcm_gold' || true
echo "=== first error grep ==="
grep -nE 'Traceback|Error|Exception|rate|429|timeout' tcar/eval_results/logs/ate_cta_fidelity.log tcar/eval_results/logs/rcm_taxonomy_rerank.log tcar/eval_results/logs/mcq_option_aware.log 2>/dev/null | head -40 || true
echo "=== cpu ==="
ps -o pid,etime,pcpu,pmem,cmd -p 695,765,767,772,774,776,778 2>/dev/null || true
