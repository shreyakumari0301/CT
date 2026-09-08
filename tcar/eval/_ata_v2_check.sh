#!/usr/bin/env bash
cd /mnt/c/Users/SK/CTI-Chatbot
source .venv/bin/activate
PYTHONPATH=. python tcar/eval/_test_seg.py
PYTHONPATH=. python tcar/eval/_ata_offline_hygiene_rescore.py
echo PROCS:
pgrep -af 'ata_grounded_v2|turbo_ata_grounded_v2|mcq_option_aware_v2' || true
tail -c 400 tcar/eval_results/logs/ata_grounded_v2_turbo_n50.log 2>/dev/null | tr '\r' '\n' | tail -8
