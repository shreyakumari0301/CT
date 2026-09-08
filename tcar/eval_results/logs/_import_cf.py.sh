#!/usr/bin/env bash
set -euo pipefail
cd /mnt/c/Users/SK/CTI-Chatbot
export PYTHONPATH=/mnt/c/Users/SK/CTI-Chatbot
.venv/bin/python -c "from tcar.eval.run_counterfactual import main; print('import ok')"
