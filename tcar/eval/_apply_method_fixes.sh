#!/usr/bin/env bash
set -euo pipefail
cd /mnt/c/Users/SK/CTI-Chatbot
source .venv/bin/activate
PYTHONPATH=. python - <<'PY'
from tcar.vsp_structured_decoder import decode_vsp_prediction
raw='{"attack_location":"network","attack_conditions":"no special condition","required_privileges":"none","user_interaction":"none","scope_change":true,"confidentiality_impact":"none","integrity_impact":"high","availability_impact":"none","uncertain":[]}'
# RCE alone should clear scope_change and maybe demote integrity without evidence
vec, meta = decode_vsp_prediction(raw, description="Remote code execution in the service.")
print(vec)
print(meta.get("consistency_diff"))
assert meta["consistency_diff"]["n_changed"] >= 1
print("ok")
PY
bash tcar/eval/_restart_vsp_structured_pilot.sh
nohup bash tcar/eval/_reaudit_rcm_stages_after.sh \
  > tcar/eval_results/logs/rcm_reaudit_stages.nohup.out 2>&1 &
echo REAUDIT_PID=$!
pgrep -af 'run_rcm_hybrid_offline|run_vsp_structured|mcq_option|_reaudit' | head -12
