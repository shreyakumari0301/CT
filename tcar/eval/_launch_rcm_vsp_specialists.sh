#!/usr/bin/env bash
# Parallel launch: RCM hybrid offline + VSP audit + VSP structured pilot.
# RCM turbo n=200 auto-starts only if hybrid gold@20 substantially beats 54.2%.
set -euo pipefail
cd /mnt/c/Users/SK/CTI-Chatbot
source .venv/bin/activate
mkdir -p tcar/eval_results/logs

eval "$(PYTHONPATH=. python - <<'PY'
from pathlib import Path
from dotenv import dotenv_values
vals = dotenv_values(Path('.env'))
for k in ['OPENAI_API_KEY', 'USE_OPENROUTER']:
    v = vals.get(k)
    if v is None or str(v).strip() == '':
        continue
    v = str(v).strip().replace('\\', '\\\\').replace('"', '\\"')
    print(f'export {k}="{v}"')
print('export GENERATION_MODEL="gpt-4-turbo"')
PY
)"
unset OPENAI_BASE_URL OPENROUTER_API_KEY || true
export USE_OPENROUTER=0 GENERATION_MODEL=gpt-4-turbo MODEL=gpt-4-turbo

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] launch RCM offline + VSP audit + VSP structured pilot"

# 1) RCM offline hybrid audit → gated n=200 pilot
nohup bash /mnt/c/Users/SK/CTI-Chatbot/tcar/eval/_job_rcm_offline_then_pilot.sh \
  > tcar/eval_results/logs/rcm_hybrid_offline_and_gate.nohup.out 2>&1 &
echo "RCM_OFFLINE_PID=$!"

# 2) VSP per-metric audit
nohup bash /mnt/c/Users/SK/CTI-Chatbot/tcar/eval/_job_vsp_audit.sh \
  > tcar/eval_results/logs/vsp_per_metric_audit.nohup.out 2>&1 &
echo "VSP_AUDIT_PID=$!"

# 3) VSP structured pilot on the same ~75 metric_wise OK IDs
nohup bash /mnt/c/Users/SK/CTI-Chatbot/tcar/eval/_job_vsp_structured_pilot.sh \
  > tcar/eval_results/logs/vsp_structured_n75.nohup.out 2>&1 &
echo "VSP_PILOT_PID=$!"

sleep 3
pgrep -af 'run_rcm_hybrid_offline|run_vsp_per_metric|run_vsp_structured|mcq_option_aware|rcm_hybrid_turbo|_job_rcm|_job_vsp' | head -15
echo done
