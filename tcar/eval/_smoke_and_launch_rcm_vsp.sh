#!/usr/bin/env bash
set -euo pipefail
cd /mnt/c/Users/SK/CTI-Chatbot
source .venv/bin/activate
PYTHONPATH=. python - <<'PY'
from tcar.rcm_mechanism_hybrid import normalize_rcm_mechanism_query, CweHybridRetriever, rcm_pipeline_mode
from tcar.vsp_structured_decoder import extract_vsp_facts_rulebased, facts_to_cvss_vector, decode_vsp_prediction
q = "Product X allows remote attackers to read arbitrary files through crafted ../ sequences."
print("mech:", normalize_rcm_mechanism_query(q))
h = CweHybridRetriever.get()
hits = h.bm25_retrieve(normalize_rcm_mechanism_query(q), k=5)
print("bm25 top:", [x.doc_id for x in hits])
f = extract_vsp_facts_rulebased("An unauthenticated remote attacker can cause a denial of service by sending crafted packets.")
print("vsp:", facts_to_cvss_vector(f), f)
raw = '{"attack_location":"network","attack_conditions":"no special condition","required_privileges":"none","user_interaction":"none","scope_change":false,"confidentiality_impact":"none","integrity_impact":"none","availability_impact":"high","uncertain":[]}'
print(decode_vsp_prediction(raw, description="dos"))
print("ok")
PY
chmod +x tcar/eval/_launch_rcm_vsp_specialists.sh tcar/eval/_job_*.sh
bash tcar/eval/_launch_rcm_vsp_specialists.sh
