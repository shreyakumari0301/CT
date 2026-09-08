#!/usr/bin/env bash
cd /mnt/c/Users/SK/CTI-Chatbot
source .venv/bin/activate
echo PROCS:
pgrep -af 'ata_grounded_v2_full|turbo_ata_grounded_v2_full' || echo '(not running)'
echo
PYTHONPATH=. python - <<'PY'
import json
from pathlib import Path

dst = Path("tcar/eval_results/counterfactual_cticonnect_ata_20260908Tturbo_ata_grounded_v2_full.jsonl")
data = Path("CTICONNECT data/data/entity_attribution/ata.jsonl")
n_data = sum(1 for _ in data.open(encoding="utf-8") if _.strip())
by = {}
errs = []
for line in dst.read_text(encoding="utf-8").splitlines():
    if not line.strip():
        continue
    r = json.loads(line)
    rid = str(r.get("id"))
    by[rid] = r
    if r.get("error"):
        errs.append(rid)
print("dataset_n", n_data)
print("unique_done", len(by))
print("errors", len(errs), errs[:10])
print("missing", n_data - len(by))
sum_path = Path("tcar/eval_results/counterfactual_summary_20260908Tturbo_ata_grounded_v2_full.json")
if sum_path.exists():
    s = json.loads(sum_path.read_text())["tasks"]["cticonnect/ata"]
    print("summary_n", s.get("n"), "CB", s.get("closed_book_score"), "RAG", s.get("forced_rag_score"))
else:
    print("summary: none")
# show last log lines
PY
echo LOG:
tail -c 600 tcar/eval_results/logs/ata_grounded_v2_turbo_full.log 2>/dev/null | tr '\r' '\n' | tail -15
