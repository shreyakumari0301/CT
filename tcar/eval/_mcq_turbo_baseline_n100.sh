#!/usr/bin/env bash
cd /mnt/c/Users/SK/CTI-Chatbot
source .venv/bin/activate
PYTHONPATH=. python <<'PY'
import json
from pathlib import Path

# Turbo Forced baseline (paper Vanilla ablation stamp)
base = Path("tcar/eval_results/counterfactual_ctibench_mcq_20260902Ttask_prompts_cb.jsonl")
rows=[]
for line in base.read_text().splitlines():
    if not line.strip():
        continue
    r=json.loads(line)
    if r.get("error"):
        continue
    if "retrieval_correct" not in r:
        continue
    rows.append(r)
    if len(rows)>=100:
        break
n=len(rows)
cb=sum(1 for r in rows if r["closed_book_correct"])/n
rag=sum(1 for r in rows if r["retrieval_correct"])/n
print(f"turbo Forced baseline first-{n}: CB={cb:.1%} RAG={rag:.1%} (stamp 20260902Ttask_prompts)")
print("Expected option_aware lift vs this Forced RAG: about +2 to +5 pp Acc (sol saw ~+3 pp Forced→option partial).")
print("vs paper CTA turbo full MCQ .752: option_aware Forced is a CF ablation; CTA E2E may differ.")
print("n=100 SE ~ ±5 pp — treat as directional.")
PY
