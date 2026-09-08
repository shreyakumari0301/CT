#!/usr/bin/env bash
cd /mnt/c/Users/SK/CTI-Chatbot
source .venv/bin/activate
PYTHONPATH=. python - <<'PY'
import json
from pathlib import Path
from eval.scoring import parse_ate_ids, parse_gold_ate, instance_macro_f1

p = Path("tcar/eval_results/counterfactual_ctibench_ate_20260907Tsol_ate_cta_fidelity.jsonl")
rows = [json.loads(l) for l in p.read_text().splitlines() if l.strip()]
errs = [r for r in rows if r.get("error")]
ok = [r for r in rows if not r.get("error") and "retrieval_prediction" in r]
print(f"total={len(rows)} ok={len(ok)} errors={len(errs)}")
if errs:
    from collections import Counter
    print("error_types", Counter(e.get("error","").split(":")[0] for e in errs).most_common(5))
    print("sample", errs[0].get("error")[:200])

preds_cb, preds_rag, golds = [], [], []
for r in ok:
    g = r.get("gold_ids")
    if not g:
        g = parse_gold_ate(str(r.get("gold") or ""))
    g = set(g)
    golds.append(g)
    preds_cb.append(parse_ate_ids(r.get("closed_book_prediction") or ""))
    preds_rag.append(parse_ate_ids(r.get("retrieval_prediction") or ""))
print(f"mean_F1 CB={instance_macro_f1(preds_cb, golds):.3f} RAG={instance_macro_f1(preds_rag, golds):.3f}")
exact_cb = sum(1 for a,b in zip(preds_cb,golds) if a==b)/len(ok)
exact_rag = sum(1 for a,b in zip(preds_rag,golds) if a==b)/len(ok)
print(f"exact CB={exact_cb:.3f} RAG={exact_rag:.3f}")
PY
