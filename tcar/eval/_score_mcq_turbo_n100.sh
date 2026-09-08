#!/usr/bin/env bash
cd /mnt/c/Users/SK/CTI-Chatbot
source .venv/bin/activate
PYTHONPATH=. python <<'PY'
import json
from pathlib import Path
from collections import Counter

p = Path("tcar/eval_results/counterfactual_ctibench_mcq_20260907Tturbo_mcq_option_aware_n100.jsonl")
rows=[json.loads(l) for l in p.read_text().splitlines() if l.strip()]
ok=[r for r in rows if not r.get("error") and "retrieval_correct" in r]
err=[r.get("error","") for r in rows if r.get("error")]
print(f"total={len(rows)} ok={len(ok)} errors={len(err)}")
print("err_types", Counter((e.split(':')[0][:50] for e in err)).most_common(5))
if ok:
    cb=sum(1 for r in ok if r["closed_book_correct"])/len(ok)
    rag=sum(1 for r in ok if r["retrieval_correct"])/len(ok)
    resc=sum(1 for r in ok if (not r["closed_book_correct"]) and r["retrieval_correct"])
    dmg=sum(1 for r in ok if r["closed_book_correct"] and not r["retrieval_correct"])
    print(f"option_aware turbo: n={len(ok)} CB={cb:.1%} RAG={rag:.1%} Δ={(rag-cb)*100:+.1f}pp rescue={resc} dmg={dmg}")

# matched vs Forced turbo baseline first ids
base=Path("tcar/eval_results/counterfactual_ctibench_mcq_20260902Ttask_prompts_cb.jsonl")
B={}
for line in base.read_text().splitlines():
    if not line.strip(): continue
    r=json.loads(line)
    if r.get("error") or "retrieval_correct" not in r: continue
    B[r["id"]]=r
ids=[r["id"] for r in ok if r["id"] in B]
if ids:
    print(f"matched n={len(ids)}")
    print(f"  Forced RAG={sum(1 for i in ids if B[i]['retrieval_correct'])/len(ids):.1%}  option_aware RAG={sum(1 for i in ids if next(x for x in ok if x['id']==i)['retrieval_correct'])/len(ids):.1%}")
    print(f"  Forced CB={sum(1 for i in ids if B[i]['closed_book_correct'])/len(ids):.1%}")
    O={r["id"]:r for r in ok}
    better=sum(1 for i in ids if O[i]["retrieval_correct"] and not B[i]["retrieval_correct"])
    worse=sum(1 for i in ids if B[i]["retrieval_correct"] and not O[i]["retrieval_correct"])
    print(f"  option_aware helps={better} hurts={worse} net={better-worse}")
PY
