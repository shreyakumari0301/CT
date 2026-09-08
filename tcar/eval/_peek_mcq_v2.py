#!/usr/bin/env python3
import json
from pathlib import Path

p = Path("tcar/eval_results/counterfactual_ctibench_mcq_20260907Tturbo_mcq_option_aware_v2.jsonl")
rows = [json.loads(l) for l in p.read_text().splitlines() if l.strip()]
print("n", len(rows))
r = rows[0]
print("keys", sorted(r.keys()))
print("meta", sorted((r.get("tcar_meta") or {}).keys()))
# damage
for x in rows:
    if x.get("closed_book_correct") and not x.get("retrieval_correct"):
        print("DAMAGE", x["id"], "effect", x.get("retrieval_effect"))
        print("gold", x.get("gold"))
        print("cb_pred", (x.get("closed_book_prediction") or "")[:200])
        print("rag_pred", (x.get("retrieval_prediction") or "")[:200])
        print("retrieved_ids", x.get("retrieved_ids"))
        print("meta", json.dumps(x.get("tcar_meta"), indent=2)[:3000])
        print("q", (x.get("question") or x.get("question_preview") or "")[:400])
        break
# counts
d = sum(1 for x in rows if x.get("closed_book_correct") and not x.get("retrieval_correct"))
rs = sum(1 for x in rows if (not x.get("closed_book_correct")) and x.get("retrieval_correct"))
bw = sum(1 for x in rows if (not x.get("closed_book_correct")) and (not x.get("retrieval_correct")))
nc = sum(1 for x in rows if x.get("closed_book_correct") and x.get("retrieval_correct"))
print("damages", d, "rescues", rs, "both_wrong", bw, "neutral_correct", nc)
