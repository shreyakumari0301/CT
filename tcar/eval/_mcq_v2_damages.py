"""List MCQ v2 damage cases (CB correct, RAG wrong)."""
import json
from pathlib import Path

p = Path("tcar/eval_results/counterfactual_ctibench_mcq_20260907Tturbo_mcq_option_aware_v2.jsonl")
by = {}
for line in p.read_text(encoding="utf-8").splitlines():
    if not line.strip():
        continue
    r = json.loads(line)
    by[str(r["id"])] = r

damages = [r for r in by.values() if r.get("retrieval_effect") == "damage"]
damages = sorted(damages, key=lambda r: int(str(r["id"]).split("-")[-1]) if "-" in str(r["id"]) else 0)

print(f"damages={len(damages)} / unique={len(by)}\n")
for r in damages:
    q = (r.get("question") or r.get("question_preview") or "")
    # shorten question to Question: span if present
    if "**Question:**" in q:
        q = q.split("**Question:**", 1)[1]
    if "**Options:**" in q:
        q = q.split("**Options:**", 1)[0]
    q = " ".join(q.split())[:180]
    gold = r.get("gold")
    meta = r.get("tcar_meta") or {}
    print(f"=== {r['id']} gold={gold} abstain={meta.get('mcq_abstain')} ===")
    print(f"Q: {q}")
    # parse Final Answer from preds
    import re
    def letter(raw):
        m = re.search(r"Final Answer:\s*([A-D])", raw or "", re.I)
        return (m.group(1).upper() if m else "?")
    print(f"CB={letter(r.get('closed_book_prediction'))}  RAG={letter(r.get('retrieval_prediction'))}")
    # brief RAG reason last ~few lines before Final Answer
    rag = r.get("retrieval_prediction") or ""
    lines = [ln.strip() for ln in rag.splitlines() if ln.strip()]
    brief = " | ".join(lines[:2])[:220]
    print(f"RAG reason: {brief}")
    print()
