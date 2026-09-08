#!/usr/bin/env bash
cd /mnt/c/Users/SK/CTI-Chatbot
source .venv/bin/activate
PYTHONPATH=. python - <<'PY'
import json
from pathlib import Path
from collections import Counter

ROOT = Path("tcar/eval_results")

# Full Forced RAG sol CTIBench (known good stamp)
stamps = {
    "sol_forced_cb": "20260904Tgpt56sol_forced_rag_cb",
    "sol_forced_cc": "20260906Tgpt56sol_forced_rag_v3_cc",
    "sol_soft_cb": "20260906Tgpt56sol_soft_gad_cb",
    "mini_forced_cc": "20260907Tgpt54mini_forced_rag_cc",
    "mini_soft_cc": "20260907Tgpt54mini_soft_gad_cc",
}
for name, stamp in stamps.items():
    p = ROOT / f"counterfactual_summary_{stamp}.json"
    if not p.exists():
        print(f"{name}: missing summary")
        continue
    d = json.loads(p.read_text())
    print(f"\n=== {name} model={d.get('model')} ===")
    for k, v in (d.get("tasks") or {}).items():
        print(f"  {k}: n={v.get('n')} CB={v.get('closed_book_score'):.3f} RAG={v.get('forced_rag_score'):.3f} metric={v.get('metric')}")

# Mini jsonl progress
print("\n=== mini jsonl counts ===")
for p in sorted(ROOT.glob("counterfactual_*gpt54mini*.jsonl")):
    rows=[json.loads(l) for l in p.read_text().splitlines() if l.strip()]
    ok=[r for r in rows if not r.get("error") and "retrieval_correct" in r]
    err=sum(1 for r in rows if r.get("error"))
    if ok:
        cb=sum(1 for r in ok if r["closed_book_correct"])/len(ok)
        rag=sum(1 for r in ok if r["retrieval_correct"])/len(ok)
        print(f"{p.name}: n={len(ok)}/{len(rows)} CB={cb:.1%} RAG={rag:.1%} err={err}")
    else:
        print(f"{p.name}: n=0/{len(rows)} err={err}")

# Specialist sol progress + error types
print("\n=== specialist sol error types ===")
for p in sorted(ROOT.glob("counterfactual_*20260907Tsol*.jsonl")):
    rows=[json.loads(l) for l in p.read_text().splitlines() if l.strip()]
    ok=[r for r in rows if not r.get("error") and "retrieval_correct" in r]
    errs=[r.get("error","") for r in rows if r.get("error")]
    top=Counter(e.split(":")[0][:60] for e in errs).most_common(3)
    if ok:
        cb=sum(1 for r in ok if r["closed_book_correct"])/len(ok)
        rag=sum(1 for r in ok if r["retrieval_correct"])/len(ok)
        print(f"{p.name}: ok={len(ok)}/{len(rows)} CB={cb:.1%} RAG={rag:.1%} top_err={top}")
    else:
        print(f"{p.name}: ok=0/{len(rows)} top_err={top}")

# turbo CTA scoreboard
sb=Path("tcar/eval_results/scoreboard_ctibench_no_confusion_20260831Tfull5.json")
if sb.exists():
    d=json.loads(sb.read_text())
    print("\n=== turbo CTA scoreboard ===")
    for t,v in (d.get("tasks") or d.get("results") or {}).items():
        if isinstance(v, dict):
            print(t, {k:v.get(k) for k in list(v)[:12]})
PY
