#!/usr/bin/env bash
cd /mnt/c/Users/SK/CTI-Chatbot
source .venv/bin/activate
PYTHONPATH=. python <<'PY'
import json
from pathlib import Path
from collections import Counter

ROOT = Path("tcar/eval_results")

def score(path):
    rows = [json.loads(l) for l in Path(path).read_text(encoding="utf-8", errors="replace").splitlines() if l.strip()]
    ok = [r for r in rows if not r.get("error") and "retrieval_correct" in r]
    err = [r.get("error","") for r in rows if r.get("error")]
    if not ok:
        return {"n_ok":0,"n":len(rows),"err":Counter(e.split(":")[0][:40] for e in err).most_common(2)}
    n=len(ok)
    cb=sum(1 for r in ok if r["closed_book_correct"])/n
    rag=sum(1 for r in ok if r["retrieval_correct"])/n
    # rescues/damages
    resc=sum(1 for r in ok if (not r["closed_book_correct"]) and r["retrieval_correct"])
    dmg=sum(1 for r in ok if r["closed_book_correct"] and (not r["retrieval_correct"]))
    # gold@5 if present
    g5=None
    if any("retrieval_audit" in r or "audit" in r for r in ok):
        pass
    gold_at5 = []
    for r in ok:
        audit = r.get("retrieval_audit") or r.get("audit") or {}
        if isinstance(audit, dict) and "gold_at_5" in audit:
            gold_at5.append(bool(audit["gold_at_5"]))
        elif isinstance(audit, dict) and "recall_at_5" in audit:
            gold_at5.append(bool(audit["recall_at_5"]))
        meta = r.get("meta") or {}
        ost = meta.get("rcm_oracle_stats") or {}
        if "gold_at_n" in ost:
            # this is usually @20 pool
            pass
        if "gold_rank" in ost and ost["gold_rank"] is not None:
            gold_at5.append(ost["gold_rank"] <= 5)
    out={
        "n_ok":n,"n":len(rows),"cb":cb,"rag":rag,"dpp":rag-cb,
        "rescues":resc,"damages":dmg,
        "err_top":Counter(e.split(":")[0][:40] for e in err).most_common(2),
    }
    if gold_at5:
        out["gold_in_promptish"]=sum(gold_at5)/len(gold_at5)
    return out

print("=== CTIBench RCM runs ===")
bench_files = [
    ("Forced sol (fullish)", "counterfactual_ctibench_rcm_20260904Tgpt56sol_forced_rag_cb.jsonl"),
    ("Soft GAD sol", "counterfactual_ctibench_rcm_20260906Tgpt56sol_soft_gad_cb.jsonl"),
    ("Force GAD sol", "counterfactual_ctibench_rcm_20260904Tgpt56sol_force_gad_cb.jsonl"),
    ("Taxonomy rerank (partial)", "counterfactual_ctibench_rcm_20260907Tsol_rcm_taxonomy_rerank.jsonl"),
    ("Gold pin (partial)", "counterfactual_ctibench_rcm_20260907Tsol_rcm_gold_pin.jsonl"),
    ("Learned rerank (partial)", "counterfactual_ctibench_rcm_20260907Tsol_rcm_learned_rerank.jsonl"),
    ("Mini Soft GAD tiny", "counterfactual_ctibench_rcm_20260907Tgpt54mini_soft_gad_cb.jsonl"),
]
for label, name in bench_files:
    p = ROOT/name
    if not p.exists():
        # try glob
        hits=list(ROOT.glob(name.replace(".jsonl","*.jsonl")))
        if not hits:
            print(f"{label}: MISSING")
            continue
        p=hits[0]
    s=score(p)
    if s["n_ok"]==0:
        print(f"{label}: n=0/{s['n']} err={s.get('err')}")
        continue
    print(f"{label}: n={s['n_ok']}/{s['n']}  CB={s['cb']:.1%}  RAG={s['rag']:.1%}  Δ={s['dpp']*100:+.1f}pp  rescue={s['rescues']} dmg={s['damages']}  err={s['err_top']}")

# summaries
print("\n=== Summaries (if any) ===")
for p in sorted(ROOT.glob("counterfactual_summary_*rcm*")) + sorted(ROOT.glob("counterfactual_summary_*forced*cb*.json")):
    try:
        d=json.loads(p.read_text())
    except Exception:
        continue
    for k,v in (d.get("tasks") or {}).items():
        if "rcm" not in k: continue
        print(f"{p.name} | {k}: n={v.get('n')} CB={v.get('closed_book_score'):.3f} RAG={v.get('forced_rag_score'):.3f} Δ={v.get('score_delta'):+.3f} rescues={v.get('rescues')} damages={v.get('damages')}")

print("\n=== CTIConnect RCM ===")
conn = [
    ("Forced sol", "counterfactual_cticonnect_rcm_20260906Tgpt56sol_forced_rag_cc.jsonl"),
    ("Forced sol v3", "counterfactual_cticonnect_rcm_20260906Tgpt56sol_forced_rag_v3_cc.jsonl"),
    ("Soft GAD sol", "counterfactual_cticonnect_rcm_20260906Tgpt56sol_soft_gad_cc.jsonl"),
    ("Mini Forced", "counterfactual_cticonnect_rcm_20260907Tgpt54mini_forced_rag_cc.jsonl"),
    ("Mini Soft", "counterfactual_cticonnect_rcm_20260907Tgpt54mini_soft_gad_cc.jsonl"),
]
# soft may have different stamp
for p in sorted(ROOT.glob("counterfactual_cticonnect_rcm_*.jsonl")):
    label=p.name
    s=score(p)
    if s["n_ok"]==0:
        print(f"{label}: n=0/{s['n']}")
        continue
    print(f"{label}: n={s['n_ok']}/{s['n']}  CB={s['cb']:.1%}  RAG={s['rag']:.1%}  Δ={s['dpp']*100:+.1f}pp  rescue={s['rescues']} dmg={s['damages']}")

print("\n=== Oracle retrieval-only ===")
for p in sorted(ROOT.glob("rcm_oracle_top20_*.json")):
    print(p.name, p.read_text()[:500])

# Compare taxonomy vs forced on matched IDs if possible
print("\n=== Matched-ID: Forced vs Taxonomy (overlap) ===")
forced=ROOT/"counterfactual_ctibench_rcm_20260904Tgpt56sol_forced_rag_cb.jsonl"
tax=ROOT/"counterfactual_ctibench_rcm_20260907Tsol_rcm_taxonomy_rerank.jsonl"
if forced.exists() and tax.exists():
    F={json.loads(l)["id"]:json.loads(l) for l in forced.read_text().splitlines() if l.strip()}
    T={json.loads(l)["id"]:json.loads(l) for l in tax.read_text().splitlines() if l.strip()}
    ids=[i for i in T if i in F and not T[i].get("error") and not F[i].get("error") and "retrieval_correct" in T[i] and "retrieval_correct" in F[i]]
    if ids:
        f_rag=sum(1 for i in ids if F[i]["retrieval_correct"])/len(ids)
        t_rag=sum(1 for i in ids if T[i]["retrieval_correct"])/len(ids)
        f_cb=sum(1 for i in ids if F[i]["closed_book_correct"])/len(ids)
        print(f"matched n={len(ids)}  Forced RAG={f_rag:.1%}  Taxonomy RAG={t_rag:.1%}  CB(forced)={f_cb:.1%}")
        better=sum(1 for i in ids if T[i]["retrieval_correct"] and not F[i]["retrieval_correct"])
        worse=sum(1 for i in ids if F[i]["retrieval_correct"] and not T[i]["retrieval_correct"])
        print(f"taxonomy helps={better} hurts={worse} net={better-worse}")

print("\n=== Matched-ID: Forced vs Gold_pin ===")
pin=ROOT/"counterfactual_ctibench_rcm_20260907Tsol_rcm_gold_pin.jsonl"
if forced.exists() and pin.exists():
    P={json.loads(l)["id"]:json.loads(l) for l in pin.read_text().splitlines() if l.strip()}
    F={json.loads(l)["id"]:json.loads(l) for l in forced.read_text().splitlines() if l.strip()}
    ids=[i for i in P if i in F and not P[i].get("error") and not F[i].get("error") and "retrieval_correct" in P[i] and "retrieval_correct" in F[i]]
    if ids:
        print(f"matched n={len(ids)} Forced={sum(1 for i in ids if F[i]['retrieval_correct'])/len(ids):.1%} GoldPin={sum(1 for i in ids if P[i]['retrieval_correct'])/len(ids):.1%}")
        better=sum(1 for i in ids if P[i]["retrieval_correct"] and not F[i]["retrieval_correct"])
        worse=sum(1 for i in ids if F[i]["retrieval_correct"] and not P[i]["retrieval_correct"])
        print(f"gold_pin helps={better} hurts={worse} net={better-worse}")
PY
