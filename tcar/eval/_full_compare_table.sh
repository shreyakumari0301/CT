#!/usr/bin/env bash
cd /mnt/c/Users/SK/CTI-Chatbot
source .venv/bin/activate
PYTHONPATH=. python - <<'PY'
import json
from pathlib import Path
from eval.scoring import parse_ate_ids, parse_gold_ate, instance_macro_f1, parse_cvss_vector, mad_cvss

ROOT = Path("tcar/eval_results")

def score_jsonl(path, task_hint=None):
    rows=[json.loads(l) for l in Path(path).read_text().splitlines() if l.strip()]
    ok=[r for r in rows if not r.get("error") and "retrieval_correct" in r]
    if not ok:
        return None
    task = task_hint or ok[0].get("task")
    n=len(ok)
    cb=sum(1 for r in ok if r.get("closed_book_correct"))/n
    rag=sum(1 for r in ok if r.get("retrieval_correct"))/n
    extra={}
    if task=="ate":
        golds=[]; pcb=[]; prag=[]
        for r in ok:
            g=set(r.get("gold_ids") or parse_gold_ate(str(r.get("gold") or "")))
            golds.append(g)
            pcb.append(parse_ate_ids(r.get("closed_book_prediction") or ""))
            prag.append(parse_ate_ids(r.get("retrieval_prediction") or ""))
        extra["cb_f1"]=instance_macro_f1(pcb,golds)
        extra["rag_f1"]=instance_macro_f1(prag,golds)
    if task=="vsp":
        try:
            pv=[parse_cvss_vector(r.get("retrieval_prediction") or "") for r in ok]
            gv=[]
            for r in ok:
                g=r.get("gold")
                if isinstance(g,list): g=g[0] if g else ""
                gv.append(str(g or ""))
            extra["rag_mad"]=mad_cvss(pv,gv)
            cbv=[parse_cvss_vector(r.get("closed_book_prediction") or "") for r in ok]
            extra["cb_mad"]=mad_cvss(cbv,gv)
        except Exception as e:
            extra["mad_err"]=str(e)
    return {"n":n,"total":len(rows),"cb":cb,"rag":rag,**extra}

# Known Forced RAG sol CTIBench files
candidates = [
    ("sol Forced RCM", "counterfactual_ctibench_rcm_20260904Tgpt56sol_forced_rag_cb.jsonl"),
    ("sol Forced MCQ", "counterfactual_ctibench_mcq_20260904Tgpt56sol_forced_rag_cb.jsonl"),
    ("sol Forced VSP", "counterfactual_ctibench_vsp_20260904Tgpt56sol_forced_rag_cb.jsonl"),
    ("sol Forced ATE", "counterfactual_ctibench_ate_20260904Tgpt56sol_forced_rag_cb.jsonl"),
    ("sol Soft MCQ", "counterfactual_ctibench_mcq_20260906Tgpt56sol_soft_gad_cb.jsonl"),
    ("sol Soft VSP", "counterfactual_ctibench_vsp_20260906Tgpt56sol_soft_gad_cb.jsonl"),
    ("sol Soft ATE", "counterfactual_ctibench_ate_20260906Tgpt56sol_soft_gad_cb.jsonl"),
    ("sol Forced ATA v3", "counterfactual_cticonnect_ata_20260906Tgpt56sol_forced_rag_v3_cc.jsonl"),
    ("sol Forced ATA", "counterfactual_cticonnect_ata_20260906Tgpt56sol_forced_rag_cc.jsonl"),
]
# also glob any forced rag sol
for p in sorted(ROOT.glob("counterfactual_*gpt56sol_forced*.jsonl")):
    label=f"sol {p.name.replace('counterfactual_','').replace('.jsonl','')}"
    if not any(c[1]==p.name for c in candidates):
        candidates.append((label, p.name))

print("=== SOL Forced / Soft (complete-ish) ===")
for label, name in candidates:
    p = ROOT/name
    if not p.exists():
        continue
    s=score_jsonl(p)
    if not s: 
        print(f"{label}: empty/errors only n={sum(1 for _ in p.open())}")
        continue
    extra=""
    if "rag_f1" in s: extra=f"  F1 CB={s['cb_f1']:.3f} RAG={s['rag_f1']:.3f}"
    if "rag_mad" in s: extra=f"  MAD CB={s.get('cb_mad')} RAG={s['rag_mad']:.3f}"
    print(f"{label}: n={s['n']}/{s['total']} CB={s['cb']:.1%} RAG={s['rag']:.1%}{extra}")

# Paper turbo CTA reference already known
print("\n=== Paper CTA-RAG gpt-4-turbo (router headline) ===")
print("MCQ Acc .752 | RCM Acc .781 | VSP MAD 1.06 | ATE F1 .945")
print("oracle_cta_rag_reference in scoreboard: MCQ .781 RCM .781 VSP 1.06 ATE .9451")

# processes
import subprocess
out=subprocess.check_output(["bash","-lc","pgrep -af 'run_counterfactual|gpt54mini' || true"], text=True)
print("\n=== running ===")
print(out[:1500])
PY
