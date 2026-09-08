#!/usr/bin/env bash
cd /mnt/c/Users/SK/CTI-Chatbot
source .venv/bin/activate
PYTHONPATH=. python - <<'PY'
import json
from pathlib import Path
from eval.scoring import parse_cwe_answer, parse_mcq_answer, parse_ate_ids, parse_gold_ate, instance_macro_f1, parse_cvss_vector, mad_cvss

ROOT = Path("tcar/eval_results")

def load(p):
    rows = []
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows

files = sorted(ROOT.glob("counterfactual_*20260907Tsol*.jsonl"))
for p in files:
    rows = load(p)
    ok = [r for r in rows if not r.get("error") and ("retrieval_correct" in r or "closed_book_correct" in r)]
    err = [r for r in rows if r.get("error")]
    n = len(ok)
    if n == 0:
        print(f"{p.name}: written={len(rows)} scored=0 errors={len(err)}  (e.g. {err[0].get('error')[:80] if err else 'n/a'})")
        continue
    cb = sum(1 for r in ok if r.get("closed_book_correct")) / n
    rag = sum(1 for r in ok if r.get("retrieval_correct")) / n
    # ATE F1 if possible
    extra = ""
    if ok[0].get("task") == "ate":
        preds, golds = [], []
        for r in ok:
            preds.append(parse_ate_ids(r.get("retrieval_prediction") or ""))
            g = r.get("gold_ids") or parse_gold_ate(str(r.get("gold") or ""))
            golds.append(set(g) if not isinstance(g, set) else g)
        extra = f"  rag_F1={instance_macro_f1(preds, golds):.3f}"
    if ok[0].get("task") == "vsp":
        pv = [parse_cvss_vector(r.get("retrieval_prediction") or "") for r in ok]
        gv = []
        for r in ok:
            g = r.get("gold")
            if isinstance(g, list):
                g = g[0] if g else ""
            gv.append(str(g or ""))
        try:
            extra = f"  rag_MAD={mad_cvss(pv, gv):.3f}"
        except Exception as e:
            extra = f"  mad_err={e}"
    abst = sum(1 for r in ok if (r.get("meta") or {}).get("ata_abstained") or (r.get("meta") or {}).get("abstained"))
    if abst:
        extra += f"  abstain={abst}/{n}"
    print(f"{p.name}: n={n}/{len(rows)}  CB={cb:.1%}  RAG={rag:.1%}  errors={len(err)}{extra}")
PY
