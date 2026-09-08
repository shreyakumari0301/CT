#!/usr/bin/env bash
cd /mnt/c/Users/SK/CTI-Chatbot
source .venv/bin/activate
echo "=== PROCS ==="
pgrep -af 'run_counterfactual|mcq_option' || echo none
echo
echo "=== V2 LOG TAIL ==="
if [[ -f tcar/eval_results/logs/mcq_option_aware_turbo_v2.log ]]; then
  tail -c 800 tcar/eval_results/logs/mcq_option_aware_turbo_v2.log | tr '\r' '\n' | tail -12
fi
echo
PYTHONPATH=. python - <<'PY'
import json
from collections import Counter
from pathlib import Path

def score(path, label):
    p = Path(path)
    if not p.exists():
        print(f"{label}: NO FILE")
        return
    by = {}
    for line in p.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        r = json.loads(line)
        by[str(r.get("id"))] = r
    rows = list(by.values())
    n = len(rows)
    if not n:
        print(f"{label}: empty")
        return
    cb = sum(1 for r in rows if r.get("closed_book_correct")) / n
    rag = sum(1 for r in rows if r.get("retrieval_correct")) / n
    eff = Counter(r.get("retrieval_effect") for r in rows)
    meta = rows[0].get("tcar_meta") or {}
    print(
        f"{label}: n={n}  CB={cb:.1%}  RAG={rag:.1%}  Δ={rag-cb:+.1%}  "
        f"R/D={eff.get('rescue',0)}/{eff.get('damage',0)}  "
        f"retrieval={meta.get('mcq_retrieval')} abstain={meta.get('mcq_abstain')} style={meta.get('prompt_style')}"
    )

score("tcar/eval_results/counterfactual_ctibench_mcq_20260907Tturbo_mcq_option_aware_v2.jsonl", "MCQ v2 (fixed OA)")
score("tcar/eval_results/counterfactual_ctibench_mcq_20260907Tturbo_mcq_option_aware_full.jsonl", "MCQ broken-OA full (baseline)")
score("tcar/eval_results/counterfactual_ctibench_mcq_20260907Tturbo_mcq_option_aware_n100.jsonl", "MCQ n100 pilot")
score("tcar/eval_results/counterfactual_cticonnect_ata_20260907Tturbo_ata_grounded_n50.jsonl", "ATA grounded n50")

for s in Path("tcar/eval_results").glob("counterfactual_summary_20260907Tturbo*.json"):
    d = json.loads(s.read_text())
    for k, t in (d.get("tasks") or {}).items():
        print(f"SUMMARY {s.name}: {k} n={t.get('n')} CB={t.get('closed_book_score')} RAG={t.get('forced_rag_score')}")
PY
