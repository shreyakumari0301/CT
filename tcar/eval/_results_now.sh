#!/usr/bin/env bash
set -euo pipefail
cd /mnt/c/Users/SK/CTI-Chatbot
source .venv/bin/activate

echo "=== PROCESSES ==="
pgrep -af 'run_counterfactual|ata_grounded|mcq_option_aware_turbo_full' || echo "(none)"

echo
echo "=== ATA LOG TAIL ==="
if [[ -f tcar/eval_results/logs/ata_grounded_turbo_n50.log ]]; then
  tail -c 600 tcar/eval_results/logs/ata_grounded_turbo_n50.log | tr '\r' '\n' | tail -8
fi
echo "ATA jsonl lines: $(wc -l < tcar/eval_results/counterfactual_cticonnect_ata_20260907Tturbo_ata_grounded_n50.jsonl 2>/dev/null || echo 0)"
ls tcar/eval_results/counterfactual_summary_20260907Tturbo_ata_grounded_n50.json 2>/dev/null || echo "ATA summary: not yet"

echo
echo "=== MCQ FULL LOG TAIL ==="
if [[ -f tcar/eval_results/logs/mcq_option_aware_turbo_full.log ]]; then
  tail -c 600 tcar/eval_results/logs/mcq_option_aware_turbo_full.log | tr '\r' '\n' | tail -8
fi
echo "MCQ full jsonl lines: $(wc -l < tcar/eval_results/counterfactual_ctibench_mcq_20260907Tturbo_mcq_option_aware_full.jsonl 2>/dev/null || echo 0)"

PYTHONPATH=. python tcar/eval/_status_three.py

PYTHONPATH=. python - <<'PY'
import json
from collections import Counter
from pathlib import Path

def score(path):
    p = Path(path)
    if not p.exists():
        return None
    rows = [json.loads(l) for l in p.read_text(encoding="utf-8").splitlines() if l.strip()]
    # dedupe by id keep last
    by = {}
    for r in rows:
        by[str(r.get("id"))] = r
    rows = list(by.values())
    n = len(rows)
    if not n:
        return {"n": 0}
    cb = sum(1 for r in rows if r.get("closed_book_correct"))
    rag = sum(1 for r in rows if r.get("retrieval_correct"))
    eff = Counter(r.get("retrieval_effect") for r in rows)
    return {
        "n": n,
        "cb": cb / n,
        "rag": rag / n,
        "delta": (rag - cb) / n,
        "rescues": eff.get("rescue", 0),
        "damages": eff.get("damage", 0),
    }

ata = score("tcar/eval_results/counterfactual_cticonnect_ata_20260907Tturbo_ata_grounded_n50.jsonl")
mcq = score("tcar/eval_results/counterfactual_ctibench_mcq_20260907Tturbo_mcq_option_aware_full.jsonl")
print("\n=== LIVE SCORES ===")
if ata:
    print(f"ATA grounded: n={ata['n']} CB={ata['cb']:.1%} RAG={ata['rag']:.1%} Δ={ata['delta']:+.1%} R/D={ata['rescues']}/{ata['damages']}")
if mcq:
    print(f"MCQ full:     n={mcq['n']} CB={mcq['cb']:.1%} RAG={mcq['rag']:.1%} Δ={mcq['delta']:+.1%} R/D={mcq['rescues']}/{mcq['damages']}")
# summary files
for s in [
    "tcar/eval_results/counterfactual_summary_20260907Tturbo_ata_grounded_n50.json",
    "tcar/eval_results/counterfactual_summary_20260907Tturbo_mcq_option_aware_full.json",
    "tcar/eval_results/counterfactual_summary_20260907Tturbo_mcq_option_aware_n100.json",
]:
    p = Path(s)
    if p.exists():
        d = json.loads(p.read_text())
        for k, t in (d.get("tasks") or {}).items():
            print(f"SUMMARY {p.name}: {k} n={t.get('n')} CB={t.get('closed_book_score')} RAG={t.get('forced_rag_score')}")
PY
