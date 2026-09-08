#!/usr/bin/env bash
cd /mnt/c/Users/SK/CTI-Chatbot
source .venv/bin/activate
echo "=== PROCS ==="
pgrep -af 'run_counterfactual|ata_grounded_v2|mcq_option_aware' || echo none
echo
echo "=== ATA v2 ==="
if [[ -f tcar/eval_results/logs/ata_grounded_v2_turbo_n50.log ]]; then
  tail -c 500 tcar/eval_results/logs/ata_grounded_v2_turbo_n50.log | tr '\r' '\n' | tail -6
fi
echo "jsonl: $(wc -l < tcar/eval_results/counterfactual_cticonnect_ata_20260908Tturbo_ata_grounded_v2_n50.jsonl 2>/dev/null || echo 0)"
ls tcar/eval_results/counterfactual_summary_20260908Tturbo_ata_grounded_v2_n50.json 2>/dev/null || echo "ATA summary: not yet"
echo
echo "=== MCQ v2 ==="
if [[ -f tcar/eval_results/logs/mcq_option_aware_turbo_v2.log ]]; then
  tail -c 400 tcar/eval_results/logs/mcq_option_aware_turbo_v2.log | tr '\r' '\n' | tail -5
fi
echo "jsonl lines: $(wc -l < tcar/eval_results/counterfactual_ctibench_mcq_20260907Tturbo_mcq_option_aware_v2.jsonl 2>/dev/null || echo 0)"

PYTHONPATH=. python - <<'PY'
import json
from collections import Counter
from pathlib import Path

def score(path, label, total=None):
    p = Path(path)
    if not p.exists():
        print(f"{label}: NO FILE")
        return
    by = {}
    for line in p.read_text(encoding="utf-8").splitlines():
        if line.strip():
            r = json.loads(line)
            by[str(r["id"])] = r
    rows = list(by.values())
    n = len(rows)
    if not n:
        print(f"{label}: empty")
        return
    cb = sum(1 for r in rows if r.get("closed_book_correct")) / n
    rag = sum(1 for r in rows if r.get("retrieval_correct")) / n
    eff = Counter(r.get("retrieval_effect") for r in rows)
    meta0 = rows[0].get("tcar_meta") or {}
    div = meta0.get("diversify") or {}
    extra = ""
    if "ata" in label.lower():
        # aggregate gold recall if present
        g_raw = g_rrf = g_gr = beh = 0
        for r in rows:
            d = (r.get("tcar_meta") or {}).get("diversify") or {}
            g_raw += int(bool(d.get("gold_in_raw_union")))
            g_rrf += int(bool(d.get("gold_in_rrf")))
            g_gr += int(bool(d.get("gold_in_grounded")))
            beh += int(d.get("n_behaviors") or 0)
        extra = (
            f"  gold_raw={g_raw/n:.0%} gold_rrf={g_rrf/n:.0%} gold_grounded={g_gr/n:.0%}"
            f"  mean_n_beh={beh/n:.2f}"
        )
    prog = f"/{total}" if total else ""
    print(
        f"{label}: n={n}{prog}  CB={cb:.1%}  RAG={rag:.1%}  Δ={rag-cb:+.1%}  "
        f"R/D={eff.get('rescue',0)}/{eff.get('damage',0)}{extra}"
    )

score("tcar/eval_results/counterfactual_cticonnect_ata_20260908Tturbo_ata_grounded_v2_n50.jsonl", "ATA grounded v2", 50)
score("tcar/eval_results/counterfactual_ctibench_mcq_20260907Tturbo_mcq_option_aware_v2.jsonl", "MCQ option-aware v2", 2500)
# finished summaries
for s in sorted(Path("tcar/eval_results").glob("counterfactual_summary_2026090*.json")):
    if "ata_grounded" in s.name or "mcq_option" in s.name:
        d = json.loads(s.read_text())
        for k, t in (d.get("tasks") or {}).items():
            print(f"SUMMARY {s.name}: {k} n={t.get('n')} CB={t.get('closed_book_score')} RAG={t.get('forced_rag_score')}")
PY
