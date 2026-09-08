"""How often RAG answer-line is exact but full-text extract_ids pollutes score."""
import json
import re
from pathlib import Path
from eval.cticonnect_metrics import score_id_item, extract_ids

rows = [
    json.loads(l)
    for l in Path(
        "tcar/eval_results/counterfactual_cticonnect_ata_20260907Tturbo_ata_grounded_n50.jsonl"
    )
    .read_text(encoding="utf-8")
    .splitlines()
    if l.strip()
]


def answer_ids(text: str):
    m = re.search(r"(?im)^answer\s*:(.+)$", text or "")
    blob = m.group(1) if m else (text or "")
    return {x.upper() for x in re.findall(r"\bT\d{4}(?:\.\d{3})?\b", blob)}


pollute = answer_ok_but_fail = 0
for r in rows:
    raw = r.get("retrieval_prediction") or ""
    item = score_id_item(raw, r["gold"], task="ata")
    ans = answer_ids(raw)
    gold = set(x.upper() for x in (r.get("gold_ids") or []))
    full = extract_ids(raw, "mitre")
    if ans == gold and item.f1 < 1.0 - 1e-9:
        answer_ok_but_fail += 1
        if full - ans:
            pollute += 1
            if answer_ok_but_fail <= 5:
                print(r["id"], "gold", gold, "answer", ans, "extra_in_text", sorted(full - ans), "f1", item.f1)

print(f"\nanswer_line_exact_but_scored_wrong: {answer_ok_but_fail}/{len(rows)}")
print(f"of those with extra IDs in reasoning: {pollute}")

# Recompute Acc if we scored answer-line only
ok = 0
for r in rows:
    ans = answer_ids(r.get("retrieval_prediction") or "")
    gold = set(x.upper() for x in (r.get("gold_ids") or []))
    if ans == gold:
        ok += 1
cb_ok = sum(1 for r in rows if r.get("closed_book_correct"))
print(f"answer-line-only RAG exact: {ok}/{len(rows)}={ok/len(rows):.1%}")
print(f"official-scored RAG: {sum(1 for r in rows if r.get('retrieval_correct'))/len(rows):.1%}")
print(f"official CB: {cb_ok/len(rows):.1%}")
