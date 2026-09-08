"""Diagnose ATA grounded n=50: where retrieval helps vs generation fails."""
import json
from collections import Counter
from pathlib import Path

from eval.scoring import parse_ate_ids

p = Path("tcar/eval_results/counterfactual_cticonnect_ata_20260907Tturbo_ata_grounded_n50.jsonl")
rows = [json.loads(l) for l in p.read_text(encoding="utf-8").splitlines() if l.strip()]

# dedupe
by = {str(r["id"]): r for r in rows}
rows = sorted(by.values(), key=lambda r: r["id"])

cb = sum(1 for r in rows if r.get("closed_book_correct"))
rag = sum(1 for r in rows if r.get("retrieval_correct"))
print(f"N={len(rows)} CB={cb}/{len(rows)}={cb/len(rows):.1%} RAG={rag}/{len(rows)}={rag/len(rows):.1%}")
print("effects", Counter(r.get("retrieval_effect") for r in rows))

gold_at5 = sum(1 for r in rows if r.get("retrieval_contains_gold"))
print(f"gold_in_prompt_hits={gold_at5}/{len(rows)}={gold_at5/len(rows):.1%}")
print(f"recall@5 from recall_at field: {sum(1 for r in rows if (r.get('recall_at') or {}).get('5'))}/{len(rows)}")

# Cases: gold retrieved but RAG wrong
gold_hit_rag_wrong = []
gold_miss = []
both_wrong = []
for r in rows:
    g = set(x.upper() for x in (r.get("gold_ids") or []))
    pred = parse_ate_ids(r.get("retrieval_prediction") or "")
    # Connect may need full IDs including subs — parse_ate_ids collapses to main
    # Use raw regex for exact-set diagnosis
    import re
    def ids(text):
        return set(x.upper() for x in re.findall(r"\bT\d{4}(?:\.\d{3})?\b", text or "", flags=re.I))
    # Prefer answer line
    raw = r.get("retrieval_prediction") or ""
    m = re.search(r"(?im)^answer\s*:(.+)$", raw)
    pred_full = ids(m.group(1) if m else raw)
    cb_raw = r.get("closed_book_prediction") or ""
    m2 = re.search(r"(?im)^answer\s*:(.+)$", cb_raw)
    cb_full = ids(m2.group(1) if m2 else cb_raw)

    meta = r.get("tcar_meta") or {}
    div = meta.get("diversify") or {}
    grounded = div.get("grounded_ids") or meta.get("grounded_ids") or []
    n_beh = div.get("n_behaviors") or meta.get("n_behaviors")
    abstain = meta.get("ata_abstain_to_cb")

    rec = {
        "id": r["id"],
        "gold": sorted(g),
        "pred": sorted(pred_full),
        "cb": sorted(cb_full),
        "gold_in_ret": r.get("retrieval_contains_gold"),
        "retrieved": r.get("retrieved_ids"),
        "grounded": grounded,
        "n_beh": n_beh,
        "effect": r.get("retrieval_effect"),
        "abstain_cb": abstain,
        "cb_ok": r.get("closed_book_correct"),
        "rag_ok": r.get("retrieval_correct"),
    }
    if r.get("retrieval_contains_gold") and not r.get("retrieval_correct"):
        gold_hit_rag_wrong.append(rec)
    if not r.get("retrieval_contains_gold"):
        gold_miss.append(rec)
    if not r.get("closed_book_correct") and not r.get("retrieval_correct"):
        both_wrong.append(rec)

print(f"\n--- FAILURE MODES ---")
print(f"gold_retrieved_but_RAG_wrong: {len(gold_hit_rag_wrong)}")
print(f"gold_NOT_in_retrieved: {len(gold_miss)}")
print(f"both_CB_and_RAG_wrong: {len(both_wrong)}")

# parent/sub confusion
parent_sub = 0
for rec in gold_hit_rag_wrong:
    g, pred = set(rec["gold"]), set(rec["pred"])
    for gid in g:
        main = gid.split(".")[0]
        if gid in pred:
            continue
        if main in pred or any(p.startswith(main + ".") for p in pred):
            parent_sub += 1
            break
print(f"among gold-hit-RAG-wrong, parent/sub-ish: {parent_sub}")

print("\n--- sample gold-hit RAG-wrong (up to 8) ---")
for rec in gold_hit_rag_wrong[:8]:
    print(
        f"{rec['id']}: gold={rec['gold']} pred={rec['pred']} cb={rec['cb']} "
        f"grounded={rec['grounded']} n_beh={rec['n_beh']} effect={rec['effect']} abstain={rec['abstain_cb']}"
    )

print("\n--- behavior counts ---")
beh_c = Counter()
for r in rows:
    meta = r.get("tcar_meta") or {}
    div = meta.get("diversify") or {}
    beh_c[div.get("n_behaviors") or meta.get("n_behaviors")] += 1
print(beh_c)

print("\n--- abstain to CB ---")
abs_n = sum(1 for r in rows if (r.get("tcar_meta") or {}).get("ata_abstain_to_cb"))
print("abstain_to_cb", abs_n)
