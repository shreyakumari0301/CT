"""ATA v3 offline: exactly-one-ID rescore + list 25 grounding losses (no API)."""
from __future__ import annotations

import json
from pathlib import Path

from eval.cticonnect_metrics import score_id_item
from tcar.ata_behavior_grounded import cleanup_ata_prediction, parse_full_technique_ids

SRC = Path("tcar/eval_results/counterfactual_cticonnect_ata_20260908Tturbo_ata_grounded_v2_full.jsonl")
rows = [json.loads(l) for l in SRC.read_text(encoding="utf-8").splitlines() if l.strip()]
n = len(rows)

official = sum(1 for r in rows if r.get("retrieval_correct"))
cb = sum(1 for r in rows if r.get("closed_book_correct"))

# Exactly-one: take first predicted ID only, wrap as predicted_id JSON
one_ok = 0
forced = 0
for r in rows:
    ids = parse_full_technique_ids(r.get("retrieval_prediction") or "")
    if len(ids) > 1:
        forced += 1
    single = ids[:1]
    raw = json.dumps({"predicted_id": single[0]}) if single else "{}"
    # also run through cleanup with allowed
    div = (r.get("tcar_meta") or {}).get("diversify") or {}
    allowed = div.get("grounded_ids") or r.get("retrieved_ids") or []
    cleaned, kept, meta = cleanup_ata_prediction(
        r.get("retrieval_prediction") or "", allowed_ids=allowed
    )
    use = cleaned if kept else raw
    item = score_id_item(use if kept else raw, r["gold"], task="ata")
    if item.f1 >= 1.0 - 1e-9:
        one_ok += 1

print("=== EXACTLY-ONE OFFLINE RESCORE ===")
print(f"n={n} CB={cb/n:.1%} official_RAG={official/n:.1%}")
print(f"exactly-one (cleanup) Acc={one_ok/n:.1%} ({one_ok}/{n})")
print(f"items with >1 predicted ID in v2 output: {forced}")

# 25 grounding losses
losses = []
for r in rows:
    d = (r.get("tcar_meta") or {}).get("diversify") or {}
    if d.get("gold_in_rrf") and not d.get("gold_in_grounded"):
        losses.append(
            {
                "id": r["id"],
                "gold": r.get("gold_ids"),
                "n_beh": d.get("n_behaviors"),
                "grounded": d.get("grounded_ids"),
                "rag_ok": r.get("retrieval_correct"),
            }
        )

print(f"\n=== GROUNDING LOSSES (gold in RRF, not grounded) ===")
print(f"count={len(losses)} (target was 25)")
for x in losses[:25]:
    print(f"  {x['id']} gold={x['gold']} n_beh={x['n_beh']} grounded={x['grounded']} rag_ok={x['rag_ok']}")
