"""Offline rescore ATA grounded n=50 with JSON/answer-line hygiene (no API)."""
import json
from pathlib import Path

from eval.cticonnect_metrics import score_id_item
from tcar.ata_behavior_grounded import cleanup_ata_prediction, parse_full_technique_ids, segment_behaviors_rulebased

src = Path("tcar/eval_results/counterfactual_cticonnect_ata_20260907Tturbo_ata_grounded_n50.jsonl")
rows = [json.loads(l) for l in src.read_text(encoding="utf-8").splitlines() if l.strip()]

official_rag = sum(1 for r in rows if r.get("retrieval_correct"))
cb = sum(1 for r in rows if r.get("closed_book_correct"))

# Rescore: take answer/JSON ids only, rebuild JSON prediction, score
hygiene_ok = 0
for r in rows:
    allowed = r.get("retrieved_ids") or (r.get("tcar_meta") or {}).get("ata_kept_ids") or []
    # Prefer grounded_ids from diversify meta
    div = (r.get("tcar_meta") or {}).get("diversify") or {}
    allowed = div.get("grounded_ids") or allowed or r.get("retrieved_ids") or []
    cleaned, kept, meta = cleanup_ata_prediction(r.get("retrieval_prediction") or "", allowed_ids=allowed)
    if not kept:
        # answer-line only without allow filter
        kept = parse_full_technique_ids(r.get("retrieval_prediction") or "")
        cleaned = json.dumps({"predicted_ids": kept}) if kept else (r.get("retrieval_prediction") or "")
    item = score_id_item(cleaned, r["gold"], task="ata")
    if item.f1 >= 1.0 - 1e-9:
        hygiene_ok += 1

print(f"n={len(rows)}")
print(f"official CB={cb/len(rows):.1%}  official RAG={official_rag/len(rows):.1%}")
print(f"hygiene-rescored RAG (JSON-only from stored outputs)={hygiene_ok/len(rows):.1%} ({hygiene_ok}/{len(rows)})")

# Segmentation check on stored questions
beh_counts = []
for r in rows:
    b = segment_behaviors_rulebased(r.get("question") or "")
    beh_counts.append(len(b))
from collections import Counter
print("new_segmentation n_behaviors:", Counter(beh_counts))
print(
    "multi-behaviour rate:",
    sum(1 for n in beh_counts if n >= 2) / len(beh_counts),
)

# demo split
ex = "The malware downloaded a payload and created a scheduled task for persistence."
print("demo:", segment_behaviors_rulebased(ex))
