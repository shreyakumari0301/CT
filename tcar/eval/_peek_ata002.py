import json
from pathlib import Path
r = json.loads(Path("tcar/eval_results/counterfactual_cticonnect_ata_20260907Tturbo_ata_grounded_n50.jsonl").read_text().splitlines()[1])
print("id", r["id"])
print("gold", r["gold"], r["gold_ids"])
print("cb_ok", r["closed_book_correct"], "rag_ok", r["retrieval_correct"], "effect", r["retrieval_effect"])
print("cb_pred answer tail:\n", r["closed_book_prediction"][-200:])
print("rag_pred answer tail:\n", r["retrieval_prediction"][-200:])
print("retrieved", r["retrieved_ids"])
print("meta keys", list((r.get("tcar_meta") or {}).keys()))
meta = r.get("tcar_meta") or {}
print("cleanup", meta.get("ata_cleanup"), "abstain", meta.get("ata_abstain_to_cb"), "kept", meta.get("ata_kept_ids"))
