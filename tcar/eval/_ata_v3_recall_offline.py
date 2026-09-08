"""Recompute ATA v3 soft-ground recall on all 160 Connect ATA items (no LLM)."""
from __future__ import annotations

import json
from pathlib import Path

from eval.cticonnect_loader import load_tasks
from eval.cticonnect_kb import CTIConnectKBRetriever
from tcar.ata_behavior_grounded import retrieve_grounded_ata

ROOT = Path(__file__).resolve().parents[2]
CORPUS = ROOT / "CTICONNECT data" / "CTIConnect-main" / "corpus_kb"
DATA = ROOT / "CTICONNECT data" / "data"

print("loading retriever...")
retriever = CTIConnectKBRetriever(corpus_dir=CORPUS)
qas = load_tasks(["ata"], data_dir=DATA, limit=None)
print(f"items={len(qas)}")

raw = rrf = grounded = 0
n_beh_ge2 = 0
changed_vs_v2 = 0

# Compare to v2 grounded sets when available
v2_path = ROOT / "tcar/eval_results/counterfactual_cticonnect_ata_20260908Tturbo_ata_grounded_v2_full.jsonl"
v2 = {}
if v2_path.exists():
    for line in v2_path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            r = json.loads(line)
            v2[str(r["id"])] = set(
                ((r.get("tcar_meta") or {}).get("diversify") or {}).get("grounded_ids") or []
            )

for qa in qas:
    gold = []
    gt = qa.ground_truth or {}
    if gt.get("target_id"):
        gold = [str(gt["target_id"]).upper()]
    else:
        gold = [str(x).upper() for x in (gt.get("target_ids") or [])]
    cands, behs, meta = retrieve_grounded_ata(
        qa.question, retriever, per_behavior_k=20, final_k=20, gold_ids=gold
    )
    raw += int(bool(meta.get("gold_in_raw_union")))
    rrf += int(bool(meta.get("gold_in_rrf")))
    grounded += int(bool(meta.get("gold_in_grounded")))
    if len(behs) >= 2:
        n_beh_ge2 += 1
    new_ids = set(meta.get("grounded_ids") or [])
    old = v2.get(str(qa.id), set())
    if new_ids != {str(x).upper() for x in old}:
        changed_vs_v2 += 1

n = len(qas)
print("\n=== ATA v3 SOFT-GROUND RECALL (no LLM) ===")
print(f"raw_union:  {raw}/{n} = {raw/n:.1%}")
print(f"rrf:        {rrf}/{n} = {rrf/n:.1%}")
print(f"grounded:   {grounded}/{n} = {grounded/n:.1%}   (v2 was 55.0%)")
print(f"multi-beh:  {n_beh_ge2}/{n} = {n_beh_ge2/n:.1%}")
print(f"candidate-set changed vs v2: {changed_vs_v2}/{n}")
print(f"target grounded recall: >=68-70%")
