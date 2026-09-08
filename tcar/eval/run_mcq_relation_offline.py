#!/usr/bin/env python3
"""Offline Relation-Aware Option Retrieval eval (no LLM regeneration).

Evaluates structured ATT&CK edge lookup on:
  - all 50 damages
  - all 227 rescues (protection set)
  - all 483 both-wrong cases

Uses a fixed holdout for screening (default 300 ids) so design metrics are not
reported as unbiased test performance.

Outputs: tcar/eval_results/mcq_v3_relation_offline/
"""
from __future__ import annotations

import csv
import hashlib
import json
import random
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, List

from tcar.mcq_relation_aware import (
    AttackRelationIndex,
    best_relation_supporting_gold,
    detect_relation_type,
    lookup_relation_options,
)
from tcar.specialist_retrieval import parse_mcq_options

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "tcar/eval_results/counterfactual_ctibench_mcq_20260907Tturbo_mcq_option_aware_v2.jsonl"
OUT = ROOT / "tcar/eval_results/mcq_v3_relation_offline"
SEED = 20260908
HOLDOUT_N = 300


def effect_of(r: dict) -> str:
    cb, rag = bool(r.get("closed_book_correct")), bool(r.get("retrieval_correct"))
    if (not cb) and rag:
        return "rescue"
    if cb and (not rag):
        return "damage"
    if cb and rag:
        return "neutral_correct"
    return "neutral_wrong"


def split_holdout(ids: List[str], n: int = HOLDOUT_N, seed: int = SEED) -> set:
    rng = random.Random(seed)
    ids = list(ids)
    rng.shuffle(ids)
    return set(ids[:n])


def eval_row(r: dict, index: AttackRelationIndex) -> dict:
    q = r.get("question") or ""
    opts = parse_mcq_options(q)
    gold = (r.get("gold") or "").strip().upper()
    pred_rel, conf = detect_relation_type(q)
    res = lookup_relation_options(q, opts, index=index, relation=pred_rel)
    best_rel, best_res = best_relation_supporting_gold(q, opts, gold, index=index)

    gold_supported_pred = gold in res.supported_letters
    gold_supported_best = bool(best_rel) and gold in (best_res.supported_letters if best_res else [])
    unique_ok = res.deterministic and res.unique_supported == gold
    unique_wrong = res.deterministic and res.unique_supported and res.unique_supported != gold
    # Simulated branch replacement: if deterministic unique → use it; else keep RAG
    rag = bool(r.get("retrieval_correct"))
    cb = bool(r.get("closed_book_correct"))
    if res.deterministic and res.unique_supported:
        sim_correct = res.unique_supported == gold
        sim_source = "stix_unique"
    else:
        sim_correct = rag
        sim_source = "keep_rag"

    return {
        "id": r.get("id"),
        "effect": effect_of(r),
        "gold": gold,
        "cb_correct": cb,
        "rag_correct": rag,
        "pred_relation": pred_rel,
        "pred_relation_conf": round(conf, 3),
        "best_relation_for_gold": best_rel or "",
        "relation_match_best": pred_rel == best_rel if best_rel else False,
        "n_endpoints": len(res.endpoint_ids) + len(res.endpoint_names),
        "supported_letters": ",".join(res.supported_letters),
        "unique_supported": res.unique_supported or "",
        "deterministic": res.deterministic,
        "gold_supported_by_pred_relation": gold_supported_pred,
        "gold_supported_by_best_relation": gold_supported_best,
        "unique_correct": unique_ok,
        "unique_wrong": unique_wrong,
        "sim_correct": sim_correct,
        "sim_source": sim_source,
        "would_fix_damage": effect_of(r) == "damage" and sim_correct and not rag,
        "would_threaten_rescue": effect_of(r) == "rescue" and (not sim_correct) and rag,
        "would_recover_both_wrong": effect_of(r) == "neutral_wrong" and sim_correct,
        "notes": res.notes,
        "endpoint_ids": "|".join(res.endpoint_ids[:20]),
        "endpoint_names": "|".join(res.endpoint_names[:15]),
    }


def summarize(rows: List[dict], label: str) -> dict:
    n = len(rows)
    if n == 0:
        return {"label": label, "n": 0}
    det = [r for r in rows if r["deterministic"]]
    return {
        "label": label,
        "n": n,
        "pred_rel_dist": dict(Counter(r["pred_relation"] for r in rows)),
        "relation_classification_proxy_acc": (
            sum(1 for r in rows if r["relation_match_best"]) / n
        ),
        "gold_option_evidence_coverage_pred": (
            sum(1 for r in rows if r["gold_supported_by_pred_relation"]) / n
        ),
        "gold_option_evidence_coverage_best_rel": (
            sum(1 for r in rows if r["gold_supported_by_best_relation"]) / n
        ),
        "unique_supported_option_rate": len(det) / n,
        "unique_correct_rate": sum(1 for r in rows if r["unique_correct"]) / n,
        "unique_wrong_rate": sum(1 for r in rows if r["unique_wrong"]) / n,
        "damages_fixed": sum(1 for r in rows if r["would_fix_damage"]),
        "rescues_threatened": sum(1 for r in rows if r["would_threaten_rescue"]),
        "both_wrong_recovered": sum(1 for r in rows if r["would_recover_both_wrong"]),
        "sim_acc": sum(1 for r in rows if r["sim_correct"]) / n,
        "rag_acc": sum(1 for r in rows if r["rag_correct"]) / n,
    }


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    print("loading MCQ v2 jsonl...", flush=True)
    rows = [json.loads(l) for l in SRC.read_text(encoding="utf-8").splitlines() if l.strip()]
    by_eff = defaultdict(list)
    for r in rows:
        by_eff[effect_of(r)].append(r)

    holdout_ids = split_holdout([r["id"] for r in rows], HOLDOUT_N, SEED)
    print(f"holdout n={len(holdout_ids)} seed={SEED}", flush=True)

    print("loading ATT&CK STIX index (may take ~30-90s)...", flush=True)
    t0 = time.time()
    AttackRelationIndex.reset()
    index = AttackRelationIndex.get()
    print(
        f"STIX ready in {time.time()-t0:.1f}s  rels={index.meta.n_relationships} "
        f"spec={index.meta.attack_spec_version} matrices={index.meta.matrix_version} "
        f"modified={index.meta.matrix_modified}",
        flush=True,
    )
    (OUT / "attack_bundle_meta.json").write_text(
        json.dumps(index.meta.to_dict() if hasattr(index.meta, "to_dict") else index.meta.__dict__, indent=2),
        encoding="utf-8",
    )

    targets = {
        "damages": by_eff["damage"],
        "rescues": by_eff["rescue"],
        "both_wrong": by_eff["neutral_wrong"],
    }
    all_eval_rows: List[dict] = []
    for label, subset in targets.items():
        print(f"evaluating {label} n={len(subset)}...", flush=True)
        for i, r in enumerate(subset):
            all_eval_rows.append(eval_row(r, index))
            if (i + 1) % 100 == 0:
                print(f"  {label}: {i+1}/{len(subset)}", flush=True)

    # write detail csv
    fields = list(all_eval_rows[0].keys())
    with (OUT / "per_item_results.csv").open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(all_eval_rows)

    # group summaries
    summaries = {}
    for label in ("damage", "rescue", "neutral_wrong"):
        sub = [r for r in all_eval_rows if r["effect"] == label]
        key = {"damage": "damages", "rescue": "rescues", "neutral_wrong": "both_wrong"}[label]
        summaries[key] = summarize(sub, key)

    # design vs holdout among evaluated items
    design = [r for r in all_eval_rows if r["id"] not in holdout_ids]
    hold = [r for r in all_eval_rows if r["id"] in holdout_ids]
    summaries["design_subset"] = summarize(design, "design_among_eval")
    summaries["holdout_subset"] = summarize(hold, "holdout_among_eval")

    # Acceptance-style projected full-set impact (deterministic-only swaps)
    damages_fixed = summaries["damages"]["damages_fixed"]
    rescues_threatened = summaries["rescues"]["rescues_threatened"]
    both_rec = summaries["both_wrong"]["both_wrong_recovered"]
    net = damages_fixed + both_rec - rescues_threatened
    projected_rag = 0.7868 + net / 2500.0
    acceptance = {
        "damages_fixed": damages_fixed,
        "damages_target": "15-20",
        "both_wrong_recovered": both_rec,
        "both_wrong_target": "15-20",
        "rescues_threatened": rescues_threatened,
        "rescues_max_loss": "3-5",
        "net_additional_correct": net,
        "need_for_80pct": 33,
        "projected_rag_if_apply_deterministic": round(projected_rag, 4),
        "pass_damage_bar": damages_fixed >= 15,
        "pass_both_wrong_bar": both_rec >= 15,
        "pass_rescue_bar": rescues_threatened <= 5,
        "note": (
            "Offline STIX-unique deterministic swaps only. "
            "LLM regen accuracy on unresolved items is not claimed."
        ),
    }

    report = {
        "attack_bundle": index.meta.__dict__,
        "summaries": summaries,
        "acceptance": acceptance,
        "holdout": {"n": HOLDOUT_N, "seed": SEED, "method": "random_shuffle_ids"},
    }
    (OUT / "summary.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
