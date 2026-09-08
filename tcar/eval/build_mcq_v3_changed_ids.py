#!/usr/bin/env python3
"""Build MCQ v3 changed-item regeneration set (not full 2500).

Includes:
  1) Deterministic STIX swaps
  2) Evidence-changed semantic path (typed relation and/or STIX endpoints)
  3) Threatened rescues from latest offline summary (unique_wrong on rescues)
  4) Random unchanged control sample (~100) for stability

Writes:
  tcar/eval_results/mcq_v3_changed/
    changed_ids.txt
    control_ids.txt
    regen_ids.txt          # changed ∪ control
    manifest.csv
    summary.json
"""
from __future__ import annotations

import csv
import json
import random
from collections import Counter, defaultdict
from pathlib import Path

from tcar.mcq_relation_aware import AttackRelationIndex, classify_mcq_v3_path
from tcar.specialist_retrieval import parse_mcq_options

ROOT = Path(__file__).resolve().parents[2]
V2 = ROOT / "tcar/eval_results/counterfactual_ctibench_mcq_20260907Tturbo_mcq_option_aware_v2.jsonl"
OFFLINE = ROOT / "tcar/eval_results/mcq_v3_relation_offline/per_item_results.csv"
OUT = ROOT / "tcar/eval_results/mcq_v3_changed"
SEED = 20260908
CONTROL_N = 100


def effect_of(r: dict) -> str:
    cb, rag = bool(r.get("closed_book_correct")), bool(r.get("retrieval_correct"))
    if (not cb) and rag:
        return "rescue"
    if cb and (not rag):
        return "damage"
    if cb and rag:
        return "neutral_correct"
    return "neutral_wrong"


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    AttackRelationIndex.reset()
    index = AttackRelationIndex.get()
    print("bundles:", [(b.domain, b.matrix_version, b.n_relationships) for b in index.meta.bundles])

    rows = [json.loads(l) for l in V2.read_text(encoding="utf-8").splitlines() if l.strip()]
    by_id = {r["id"]: r for r in rows}

    # Threatened rescues from prior offline (if present)
    threatened: set = set()
    if OFFLINE.exists():
        for r in csv.DictReader(OFFLINE.open(encoding="utf-8")):
            if r.get("would_threaten_rescue") == "True":
                threatened.add(r["id"])

    manifest = []
    buckets = defaultdict(list)
    for i, r in enumerate(rows):
        opts = parse_mcq_options(r["question"])
        dec = classify_mcq_v3_path(r["question"], opts, index=index)
        eff = effect_of(r)
        reasons = []
        if dec.decision_source == "STIX":
            reasons.append("deterministic_stix")
        if dec.evidence_changed and dec.decision_source == "semantic":
            reasons.append("evidence_changed_semantic")
        if r["id"] in threatened:
            reasons.append("threatened_rescue")
        row = {
            "id": r["id"],
            "effect": eff,
            "gold": r.get("gold"),
            "v2_rag_pred": (r.get("retrieval_prediction") or ""),
            "v2_rag_correct": bool(r.get("retrieval_correct")),
            "v2_cb_correct": bool(r.get("closed_book_correct")),
            "decision_source": dec.decision_source,
            "relation": dec.relation,
            "evidence_changed": dec.evidence_changed,
            "matrices": "|".join(dec.matrices),
            "stix_unique": dec.stix.unique_supported or "",
            "stix_method": dec.stix.method,
            "reasons": "|".join(reasons) if reasons else "unchanged_fallback",
            "include_regen": bool(reasons),
        }
        manifest.append(row)
        if reasons:
            buckets["changed"].append(r["id"])
        else:
            buckets["unchanged"].append(r["id"])
        if (i + 1) % 500 == 0:
            print(f"  classified {i+1}/{len(rows)}")

    rng = random.Random(SEED)
    unchanged = list(buckets["unchanged"])
    rng.shuffle(unchanged)
    control = unchanged[:CONTROL_N]

    regen = sorted(set(buckets["changed"]) | set(control))
    (OUT / "changed_ids.txt").write_text("\n".join(sorted(buckets["changed"])) + "\n", encoding="utf-8")
    (OUT / "control_ids.txt").write_text("\n".join(control) + "\n", encoding="utf-8")
    (OUT / "regen_ids.txt").write_text("\n".join(regen) + "\n", encoding="utf-8")

    # mark control in manifest
    control_set = set(control)
    for row in manifest:
        if row["id"] in control_set and not row["include_regen"]:
            row["reasons"] = "control_unchanged"
            row["include_regen"] = True

    fields = list(manifest[0].keys())
    with (OUT / "manifest.csv").open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(manifest)

    # Offline projection after ICS (deterministic only among changed)
    det = [m for m in manifest if m["decision_source"] == "STIX"]
    det_fix_damage = sum(
        1
        for m in det
        if m["effect"] == "damage"
        and m["stix_unique"]
        and m["stix_unique"] == m["gold"]
        and not m["v2_rag_correct"]
    )
    det_recover_bw = sum(
        1
        for m in det
        if m["effect"] == "neutral_wrong"
        and m["stix_unique"]
        and m["stix_unique"] == m["gold"]
    )
    det_threat_rescue = sum(
        1
        for m in det
        if m["effect"] == "rescue"
        and m["stix_unique"]
        and m["stix_unique"] != m["gold"]
        and m["v2_rag_correct"]
    )
    net = det_fix_damage + det_recover_bw - det_threat_rescue
    projected = 0.7868 + net / 2500.0

    summary = {
        "attack_bundle": index.meta.to_dict(),
        "n_total": len(rows),
        "n_changed": len(buckets["changed"]),
        "n_unchanged_fallback": len(buckets["unchanged"]),
        "n_control": len(control),
        "n_regen": len(regen),
        "decision_source_counts": dict(Counter(m["decision_source"] for m in manifest)),
        "relation_counts": dict(Counter(m["relation"] for m in manifest)),
        "changed_by_effect": dict(
            Counter(m["effect"] for m in manifest if m["reasons"] not in {"unchanged_fallback", "control_unchanged"})
        ),
        "threatened_rescue_ids_prior_offline": sorted(threatened),
        "deterministic_offline_projection": {
            "n_stix": len(det),
            "damages_fixed": det_fix_damage,
            "both_wrong_recovered": det_recover_bw,
            "rescues_threatened": det_threat_rescue,
            "net": net,
            "projected_rag": round(projected, 4),
            "note": (
                "STIX-only swaps after ICS+Mobile merge; still development-tainted gate. "
                "Not a final Acc claim. Prefer ≥81% after regen."
            ),
        },
        "reuse_policy": (
            "fallback path uses option_aware retrieval identical to v2; "
            "stored v2 answers may be reused for those IDs."
        ),
    }
    (OUT / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
