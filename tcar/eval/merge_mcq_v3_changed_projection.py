#!/usr/bin/env python3
"""Merge v2 answers with v3 changed-item regen (screening helper).

For paper Acc use merge_mcq_v3_final.py after full regen (asserts 2500).
This script still refuses to print Acc unless --allow-partial or regen complete.
"""
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
V2 = ROOT / "tcar/eval_results/counterfactual_ctibench_mcq_20260907Tturbo_mcq_option_aware_v2.jsonl"
MANIFEST = ROOT / "tcar/eval_results/mcq_v3_changed/manifest.csv"
OUT_DIR = ROOT / "tcar/eval_results/mcq_v3_changed"


def load_jsonl(path: Path) -> dict:
    rows = {}
    for ln in path.read_text(encoding="utf-8").splitlines():
        if not ln.strip():
            continue
        r = json.loads(ln)
        rows[r["id"]] = r
    return rows


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--v3-jsonl", type=Path, required=True)
    ap.add_argument("--allow-partial", action="store_true")
    args = ap.parse_args()

    v2 = load_jsonl(V2)
    v3 = load_jsonl(args.v3_jsonl)
    man = {r["id"]: r for r in csv.DictReader(MANIFEST.open(encoding="utf-8"))}
    regen_ids = {
        mid for mid, m in man.items() if m.get("include_regen") in {True, "True", "true", "1"}
    }
    missing = sorted(regen_ids - set(v3.keys()))
    if missing and not args.allow_partial:
        raise SystemExit(
            f"Regen incomplete ({len(v3)}/{len(regen_ids)}); refusing Acc. "
            "Use merge_mcq_v3_final.py after completion, or --allow-partial for debug logs only."
        )

    logs = []
    correct = 0
    n = len(v2)
    rescue_gained = rescue_lost = 0
    for mid, r2 in v2.items():
        gold = (r2.get("gold") or "").strip().upper()
        v2_ok = bool(r2.get("retrieval_correct"))
        v2_pred = (r2.get("retrieval_prediction") or "").strip().upper()
        m = man.get(mid) or {}
        if mid in v3:
            r3 = v3[mid]
            v3_ok = bool(r3.get("retrieval_correct"))
            v3_pred = (r3.get("retrieval_prediction") or "").strip().upper()
            meta = r3.get("tcar_meta") or r3.get("meta") or {}
            src = meta.get("decision_source") or m.get("decision_source") or ""
            if not src:
                src = r3.get("decision_source") or m.get("decision_source") or "?"
            evid = m.get("evidence_changed", "")
            used = "regenerated"
            ok = v3_ok
        else:
            v3_ok = v2_ok
            v3_pred = v2_pred
            src = "fallback_reuse_v2"
            evid = False
            used = "reused_v2"
            ok = v2_ok
        if ok:
            correct += 1
        cb_ok = bool(r2.get("closed_book_correct"))
        was_rescue = (not cb_ok) and v2_ok
        now_rescue = (not cb_ok) and ok
        if now_rescue and not was_rescue:
            rescue_gained += 1
        if was_rescue and not now_rescue:
            rescue_lost += 1
        if mid in v3 or m.get("include_regen") in {True, "True", "true"}:
            logs.append(
                {
                    "id": mid,
                    "gold": gold,
                    "v2_answer": v2_pred,
                    "relation_aware_answer": v3_pred,
                    "v2_correct": v2_ok,
                    "v3_correct": ok,
                    "decision_source": src,
                    "evidence_changed": evid,
                    "answer_source": used,
                    "rescue_gained": now_rescue and not was_rescue,
                    "rescue_lost": was_rescue and not now_rescue,
                    "effect_v2": m.get("effect", ""),
                }
            )

    assert n == 2500, f"expected 2500 v2 IDs, got {n}"
    acc = correct / max(1, n)
    summary = {
        "n": n,
        "unique_ids": n,
        "projected_correct": correct,
        "projected_acc": round(acc, 4) if not missing else None,
        "partial": bool(missing),
        "v2_acc": 0.7868,
        "delta_pp": round((acc - 0.7868) * 100, 2) if not missing else None,
        "rescue_gained": rescue_gained,
        "rescue_lost": rescue_lost,
        "n_regenerated": len(v3),
        "n_logged": len(logs),
        "note": (
            "Do not cite Acc if partial=true. Prefer merge_mcq_v3_final.py for paper table."
        ),
    }
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    with (OUT_DIR / "changed_item_comparison.csv").open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(logs[0].keys()) if logs else ["id"])
        w.writeheader()
        w.writerows(logs)
    (OUT_DIR / "projection_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
