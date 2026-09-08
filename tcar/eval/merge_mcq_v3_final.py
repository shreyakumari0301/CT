#!/usr/bin/env python3
"""Final MCQ v3 merge: v2 unchanged IDs + v3 regenerated IDs → assert 2500 unique.

Reports overall Acc, CB→v2→v3, rescues/damages vs CB, v3Δv2, STIX vs semantic.
Does NOT report intermediate/partial merges — refuse if regen incomplete.
"""
from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
V2 = ROOT / "tcar/eval_results/counterfactual_ctibench_mcq_20260907Tturbo_mcq_option_aware_v2.jsonl"
MANIFEST = ROOT / "tcar/eval_results/mcq_v3_changed/manifest.csv"
OUT_DIR = ROOT / "tcar/eval_results/mcq_v3_changed"
EXPECTED_N = 2500


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
    ap.add_argument(
        "--allow-partial",
        action="store_true",
        help="Dev only — do not use for paper Acc",
    )
    args = ap.parse_args()

    v2 = load_jsonl(V2)
    v3 = load_jsonl(args.v3_jsonl)
    man = {r["id"]: r for r in csv.DictReader(MANIFEST.open(encoding="utf-8"))}
    regen_ids = {mid for mid, m in man.items() if m.get("include_regen") in {True, "True", "true", "1"}}
    missing_regen = sorted(regen_ids - set(v3.keys()))
    if missing_regen and not args.allow_partial:
        raise SystemExit(
            f"Regen incomplete: {len(v3)}/{len(regen_ids)} regenerated; "
            f"missing {len(missing_regen)} (e.g. {missing_regen[:5]}). "
            "Refusing merge Acc — wait for full run or pass --allow-partial for debug."
        )

    merged_ids = set(v2.keys())
    if len(merged_ids) != EXPECTED_N:
        raise SystemExit(f"v2 has {len(merged_ids)} IDs, expected {EXPECTED_N}")

    logs = []
    n_ok = n_cb = n_v2 = 0
    rescues_v2 = damages_v2 = 0
    rescues_v3 = damages_v3 = 0
    v3_improve = v3_regress = 0
    by_source = Counter()
    ok_by_source = Counter()

    for mid, r2 in v2.items():
        gold = (r2.get("gold") or "").strip().upper()
        cb_ok = bool(r2.get("closed_book_correct"))
        v2_ok = bool(r2.get("retrieval_correct"))
        v2_pred = (r2.get("retrieval_prediction") or "").strip().upper()
        m = man.get(mid) or {}

        if mid in v3:
            r3 = v3[mid]
            ok = bool(r3.get("retrieval_correct"))
            pred = (r3.get("retrieval_prediction") or "").strip().upper()
            meta = r3.get("tcar_meta") or r3.get("meta") or {}
            src = (
                meta.get("decision_source")
                or r3.get("decision_source")
                or m.get("decision_source")
                or "regenerated"
            )
            used = "regenerated"
        else:
            ok = v2_ok
            pred = v2_pred
            src = "fallback_reuse_v2"
            used = "reused_v2"

        if cb_ok:
            n_cb += 1
        if v2_ok:
            n_v2 += 1
        if ok:
            n_ok += 1

        if (not cb_ok) and v2_ok:
            rescues_v2 += 1
        if cb_ok and (not v2_ok):
            damages_v2 += 1
        if (not cb_ok) and ok:
            rescues_v3 += 1
        if cb_ok and (not ok):
            damages_v3 += 1
        if (not v2_ok) and ok:
            v3_improve += 1
        if v2_ok and (not ok):
            v3_regress += 1

        by_source[src] += 1
        if ok:
            ok_by_source[src] += 1

        if used == "regenerated" or m.get("include_regen") in {True, "True", "true", "1"}:
            logs.append(
                {
                    "id": mid,
                    "gold": gold,
                    "v2_answer": v2_pred,
                    "v3_answer": pred,
                    "v2_correct": v2_ok,
                    "v3_correct": ok,
                    "cb_correct": cb_ok,
                    "decision_source": src,
                    "answer_source": used,
                }
            )

    assert len(merged_ids) == EXPECTED_N
    n = EXPECTED_N
    source_acc = {
        s: (ok_by_source[s] / by_source[s] if by_source[s] else None)
        for s in sorted(by_source.keys())
    }
    # STIX deterministic vs semantic-fallback buckets
    stix_keys = [s for s in by_source if "stix" in s.lower() or s.lower() in {"deterministic", "edge"}]
    sem_keys = [s for s in by_source if "semantic" in s.lower()]
    def bucket_acc(keys):
        c = sum(ok_by_source[k] for k in keys)
        t = sum(by_source[k] for k in keys)
        return {"n": t, "correct": c, "acc": (c / t if t else None), "keys": keys}

    summary = {
        "n": n,
        "unique_ids": len(merged_ids),
        "assert_2500": len(merged_ids) == EXPECTED_N,
        "n_regenerated": len(v3),
        "n_reused_v2": n - len(v3),
        "partial": bool(missing_regen),
        "accuracy": {
            "closed_book": round(n_cb / n, 4),
            "v2": round(n_v2 / n, 4),
            "v3_merged": round(n_ok / n, 4),
            "cb_count": n_cb,
            "v2_count": n_v2,
            "v3_count": n_ok,
        },
        "rescues_damages_vs_cb": {
            "v2": {"rescues": rescues_v2, "damages": damages_v2, "net_pp": round((rescues_v2 - damages_v2) / n * 100, 2)},
            "v3_merged": {
                "rescues": rescues_v3,
                "damages": damages_v3,
                "net_pp": round((rescues_v3 - damages_v3) / n * 100, 2),
            },
        },
        "v3_vs_v2": {
            "improvements": v3_improve,
            "regressions": v3_regress,
            "net": v3_improve - v3_regress,
            "delta_pp": round((n_ok - n_v2) / n * 100, 2),
        },
        "by_decision_source": {
            "counts": dict(by_source),
            "accuracy": {k: (round(v, 4) if v is not None else None) for k, v in source_acc.items()},
            "stix_deterministic": bucket_acc(stix_keys),
            "semantic_fallback": bucket_acc(sem_keys),
        },
        "note": "Final overlay Acc only after full regen; STIX vs semantic from decision_source labels.",
    }

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    with (OUT_DIR / "final_changed_item_comparison.csv").open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(logs[0].keys()) if logs else ["id"])
        w.writeheader()
        w.writerows(logs)
    (OUT_DIR / "final_merge_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
