#!/usr/bin/env python3
"""Quick pattern summary over MCQ v2 damage + both-wrong audits."""
from __future__ import annotations

import csv
import json
import re
from collections import Counter
from pathlib import Path

DIR = Path("tcar/eval_results/mcq_v2_audit")


def load(name: str):
    with (DIR / name).open(encoding="utf-8") as f:
        return list(csv.DictReader(f))


def summarize(rows, label: str):
    print(f"\n=== {label} n={len(rows)} ===")
    gold_dist = Counter(r["gold"] for r in rows)
    rag_dist = Counter(r["rag_answer"] for r in rows)
    cb_dist = Counter(r["cb_answer"] for r in rows)
    print("gold", dict(gold_dist))
    print("cb_answers", dict(cb_dist))
    print("rag_answers", dict(rag_dist))
    # confusion gold->rag for damages
    conf = Counter((r["gold"], r["rag_answer"]) for r in rows)
    print("top gold→rag", conf.most_common(8))
    contam = sum(1 for r in rows if r.get("has_contamination") == "True")
    print(f"contamination_flagged={contam}/{len(rows)}")
    none_n = sum(1 for r in rows if r.get("none_of_the_above_option") == "True")
    print(f"has_none_option={none_n}")
    # relation anchors
    rels = Counter()
    techs = 0
    actors = 0
    for r in rows:
        a = json.loads(r.get("anchors") or "{}")
        for x in a.get("relations") or []:
            rels[x] += 1
        if a.get("technique_ids"):
            techs += 1
        if a.get("actors"):
            actors += 1
    print("relations", dict(rels))
    print(f"with_technique_id={techs} with_actor={actors}")
    # evidence balance: empty options
    empty_opts = 0
    unbalanced = 0
    for r in rows:
        per = json.loads(r.get("retrieved_evidence_per_option") or "{}")
        counts = {lab: len(hits or []) for lab, hits in per.items()}
        if any(v == 0 for v in counts.values()) and len(counts) >= 4:
            empty_opts += 1
        scores = []
        for lab, hits in per.items():
            if hits:
                scores.append(float(hits[0].get("score") or 0))
        if scores and (max(scores) - min(scores) > 0.15):
            unbalanced += 1
    print(f"options_with_empty_evidence={empty_opts} score_spread>0.15={unbalanced}")


def main():
    summarize(load("damages.csv"), "DAMAGES")
    summarize(load("both_wrong_100.csv"), "BOTH_WRONG_100")
    summarize(load("rescues.csv"), "RESCUES")
    s = json.loads((DIR / "summary.json").read_text())
    print("\n=== CEILING ===")
    print(json.dumps({k: s[k] for k in [
        "cb_acc","rag_acc","delta","rescues","damages","branch_oracle_acc",
        "rag_correct_count","to_reach_80pct_need","contamination"
    ]}, indent=2))


if __name__ == "__main__":
    main()
