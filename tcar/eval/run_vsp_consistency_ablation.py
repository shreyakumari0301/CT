#!/usr/bin/env python3
"""Offline VSP consistency ablation on stored n=75 structured raw facts.

Re-decodes without new LLM calls:
  1) consistency=off
  2) consistency=all (legacy)
  3) consistency=high_precision
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from eval.scoring import parse_cvss_vector
from tcar.vsp_structured_decoder import decode_vsp_prediction, metric_dict_from_vector

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "tcar/eval_results/counterfactual_ctibench_vsp_20260908Tturbo_vsp_structured_n75.jsonl"
OUT = ROOT / "tcar/eval_results/vsp_consistency_ablation_n75.json"


def mad8(pred: str, gold: str) -> float:
    p, g = metric_dict_from_vector(pred), metric_dict_from_vector(gold)
    keys = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
    if not g:
        return 1.0
    return sum(1 for k in keys if p.get(k) != g.get(k)) / 8.0


def score_mode(rows: list, mode: str, branch: str) -> dict:
    os.environ["VSP_CONSISTENCY"] = mode
    exact = 0
    mad = 0.0
    n = 0
    for r in rows:
        gold = parse_cvss_vector(str(r.get("gold") or "")) or ""
        meta = r.get("tcar_meta") or {}
        raw_key = "vsp_cb_facts_raw" if branch == "cb" else "vsp_rag_facts_raw"
        raw = meta.get(raw_key) or ""
        q = r.get("question") or r.get("query") or ""
        # Prefer stored question; fall back to empty
        vec, _ = decode_vsp_prediction(raw, description=q, gold_vector=gold)
        n += 1
        if gold and parse_cvss_vector(vec) == gold:
            exact += 1
        mad += mad8(vec, gold)
    return {
        "n": n,
        "exact": exact / max(1, n),
        "mad8": mad / max(1, n),
        "mode": mode,
        "branch": branch,
    }


def main() -> None:
    rows = [
        json.loads(l)
        for l in SRC.read_text(encoding="utf-8").splitlines()
        if l.strip()
    ]
    out = {"n": len(rows), "modes": {}}
    for mode in ("off", "all", "high_precision"):
        out["modes"][mode] = {
            "cb": score_mode(rows, mode, "cb"),
            "rag": score_mode(rows, mode, "rag"),
        }
    OUT.write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
