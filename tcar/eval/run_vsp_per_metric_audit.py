#!/usr/bin/env python3
"""VSP per-metric confusion audit from existing CF jsonl (no LLM)."""
from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path

from eval.scoring import mad_cvss, mad_cvss_base_score, parse_cvss_vector
from tcar.vsp_structured_decoder import (
    apply_vsp_consistency,
    extract_vsp_facts_rulebased,
    facts_to_cvss_vector,
    metric_dict_from_vector,
)

ROOT = Path(__file__).resolve().parents[2]
CANDIDATES = [
    ROOT / "tcar/eval_results/counterfactual_ctibench_vsp_20260902Ttask_prompts_cb.jsonl",
    ROOT / "tcar/eval_results/counterfactual_ctibench_vsp_20260907Tsol_vsp_metric_wise.jsonl",
    ROOT / "tcar/eval_results/counterfactual_ctibench_vsp_20260904Tgpt56sol_forced_rag_cb.jsonl",
]
OUT = ROOT / "tcar/eval_results/vsp_per_metric_audit.json"
METRICS = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]


def load_rows(path: Path):
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        r = json.loads(line)
        if r.get("error"):
            continue
        rows.append(r)
    return rows


def audit(path: Path) -> dict:
    rows = load_rows(path)
    conf = {m: Counter() for m in METRICS}  # (gold,pred) counts
    correct = Counter()
    total = Counter()
    rag_vecs = []
    gold_vecs = []
    questions = []
    for r in rows:
        gold = (r.get("gold") or "").strip()
        pred = parse_cvss_vector(r.get("retrieval_prediction") or "") or ""
        if not gold:
            continue
        g = metric_dict_from_vector(gold)
        p = metric_dict_from_vector(pred) if pred else {}
        gold_vecs.append(gold)
        rag_vecs.append(pred or None)
        questions.append(r.get("question") or r.get("question_preview") or "")
        for m in METRICS:
            gv = g.get(m, "?")
            pv = p.get(m, "?")
            total[m] += 1
            if gv == pv:
                correct[m] += 1
            conf[m][(gv, pv)] += 1

    # Rule-based structured decoder on same questions (offline baseline)
    rb_exact = 0
    rb_metric_acc = Counter()
    rb_vecs = []
    for q, gold in zip(questions, gold_vecs):
        vec = facts_to_cvss_vector(apply_vsp_consistency(extract_vsp_facts_rulebased(q), q))
        rb_vecs.append(vec)
        if mad_cvss([vec], [gold]) == 0:
            rb_exact += 1
        gm = metric_dict_from_vector(gold)
        pm = metric_dict_from_vector(vec)
        for m in METRICS:
            if gm.get(m) == pm.get(m):
                rb_metric_acc[m] += 1

    n = len(gold_vecs)
    weakest = sorted(
        ((m, correct[m] / max(1, total[m])) for m in METRICS),
        key=lambda x: x[1],
    )
    return {
        "source": str(path),
        "n": n,
        "exact_rag": sum(1 for p, g in zip(rag_vecs, gold_vecs) if p and mad_cvss([p], [g]) == 0) / max(1, n),
        "mad8_rag": mad_cvss(rag_vecs, gold_vecs) if n else None,
        "mad_base_rag": mad_cvss_base_score(rag_vecs, gold_vecs) if n else None,
        "per_metric_acc_rag": {m: correct[m] / max(1, total[m]) for m in METRICS},
        "weakest_metrics": weakest[:3],
        "confusion_top": {
            m: conf[m].most_common(8) for m in METRICS
        },
        "rulebased_exact": rb_exact / max(1, n),
        "rulebased_mad8": mad_cvss(rb_vecs, gold_vecs) if n else None,
        "rulebased_mad_base": mad_cvss_base_score(rb_vecs, gold_vecs) if n else None,
        "rulebased_per_metric_acc": {m: rb_metric_acc[m] / max(1, n) for m in METRICS},
    }


def main() -> None:
    reports = []
    for p in CANDIDATES:
        if p.exists():
            print(f"auditing {p.name} ...", flush=True)
            reports.append(audit(p))
        else:
            print(f"missing {p}")
    OUT.write_text(json.dumps(reports, indent=2, default=str))
    print(json.dumps(reports, indent=2, default=str)[:4000])
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
