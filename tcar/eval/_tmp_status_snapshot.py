#!/usr/bin/env python3
from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def mean(xs):
    xs = [float(x) for x in xs if x is not None]
    return sum(xs) / len(xs) if xs else None


def load_cf(path: Path):
    by = {}
    for line in path.open(encoding="utf-8", errors="replace"):
        try:
            r = json.loads(line)
        except Exception:
            continue
        rid = r.get("id") or r.get("example_id") or f"{r.get('task')}-{r.get('idx')}"
        by[str(rid)] = r
    return list(by.values())


def pick(r, *keys):
    for k in keys:
        if k in r and r[k] is not None:
            return r[k]
    br = r.get("branches") or {}
    for name in ("closed_book", "forced_rag", "rag"):
        b = br.get(name)
        if isinstance(b, dict):
            for k in keys:
                if k in b and b[k] is not None:
                    return b[k]
    return None


def score_rows(rows):
    def as01(xs):
        out = []
        for x in xs:
            if x is None:
                continue
            if isinstance(x, bool):
                out.append(1.0 if x else 0.0)
            else:
                try:
                    out.append(float(x))
                except Exception:
                    pass
        return out

    cb01 = as01([pick(r, "closed_book_correct", "cb_correct") for r in rows])
    rag01 = as01(
        [pick(r, "retrieval_correct", "forced_rag_correct", "rag_correct") for r in rows]
    )
    cbf1 = as01(
        [
            pick(r, "closed_book_f1", "cb_f1", "closed_book_instance_f1")
            for r in rows
        ]
    )
    ragf1 = as01(
        [
            pick(r, "retrieval_f1", "forced_rag_f1", "rag_f1", "retrieval_instance_f1")
            for r in rows
        ]
    )
    return mean(cb01), mean(rag01), mean(cbf1), mean(ragf1), len(rows)


# schema peek
p0 = ROOT / "tcar/eval_results/counterfactual_ctibench_rcm_20260904Tgpt56sol_forced_rag_cb.jsonl"
r0 = json.loads(p0.open(encoding="utf-8").readline())
print("RCM sample top keys:", sorted(r0.keys()))
if "branches" in r0:
    print("branch keys:", {k: sorted((r0["branches"][k] or {}).keys()) for k in r0["branches"]})

print("\n=== Forced RAG sol ===")
jobs = [
    ("CTIBench ATE", "counterfactual_ctibench_ate_20260904Tgpt56sol_forced_rag_cb.jsonl"),
    ("CTIBench RCM", "counterfactual_ctibench_rcm_20260904Tgpt56sol_forced_rag_cb.jsonl"),
    ("CTIBench MCQ", "counterfactual_ctibench_mcq_20260904Tgpt56sol_forced_rag_cb.jsonl"),
    ("CTIBench VSP", "counterfactual_ctibench_vsp_20260904Tgpt56sol_forced_rag_cb.jsonl"),
    ("Connect RCM", "counterfactual_cticonnect_rcm_20260906Tgpt56sol_forced_rag_cc.jsonl"),
    ("Connect ATA", "counterfactual_cticonnect_ata_20260906Tgpt56sol_forced_rag_cc.jsonl"),
]
for label, fn in jobs:
    p = ROOT / "tcar/eval_results" / fn
    rows = load_cf(p)
    cb, rag, cbf1, ragf1, n = score_rows(rows)
    print(f"{label}: n={n} CB={cb} RAG={rag} cbf1={cbf1} ragf1={ragf1}")

# If still None, dump first ATE record fields with score-like names
ate = load_cf(ROOT / "tcar/eval_results/counterfactual_ctibench_ate_20260904Tgpt56sol_forced_rag_cb.jsonl")[0]
print("\nATE field dump:")
for k, v in ate.items():
    if k in {"prompt", "raw", "context", "retrieved"}:
        continue
    print(f"  {k}: {type(v).__name__} {repr(v)[:140]}")

print("\n=== Baselines (parsed==gold) ===")
from eval.scoring import parse_mcq_answer, parse_cwe_answer, parse_ate_ids, parse_gold_ate, instance_macro_f1

def score_baseline(path: Path):
    by = defaultdict(list)
    for line in path.open(encoding="utf-8", errors="replace"):
        try:
            r = json.loads(line)
        except Exception:
            continue
        task = r.get("task")
        gold = r.get("gold")
        parsed = r.get("parsed")
        raw = r.get("raw") or ""
        if task == "mcq":
            pred = parsed if parsed in {"A", "B", "C", "D"} else parse_mcq_answer(str(raw))
            by[task].append(1.0 if pred and str(pred).upper() == str(gold).upper() else 0.0)
        elif task == "rcm":
            pred = parsed or parse_cwe_answer(str(raw))
            g = parse_cwe_answer(str(gold)) if gold else None
            by[task].append(1.0 if pred and g and str(pred).upper() == str(g).upper() else 0.0)
        elif task == "ate":
            pred = parsed if isinstance(parsed, list) else parse_ate_ids(str(raw))
            g = parse_gold_ate(str(gold)) if not isinstance(gold, list) else gold
            by[task].append(instance_macro_f1(pred or [], g or []))
        elif task == "vsp":
            # leave for mad; mark presence
            by[task].append(None)
        else:
            by[str(task)].append(None)
    return {t: (len(v), mean([x for x in v if x is not None])) for t, v in by.items()}

for fn in [
    "selfrag_20260906Tgpt56sol_baselines.jsonl",
    "adaptive_rag_20260906Tgpt56sol_baselines.jsonl",
    "graphrag_edge_20260906Tgpt56sol_baselines.jsonl",
    "tadarag_20260906Tgpt56sol_baselines.jsonl",
]:
    p = ROOT / "eval_results" / fn
    if not p.exists():
        continue
    sc = score_baseline(p)
    parts = [f"{t}:n={n} score={s}" for t, (n, s) in sorted(sc.items())]
    print(fn, " | ".join(parts))

cc = ROOT / "CTICONNECT benchmark/eval_results/cticonnect_cta_rag_port_20260906Tgpt56sol_cta_port.jsonl"
print("\n=== CTA E2E ===")
print("Connect cta_rag_port lines:", sum(1 for _ in cc.open()) if cc.exists() else 0)
print("CTIBench CTA: no finished *_oracle_* / *_router_* summaries from today yet")
