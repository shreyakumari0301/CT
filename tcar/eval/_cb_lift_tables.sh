#!/usr/bin/env bash
cd /mnt/c/Users/SK/CTI-Chatbot
source .venv/bin/activate
PYTHONPATH=. python <<'PY'
import json
from pathlib import Path

def rer(cb, sys):
    """Relative error reduction: (err_cb - err_sys) / err_cb. For MAD↓ use relative reduction of MAD."""
    err_cb = 1.0 - cb
    if err_cb <= 1e-12:
        return None
    return (err_cb - (1.0 - sys)) / err_cb

def mad_rer(cb_mad, sys_mad):
    if cb_mad <= 1e-12:
        return None
    return (cb_mad - sys_mad) / cb_mad

print("=== CTIBench paper ladder (turbo CTA vs zero-shot) ===")
bench = [
    ("MCQ Acc↑", 0.710, 0.752),
    ("RCM Acc↑", 0.720, 0.781),
    ("ATE F1↑", 0.639, 0.945),
]
for name, cb, sys in bench:
    print(f"{name}: CB={cb:.3f} CTA={sys:.3f}  Δpp={+(sys-cb)*100:.1f}  RER={rer(cb,sys)*100:+.1f}%")
print(f"VSP MAD↓: CB=1.31 CTA=1.06  Δ={1.06-1.31:+.2f}  RER={mad_rer(1.31,1.06)*100:+.1f}%")

print("\n=== CTIBench Vanilla RAG ablation (paper) ===")
for gen, rows in [
    ("turbo", [("RCM",0.704,0.766),("MCQ",0.723,0.743),("ATE exact",0.067,0.300),("VSP exact",0.248,0.270)]),
    ("sol*", [("RCM",0.748,0.801),("MCQ",0.837,0.867),("ATE exact",0.183,0.667),("VSP exact",0.536,0.533)]),
]:
    print(f"-- {gen}")
    for name, cb, rag in rows:
        print(f"  {name}: CB={cb:.3f} RAG={rag:.3f}  Δpp={+(rag-cb)*100:.1f}  RER={rer(cb,rag)*100:+.1f}%")

print("\n=== CTIConnect (paper gpt-4o Vanilla CF) ===")
conn_paper = [("RCM exact",0.645,0.524),("ATA exact",0.250,0.269)]
for name, cb, rag in conn_paper:
    print(f"{name}: CB={cb:.3f} RAG={rag:.3f}  Δpp={+(rag-cb)*100:.1f}  RER={rer(cb,rag)*100:+.1f}%")

ROOT = Path("tcar/eval_results")

def score_jsonl(path):
    rows = [json.loads(l) for l in path.read_text().splitlines() if l.strip()]
    ok = [r for r in rows if not r.get("error") and "retrieval_correct" in r]
    if not ok:
        return None
    n = len(ok)
    cb = sum(1 for r in ok if r["closed_book_correct"]) / n
    rag = sum(1 for r in ok if r["retrieval_correct"]) / n
    return n, cb, rag

print("\n=== CTIConnect local Forced RAG (exact F1_i>=1) ===")
for name in [
    "counterfactual_cticonnect_rcm_20260906Tgpt56sol_forced_rag_cc.jsonl",
    "counterfactual_cticonnect_rcm_20260906Tgpt56sol_forced_rag_v3_cc.jsonl",
    "counterfactual_cticonnect_ata_20260906Tgpt56sol_forced_rag_cc.jsonl",
    "counterfactual_cticonnect_ata_20260906Tgpt56sol_forced_rag_v3_cc.jsonl",
    "counterfactual_cticonnect_rcm_20260907Tgpt54mini_forced_rag_cc.jsonl",
    "counterfactual_cticonnect_ata_20260907Tgpt54mini_forced_rag_cc.jsonl",
    "counterfactual_cticonnect_ata_20260907Tgpt54mini_soft_gad_cc.jsonl",
]:
    p = ROOT / name
    if not p.exists():
        continue
    s = score_jsonl(p)
    if not s:
        continue
    n, cb, rag = s
    print(f"{name}: n={n} CB={cb:.3f} RAG={rag:.3f}  Δpp={+(rag-cb)*100:.1f}  RER={rer(cb,rag)*100:+.1f}%")

print("\n=== CTIConnect CTA port (EM; no matched CB in same file) ===")
for p in [
    Path("CTICONNECT benchmark/eval_results/cticonnect_scoreboard_20260907Tgpt56sol_cta_port.json"),
    Path("CTICONNECT benchmark/eval_results/cticonnect_scoreboard_20260907Tgpt54mini_cta_port.json"),
]:
    if not p.exists():
        continue
    d = json.loads(p.read_text())
    gen = d.get("generator")
    for task, v in (d.get("systems", {}).get("cta_rag_port", {}).get("per_task") or {}).items():
        print(f"{gen} CTA-port {task}: EM={v['exact_match']:.3f} F1={v['f1']:.3f} n={v['n']}")
PY
