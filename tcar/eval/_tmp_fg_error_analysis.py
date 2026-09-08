#!/usr/bin/env python3
"""Error analysis: Forced RAG vs Force GAD (gpt-5.6-sol partial)."""
from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from pathlib import Path

BASE = Path("tcar/eval_results")
FORCED = "20260904Tgpt56sol_forced_rag_cb"
GAD = "20260904Tgpt56sol_force_gad_cb"


def load(stamp: str, task: str) -> dict:
    p = BASE / f"counterfactual_ctibench_{task}_{stamp}.jsonl"
    by = {}
    if not p.exists():
        return by
    for line in p.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            r = json.loads(line)
        except Exception:
            continue
        rid = r.get("id")
        if not rid or r.get("error"):
            continue
        by[rid] = r
    return by


def pred_snip(text: str, n: int = 180) -> str:
    t = (text or "").replace("\n", " ").strip()
    return t[:n] + ("…" if len(t) > n else "")


def extract_ids_ate(text: str) -> list[str]:
    # last answer-like line
    ids = re.findall(r"\bT\d{4}(?:\.\d{3})?\b", text or "")
    return ids


def extract_cwe(text: str) -> str | None:
    m = re.search(r"CWE-?\d+", text or "", re.I)
    return m.group(0).upper().replace("CWE", "CWE-").replace("CWE--", "CWE-") if m else None


def analyze_task(task: str, max_examples: int = 5):
    f = load(FORCED, task)
    g = load(GAD, task)
    ids = sorted(set(f) & set(g))
    print(f"\n{'='*70}\nTASK {task}  paired_ok={len(ids)}  forced_only={len(set(f)-set(g))}  gad_only={len(set(g)-set(f))}")
    if not ids:
        print("  (no paired successful rows)")
        return

    # RAG branch comparison
    both_ok = both_bad = forced_only = gad_only = 0
    damages = []  # forced correct, gad wrong
    rescues = []  # gad correct, forced wrong
    for i in ids:
        fr = bool(f[i].get("retrieval_correct"))
        gr = bool(g[i].get("retrieval_correct"))
        if fr and gr:
            both_ok += 1
        elif not fr and not gr:
            both_bad += 1
        elif fr and not gr:
            forced_only += 1
            damages.append(i)
        else:
            gad_only += 1
            rescues.append(i)

    f_rag = sum(1 for i in ids if f[i].get("retrieval_correct")) / len(ids)
    g_rag = sum(1 for i in ids if g[i].get("retrieval_correct")) / len(ids)
    f_cb = sum(1 for i in ids if f[i].get("closed_book_correct")) / len(ids)
    g_cb = sum(1 for i in ids if g[i].get("closed_book_correct")) / len(ids)
    print(f"  paired CB:   ForcedRAG={f_cb:.1%}  ForceGAD={g_cb:.1%}")
    print(f"  paired RAG:  ForcedRAG={f_rag:.1%}  ForceGAD={g_rag:.1%}")
    print(f"  both RAG ok={both_ok}  both bad={both_bad}  Forced-only(damages by GAD)={forced_only}  GAD-only(rescues)={gad_only}")

    # Show damage examples
    print(f"\n  --- Force GAD DAMAGES (Forced RAG correct, GAD wrong) n={len(damages)} ---")
    for i in damages[:max_examples]:
        row_f, row_g = f[i], g[i]
        q = (row_f.get("question") or row_f.get("question_preview") or "")[:160]
        gold = row_f.get("gold") or row_f.get("gold_ids")
        print(f"\n  [{i}] gold={gold}")
        print(f"    Q: {q}")
        print(f"    ForcedRAG pred: {pred_snip(row_f.get('retrieval_prediction') or '')}")
        print(f"    ForceGAD  pred: {pred_snip(row_g.get('retrieval_prediction') or '')}")
        meta = row_g.get("tcar_meta") or {}
        gad = meta.get("gad") or meta.get("diversify") or {}
        if isinstance(gad, dict):
            sel = gad.get("selected_ids") or (gad.get("mitre_gad") or {}).get("selected_ids")
            if sel:
                print(f"    GAD catalogue IDs: {sel[:12]}")
        if task == "ate":
            gids = extract_ids_ate(row_g.get("retrieval_prediction") or "")
            fids = extract_ids_ate(row_f.get("retrieval_prediction") or "")
            print(f"    Forced IDs={fids[-8:]}  GAD IDs={gids[-8:]}")

    print(f"\n  --- Force GAD RESCUES (GAD correct, Forced wrong) n={len(rescues)} ---")
    for i in rescues[: max(2, max_examples // 2)]:
        row_f, row_g = f[i], g[i]
        gold = row_f.get("gold") or row_f.get("gold_ids")
        print(f"  [{i}] gold={gold}")
        print(f"    Forced: {pred_snip(row_f.get('retrieval_prediction') or '', 120)}")
        print(f"    GAD:    {pred_snip(row_g.get('retrieval_prediction') or '', 120)}")


def main():
    for task in ("ate", "rcm", "mcq", "vsp"):
        analyze_task(task, max_examples=4)


if __name__ == "__main__":
    main()
