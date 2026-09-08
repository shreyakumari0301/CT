#!/usr/bin/env python3
"""Offline RCM hybrid audit with full stage table (no LLM).

Stages reported:
  Dense@20, BM25@20, Dense∪BM25@20, RRF@20, Taxonomy@5 (on dense), Hybrid→Taxonomy@5
"""
from __future__ import annotations

import csv
import json
import time
from pathlib import Path

from tcar.ctibench_kb import CTIBenchKBRetriever
from tcar.rcm_mechanism_hybrid import (
    CweHybridRetriever,
    hybrid_retrieve_cwe,
    normalize_rcm_mechanism_query,
    retrieve_rcm_mechanism_hybrid,
)
from tcar.specialist_retrieval import _norm_cwe, gold_in_top_n, rerank_cwe_taxonomy

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "data" / "cti-rcm.tsv"
OUT = ROOT / "tcar" / "eval_results" / "rcm_hybrid_offline_audit.json"

# Gate thresholds (methodological)
MIN_HYBRID_R20 = 0.60
MIN_TAX5 = 0.455  # must exceed prior taxonomy@5 = 45.5%
BASE_DENSE_R20 = 0.542


def _hit(ids, gold: str) -> bool:
    g = _norm_cwe(gold)
    return g in {_norm_cwe(x) for x in ids}


def main() -> None:
    rows = list(csv.DictReader(DATA.open(encoding="utf-8", errors="replace"), delimiter="\t"))
    print(f"loading retrievers on n={len(rows)} ...", flush=True)
    t0 = time.time()
    dense = CTIBenchKBRetriever()
    _ = dense.retrieve("injection", "cwe", k=5)
    _ = CweHybridRetriever.get()
    print(f"ready in {time.time()-t0:.1f}s", flush=True)

    c_dense20 = c_bm25 = c_union = c_rrf = c_tax5_dense = c_tax5_hyb = c_dense5 = 0
    gold_in_union_lost_rrf = 0
    n = 0
    for i, row in enumerate(rows):
        q = (row.get("Description") or "").strip()
        gold = _norm_cwe((row.get("GT") or "").strip())
        if not q or not gold:
            continue
        n += 1
        mech = normalize_rcm_mechanism_query(q)

        d_hits = dense.retrieve(q, "cwe", k=20)
        if gold_in_top_n(d_hits, [gold], n=20)["gold_at_n"]:
            c_dense20 += 1
        if gold_in_top_n(d_hits, [gold], n=5)["gold_at_n"]:
            c_dense5 += 1

        bm = CweHybridRetriever.get().bm25_retrieve(mech or q, k=20)
        if gold_in_top_n(bm, [gold], n=20)["gold_at_n"]:
            c_bm25 += 1

        pool, meta = hybrid_retrieve_cwe(q, dense, pool_k=20)
        dense_ids = meta.get("dense_ids") or []
        bm25_ids = meta.get("bm25_ids") or [h.doc_id for h in bm]
        # True dense∪BM25 ceiling uses mechanism+raw lists already in meta.union_ids
        union_ids = meta.get("union_ids") or list(dict.fromkeys(list(dense_ids) + list(bm25_ids)))
        rrf_ids = meta.get("rrf_ids") or [h.doc_id for h in pool]

        if _hit(union_ids, gold):
            c_union += 1
            if not _hit(rrf_ids, gold):
                gold_in_union_lost_rrf += 1
        if _hit(rrf_ids, gold):
            c_rrf += 1

        tax = rerank_cwe_taxonomy(mech or q, d_hits, top_k=5, diversify=False)
        if gold_in_top_n(tax, [gold], n=5)["gold_at_n"]:
            c_tax5_dense += 1

        _, selected, _ = retrieve_rcm_mechanism_hybrid(
            q, dense, pool_k=20, top_k=5, gold_ids=[gold]
        )
        if gold_in_top_n(selected, [gold], n=5)["gold_at_n"]:
            c_tax5_hyb += 1

        if (i + 1) % 100 == 0:
            print(
                f"[{i+1}/{len(rows)}] dense@20={c_dense20/n:.3f} bm25@20={c_bm25/n:.3f} "
                f"union@20={c_union/n:.3f} rrf@20={c_rrf/n:.3f} hyb_tax@5={c_tax5_hyb/n:.3f}",
                flush=True,
            )

    hybrid_r20 = c_rrf / n
    tax5 = c_tax5_hyb / n
    gate_ok = (hybrid_r20 >= MIN_HYBRID_R20) and (tax5 > MIN_TAX5)
    summary = {
        "n": n,
        "stages": {
            "dense_recall@20": c_dense20 / n,
            "bm25_recall@20": c_bm25 / n,
            "dense_union_bm25_recall@20": c_union / n,
            "rrf_recall@20": c_rrf / n,
            "taxonomy_on_dense_recall@5": c_tax5_dense / n,
            "hybrid_then_taxonomy_recall@5": tax5,
            "dense_recall@5": c_dense5 / n,
        },
        # Back-compat keys for gate script
        "dense_gold@20": c_dense20 / n,
        "bm25_mech_gold@20": c_bm25 / n,
        "union_gold@20": c_union / n,
        "hybrid_gold@20": hybrid_r20,
        "taxonomy_on_dense_gold@5": c_tax5_dense / n,
        "hybrid_then_taxonomy_gold@5": tax5,
        "gold_in_union_lost_by_rrf": gold_in_union_lost_rrf,
        "gold_in_union_lost_by_rrf_rate": gold_in_union_lost_rrf / n,
        "baselines": {
            "prior_dense_gold@20": BASE_DENSE_R20,
            "prior_taxonomy_gold@5": MIN_TAX5,
        },
        "gate": {
            "min_hybrid_recall@20": MIN_HYBRID_R20,
            "min_taxonomy_recall@5": MIN_TAX5,
            "pass": gate_ok,
            "reasons": {
                "hybrid@20_ok": hybrid_r20 >= MIN_HYBRID_R20,
                "taxonomy@5_ok": tax5 > MIN_TAX5,
            },
        },
        "elapsed_s": round(time.time() - t0, 1),
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary, indent=2))
    print(f"wrote {OUT} gate_pass={gate_ok}")


if __name__ == "__main__":
    main()
