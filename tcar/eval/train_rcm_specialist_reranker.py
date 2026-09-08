#!/usr/bin/env python3
"""Train a lightweight RCM specialist reranker (pairwise, hard taxonomy negatives).

Positive = gold CWE. Hard negatives = retrieved sibling/parent/child CWEs in dense top-20.
Features: dense score, taxonomy_score, mechanism overlap, sibling/parent flags.
Loss: logistic pairwise (gold should outrank each hard negative).

Usage (no LLM):
  PYTHONPATH=. python -m tcar.eval.train_rcm_specialist_reranker --limit 0
  # then: RCM_RERANK=learned
"""

from __future__ import annotations

import argparse
import csv
import json
import pickle
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Sequence, Tuple

import numpy as np

ROOT = Path(__file__).resolve().parents[2]

from eval.cticonnect_kb import KBHit  # noqa: E402
from eval.cta_rag_port import cwe_graph  # noqa: E402
from tcar.ctibench_kb import CTIBenchKBRetriever  # noqa: E402
from tcar.specialist_retrieval import (  # noqa: E402
    RCM_RERANK_FEATURE_NAMES,
    RcmRerankModel,
    _norm_cwe,
    _tokset,
    taxonomy_score_cwe,
)


def _mech_overlap(query: str, hit: KBHit) -> float:
    from tcar.specialist_retrieval import _RCM_MECH_TERMS

    q = (query or "").lower()
    blob = f"{hit.title or ''} {hit.text or ''}".lower()
    return float(sum(1 for t in _RCM_MECH_TERMS if t in q and t in blob))


def _jaccard(query: str, hit: KBHit) -> float:
    qt, ht = _tokset(query), _tokset(f"{hit.title or ''} {hit.text or ''}")
    if not qt or not ht:
        return 0.0
    return len(qt & ht) / max(1, len(qt | ht))


def feature_vector(query: str, hit: KBHit) -> List[float]:
    """Query–candidate features only (usable at inference without gold)."""
    return [
        float(hit.score or 0.0),
        taxonomy_score_cwe(query, hit),
        _mech_overlap(query, hit),
        _jaccard(query, hit),
    ]


def _pairs_for_row(
    query: str,
    gold: str,
    pool: Sequence[KBHit],
    graph,
) -> List[Tuple[List[float], List[float]]]:
    g = _norm_cwe(gold)
    by_id = {_norm_cwe(h.doc_id): h for h in pool}
    gold_hit = by_id.get(g)
    if gold_hit is None:
        return []
    neigh = set(graph.siblings(g))
    if g in graph.parent_of:
        neigh.add(graph.parent_of[g])
    neigh.update(graph.children_of.get(g, ()))
    hard: List[KBHit] = []
    soft: List[KBHit] = []
    for h in pool:
        cid = _norm_cwe(h.doc_id)
        if cid == g:
            continue
        if cid in neigh:
            hard.append(h)
        else:
            soft.append(h)
    # Prefer sibling/parent/child hard negatives; fill from other pool members.
    negs = (hard + soft)[:8]
    if not negs:
        return []
    g_feats = feature_vector(query, gold_hit)
    return [(g_feats, feature_vector(query, h)) for h in negs]


def train_pairwise(
    pairs: List[Tuple[List[float], List[float]]],
    *,
    lr: float = 0.05,
    epochs: int = 40,
) -> RcmRerankModel:
    """Simple logistic RankNet-style on feature differences (pos - neg)."""
    if not pairs:
        return RcmRerankModel(
            weights=[0.0] * len(RCM_RERANK_FEATURE_NAMES),
            bias=0.0,
            feature_names=list(RCM_RERANK_FEATURE_NAMES),
        )
    w = np.zeros(len(RCM_RERANK_FEATURE_NAMES), dtype=np.float64)
    b = 0.0
    for _ in range(epochs):
        for pos, neg in pairs:
            diff = np.asarray(pos, dtype=np.float64) - np.asarray(neg, dtype=np.float64)
            s = float(np.dot(w, diff) + b)
            # P(pos > neg) = sigmoid(s); maximize log-likelihood
            p = 1.0 / (1.0 + np.exp(-np.clip(s, -20, 20)))
            grad = (1.0 - p)
            w += lr * grad * diff
            b += lr * grad * 0.1
    return RcmRerankModel(
        weights=w.tolist(),
        bias=float(b),
        feature_names=list(RCM_RERANK_FEATURE_NAMES),
    )


def apply_learned(query: str, hits: Sequence[KBHit], model: RcmRerankModel) -> List[KBHit]:
    scored = [(model.score(feature_vector(query, h)), h) for h in hits]
    scored.sort(key=lambda x: x[0], reverse=True)
    return [h for _, h in scored]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--pool", type=int, default=20)
    ap.add_argument(
        "--out",
        type=Path,
        default=ROOT / "tcar" / "eval_results" / "rcm_specialist_reranker.pkl",
    )
    args = ap.parse_args()

    data = ROOT / "data" / "cti-rcm.tsv"
    rows = list(csv.DictReader(data.open(encoding="utf-8", errors="replace"), delimiter="\t"))
    if args.limit and args.limit > 0:
        rows = rows[: args.limit]

    retriever = CTIBenchKBRetriever()
    graph = cwe_graph()
    pairs: List[Tuple[List[float], List[float]]] = []
    gold_at20 = 0
    for row in rows:
        q = (row.get("Description") or "").strip()
        gold = _norm_cwe(row.get("GT") or "")
        pool = retriever.retrieve(q, "cwe", k=args.pool)
        if any(_norm_cwe(h.doc_id) == gold for h in pool):
            gold_at20 += 1
        pairs.extend(_pairs_for_row(q, gold, pool, graph))

    model = train_pairwise(pairs)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("wb") as f:
        pickle.dump(model, f)
    meta = {
        "n_rows": len(rows),
        "n_pairs": len(pairs),
        "gold_at_20": gold_at20 / len(rows) if rows else 0.0,
        "weights": dict(zip(RCM_RERANK_FEATURE_NAMES, model.weights)),
        "bias": model.bias,
        "out": str(args.out),
        "stamp": datetime.now(timezone.utc).isoformat(),
    }
    meta_path = args.out.with_suffix(".json")
    meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")
    print(json.dumps(meta, indent=2))
    print(f"wrote {args.out}")


if __name__ == "__main__":
    main()
