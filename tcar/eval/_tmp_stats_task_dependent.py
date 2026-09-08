#!/usr/bin/env python3
"""Stats for task-dependent Forced RAG claims: McNemar, bootstrap, common-ID."""
from __future__ import annotations

import json
import random
from pathlib import Path
from typing import Any, Dict, List, Sequence, Tuple

from eval.cticonnect_metrics import score_id_item
from eval.run_unified_rag import parse_for_task
from eval.scoring import mad_cvss, parse_cvss_vector

BASE = Path("tcar/eval_results")
EVAL = Path("eval_results")
RNG = random.Random(13)


def load_cf(path: Path) -> Dict[str, Dict[str, Any]]:
    by: Dict[str, Dict[str, Any]] = {}
    if not path.exists():
        return by
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        r = json.loads(line)
        rid = str(r.get("id") or "")
        if not rid:
            continue
        prev = by.get(rid)
        if prev is None or (prev.get("error") and not r.get("error")):
            by[rid] = r
        elif bool(prev.get("error")) == bool(r.get("error")):
            by[rid] = r
    return {k: v for k, v in by.items() if not v.get("error")}


def mcnemar(cb: Sequence[bool], rag: Sequence[bool]) -> Dict[str, float]:
    rescue = damage = both = neither = 0
    for a, b in zip(cb, rag):
        if (not a) and b:
            rescue += 1
        elif a and (not b):
            damage += 1
        elif a and b:
            both += 1
        else:
            neither += 1
    n = rescue + damage
    if n == 0:
        p = 1.0
    else:
        from math import comb

        k = min(rescue, damage)
        cdf = sum(comb(n, i) for i in range(k + 1)) / (2**n)
        p = min(1.0, max(0.0, 2 * cdf - comb(n, k) / (2**n)))
    return {
        "n": float(len(cb)),
        "rescue": float(rescue),
        "damage": float(damage),
        "both": float(both),
        "neither": float(neither),
        "cb": sum(cb) / len(cb),
        "rag": sum(rag) / len(rag),
        "mid_p": p,
    }


def bootstrap_mean_diff(
    a: Sequence[float], b: Sequence[float], *, B: int = 2000
) -> Tuple[float, float, float]:
    """Paired bootstrap CI for mean(b-a)."""
    n = len(a)
    diffs = [b[i] - a[i] for i in range(n)]
    point = sum(diffs) / n
    boots = []
    for _ in range(B):
        idxs = [RNG.randrange(n) for _ in range(n)]
        boots.append(sum(diffs[i] for i in idxs) / n)
    boots.sort()
    lo = boots[int(0.025 * B)]
    hi = boots[int(0.975 * B) - 1]
    return point, lo, hi


def print_mc(label: str, rows: List[Dict[str, Any]]) -> None:
    cb = [bool(r.get("closed_book_correct")) for r in rows]
    rag = [bool(r.get("retrieval_correct")) for r in rows]
    m = mcnemar(cb, rag)
    print(
        f"{label}: n={m['n']:.0f} CB={m['cb']:.3f} RAG={m['rag']:.3f} "
        f"rescue={m['rescue']:.0f} damage={m['damage']:.0f} both={m['both']:.0f} neither={m['neither']:.0f} "
        f"McNemar mid-p≈{m['mid_p']:.4g}"
    )


def main() -> None:
    stamp = "20260904Tgpt56sol_forced_rag_cb"
    print("=== Forced RAG sol: McNemar CB vs RAG ===")
    rcm = list(load_cf(BASE / f"counterfactual_ctibench_rcm_{stamp}.jsonl").values())
    mcq = list(load_cf(BASE / f"counterfactual_ctibench_mcq_{stamp}.jsonl").values())
    vsp = list(load_cf(BASE / f"counterfactual_ctibench_vsp_{stamp}.jsonl").values())
    print_mc("CTIBench RCM", rcm)
    print_mc("CTIBench MCQ", mcq)
    print_mc("CTIBench VSP (exact)", vsp)

    print("\n=== VSP paired bootstrap on exact Acc and MAD_base (partial) ===")
    # exact as 0/1; MAD where both parse
    cb_exact = [1.0 if r.get("closed_book_correct") else 0.0 for r in vsp]
    rag_exact = [1.0 if r.get("retrieval_correct") else 0.0 for r in vsp]
    d, lo, hi = bootstrap_mean_diff(cb_exact, rag_exact)
    print(f"VSP exact Acc Δ RAG-CB={d:+.4f} 95% CI [{lo:+.4f}, {hi:+.4f}]")

    cb_mad, rag_mad = [], []
    for r in vsp:
        gold = str(r.get("gold") or "")
        cbv = parse_cvss_vector(r.get("closed_book_prediction") or "")
        rgv = parse_cvss_vector(r.get("retrieval_prediction") or "")
        if cbv and rgv and gold:
            cb_mad.append(mad_cvss([cbv], [gold]))
            rag_mad.append(mad_cvss([rgv], [gold]))
    if cb_mad:
        d, lo, hi = bootstrap_mean_diff(cb_mad, rag_mad)
        print(
            f"VSP MAD_base Δ RAG-CB={d:+.4f} 95% CI [{lo:+.4f}, {hi:+.4f}] "
            f"(n_parsed_both={len(cb_mad)}; lower MAD better)"
        )

    print("\n=== CTIConnect ATA F1 bootstrap (dense full) ===")
    ata = list(load_cf(BASE / "counterfactual_cticonnect_ata_20260906Tgpt56sol_forced_rag_cc.jsonl").values())
    cb_f1 = [
        score_id_item(r.get("closed_book_prediction") or "", r["gold"], task="ata").f1 for r in ata
    ]
    rag_f1 = [
        score_id_item(r.get("retrieval_prediction") or "", r["gold"], task="ata").f1 for r in ata
    ]
    d, lo, hi = bootstrap_mean_diff(cb_f1, rag_f1)
    print(
        f"ATA dense F1 Δ RAG-CB={d:+.4f} 95% CI [{lo:+.4f}, {hi:+.4f}] "
        f"(mean CB={sum(cb_f1)/len(cb_f1):.3f} RAG={sum(rag_f1)/len(rag_f1):.3f} n={len(ata)})"
    )

    beh = list(load_cf(BASE / "counterfactual_cticonnect_ata_20260906Tgpt56sol_ata_behavior_cc.jsonl").values())
    if beh:
        cb_f1 = [
            score_id_item(r.get("closed_book_prediction") or "", r["gold"], task="ata").f1 for r in beh
        ]
        rag_f1 = [
            score_id_item(r.get("retrieval_prediction") or "", r["gold"], task="ata").f1 for r in beh
        ]
        d, lo, hi = bootstrap_mean_diff(cb_f1, rag_f1)
        print(
            f"ATA behavior F1 Δ RAG-CB={d:+.4f} 95% CI [{lo:+.4f}, {hi:+.4f}] "
            f"(mean CB={sum(cb_f1)/len(cb_f1):.3f} RAG={sum(rag_f1)/len(rag_f1):.3f} n={len(beh)})"
        )

    print("\n=== CTIConnect RCM McNemar ===")
    cc_rcm = list(load_cf(BASE / "counterfactual_cticonnect_rcm_20260906Tgpt56sol_forced_rag_cc.jsonl").values())
    print_mc("CTIConnect RCM", cc_rcm)

    print("\n=== Common-ID: Forced RAG vs Self-RAG (MCQ) ===")
    # Self-RAG keys (task, idx); Forced RAG ids mcq-{idx}
    self_path = EVAL / "selfrag_20260906Tgpt56sol_baselines.jsonl"
    self_map = {}
    if self_path.exists():
        for line in self_path.read_text(encoding="utf-8").splitlines():
            r = json.loads(line)
            if r.get("error") or r.get("task") != "mcq":
                continue
            idx = int(r["idx"])
            parsed = r.get("parsed")
            if parsed is None:
                parsed = parse_for_task("mcq", r.get("raw") or "")
            gold = str(r.get("gold") or "").strip().upper()
            self_map[idx] = parsed is not None and str(parsed).upper() == gold

    fr_map = {}
    for r in mcq:
        # id like mcq-12
        rid = str(r["id"])
        if not rid.startswith("mcq-"):
            continue
        idx = int(rid.split("-", 1)[1])
        fr_map[idx] = bool(r.get("retrieval_correct"))

    common = sorted(set(self_map) & set(fr_map))
    print(f"common MCQ IDs: {len(common)} (self={len(self_map)} forced_rag={len(fr_map)})")
    if common:
        s = [self_map[i] for i in common]
        f = [fr_map[i] for i in common]
        print(f"Self-RAG Acc={sum(s)/len(s):.3f}  Forced-RAG Acc={sum(f)/len(f):.3f}")
        # McNemar Self vs Forced
        # treat Self as A, Forced as B
        m = mcnemar(s, f)  # rescue=Forced-only, damage=Self-only when A=self B=forced... wait
        # mcnemar(cb, rag): rescue = not cb and rag. So mcnemar(self, forced):
        # rescue = Forced wins where Self wrong; damage = Self wins where Forced wrong
        print(
            f"McNemar Self vs Forced-RAG: Forced_only={m['rescue']:.0f} Self_only={m['damage']:.0f} "
            f"mid-p≈{m['mid_p']:.4g}"
        )


if __name__ == "__main__":
    main()
