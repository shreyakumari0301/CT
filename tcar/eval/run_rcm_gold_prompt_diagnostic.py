#!/usr/bin/env python3
"""RCM prompt-coverage diagnostic: gold@1/@3/@5 and confusion taxonomy.

Uses hybrid n=200 + matched Vanilla. Writes:
  tcar/eval_results/rcm_prompt_diagnostic/
"""
from __future__ import annotations

import csv
import json
from collections import Counter
from pathlib import Path
from typing import Dict, List, Optional, Set

from eval.scoring import parse_cwe_answer
from tcar.config import TCARConfig
from tcar.taxonomy.cwe_graph import CWEGraph

ROOT = Path(__file__).resolve().parents[2]
HYBRID = ROOT / "tcar/eval_results/counterfactual_ctibench_rcm_20260908Tturbo_rcm_hybrid_n200.jsonl"
VANILLA = ROOT / "tcar/eval_results/counterfactual_ctibench_rcm_20260902Ttask_prompts_cb.jsonl"
OUT = ROOT / "tcar/eval_results/rcm_prompt_diagnostic"
PROMPT_K = 3  # hybrid RCM_TOP_K


def load(path: Path) -> Dict[str, dict]:
    return {
        json.loads(l)["id"]: json.loads(l)
        for l in path.read_text(encoding="utf-8").splitlines()
        if l.strip()
    }


def norm(x: str) -> str:
    return parse_cwe_answer(x) or (x or "").strip().upper()


def cwe_list(ids) -> List[str]:
    out = []
    for s in ids or []:
        c = norm(str(s))
        if c.startswith("CWE-"):
            out.append(c)
    return list(dict.fromkeys(out))


def classify_relation(
    gold: str,
    pred: str,
    graph: CWEGraph,
    *,
    gold_in_prompt3: bool,
    official_rank: Optional[int],
    vanilla_ok: bool,
    hybrid_ok: bool,
) -> str:
    g, p = norm(gold), norm(pred)
    if hybrid_ok or not g or not p or g == p:
        return ""
    if (not gold_in_prompt3) and official_rank is not None and 4 <= official_rank <= 5:
        return "gold_ranked_4_or_5_not_prompted"
    if not gold_in_prompt3:
        return "gold_absent_from_prompt_top3"
    if graph.parent_of.get(p) == g:
        return "child_selected_instead_of_parent"
    if graph.parent_of.get(g) == p:
        return "parent_selected_instead_of_child"
    if p in graph.siblings(g) or g in graph.siblings(p):
        return "sibling_selected"
    gp, pp = graph.parent_of.get(g), graph.parent_of.get(p)
    if gp and pp and gp == pp:
        return "sibling_selected"
    if gp == p or pp == g:
        return "correct_mechanism_wrong_abstraction"
    try:
        gn, pn = int(g.split("-")[1]), int(p.split("-")[1])
        if abs(gn - pn) <= 5:
            return "correct_mechanism_wrong_abstraction"
    except Exception:
        pass
    if vanilla_ok and (not hybrid_ok):
        return "catalogue_candidate_overrides_kb_analogy"
    return "catalogue_override_or_other"


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    hybrid = load(HYBRID)
    vanilla = load(VANILLA)
    cfg = TCARConfig()
    xref = Path(cfg.cwe_xrefs) if not isinstance(cfg.cwe_xrefs, Path) else cfg.cwe_xrefs
    graph = CWEGraph(xref)

    rows = []
    gold_at = {1: 0, 3: 0, 5: 0}
    acc_by_rank = Counter()
    rank_n = Counter()
    confusions = []

    for mid, h in hybrid.items():
        gold = norm(str(h.get("gold") or ""))
        pred = norm(h.get("retrieval_prediction") or "")
        cands = cwe_list(h.get("retrieved_ids"))
        # Prompt shows top-PROMPT_K of the selected/reranked list. Audit retrieved_ids
        # are pool-ordered; prefer tcar_meta selected if present.
        meta = h.get("tcar_meta") or {}
        hy = meta.get("rcm_hybrid") or {}
        sel = cwe_list(hy.get("selected_ids") or [])
        if not sel:
            # fall back: first PROMPT_K of retrieved CWE ids (approx prompt order)
            sel = cands[:PROMPT_K]
        prompt_cands = sel[:PROMPT_K] if sel else cands[:PROMPT_K]
        pool_ids = cwe_list(meta.get("cwe_pool_ids") or cands)
        pool_cands = pool_ids[:5] if pool_ids else prompt_cands
        retrieved5 = cands[:5]

        def rank_in(lst: List[str]) -> Optional[int]:
            if not gold:
                return None
            for i, c in enumerate(lst, 1):
                if c == gold:
                    return i
            return None

        r_prompt = rank_in(prompt_cands)
        r_pool5 = rank_in(pool_cands)
        r_ret5 = rank_in(retrieved5)
        # also official gold_rank from CF (pool)
        gr = h.get("gold_rank")
        official_rank = int(gr) if gr is not None else None

        for k in (1, 3):
            if gold and any(c == gold for c in prompt_cands[:k]):
                gold_at[k] += 1
        # gold@5 = retrieved audit top-5 (matches prior neighbour audit)
        if gold and any(c == gold for c in retrieved5[:5]):
            gold_at[5] += 1

        h_ok = bool(h.get("retrieval_correct"))
        v = vanilla.get(mid) or {}
        v_ok = bool(v.get("retrieval_correct"))
        key = f"rank_{r_prompt}" if r_prompt else "absent_from_prompt_top3"
        rank_n[key] += 1
        if h_ok:
            acc_by_rank[key] += 1

        gold_in_prompt3 = r_prompt is not None
        gold_in_pool5 = (
            r_ret5 is not None
            or r_pool5 is not None
            or (official_rank is not None and official_rank <= 5)
        )

        rel = classify_relation(
            gold,
            pred,
            graph,
            gold_in_prompt3=gold_in_prompt3,
            official_rank=official_rank,
            vanilla_ok=v_ok,
            hybrid_ok=h_ok,
        )

        row = {
            "id": mid,
            "gold": gold,
            "hybrid_pred": pred,
            "hybrid_correct": h_ok,
            "vanilla_rag_correct": v_ok,
            "prompt_top3": "|".join(prompt_cands),
            "gold_rank_in_prompt3": r_prompt or "",
            "gold_rank_official_pool": official_rank or "",
            "gold_in_prompt_top3": gold_in_prompt3,
            "gold_in_pool_top5": gold_in_pool5,
            "effect": h.get("retrieval_effect"),
            "confusion_class": rel,
        }
        rows.append(row)
        if rel and (not h_ok):
            confusions.append(row)

    n = len(rows)
    # rescues/damages vs CB for hybrid
    rescues = [r for r in rows if (hybrid[r["id"]].get("retrieval_effect") == "rescue")]
    damages = [r for r in rows if (hybrid[r["id"]].get("retrieval_effect") == "damage")]

    # Original "32 confusion" style: hybrid wrong while gold in pool top-5
    wrong_with_gold5 = [
        r
        for r in rows
        if (not r["hybrid_correct"]) and r["gold_in_pool_top5"]
    ]
    wrong_with_gold3 = [
        r
        for r in rows
        if (not r["hybrid_correct"]) and r["gold_in_prompt_top3"]
    ]

    # targeted ID lists for cheap pilot (user: 32 confusions + 14 R + 12 D + 50 controls)
    confusion_ids = [r["id"] for r in wrong_with_gold5]
    rescue_ids = [r["id"] for r in rescues]
    damage_ids = [r["id"] for r in damages]
    neutrals = [
        r["id"]
        for r in rows
        if r["hybrid_correct"]
        and r["vanilla_rag_correct"]
        and r["id"] not in set(confusion_ids + rescue_ids + damage_ids)
    ][:50]

    summary = {
        "n": n,
        "prompt_k": PROMPT_K,
        "gold_at_prompt": {
            "gold@1": gold_at[1] / n,
            "gold@3": gold_at[3] / n,
            "gold@5_pool": gold_at[5] / n,
            "counts": {"@1": gold_at[1], "@3": gold_at[3], "@5_pool": gold_at[5]},
            "note": "gold@1/@3 use selected prompt candidates (top-3); gold@5 uses pool top-5.",
        },
        "acc_conditional": {
            "acc_when_gold_in_prompt_top3": (
                sum(1 for r in rows if r["gold_in_prompt_top3"] and r["hybrid_correct"])
                / max(1, sum(1 for r in rows if r["gold_in_prompt_top3"]))
            ),
            "acc_when_gold_absent_from_prompt_top3": (
                sum(1 for r in rows if (not r["gold_in_prompt_top3"]) and r["hybrid_correct"])
                / max(1, sum(1 for r in rows if not r["gold_in_prompt_top3"]))
            ),
            "acc_when_gold_in_pool_top5": (
                sum(1 for r in rows if r["gold_in_pool_top5"] and r["hybrid_correct"])
                / max(1, sum(1 for r in rows if r["gold_in_pool_top5"]))
            ),
            "n_gold_in_prompt_top3": sum(1 for r in rows if r["gold_in_prompt_top3"]),
            "n_gold_absent_prompt_top3": sum(1 for r in rows if not r["gold_in_prompt_top3"]),
            "n_gold_in_pool_top5": sum(1 for r in rows if r["gold_in_pool_top5"]),
            "note": (
                "Prior 77.9% used gold@pool5 presence; Acc|gold@prompt3 is the "
                "generator-relevant figure."
            ),
        },
        "acc_by_prompt_rank": {
            k: (acc_by_rank[k] / rank_n[k] if rank_n[k] else None)
            for k in sorted(rank_n.keys())
        },
        "rank_counts": dict(rank_n),
        "wrong_with_gold_in_prompt_top3": {
            "n": len(wrong_with_gold3),
            "class_counts": dict(Counter(r["confusion_class"] for r in wrong_with_gold3)),
        },
        "wrong_with_gold_in_pool_top5": {
            "n": len(wrong_with_gold5),
            "class_counts": dict(Counter(r["confusion_class"] for r in wrong_with_gold5)),
            "note": "Matches prior ~32 neighbour-confusion audit scope (gold@5 present, pred wrong).",
        },
        "confusion_n_all_hybrid_wrong": len(confusions),
        "confusion_class_counts_all_wrong": dict(Counter(r["confusion_class"] for r in confusions)),
        "hybrid_rescues": len(rescue_ids),
        "hybrid_damages": len(damage_ids),
        "pilot_ids": {
            "confusion_prompt_top3": len(wrong_with_gold3),
            "confusion_pool_top5": len(wrong_with_gold5),
            "rescues": len(rescue_ids),
            "damages": len(damage_ids),
            "neutral_controls": len(neutrals),
            "total_unique": len(set(confusion_ids + rescue_ids + damage_ids + neutrals)),
        },
    }

    with (OUT / "per_item.csv").open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    with (OUT / "confusions.csv").open("w", encoding="utf-8", newline="") as f:
        if wrong_with_gold5:
            w = csv.DictWriter(f, fieldnames=list(wrong_with_gold5[0].keys()))
            w.writeheader()
            w.writerows(wrong_with_gold5)
    with (OUT / "confusions_prompt_top3.csv").open("w", encoding="utf-8", newline="") as f:
        if wrong_with_gold3:
            w = csv.DictWriter(f, fieldnames=list(wrong_with_gold3[0].keys()))
            w.writeheader()
            w.writerows(wrong_with_gold3)

    def write_ids(name: str, ids: List[str]) -> None:
        (OUT / name).write_text("\n".join(ids) + ("\n" if ids else ""), encoding="utf-8")

    write_ids("confusion_ids.txt", confusion_ids)
    write_ids("confusion_prompt_top3_ids.txt", [r["id"] for r in wrong_with_gold3])
    write_ids("rescue_ids.txt", rescue_ids)
    write_ids("damage_ids.txt", damage_ids)
    write_ids("neutral_control_ids.txt", neutrals)
    pilot = list(dict.fromkeys(confusion_ids + rescue_ids + damage_ids + neutrals))
    write_ids("pilot_ids.txt", pilot)

    (OUT / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
