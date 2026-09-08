#!/usr/bin/env python3
"""Paper-facing corrections: matched-ID RCM/VSP, ATE metric labels, VSP decode audit, MCQ merge check."""
from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from eval.scoring import (
    cvss_base_score,
    instance_macro_f1,
    mad_cvss,
    mad_cvss_base_score,
    parse_ate_ids,
    parse_cwe_answer,
    parse_cvss_vector,
    parse_gold_ate,
)
from tcar.vsp_structured_decoder import (  # noqa: F401 — kept for future deeper audit
    decode_vsp_prediction,
)

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "tcar/eval_results/status_corrections_20260908.json"

VANILLA_RCM = ROOT / "tcar/eval_results/counterfactual_ctibench_rcm_20260902Ttask_prompts_cb.jsonl"
HYBRID_RCM = ROOT / "tcar/eval_results/counterfactual_ctibench_rcm_20260908Tturbo_rcm_hybrid_n200.jsonl"
VANILLA_VSP = ROOT / "tcar/eval_results/counterfactual_ctibench_vsp_20260902Ttask_prompts_cb.jsonl"
STRUCT_VSP = ROOT / "tcar/eval_results/counterfactual_ctibench_vsp_20260908Tturbo_vsp_structured_n75.jsonl"
ATE = ROOT / "tcar/eval_results/counterfactual_ctibench_ate_20260902Ttask_prompts_cb.jsonl"
ATA_V4 = ROOT / "tcar/eval_results/counterfactual_cticonnect_ata_20260908Tturbo_ata_grounded_v4_full.jsonl"
MCQ_V2 = ROOT / "tcar/eval_results/counterfactual_ctibench_mcq_20260907Tturbo_mcq_option_aware_v2.jsonl"
MCQ_V3 = ROOT / "tcar/eval_results/counterfactual_ctibench_mcq_20260908Tturbo_mcq_relation_aware_changed.jsonl"
MCQ_REGEN_IDS = ROOT / "tcar/eval_results/mcq_v3_changed/regen_ids.txt"


def load_jsonl(path: Path) -> Dict[str, dict]:
    out = {}
    for ln in path.read_text(encoding="utf-8").splitlines():
        if not ln.strip():
            continue
        r = json.loads(ln)
        out[r["id"]] = r
    return out


def mean(xs: List[float]) -> Optional[float]:
    return sum(xs) / len(xs) if xs else None


def ata_delta() -> dict:
    rows = list(load_jsonl(ATA_V4).values())
    n = len(rows)
    cb = sum(1 for r in rows if r.get("closed_book_correct"))
    rag = sum(1 for r in rows if r.get("retrieval_correct"))
    rescues = sum(1 for r in rows if (not r.get("closed_book_correct")) and r.get("retrieval_correct"))
    damages = sum(1 for r in rows if r.get("closed_book_correct") and (not r.get("retrieval_correct")))
    delta_pp = (rescues - damages) / n * 100
    return {
        "n": n,
        "cb_count": cb,
        "rag_count": rag,
        "cb_pct": round(100 * cb / n, 1),
        "rag_pct": round(100 * rag / n, 1),
        "rescues": rescues,
        "damages": damages,
        "delta_pp_rounded_half_up_1": 26.3,
        "delta_pp_exact": round(delta_pp, 2),
        "formula": f"({rescues}-{damages})/{n} = {delta_pp:.2f} pp → report +26.3 pp (half-up)",
        "oracle_headroom_note": "branch oracle ≈71/160; v4 ≈70/160; ~1 item headroom",
        "publication_caveat": (
            "If damage gate was tuned on these 160 gold outcomes, treat as development; "
            "need held-out eval for paper claim."
        ),
    }


def rcm_matched() -> dict:
    hybrid = load_jsonl(HYBRID_RCM)
    vanilla = load_jsonl(VANILLA_RCM)
    ids = sorted(hybrid.keys())
    missing = [i for i in ids if i not in vanilla]
    rows = []
    gold_in_top5_ok = []
    gold_absent_ok = []
    neighbour_confusion = 0
    cand_counts = []
    prompt_lens = []

    for mid in ids:
        h, v = hybrid[mid], vanilla.get(mid)
        if not v:
            continue
        gold = parse_cwe_answer(h.get("gold") or "") or (h.get("gold") or "").strip().upper()
        h_pred = parse_cwe_answer(h.get("retrieval_prediction") or "")
        v_cb = bool(v.get("closed_book_correct"))
        v_rag = bool(v.get("retrieval_correct"))
        h_cb = bool(h.get("closed_book_correct"))
        h_rag = bool(h.get("retrieval_correct"))
        meta = h.get("tcar_meta") or {}
        seeds = meta.get("seed_ids") or []
        retrieved = list(h.get("retrieved_ids") or [])
        # Prefer CWE-looking retrieved_ids for utilization; seed_ids are often chunk ints
        cand = []
        for s in retrieved + list(meta.get("catalogue_ids") or []):
            c = parse_cwe_answer(str(s)) or (str(s).upper() if str(s).upper().startswith("CWE-") else "")
            if c:
                cand.append(c)
        cand = list(dict.fromkeys(cand))
        cand_counts.append(len(cand) if cand else len(seeds))
        prompt_k = meta.get("prompt_k") or len(cand) or len(seeds)
        prompt_lens.append(int(prompt_k) if prompt_k else 0)

        gold_at5 = bool(h.get("retrieval_contains_gold")) or (
            h.get("gold_rank") is not None and int(h.get("gold_rank") or 999) <= 5
        )
        if gold and any(gold == s for s in cand[:5]):
            gold_at5 = True
        if gold_at5:
            gold_in_top5_ok.append(1 if h_rag else 0)
        else:
            gold_absent_ok.append(1 if h_rag else 0)
        # incorrect neighbour: gold present but model picks another candidate CWE
        if gold_at5 and h_pred and gold and h_pred != gold and h_pred in cand:
            neighbour_confusion += 1

        rows.append(
            {
                "id": mid,
                "vanilla_cb": v_cb,
                "vanilla_rag": v_rag,
                "hybrid_cb": h_cb,
                "hybrid_rag": h_rag,
                "gold_at5": gold_at5,
            }
        )

    n = len(rows)
    return {
        "n": n,
        "vanilla_missing_ids": len(missing),
        "same_200": {
            "Vanilla": {
                "CB": round(sum(r["vanilla_cb"] for r in rows) / n, 4) if n else None,
                "RAG": round(sum(r["vanilla_rag"] for r in rows) / n, 4) if n else None,
            },
            "Hybrid": {
                "CB": round(sum(r["hybrid_cb"] for r in rows) / n, 4) if n else None,
                "RAG": round(sum(r["hybrid_rag"] for r in rows) / n, 4) if n else None,
            },
        },
        "hybrid_internal_delta_pp": round(
            (sum(r["hybrid_rag"] for r in rows) - sum(r["hybrid_cb"] for r in rows)) / n * 100, 1
        )
        if n
        else None,
        "hybrid_vs_vanilla_rag_delta_pp": round(
            (sum(r["hybrid_rag"] for r in rows) - sum(r["vanilla_rag"] for r in rows)) / n * 100, 1
        )
        if n
        else None,
        "utilization": {
            "n_gold_in_top5": sum(1 for r in rows if r["gold_at5"]),
            "acc_when_gold_in_top5": round(mean([float(x) for x in gold_in_top5_ok]) or 0, 4),
            "n_gold_absent": sum(1 for r in rows if not r["gold_at5"]),
            "acc_when_gold_absent": round(mean([float(x) for x in gold_absent_ok]) or 0, 4)
            if gold_absent_ok
            else None,
            "incorrect_retrieved_neighbour_count": neighbour_confusion,
            "incorrect_neighbour_rate_among_gold_at5": round(
                neighbour_confusion / max(1, sum(1 for r in rows if r["gold_at5"])), 4
            ),
            "mean_candidate_count": round(mean([float(c) for c in cand_counts]) or 0, 3),
            "mean_prompt_k": round(mean([float(c) for c in prompt_lens]) or 0, 3),
        },
        "note": (
            "Matched Vanilla is task_prompts_cb turbo on the same 200 hybrid IDs. "
            "Do not compare hybrid n=200 to Vanilla full n=1000."
        ),
    }


def _facts_from_meta(meta: dict, side: str) -> Optional[dict]:
    key = "vsp_cb_decoder" if side == "cb" else "vsp_rag_decoder"
    dec = meta.get(key) or {}
    return dec.get("facts")


def vsp_audit() -> dict:
    struct = load_jsonl(STRUCT_VSP)
    vanilla = load_jsonl(VANILLA_VSP)
    ids = sorted(struct.keys())

    # Matched Vanilla
    v_cb_ok = v_rag_ok = 0
    v_cb_vecs, v_rag_vecs, gold_vecs = [], [], []
    s_cb_ok = s_rag_ok = 0
    s_cb_vecs, s_rag_vecs = [], []

    decode_stats = Counter()
    consistency_harm = consistency_help = 0
    missing_fields = 0
    invalid_cats = 0
    defaults_used = 0

    required_fact_keys = [
        "attack_location",
        "attack_conditions",
        "required_privileges",
        "user_interaction",
        "scope_change",
        "confidentiality_impact",
        "integrity_impact",
        "availability_impact",
    ]
    valid = {
        "attack_location": {"network", "adjacent", "local", "physical"},
        "attack_conditions": {"no special condition", "special"},
        "required_privileges": {"none", "low", "high"},
        "user_interaction": {"none", "required"},
        "confidentiality_impact": {"none", "low", "high"},
        "integrity_impact": {"none", "low", "high"},
        "availability_impact": {"none", "low", "high"},
    }

    for mid in ids:
        s = struct[mid]
        v = vanilla.get(mid)
        gold = parse_cvss_vector(str(s.get("gold") or "")) or str(s.get("gold") or "")
        gold_vecs.append(gold)
        meta = s.get("tcar_meta") or {}

        if v:
            vcb = parse_cvss_vector(v.get("closed_book_prediction") or "")
            vrag = parse_cvss_vector(v.get("retrieval_prediction") or "")
            v_cb_vecs.append(vcb)
            v_rag_vecs.append(vrag)
            if v.get("closed_book_correct"):
                v_cb_ok += 1
            if v.get("retrieval_correct"):
                v_rag_ok += 1
        else:
            v_cb_vecs.append(None)
            v_rag_vecs.append(None)

        scb = parse_cvss_vector(s.get("closed_book_prediction") or "")
        srag = parse_cvss_vector(s.get("retrieval_prediction") or "")
        s_cb_vecs.append(scb)
        s_rag_vecs.append(srag)
        if s.get("closed_book_correct"):
            s_cb_ok += 1
        if s.get("retrieval_correct"):
            s_rag_ok += 1

        # Decode audit on RAG side (and CB)
        for side in ("cb", "rag"):
            facts = _facts_from_meta(meta, side)
            if not facts:
                decode_stats[f"{side}_missing_facts_blob"] += 1
                continue
            for k in required_fact_keys:
                if k not in facts or facts.get(k) is None or facts.get(k) == "":
                    missing_fields += 1
                    decode_stats[f"{side}_missing_{k}"] += 1
            for k, allowed in valid.items():
                val = facts.get(k)
                if val is None:
                    continue
                if isinstance(val, bool):
                    continue
                if str(val).lower() not in {a.lower() for a in allowed}:
                    invalid_cats += 1
                    decode_stats[f"{side}_invalid_{k}"] += 1
            unc = facts.get("uncertain") or []
            if unc:
                defaults_used += 1
                decode_stats[f"{side}_has_uncertain"] += 1

            # Compare rulebased vector vs decoded vector disagreement with gold
            dec = meta.get("vsp_cb_decoder" if side == "cb" else "vsp_rag_decoder") or {}
            raw_facts = meta.get("vsp_cb_facts_raw" if side == "cb" else "vsp_rag_facts_raw")
            rb_vec = parse_cvss_vector(str(meta.get("vsp_rulebased_vector") or ""))
            final_vec = parse_cvss_vector(str(dec.get("vector") or ""))
            if rb_vec and final_vec and gold and side == "rag":
                mad_rb = mad_cvss([rb_vec], [gold])
                mad_fi = mad_cvss([final_vec], [gold])
                if mad_fi < mad_rb - 1e-9:
                    consistency_help += 1
                elif mad_fi > mad_rb + 1e-9:
                    consistency_harm += 1

            if raw_facts:
                decode_stats[f"{side}_has_raw_facts"] += 1
            else:
                decode_stats[f"{side}_no_raw_facts"] += 1

    n = len(ids)
    n_v = sum(1 for mid in ids if mid in vanilla)

    return {
        "n_structured": n,
        "n_vanilla_matched": n_v,
        "same_75": {
            "Vanilla": {
                "exact_CB": round(v_cb_ok / n, 4),
                "exact_RAG": round(v_rag_ok / n, 4),
                "MAD8_CB": round(mad_cvss(v_cb_vecs, gold_vecs), 4),
                "MAD8_RAG": round(mad_cvss(v_rag_vecs, gold_vecs), 4),
                "MAD_base_CB": round(mad_cvss_base_score(v_cb_vecs, gold_vecs), 4),
                "MAD_base_RAG": round(mad_cvss_base_score(v_rag_vecs, gold_vecs), 4),
            },
            "Structured": {
                "exact_CB": round(s_cb_ok / n, 4),
                "exact_RAG": round(s_rag_ok / n, 4),
                "MAD8_CB": round(mad_cvss(s_cb_vecs, gold_vecs), 4),
                "MAD8_RAG": round(mad_cvss(s_rag_vecs, gold_vecs), 4),
                "MAD_base_CB": round(mad_cvss_base_score(s_cb_vecs, gold_vecs), 4),
                "MAD_base_RAG": round(mad_cvss_base_score(s_rag_vecs, gold_vecs), 4),
            },
        },
        "decode_audit": {
            "missing_field_events": missing_fields,
            "invalid_categorical_events": invalid_cats,
            "sides_with_uncertain_defaults": defaults_used,
            "consistency_helped_vs_gold": consistency_help,
            "consistency_harmed_vs_gold": consistency_harm,
            "counters": dict(decode_stats),
            "note": (
                "Structured CB exact 6.7% vs Vanilla same-75 CB is the key signal of "
                "prompt/parser/decoder loss — not a n=1000 comparison."
            ),
        },
    }


def ate_metrics() -> dict:
    rows = list(load_jsonl(ATE).values())
    golds = [parse_gold_ate(str(r.get("gold") or "")) for r in rows]
    cb_preds = [parse_ate_ids(r.get("closed_book_prediction") or "") for r in rows]
    rag_preds = [parse_ate_ids(r.get("retrieval_prediction") or "") for r in rows]
    cb_exact = sum(1 for r in rows if r.get("closed_book_correct")) / len(rows)
    rag_exact = sum(1 for r in rows if r.get("retrieval_correct")) / len(rows)
    # verify exact == F1>=1
    def f1_eq1(pred, gold):
        if not gold and not pred:
            return True
        if not gold or not pred:
            return False
        tp = len(gold & pred)
        p, r = tp / len(pred), tp / len(gold)
        return (2 * p * r / (p + r)) >= 1.0 - 1e-9 if (p + r) else False

    cb_exact2 = sum(1 for p, g in zip(cb_preds, golds) if f1_eq1(p, g)) / len(rows)
    rag_exact2 = sum(1 for p, g in zip(rag_preds, golds) if f1_eq1(p, g)) / len(rows)
    return {
        "n": len(rows),
        "stamp": "20260902Ttask_prompts_cb",
        "cf_summary_metric_label": "Macro-F1 (MISLABELED for CF closed_book_score/forced_rag_score)",
        "what_cf_boolean_actually_is": "exact-set accuracy (instance F1 >= 1)",
        "exact_set_accuracy": {
            "CB": round(cb_exact, 4),
            "Forced_RAG": round(rag_exact, 4),
            "verified_recompute_CB": round(cb_exact2, 4),
            "verified_recompute_RAG": round(rag_exact2, 4),
        },
        "mean_instance_F1": {
            "CB": round(instance_macro_f1(cb_preds, golds), 4),
            "Forced_RAG": round(instance_macro_f1(rag_preds, golds), 4),
        },
        "paper_write": (
            "Report Exact-set Acc = 30.0% for Turbo Forced-RAG on this stamp; "
            "also report mean instance F1 separately (≈0.86 here). "
            "Do not call the CF Acc column Macro-F1."
        ),
    }


def mcq_merge_status() -> dict:
    v2 = load_jsonl(MCQ_V2)
    v3_path = MCQ_V3
    v3 = load_jsonl(v3_path) if v3_path.exists() else {}
    regen_ids = [
        ln.strip()
        for ln in MCQ_REGEN_IDS.read_text(encoding="utf-8").splitlines()
        if ln.strip()
    ]
    # Partial merge projection if any v3 rows exist
    correct = 0
    replaced = 0
    for mid, r2 in v2.items():
        if mid in v3:
            ok = bool(v3[mid].get("retrieval_correct"))
            replaced += 1
        else:
            ok = bool(r2.get("retrieval_correct"))
        if ok:
            correct += 1
    return {
        "v2_n": len(v2),
        "v2_unique_ids": len(v2),
        "regen_target_n": len(regen_ids),
        "v3_completed_n": len(v3),
        "v3_progress_pct": round(100 * len(v3) / max(1, len(regen_ids)), 2),
        "merged_would_have_n": len(v2),  # always 2500 if overlay
        "partial_merged_acc_if_score_now": round(correct / max(1, len(v2)), 4),
        "note": "Do not report partial merge Acc. Wait until v3_completed_n == regen_target_n, then overlay.",
        "merge_recipe": (
            "Start from v2 predictions; replace only regen_ids with v3; "
            "assert len(unique ids)==2500 before scoring."
        ),
    }


def main() -> None:
    report = {
        "ATA_v4": ata_delta(),
        "RCM_matched_200": rcm_matched(),
        "VSP_matched_75_and_decode_audit": vsp_audit(),
        "ATE_metric_correction": ate_metrics(),
        "MCQ_v3_merge_status": mcq_merge_status(),
    }
    OUT.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))
    print(f"\nwrote {OUT}")


if __name__ == "__main__":
    main()
