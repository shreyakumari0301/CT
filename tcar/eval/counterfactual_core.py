"""Paired closed-book vs forced-retrieval counterfactual evaluation."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from eval.cticonnect_kb import CTIConnectKBRetriever, KBHit
from eval.cticonnect_loader import QARecord
from eval.cticonnect_metrics import score_id_item
from eval.run_ctibench import TASK_CONFIG, parse_for_task
from eval.scoring import mad_cvss, parse_cwe_answer, parse_gold_ate

from tcar.config import TCARConfig
from tcar.gate import GateDecision
from tcar.task_branches import audit_task_kind

_TID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)


@dataclass
class RetrievalAudit:
    recall_at: Dict[int, bool]
    gold_rank: Optional[int]
    retrieval_contains_gold: bool
    retrieved_ids: List[str]


@dataclass
class CounterfactualOutcome:
    closed_book_correct: bool
    retrieval_correct: bool
    retrieval_effect: str  # rescue | damage | neutral_correct | neutral_wrong
    gate_correct_admission: bool
    gate_correct_rejection: bool
    false_rejection: bool
    harmful_admission: bool


def _normalize_cwe(raw: str) -> Optional[str]:
    return parse_cwe_answer(raw or "")


def _gold_ids_cticonnect(ground_truth: dict) -> Set[str]:
    if ground_truth.get("target_id"):
        return {str(ground_truth["target_id"]).upper()}
    ids = ground_truth.get("target_ids") or []
    return {str(x).upper() for x in ids}


def _gold_ids_ctibench(task: str, gold: str) -> Set[str]:
    if task in ("rcm", "rcm2021"):
        cid = _normalize_cwe(gold)
        return {cid} if cid else set()
    if task == "ate":
        return parse_gold_ate(gold)
    if task == "mcq":
        letter = (gold or "").strip().upper()
        return {letter} if letter in {"A", "B", "C", "D"} else set()
    return set()


def _is_correct_cticonnect(prediction: str, ground_truth: dict, *, task: str) -> bool:
    item = score_id_item(prediction, ground_truth, task=task)
    return item.f1 >= 1.0 - 1e-9


def _is_correct_ctibench(task: str, raw: str, gold: str) -> bool:
    parsed = parse_for_task(task, raw or "")
    if task in ("rcm", "rcm2021"):
        p = _normalize_cwe(parsed or "")
        g = _normalize_cwe(gold)
        return bool(p and g and p == g)
    if task == "mcq":
        return parsed is not None and gold is not None and str(parsed).upper() == str(gold).upper()
    if task == "ate":
        pred_set = parsed if isinstance(parsed, set) else set()
        gold_set = parse_gold_ate(gold)
        if not gold_set and not pred_set:
            return True
        if not gold_set or not pred_set:
            return False
        tp = len(gold_set & pred_set)
        prec = tp / len(pred_set)
        rec = tp / len(gold_set)
        if prec + rec == 0:
            return False
        f1 = 2 * prec * rec / (prec + rec)
        return f1 >= 1.0 - 1e-9
    if task == "vsp":
        pred_vec = parsed if isinstance(parsed, str) else None
        if not pred_vec or not gold:
            return False
        return mad_cvss([pred_vec], [gold]) == 0.0
    return False


def _retrieved_id_set(hits: List[KBHit], *, task_kind: str) -> List[str]:
    ids: List[str] = []
    seen: Set[str] = set()
    for h in hits:
        if task_kind in {"rcm", "cwe"}:
            cid = h.doc_id.upper()
            if not cid.startswith("CWE-"):
                cid = f"CWE-{cid}"
            key = cid
        elif task_kind in {"ata", "ate", "mem"}:
            keys: List[str] = []
            if h.doc_id.upper().startswith("T"):
                keys.append(h.doc_id.upper().split(".")[0])
            for tid in _TID_RE.findall(h.text or ""):
                keys.append(tid.upper().split(".")[0])
            if not keys:
                keys.append(h.doc_id)
            for key in keys:
                if key not in seen:
                    seen.add(key)
                    ids.append(key)
            continue
        else:
            key = h.doc_id
        if key not in seen:
            seen.add(key)
            ids.append(key)
    return ids


def audit_retrieval(
    hits: List[KBHit],
    gold_ids: Set[str],
    *,
    task_kind: str,
    ks: Tuple[int, ...] = (1, 3, 5, 10, 20),
) -> RetrievalAudit:
    ordered = _retrieved_id_set(hits, task_kind=task_kind)
    if not gold_ids:
        return RetrievalAudit(
            recall_at={k: False for k in ks},
            gold_rank=None,
            retrieval_contains_gold=False,
            retrieved_ids=ordered,
        )

    gold_main = set()
    for gid in gold_ids:
        if gid.startswith("CWE-"):
            gold_main.add(gid.upper())
        elif gid.startswith("T"):
            gold_main.add(gid.upper().split(".")[0])
        else:
            gold_main.add(gid.upper())

    rank: Optional[int] = None
    for i, rid in enumerate(ordered, start=1):
        rid_norm = rid.upper()
        if rid_norm in gold_main:
            rank = i
            break
        if rid_norm.startswith("CWE-") and rid_norm in gold_main:
            rank = i
            break

    recall_at: Dict[int, bool] = {}
    for k in ks:
        top = set(ordered[:k])
        recall_at[k] = bool(gold_main & top) or any(
            g in top or any(g in t for t in top) for g in gold_main
        )

    return RetrievalAudit(
        recall_at=recall_at,
        gold_rank=rank,
        retrieval_contains_gold=rank is not None and rank <= max(ks),
        retrieved_ids=ordered[: max(ks)],
    )


def classify_outcome(
    *,
    closed_book_correct: bool,
    retrieval_correct: bool,
    gate_admits: bool,
) -> CounterfactualOutcome:
    if closed_book_correct and retrieval_correct:
        effect = "neutral_correct"
    elif not closed_book_correct and retrieval_correct:
        effect = "rescue"
    elif closed_book_correct and not retrieval_correct:
        effect = "damage"
    else:
        effect = "neutral_wrong"

    branches_differ = closed_book_correct != retrieval_correct
    false_rejection = effect == "rescue" and not gate_admits
    harmful_admission = effect == "damage" and gate_admits
    correct_admission = effect == "rescue" and gate_admits
    correct_rejection = effect == "damage" and not gate_admits

    return CounterfactualOutcome(
        closed_book_correct=closed_book_correct,
        retrieval_correct=retrieval_correct,
        retrieval_effect=effect,
        gate_correct_admission=correct_admission,
        gate_correct_rejection=correct_rejection,
        false_rejection=false_rejection,
        harmful_admission=harmful_admission,
    )


def _tcar_kind(task: str) -> str:
    """Retrieval audit bucket per task (alias for task_branches.audit_task_kind)."""
    return audit_task_kind(task)


def build_record(
    *,
    item_id: str,
    benchmark: str,
    task: str,
    question: str,
    gold: Any,
    gold_ids: Set[str],
    closed_book_raw: str,
    retrieval_raw: str,
    gate: GateDecision,
    audit: RetrievalAudit,
    meta: dict,
) -> Dict[str, Any]:
    if benchmark == "cticonnect":
        gt = gold if isinstance(gold, dict) else {}
        cb_ok = _is_correct_cticonnect(closed_book_raw, gt, task=task)
        rag_ok = _is_correct_cticonnect(retrieval_raw, gt, task=task)
    else:
        cb_ok = _is_correct_ctibench(task, closed_book_raw, str(gold))
        rag_ok = _is_correct_ctibench(task, retrieval_raw, str(gold))

    outcome = classify_outcome(
        closed_book_correct=cb_ok,
        retrieval_correct=rag_ok,
        gate_admits=gate.admit_retrieval,
    )

    return {
        "id": item_id,
        "benchmark": benchmark,
        "task": task,
        "question": question,
        "question_preview": question[:300],
        "gold": gold,
        "gold_ids": sorted(gold_ids),
        "closed_book_prediction": closed_book_raw[:4000],
        "retrieval_prediction": retrieval_raw[:4000],
        "closed_book_correct": cb_ok,
        "retrieval_correct": rag_ok,
        "retrieval_effect": outcome.retrieval_effect,
        "gate_decision": "admit" if gate.admit_retrieval else "reject",
        "gate_reliability": round(gate.reliability, 4),
        "retrieval_contains_gold": audit.retrieval_contains_gold,
        "gold_rank": audit.gold_rank,
        "recall_at": audit.recall_at,
        "retrieved_ids": audit.retrieved_ids,
        "false_rejection": outcome.false_rejection,
        "harmful_admission": outcome.harmful_admission,
        "gate_correct_admission": outcome.gate_correct_admission,
        "gate_correct_rejection": outcome.gate_correct_rejection,
        "tcar_meta": meta,
    }


def evaluate_gate_policies(
    records: List[Dict[str, Any]],
    *,
    random_seed: int = 42,
) -> Dict[str, Any]:
    """Score always-CB, always-RAG, current gate, matched-rate random, and oracle."""
    n = len(records)
    if n == 0:
        return {}

    def _score(admit_flags: List[bool]) -> float:
        correct = sum(
            1
            for r, admit in zip(records, admit_flags)
            if (r["retrieval_correct"] if admit else r["closed_book_correct"])
        )
        return round(correct / n, 4)

    always_cb = _score([False] * n)
    always_rag = _score([True] * n)
    current = _score([r.get("gate_decision") == "admit" for r in records])

    admit_rate = sum(1 for r in records if r.get("gate_decision") == "admit") / n
    import random

    rng = random.Random(random_seed)
    random_flags = [rng.random() < admit_rate for _ in range(n)]
    random_matched = _score(random_flags)

    oracle_flags: List[bool] = []
    for r in records:
        effect = r.get("retrieval_effect", "")
        if effect == "rescue":
            oracle_flags.append(True)
        elif effect == "damage":
            oracle_flags.append(False)
        else:
            oracle_flags.append(False)
    oracle = _score(oracle_flags)
    oracle_ceiling = round(
        sum(1 for r in records if r["closed_book_correct"] or r["retrieval_correct"]) / n,
        4,
    )

    differ = [r for r in records if r["closed_book_correct"] != r["retrieval_correct"]]
    gate_acc = None
    if differ:
        gate_acc = round(
            sum(
                1
                for r in differ
                if r.get("gate_correct_admission") or r.get("gate_correct_rejection")
            )
            / len(differ),
            4,
        )

    return {
        "always_closed_book": always_cb,
        "always_rag": always_rag,
        "current_gate": current,
        "random_matched_rate": random_matched,
        "oracle_utility": oracle,
        "oracle_ceiling": oracle_ceiling,
        "gate_admit_rate": round(admit_rate, 4),
        "gate_accuracy_differing": gate_acc,
        "n_differing": len(differ),
    }


def summarize_records(records: List[Dict[str, Any]], *, metric: str) -> Dict[str, Any]:
    n = len(records)
    if n == 0:
        return {"n": 0}

    rescues = sum(1 for r in records if r["retrieval_effect"] == "rescue")
    damages = sum(1 for r in records if r["retrieval_effect"] == "damage")
    neutral_correct = sum(1 for r in records if r["retrieval_effect"] == "neutral_correct")
    neutral_wrong = sum(1 for r in records if r["retrieval_effect"] == "neutral_wrong")

    cb_correct = sum(1 for r in records if r["closed_book_correct"])
    rag_correct = sum(1 for r in records if r["retrieval_correct"])

    differ = [r for r in records if r["closed_book_correct"] != r["retrieval_correct"]]
    gate_correct = sum(
        1 for r in differ if r["gate_correct_admission"] or r["gate_correct_rejection"]
    )

    gold_retrieved = [r for r in records if r.get("recall_at", {}).get(5, False)]
    rag_correct_when_gold = (
        sum(1 for r in gold_retrieved if r["retrieval_correct"]) / len(gold_retrieved)
        if gold_retrieved
        else None
    )

    ks = (1, 3, 5, 10, 20)
    recall_summary = {
        f"recall@{k}": round(
            sum(1 for r in records if r.get("recall_at", {}).get(k, False)) / n, 4
        )
        for k in ks
    }

    ranks = [r["gold_rank"] for r in records if r.get("gold_rank")]
    mrr = round(sum(1.0 / r for r in ranks) / n, 4) if ranks else 0.0
    mean_gold_rank = round(sum(ranks) / len(ranks), 2) if ranks else None

    return {
        "n": n,
        "metric": metric,
        "closed_book_score": round(cb_correct / n, 4),
        "forced_rag_score": round(rag_correct / n, 4),
        "score_delta": round((rag_correct - cb_correct) / n, 4),
        "rescues": rescues,
        "damages": damages,
        "neutral_correct": neutral_correct,
        "neutral_wrong": neutral_wrong,
        "rescue_rate": round(rescues / n, 4),
        "damage_rate": round(damages / n, 4),
        "net_retrieval_utility": round((rescues - damages) / n, 4),
        "false_rejections": sum(1 for r in records if r["false_rejection"]),
        "harmful_admissions": sum(1 for r in records if r["harmful_admission"]),
        "false_rejection_rate": round(sum(1 for r in records if r["false_rejection"]) / n, 4),
        "harmful_admission_rate": round(sum(1 for r in records if r["harmful_admission"]) / n, 4),
        "gate_decision_accuracy": round(gate_correct / len(differ), 4) if differ else None,
        "n_branches_differ": len(differ),
        "gate_admit_rate": round(
            sum(1 for r in records if r["gate_decision"] == "admit") / n, 4
        ),
        "p_rag_correct_given_gold_at_5": (
            round(rag_correct_when_gold, 4) if rag_correct_when_gold is not None else None
        ),
        "n_gold_at_5": len(gold_retrieved),
        "mrr_at_20": mrr,
        "mean_gold_rank": mean_gold_rank,
        "gate_policies": evaluate_gate_policies(records),
        **recall_summary,
    }
