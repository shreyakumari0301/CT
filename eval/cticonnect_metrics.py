"""CTIConnect identifier P/R/F1 scoring (ported from CTIConnect evaluation/metrics.py)."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, List


ID_PATTERNS: dict[str, re.Pattern] = {
    "cve": re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE),
    "cwe": re.compile(r"CWE-\d+", re.IGNORECASE),
    "capec": re.compile(r"CAPEC-\d+", re.IGNORECASE),
    "mitre": re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE),
}


def normalize_id(raw: str, kind: str) -> str:
    if not raw:
        return ""
    s = raw.strip().upper()
    if kind == "mitre":
        m = re.search(r"T\s*\d{4}(?:\.\d{3})?", s)
        return m.group(0).replace(" ", "") if m else ""
    prefix = {"cve": "CVE", "cwe": "CWE", "capec": "CAPEC"}.get(kind)
    if prefix is None:
        return s
    if kind == "cve":
        m = re.search(r"CVE[\s-]*(\d{4})[\s-]*(\d{4,})", s)
        return f"CVE-{m.group(1)}-{m.group(2)}" if m else ""
    m = re.search(rf"{prefix}[\s-]*(\d+)", s)
    return f"{prefix}-{m.group(1)}" if m else ""


def extract_ids(text: str, kind: str) -> set[str]:
    if not text:
        return set()
    out: set[str] = set()
    for m in ID_PATTERNS[kind].finditer(text):
        norm = normalize_id(m.group(0), kind)
        if norm:
            out.add(norm)
    return out


def prf1(pred: set[str], gold: set[str]) -> tuple[float, float, float]:
    if not gold and not pred:
        return 1.0, 1.0, 1.0
    if not pred or not gold:
        return 0.0, 0.0, 0.0
    inter = len(pred & gold)
    p = inter / len(pred)
    r = inter / len(gold)
    f1 = (2 * p * r / (p + r)) if (p + r) > 0 else 0.0
    return p, r, f1


@dataclass
class ItemScore:
    id: str
    task: str
    precision: float
    recall: float
    f1: float
    pred_ids: list[str]
    gold_ids: list[str]
    exact_match: bool


def _gold_id_set(ground_truth: dict) -> tuple[str, set[str], set[str]]:
    kind = ground_truth["target_type"]
    if ground_truth.get("target_id"):
        gold = {str(ground_truth["target_id"]).upper()}
    else:
        gold = {g.upper() for g in (ground_truth.get("target_ids") or [])}
    valid = {g.upper() for g in (ground_truth.get("valid_target_ids") or [])} | gold
    return kind, gold, valid


def _primary_cwe_pred(prediction: str) -> set[str]:
    """RCM answers commit to one CWE; score the first structured ID only."""
    from eval.scoring import parse_cwe_answer

    primary = parse_cwe_answer(prediction or "")
    return {primary} if primary else set()


def score_id_item(
    prediction: str,
    ground_truth: dict,
    *,
    task: str = "",
    item_id: str = "",
) -> ItemScore:
    kind, gold, valid = _gold_id_set(ground_truth)
    # RCM is single-label: do not punish extra CWE mentions in the justification.
    if kind == "cwe" and (task in ("", "rcm") or task.startswith("rcm")):
        pred = _primary_cwe_pred(prediction)
    else:
        pred = {p.upper() for p in extract_ids(prediction, kind)}
    if pred and pred <= valid and len(valid) > len(gold):
        return ItemScore(
            id=item_id,
            task=task,
            precision=1.0,
            recall=1.0,
            f1=1.0,
            pred_ids=sorted(pred),
            gold_ids=sorted(gold),
            exact_match=True,
        )
    p, r, f1 = prf1(pred, gold)
    return ItemScore(
        id=item_id,
        task=task,
        precision=p,
        recall=r,
        f1=f1,
        pred_ids=sorted(pred),
        gold_ids=sorted(gold),
        exact_match=(pred == gold),
    )


def aggregate_scores(items: List[ItemScore]) -> Dict[str, Any]:
    def _mean(xs: List[float]) -> float:
        return sum(xs) / len(xs) if xs else 0.0

    by_task: Dict[str, List[ItemScore]] = {}
    for it in items:
        by_task.setdefault(it.task, []).append(it)

    per_task = {}
    for task, its in sorted(by_task.items()):
        per_task[task] = {
            "n": len(its),
            "precision": _mean([i.precision for i in its]),
            "recall": _mean([i.recall for i in its]),
            "f1": _mean([i.f1 for i in its]),
            "exact_match": _mean([1.0 if i.exact_match else 0.0 for i in its]),
        }
    overall = {
        "n": len(items),
        "precision": _mean([i.precision for i in items]),
        "recall": _mean([i.recall for i in items]),
        "f1": _mean([i.f1 for i in items]),
        "exact_match": _mean([1.0 if i.exact_match else 0.0 for i in items]),
    }
    return {"overall": overall, "per_task": per_task}
