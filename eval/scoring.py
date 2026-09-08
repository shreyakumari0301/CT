"""Answer parsers and CTIBench-style metrics for Phase-1 oracle eval."""

from __future__ import annotations

import json
import re
from typing import Iterable, Optional, Sequence, Set

from cvss import CVSS3
from sklearn.metrics import f1_score
from sklearn.preprocessing import MultiLabelBinarizer


def parse_mcq_answer(text: str) -> Optional[str]:
    """Extract final MCQ letter A/B/C/D from model output."""
    if not text:
        return None
    m = re.search(r"Final Answer:\s*([A-Da-d])\b", text)
    if m:
        return m.group(1).upper()
    # Prefer last standalone letter line
    letters = re.findall(r"(?m)^\s*([A-Da-d])\s*$", text)
    if letters:
        return letters[-1].upper()
    m = re.search(r"\b([A-Da-d])\b\s*$", text.strip())
    return m.group(1).upper() if m else None


def parse_cwe_answer(text: str) -> Optional[str]:
    """Extract CWE-ID from free text or JSON-ish output."""
    if not text:
        return None
    try:
        obj = json.loads(text)
        if isinstance(obj, dict):
            val = obj.get("predicted_cwe") or obj.get("cwe") or obj.get("CWE")
            if val:
                text = str(val)
    except Exception:
        pass
    m = re.search(r"CWE[-\s]?(\d+)", text, flags=re.IGNORECASE)
    if m:
        return f"CWE-{m.group(1)}"
    # last-line preference used by CTIBench prompts
    last = text.strip().splitlines()[-1]
    m = re.search(r"CWE[-\s]?(\d+)", last, flags=re.IGNORECASE)
    return f"CWE-{m.group(1)}" if m else None


def parse_cvss_vector(text: str) -> Optional[str]:
    if not text:
        return None
    compact = text.replace(" ", "")
    m = re.search(r"CVSS:3\.1(?:/[A-Z]+:[A-Z]){8}", compact)
    if m:
        return m.group(0)
    m = re.search(r"CVSS:3\.1/[^\s\n\r]+", text)
    return m.group(0).strip() if m else None


def cvss_base_score(vector: str) -> Optional[float]:
    try:
        return float(CVSS3(vector).scores()[0])
    except Exception:
        return None


def parse_ate_ids(text: str) -> Set[str]:
    """Parse main MITRE technique IDs (drop subtechniques Txxxx.yyy)."""
    if not text:
        return set()
    # Prefer an explicit answer: line
    answer_line = None
    m = re.search(r"(?im)^\s*answer:\s*(.+)$", text)
    if m:
        answer_line = m.group(1)
    else:
        # last non-empty line often holds IDs
        lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
        answer_line = lines[-1] if lines else text

    ids = re.findall(r"\bT\d{4}(?:\.\d{3})?\b", answer_line, flags=re.IGNORECASE)
    mains = set()
    for tid in ids:
        tid = tid.upper()
        mains.add(tid.split(".")[0])
    return mains


def parse_gold_ate(gt: str) -> Set[str]:
    ids = re.findall(r"\bT\d{4}(?:\.\d{3})?\b", gt or "", flags=re.IGNORECASE)
    return {tid.upper().split(".")[0] for tid in ids}


def accuracy(preds: Sequence[Optional[str]], golds: Sequence[str]) -> float:
    if not golds:
        return 0.0
    correct = 0
    for p, g in zip(preds, golds):
        if p is not None and str(p).strip().upper() == str(g).strip().upper():
            correct += 1
    return correct / len(golds)


def mad_cvss(pred_vectors: Sequence[Optional[str]], gold_vectors: Sequence[str]) -> float:
    """
    Paper Eq. (6): MAD over the 8 CVSS v3.1 base metrics (lower is better).
    Each mismatched metric contributes 1; score is mean over metrics, then over examples.
    (Legacy base-score MAD is available as mad_cvss_base_score.)
    """
    metrics = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]

    def parts(vector: Optional[str]) -> dict:
        out = {}
        if not vector:
            return out
        for bit in vector.replace(" ", "").split("/")[1:]:
            if ":" in bit:
                k, v = bit.split(":", 1)
                out[k] = v
        return out

    diffs = []
    for p, g in zip(pred_vectors, gold_vectors):
        pg, gg = parts(p), parts(g)
        if not gg:
            diffs.append(0.0)
            continue
        if not pg:
            diffs.append(1.0)
            continue
        diffs.append(sum(0.0 if pg.get(m) == gg.get(m) else 1.0 for m in metrics) / 8.0)
    return sum(diffs) / len(diffs) if diffs else 0.0


def mad_cvss_base_score(pred_vectors: Sequence[Optional[str]], gold_vectors: Sequence[str]) -> float:
    """Mean absolute difference of CVSS base scores (legacy / extra diagnostic)."""
    diffs = []
    for p, g in zip(pred_vectors, gold_vectors):
        ps = cvss_base_score(p) if p else None
        gs = cvss_base_score(g)
        if ps is None or gs is None:
            diffs.append(10.0 if gs is not None else 0.0)
            continue
        diffs.append(abs(ps - gs))
    return sum(diffs) / len(diffs) if diffs else 0.0


def instance_macro_f1(preds: Sequence[Set[str]], golds: Sequence[Set[str]]) -> float:
    """
    Paper CTI-ATE: per-instance multi-label F1, then mean over instances.
    F1_i = 2PR/(P+R) on technique-ID sets for example i.
    """
    if not golds:
        return 0.0
    scores = []
    for pred, gold in zip(preds, golds):
        pred = pred or set()
        gold = gold or set()
        if not gold and not pred:
            scores.append(1.0)
            continue
        if not gold or not pred:
            scores.append(0.0)
            continue
        tp = len(gold & pred)
        precision = tp / len(pred)
        recall = tp / len(gold)
        scores.append(0.0 if precision + recall == 0 else 2 * precision * recall / (precision + recall))
    return sum(scores) / len(scores)


def macro_f1_multilabel(preds: Sequence[Set[str]], golds: Sequence[Set[str]]) -> float:
    """Label-macro F1 via MultiLabelBinarizer (diagnostic; not the paper ATE metric)."""
    if not golds:
        return 0.0
    mlb = MultiLabelBinarizer()
    y_true = mlb.fit_transform(golds)
    y_pred = mlb.transform(preds)
    return float(f1_score(y_true, y_pred, average="macro", zero_division=0))
