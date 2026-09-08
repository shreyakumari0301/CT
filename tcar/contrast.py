"""Contrastive scoring and contrast-card generation."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Tuple

from tcar.attributes import RCMAttributes, extract_rcm_attributes
from tcar.config import TCARConfig
from tcar.corpus_store import CorpusStore


@dataclass
class CandidateScore:
    doc_id: str
    similarity: float
    support: float
    contradiction: float
    abstraction_penalty: float
    total: float
    support_notes: List[str] = field(default_factory=list)
    against_notes: List[str] = field(default_factory=list)


def _token_overlap(a: str, b: str) -> float:
    ta = set(re.findall(r"[a-z0-9]{4,}", a.lower()))
    tb = set(re.findall(r"[a-z0-9]{4,}", b.lower()))
    if not ta or not tb:
        return 0.0
    return len(ta & tb) / len(ta | tb)


def _rcm_support_contradiction(
    q_attrs: RCMAttributes, cwe_id: str, store: CorpusStore
) -> Tuple[float, float, List[str], List[str]]:
    row = store.cwe(cwe_id)
    title = (row or {}).get("title", "") or ""
    blob = f"{title} {cwe_id}".lower()
    support, against = 0.0, 0.0
    sup_notes: List[str] = []
    ag_notes: List[str] = []

    if q_attrs.mechanism:
        if q_attrs.mechanism.replace("-", " ") in blob or any(
            w in blob for w in q_attrs.mechanism.split()
        ):
            support += 0.4
            sup_notes.append(f"Mechanism '{q_attrs.mechanism}' aligns with catalogue title.")
        else:
            against += 0.15

    if q_attrs.path_type == "relative" and "relative" in blob:
        support += 0.35
        sup_notes.append("Relative path cue matches candidate scope.")
    elif q_attrs.path_type == "relative" and "absolute" in blob:
        against += 0.35
        ag_notes.append("Question implies relative path; candidate mentions absolute path.")

    if q_attrs.path_type == "absolute" and "absolute" in blob:
        support += 0.35
        sup_notes.append("Absolute path cue matches candidate.")
    elif q_attrs.path_type == "absolute" and "relative" in blob:
        against += 0.35
        ag_notes.append("Question implies absolute path; candidate is relative-specific.")

    # Parent-child heuristic from ID numbering (CWE-22 family)
    if cwe_id.upper() in {"CWE-22", "CWE-35", "CWE-36", "CWE-37"} and q_attrs.path_type == "relative":
        if cwe_id.upper() != "CWE-23":
            against += 0.2
            ag_notes.append("Relative path described; CWE-23 may be more specific than this parent/sibling.")

    if "parent" in title.lower() or cwe_id.upper() in {"CWE-20", "CWE-707"}:
        against += 0.15
        ag_notes.append("Candidate may be overly broad (parent/category CWE).")

    return min(support, 1.0), min(against, 1.0), sup_notes, ag_notes


def score_rcm_candidates(
    question: str,
    candidate_ids: List[str],
    similarities: Dict[str, float],
    store: CorpusStore,
    cfg: TCARConfig,
) -> List[CandidateScore]:
    q_attrs = extract_rcm_attributes(question)
    scored: List[CandidateScore] = []
    for cid in candidate_ids:
        sim = similarities.get(cid, 0.0)
        sup, con, sn, an = _rcm_support_contradiction(q_attrs, cid, store)
        abs_pen = 0.2 if cid.upper() in {"CWE-20", "CWE-707", "CWE-699"} else 0.0
        total = (
            sim
            + cfg.alpha_support * sup
            - cfg.beta_contradiction * con
            - cfg.gamma_abstraction * abs_pen
        )
        scored.append(
            CandidateScore(
                doc_id=cid,
                similarity=sim,
                support=sup,
                contradiction=con,
                abstraction_penalty=abs_pen,
                total=total,
                support_notes=sn,
                against_notes=an,
            )
        )
    scored.sort(key=lambda x: x.total, reverse=True)
    return scored


_BEHAVIOR_TO_TECHNIQUE: Dict[str, List[str]] = {
    "exploit_public_app": ["T1190"],
    "privilege_escalation": ["T1068"],
    "vps_c2": ["T1583.003"],
    "ransomware": ["T1486"],
    "phishing": ["T1566"],
    "credential": ["T1110"],
    "persistence": ["T1053"],
    "lateral": ["T1021"],
    "motw_bypass": ["T1553.005"],
    "client_execution": ["T1203"],
}


def score_ata_candidates(
    question: str,
    candidate_ids: List[str],
    similarities: Dict[str, float],
    store: CorpusStore,
    cfg: TCARConfig,
) -> List[CandidateScore]:
    from tcar.attributes import extract_ata_behaviors

    beh = extract_ata_behaviors(question)
    scored: List[CandidateScore] = []
    for tid in candidate_ids:
        sim = similarities.get(tid, 0.0)
        sup, con = 0.0, 0.0
        sn, an = [], []
        row = store.mitre(tid)
        title = (row or {}).get("title", "").lower()
        for b in beh.behaviors:
            mapped = _BEHAVIOR_TO_TECHNIQUE.get(b["label"], [])
            if tid.upper() in [m.upper() for m in mapped]:
                sup += 0.45
                sn.append(f"Behavior '{b['label']}' supports {tid}.")
            elif mapped and tid.upper().split(".")[0] in [m.split(".")[0] for m in mapped]:
                sup += 0.2
                sn.append(f"Parent technique related to behavior '{b['label']}'.")
        if beh.keywords and tid.upper() in {k.upper() for k in beh.keywords}:
            sup += 0.5
            sn.append("Technique ID explicitly mentioned in text.")
        # Penalize parent when sub-technique cues present
        if "." not in tid and store.mitre_subtechniques(tid):
            con += 0.15
            an.append("Sub-techniques exist; prefer sub-ID if text supports granularity.")
        if not sn and sim < 0.25:
            con += 0.1
            an.append("Weak semantic and behavioral support.")
        total = sim + cfg.alpha_support * min(sup, 1.0) - cfg.beta_contradiction * min(con, 1.0)
        scored.append(
            CandidateScore(
                doc_id=tid.upper(),
                similarity=sim,
                support=min(sup, 1.0),
                contradiction=min(con, 1.0),
                abstraction_penalty=0.0,
                total=total,
                support_notes=sn,
                against_notes=an,
            )
        )
    scored.sort(key=lambda x: x.total, reverse=True)
    return scored


def build_contrast_card(scored: List[CandidateScore], store: CorpusStore, kind: str) -> str:
    lines = ["TAXONOMY CONTRAST CARD (select ONE best ID):"]
    for cs in scored[:5]:
        label = store.short_label(kind, cs.doc_id)
        lines.append(f"\nCandidate: {label}")
        if cs.support_notes:
            lines.append("Support:")
            for n in cs.support_notes[:3]:
                lines.append(f"- {n}")
        else:
            lines.append("Support: (weak)")
        if cs.against_notes:
            lines.append("Against:")
            for n in cs.against_notes[:3]:
                lines.append(f"- {n}")
        else:
            lines.append("Against: (none noted)")
    lines.append("\nSelect exactly one identifier supported by the question text.")
    return "\n".join(lines)
