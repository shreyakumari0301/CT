"""Cascade router: probes in paper order, then a 10-token classifier."""
from __future__ import annotations

import os
import re
from typing import Optional, Tuple

VALID_LABELS = {
    "memorization",
    "understanding",
    "problem_solving",
    "reasoning_ate",
    "reasoning_ata",
    "reasoning_taa",
}

_CVSS_RE = re.compile(
    r"\bCVSS\b|vector string|base score|"
    r"AV:[NALP]|attack vector|attack complexity",
    re.IGNORECASE,
)
_MCQ_RE = re.compile(
    r"(multiple[-\s]?choice|\bMCQ\b|"
    r"options?\s*:\s*|option\s*[ABCD]\b|"
    r"\b[ABCD]\)\s|"
    r"choose the best option|"
    r"single uppercase letter|"
    r"among\s+[ABCD])",
    re.IGNORECASE,
)
# Extraction: a set of IDs. Must not fire on "identify the ATT&CK category".
_ATE_RE = re.compile(
    r"extract all MITRE|"
    r"extract all (?:MITRE\s+)?ATT&CK|"
    r"main technique IDs|"
    r"technique IDs from|"
    r"MITRE Enterprise techniques",
    re.IGNORECASE,
)
# Single-technique identification (ATA / CTIConnect).
_ATA_RE = re.compile(
    r"identify the MITRE ATT&CK|"
    r"identify the ATT&CK|"
    r"which MITRE ATT&CK|"
    r"what is the MITRE ATT&CK|"
    r"ATT&CK (?:category|technique)|"
    r"maps to this behavior|"
    r"maps to these behaviors|"
    r"does this (?:attack |behavior )?align|"
    r"single technique ID|"
    r"identify the ATT&CK technique",
    re.IGNORECASE,
)
_TAA_RE = re.compile(
    r"attribute (?:the )?(?:anonymized |anonymised )?(?:threat )?report|"
    r"attribute the incident|"
    r"known threat actor|"
    r"\[PLACEHOLDER\]|"
    r"responsible (?:threat )?actor",
    re.IGNORECASE,
)
_CWE_RE = re.compile(
    r"\bCWE\b|map(?:ping)?\s+(?:the\s+)?(?:CVE|vulnerability)\s+to|"
    r"root\s*cause\s*mapping|appropriate CWE",
    re.IGNORECASE,
)


def _heuristic_classify(text: str) -> Optional[Tuple[str, str]]:
    if _CVSS_RE.search(text):
        return "problem_solving", "cvss_cues"
    if _MCQ_RE.search(text):
        return "memorization", "mcq_cues"
    if _ATE_RE.search(text):
        return "reasoning_ate", "ate_cues"
    if _ATA_RE.search(text):
        return "reasoning_ata", "ata_cues"
    if _TAA_RE.search(text):
        return "reasoning_taa", "taa_cues"
    if _CWE_RE.search(text):
        return "understanding", "cwe_cues"
    return None


def _llm_classify(combined_text: str) -> str:
    from dotenv import load_dotenv

    load_dotenv()
    from utils.llm_client import get_openai_client, resolve_classifier_model
    system_prompt = """You are a CTI task router.
Return exactly one label from:
memorization, understanding, problem_solving, reasoning_ate, reasoning_ata, reasoning_taa

Rules in order:
1. problem_solving — CVSS vector or base score.
2. memorization — MCQ / options A–D.
3. reasoning_ate — extract ALL ATT&CK technique IDs from a description (a set).
4. reasoning_ata — identify ONE ATT&CK technique/category for a described behaviour.
5. reasoning_taa — attribute a threat report to an actor ([PLACEHOLDER] reports).
6. understanding — map a CVE to a CWE.

Output: only the label.
"""
    client = get_openai_client()
    response = client.chat.completions.create(
        model=resolve_classifier_model("gpt-4o-mini"),
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": combined_text[:12000]},
        ],
        temperature=0,
        max_tokens=10,
    )
    label = (response.choices[0].message.content or "").strip().lower()
    label = label.replace("`", "").replace('"', "").split()[0] if label else ""
    label = label.strip(".,:; ")
    if label not in VALID_LABELS:
        return "understanding"
    return label


def _post_override(text: str, label: str) -> str:
    if _MCQ_RE.search(text) and label != "memorization":
        return "memorization"
    if _CVSS_RE.search(text) and label not in {"problem_solving", "memorization"}:
        return "problem_solving"
    if _ATE_RE.search(text) and label == "understanding":
        return "reasoning_ate"
    if _ATA_RE.search(text) and label in {"reasoning_ate", "understanding"}:
        return "reasoning_ata"
    if _CWE_RE.search(text) and label == "memorization" and not _MCQ_RE.search(text):
        return "understanding"
    return label


def classify_query(task: str, context: str) -> str:
    combined_text = f"{task.strip()}\n\n{context.strip()}".strip()
    if not combined_text:
        return "understanding"
    hit = _heuristic_classify(task.strip()) or _heuristic_classify(combined_text)
    if hit is not None:
        return hit[0]
    try:
        return _post_override(combined_text, _llm_classify(combined_text))
    except Exception:
        return "understanding"


def classify_query_debug(task: str, context: str) -> dict:
    combined_text = f"{task.strip()}\n\n{context.strip()}".strip()
    hit = _heuristic_classify(task.strip()) or _heuristic_classify(combined_text)
    if hit is not None:
        label, reason = hit
        return {"label": label, "path": "heuristic", "reason": reason}
    llm_label = None
    try:
        llm_label = _llm_classify(combined_text)
        final = _post_override(combined_text, llm_label)
        return {
            "label": final,
            "path": "llm_override" if final != llm_label else "llm",
            "llm_label": llm_label,
            "reason": "post_override" if final != llm_label else "llm",
        }
    except Exception as exc:
        return {
            "label": "understanding",
            "path": "heuristic_miss",
            "reason": type(exc).__name__,
            "snippet": combined_text[:400],
        }
