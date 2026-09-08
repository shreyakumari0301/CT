"""Strip gold CWE/CVE/CVSS strings from overlapping CTI corpora."""

from __future__ import annotations

import re

_CVE_ID_RE = re.compile(r"CVE-\d{4}-\d+", re.I)
_CWE_ID_RE = re.compile(r"CWE-\d+", re.I)
_CVSS_RE = re.compile(r"CVSS:3\.[01]/[A-Za-z0-9:/]+", re.I)
_VULN_TYPE_RE = re.compile(r"Vulnerability type:\s*CWE-\d+", re.I)
_NVD_URL_RE = re.compile(r"https?://nvd\.nist\.gov/vuln/detail/CVE-\d{4}-\d+", re.I)


def norm_text(text: str) -> str:
    return re.sub(r"\W+", " ", (text or "").lower()).strip()


def is_query_near_dup(query: str, passage: str) -> bool:
    q, p = norm_text(query), norm_text(passage)
    if not p or not q:
        return False
    if p == q:
        return True
    if len(p) >= 40 and p in q:
        return True
    if len(q) >= 40 and q in p:
        return True
    return False


def has_gold_label(text: str) -> bool:
    """True if prose still contains an answer-key identifier."""
    if not text:
        return False
    return bool(_CWE_ID_RE.search(text) or _CVE_ID_RE.search(text) or _CVSS_RE.search(text))


def sanitize_cve_store_passage(text: str) -> str:
    """Drop gold CWE/CVE/CVSS strings; keep neighbour prose only."""
    text = _VULN_TYPE_RE.sub("", text or "")
    text = _CVSS_RE.sub("", text)
    text = _NVD_URL_RE.sub("", text)
    text = _CVE_ID_RE.sub("", text)
    text = _CWE_ID_RE.sub("", text)
    return re.sub(r"\s+", " ", text).strip()
