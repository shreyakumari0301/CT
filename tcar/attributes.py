"""Rule-based attribute extraction for RCM / ATA (no extra LLM)."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Set


@dataclass
class RCMAttributes:
    mechanism: str = ""
    path_type: str = ""  # relative | absolute | ""
    operation: str = ""
    root_cause: str = ""
    impact: str = ""
    keywords: Set[str] = field(default_factory=set)


@dataclass
class ATAAttributes:
    behaviors: List[Dict[str, str]] = field(default_factory=list)
    keywords: Set[str] = field(default_factory=set)


_PATH_REL = re.compile(r"\b(relative path|\.\./|\.\.\\|directory traversal)\b", re.I)
_PATH_ABS = re.compile(r"\b(absolute path|root directory|/etc/|c:\\\\)\b", re.I)
_OVERFLOW = re.compile(r"\b(buffer overflow|out-of-bounds|stack overflow|heap overflow)\b", re.I)
_XSS = re.compile(r"\b(cross[- ]site scripting|xss|script injection)\b", re.I)
_SESSION = re.compile(r"\b(session fixation|session hijack|session id)\b", re.I)
_TRAVERSAL = re.compile(r"\b(path traversal|directory traversal)\b", re.I)
_NULL_DEREF = re.compile(r"\b(null pointer|null dereference)\b", re.I)
_AUTH = re.compile(r"\b(authentication bypass|login bypass|without password)\b", re.I)
_LOCK = re.compile(r"\b(deadlock|race condition|improper lock)\b", re.I)


def extract_rcm_attributes(text: str) -> RCMAttributes:
    t = text.lower()
    attrs = RCMAttributes(keywords=set(re.findall(r"[a-z]{5,}", t)[:40]))
    if _TRAVERSAL.search(text) or "path" in t and "travers" in t:
        attrs.mechanism = "path traversal"
        attrs.root_cause = "improper pathname restriction"
    elif _XSS.search(text):
        attrs.mechanism = "cross-site scripting"
    elif _SESSION.search(text):
        attrs.mechanism = "session management"
        attrs.root_cause = "session identifier acceptance"
    elif _OVERFLOW.search(text):
        attrs.mechanism = "memory buffer overflow"
        attrs.root_cause = "missing bounds check"
    elif _NULL_DEREF.search(text):
        attrs.mechanism = "null pointer dereference"
    elif _AUTH.search(text):
        attrs.mechanism = "authentication bypass"
    elif _LOCK.search(text):
        attrs.mechanism = "improper locking"
    if _PATH_REL.search(text):
        attrs.path_type = "relative"
    elif _PATH_ABS.search(text):
        attrs.path_type = "absolute"
    if "denial of service" in t or "crash" in t:
        attrs.impact = "availability"
    if "integrity" in t or "delete" in t:
        attrs.impact = "integrity"
    return attrs


# ATA behavior cues
_BEHAVIOR_PATTERNS: List[tuple[str, re.Pattern[str]]] = [
    ("exploit_public_app", re.compile(r"\b(exploit(s|ing)?\s+(a\s+)?(public[- ]facing|web[- ]facing|internet[- ]facing))\b", re.I)),
    ("privilege_escalation", re.compile(r"\b(elevat(e|ion|es)\s+privilege|elevation of privilege|eop)\b", re.I)),
    ("vps_c2", re.compile(r"\b(virtual private server|\bvps\b|command[- ]and[- ]control|\bc2\b)\b", re.I)),
    ("ransomware", re.compile(r"\b(ransomware|encrypt(s|ed|ing)?\s+(files|data|user))\b", re.I)),
    ("phishing", re.compile(r"\b(phishing|spear[- ]phishing|malicious email)\b", re.I)),
    ("credential", re.compile(r"\b(credential(s)?|password(s)?|brute[- ]force)\b", re.I)),
    ("persistence", re.compile(r"\b(persist(s|ence|ent)|scheduled task|registry run)\b", re.I)),
    ("lateral", re.compile(r"\b(lateral movement|remote service|rdp|smb)\b", re.I)),
    ("motw_bypass", re.compile(r"\b(mark of the web|motw)\b", re.I)),
    ("client_execution", re.compile(r"\b(craft(ed|ing)?\s+(office|document|macro)|remote code execution)\b", re.I)),
]


def extract_ata_behaviors(text: str) -> ATAAttributes:
    behaviors: List[Dict[str, str]] = []
    seen: Set[str] = set()
    for label, pat in _BEHAVIOR_PATTERNS:
        if pat.search(text) and label not in seen:
            seen.add(label)
            m = pat.search(text)
            snippet = (m.group(0) if m else label)[:120]
            behaviors.append({"label": label, "snippet": snippet})
    keywords = set(re.findall(r"\b(?:CVE-\d{4}-\d+|T\d{4}(?:\.\d{3})?)\b", text, re.I))
    return ATAAttributes(behaviors=behaviors, keywords=keywords)
