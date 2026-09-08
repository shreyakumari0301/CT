"""VSP structured fact extraction → deterministic CVSS v3.1 decoding.

Enable with:
  VSP_RETRIEVAL=structured
  GAD_MODE=off

Consistency:
  VSP_CONSISTENCY=off|high_precision|all   (default: high_precision)

Schema: each metric is {value, confidence, evidence}. Never emit value="uncertain".
Do not map uncertainty onto fixed defaults (PR:N / S:U).
"""

from __future__ import annotations

import json
import os
import re
from copy import deepcopy
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

from eval.scoring import parse_cvss_vector

_METRICS = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")

# Sentinel: field not provided by model; filled from description heuristics (not silent N/U).
_MISSING = ""


def env_flag(name: str, default: str = "") -> str:
    return (os.getenv(name) or default).strip().lower()


def vsp_consistency_mode() -> str:
    raw = env_flag("VSP_CONSISTENCY", "high_precision")
    if raw in {"0", "off", "none", "false", "no"}:
        return "off"
    if raw in {"all", "full", "legacy"}:
        return "all"
    if raw in {"high_precision", "hp", "strict", "1", "true", "yes", ""}:
        return "high_precision"
    return "high_precision"


@dataclass
class VspFacts:
    attack_location: str = _MISSING  # network|adjacent|local|physical
    attack_conditions: str = _MISSING  # no special condition|special
    required_privileges: str = _MISSING  # none|low|high
    user_interaction: str = _MISSING  # none|required
    scope_change: Optional[bool] = None
    confidentiality_impact: str = _MISSING  # none|low|high
    integrity_impact: str = _MISSING
    availability_impact: str = _MISSING
    # confidence / evidence parallel the metric fields (not used for vector encoding)
    confidence: Dict[str, str] = field(default_factory=dict)
    evidence: Dict[str, str] = field(default_factory=dict)
    # legacy list retained for audits; never used to force defaults
    uncertain: List[str] = field(default_factory=list)
    filled_from_rulebased: List[str] = field(default_factory=list)

    def to_json_dict(self) -> dict:
        return asdict(self)


_LOC_PATTERNS = (
    (re.compile(r"\bphysical(ly)?\b|usb|removable media", re.I), "physical"),
    (re.compile(r"\badjacent(\s+network)?\b|same\s+(lan|subnet|wifi|bluetooth)", re.I), "adjacent"),
    (re.compile(r"\blocal(ly)?\b|local\s+user|local\s+access|authenticated\s+local", re.I), "local"),
    (re.compile(
        r"\bremote(ly)?\b|over\s+the\s+network|network\s+attacker|"
        r"unauthenticated\s+remote|via\s+the\s+internet|http|tcp|udp",
        re.I,
    ), "network"),
)
_PR_PATTERNS = (
    (re.compile(r"\bunauthenticated\b|without\s+authentication|no\s+authentication|"
                r"anonymous|before\s+authentication|attacker\s+need\s+not", re.I), "none"),
    (re.compile(r"\badmin(istrator)?\b|root\b|elevated\s+privileges|high\s+privileges", re.I), "high"),
    (re.compile(r"\bauthenticated\b|logged[\s-]?in|valid\s+(user|account)|low\s+privileges|"
                r"requires?\s+privileges?", re.I), "low"),
)
_UI_PATTERNS = (
    (re.compile(
        r"\buser\s+interaction\b|victim\s+(opens?|clicks?|visits?|views?)|"
        r"malicious\s+(file|document|link|email|attachment)|social\s+engineering|"
        r"requires?\s+user",
        re.I,
    ), "required"),
    (re.compile(r"\bno\s+user\s+interaction\b|without\s+user\s+interaction", re.I), "none"),
)
_AC_PATTERNS = (
    (re.compile(
        r"\brace\s+condition\b|special\s+(condition|configuration)|"
        r"non[\s-]?default|complex\s+condition|difficult\s+to\s+exploit|"
        r"requires?\s+additional",
        re.I,
    ), "special"),
)
_SCOPE_PATTERNS = (
    (re.compile(
        r"\bscope\s+change\b|cross(?:es|-)?\s*(security\s+)?boundary|"
        r"impact\s+beyond|other\s+components?|sandbox\s+escape|"
        r"privilege\s+boundary",
        re.I,
    ), True),
)
_C_PATTERNS = (
    (re.compile(r"\bread\s+arbitrary|disclose|exfiltrat|information\s+disclosure|"
                r"leak(s|ed|ing)?\s+(sensitive|confidential)|steal\s+(data|credential)", re.I), "high"),
    (re.compile(r"\bpartial\s+(disclosure|confidential)|limited\s+information", re.I), "low"),
)
_I_PATTERNS = (
    (re.compile(r"\bmodify\s+arbitrary|write\s+arbitrary|tamper|alter\s+data|"
                r"integrity\s+(impact|violation)|inject\s+code|remote\s+code\s+execution|"
                r"\brce\b|execute\s+arbitrary", re.I), "high"),
    (re.compile(r"\bpartial\s+(modification|integrity)|limited\s+modification", re.I), "low"),
)
_A_PATTERNS = (
    (re.compile(r"\bdenial\s+of\s+service|\bdos\b|crash(es|ing)?|hang(s|ing)?|"
                r"unavailable|resource\s+exhaust", re.I), "high"),
    (re.compile(r"\bpartial\s+(availability|dos)|degraded\s+performance", re.I), "low"),
)


def extract_vsp_facts_rulebased(description: str) -> VspFacts:
    text = description or ""
    facts = VspFacts()
    uncertain: List[str] = []

    loc = None
    for pat, val in _LOC_PATTERNS:
        if pat.search(text):
            loc = val
            break
    if loc:
        facts.attack_location = loc
    else:
        uncertain.append("attack_location")

    pr = None
    for pat, val in _PR_PATTERNS:
        if pat.search(text):
            pr = val
            break
    if pr:
        facts.required_privileges = pr
    else:
        uncertain.append("required_privileges")

    ui = None
    for pat, val in _UI_PATTERNS:
        if pat.search(text):
            ui = val
            break
    if ui:
        facts.user_interaction = ui
    else:
        # default none unless file/open cues absent
        uncertain.append("user_interaction")

    ac = "no special condition"
    for pat, val in _AC_PATTERNS:
        if pat.search(text):
            ac = val
            break
    facts.attack_conditions = ac

    scope = False
    for pat, val in _SCOPE_PATTERNS:
        if pat.search(text):
            scope = bool(val)
            break
    facts.scope_change = scope

    for pats, attr, default_uncertain in (
        (_C_PATTERNS, "confidentiality_impact", True),
        (_I_PATTERNS, "integrity_impact", True),
        (_A_PATTERNS, "availability_impact", True),
    ):
        hit = None
        for pat, val in pats:
            if pat.search(text):
                hit = val
                break
        if hit:
            setattr(facts, attr, hit)
        elif default_uncertain:
            uncertain.append(attr)

    # Strong phrase overrides
    if re.search(r"\bunauthenticated\s+remote\b", text, re.I):
        facts.attack_location = "network"
        facts.required_privileges = "none"
        for u in ("attack_location", "required_privileges"):
            if u in uncertain:
                uncertain.remove(u)

    facts.uncertain = uncertain
    # Do not apply consistency here — callers log LLM/rule raw then consistency.
    return facts


_FACT_FIELDS = (
    "attack_location",
    "attack_conditions",
    "required_privileges",
    "user_interaction",
    "scope_change",
    "confidentiality_impact",
    "integrity_impact",
    "availability_impact",
)


def apply_vsp_consistency(facts: VspFacts, description: str = "") -> VspFacts:
    """Deterministic consistency rules; mode via VSP_CONSISTENCY.

    high_precision: only unauthenticated-remote and malicious-file UI rules.
    all: also demote unsupported S:C and high C/I/A (legacy; can ruin exact vectors).
    off: identity.
    """
    mode = vsp_consistency_mode()
    facts = deepcopy(facts)
    if mode == "off":
        return facts
    text = description or ""
    # High-precision rules (kept): strong lexical cues
    if re.search(r"\bunauthenticated\s+remote\b", text, re.I):
        facts.attack_location = "network"
        facts.required_privileges = "none"
    if re.search(
        r"\b(opens?|clicks?)\s+a\s+malicious\b|\bmalicious\s+(file|document|attachment)\b",
        text,
        re.I,
    ):
        facts.user_interaction = "required"
    if mode != "all":
        return facts
    # Legacy broader rules (opt-in via VSP_CONSISTENCY=all)
    if facts.scope_change and not re.search(
        r"\bscope|boundary|sandbox\s+escape|other\s+components?|cross(?:es|-)?\s*security",
        text,
        re.I,
    ):
        facts.scope_change = False
        if "scope_change" not in facts.uncertain:
            facts.uncertain.append("scope_change")
    for attr, pats in (
        ("confidentiality_impact", _C_PATTERNS),
        ("integrity_impact", _I_PATTERNS),
        ("availability_impact", _A_PATTERNS),
    ):
        val = getattr(facts, attr)
        if val == "high" and not any(p.search(text) for p, _ in pats):
            setattr(facts, attr, "none")
            if attr not in facts.uncertain:
                facts.uncertain.append(attr)
    return facts


def consistency_field_diff(
    before: VspFacts,
    after: VspFacts,
    *,
    gold_vector: str = "",
) -> dict:
    """Classify each changed field vs optional gold: corrected / harmful / changed."""
    gold = metric_dict_from_vector(gold_vector) if gold_vector else {}
    # Map fact fields → CVSS metric letters for gold compare
    field_to_metric = {
        "attack_location": "AV",
        "attack_conditions": "AC",
        "required_privileges": "PR",
        "user_interaction": "UI",
        "scope_change": "S",
        "confidentiality_impact": "C",
        "integrity_impact": "I",
        "availability_impact": "A",
    }
    changes = []
    n_corrected = n_harmful = n_neutral = 0
    for f in _FACT_FIELDS:
        b, a = getattr(before, f), getattr(after, f)
        if b == a:
            continue
        entry = {"field": f, "before": b, "after": a, "effect": "changed"}
        m = field_to_metric[f]
        if gold:
            gv = gold.get(m)
            # Decode before/after to metric letters for comparison
            vb = metric_dict_from_vector(facts_to_cvss_vector(before)).get(m)
            va = metric_dict_from_vector(facts_to_cvss_vector(after)).get(m)
            if vb != gv and va == gv:
                entry["effect"] = "corrected"
                n_corrected += 1
            elif vb == gv and va != gv:
                entry["effect"] = "harmful_override"
                n_harmful += 1
            else:
                entry["effect"] = "neutral_change"
                n_neutral += 1
        changes.append(entry)
    return {
        "n_changed": len(changes),
        "n_corrected": n_corrected,
        "n_harmful_override": n_harmful,
        "n_neutral_change": n_neutral,
        "changes": changes,
        "focus_metrics": ["PR", "S", "I"],
    }


def apply_vsp_consistency_logged(
    facts: VspFacts,
    description: str = "",
    *,
    gold_vector: str = "",
) -> Tuple[VspFacts, dict]:
    before = deepcopy(facts)
    after = apply_vsp_consistency(facts, description)
    diff = consistency_field_diff(before, after, gold_vector=gold_vector)
    return after, {
        "consistency_mode": vsp_consistency_mode(),
        "llm_or_raw_facts": before.to_json_dict(),
        "after_consistency_facts": after.to_json_dict(),
        "vector_before": facts_to_cvss_vector(before),
        "vector_after": facts_to_cvss_vector(after),
        "consistency_diff": diff,
    }


_FACT_MAP = {
    "attack_location": {"network": "N", "adjacent": "A", "local": "L", "physical": "P"},
    "attack_conditions": {"no special condition": "L", "special": "H", "low": "L", "high": "H"},
    "required_privileges": {"none": "N", "low": "L", "high": "H"},
    "user_interaction": {"none": "N", "required": "R"},
    "confidentiality_impact": {"none": "N", "low": "L", "high": "H"},
    "integrity_impact": {"none": "N", "low": "L", "high": "H"},
    "availability_impact": {"none": "N", "low": "L", "high": "H"},
}


def _map_or_empty(fmap: dict, raw: str) -> Optional[str]:
    if raw is None:
        return None
    key = str(raw).strip().lower()
    if not key or key in {"uncertain", "unknown", "n/a", "na", "null", "none_of_the_above"}:
        # "none" is a valid CIA/PR value — handled via fmap; reject only uncertain-like
        if key in {"uncertain", "unknown", "n/a", "na", "null", "none_of_the_above"}:
            return None
    if key in fmap:
        return fmap[key]
    return None


def fill_missing_from_rulebased(facts: VspFacts, description: str) -> VspFacts:
    """Fill empty fields from description heuristics — not silent PR:N/S:U defaults."""
    facts = deepcopy(facts)
    rb = extract_vsp_facts_rulebased(description)
    filled: List[str] = list(facts.filled_from_rulebased or [])
    for attr in _FACT_FIELDS:
        cur = getattr(facts, attr)
        if attr == "scope_change":
            if cur is None:
                setattr(facts, attr, bool(rb.scope_change))
                filled.append(attr)
            continue
        if cur is None or str(cur).strip() == "" or str(cur).strip().lower() in {
            "uncertain",
            "unknown",
        }:
            setattr(facts, attr, getattr(rb, attr))
            filled.append(attr)
            if attr in (rb.uncertain or []):
                facts.confidence.setdefault(attr, "low")
    facts.filled_from_rulebased = filled
    return facts


def facts_to_cvss_vector(facts: VspFacts) -> str:
    """Encode facts. Missing values must be filled before calling (see fill_missing_from_rulebased)."""

    def enc(attr: str, default_letter: str) -> str:
        raw = getattr(facts, attr)
        if raw is None or str(raw).strip() == "":
            return default_letter
        letter = _map_or_empty(_FACT_MAP[attr], str(raw))
        return letter if letter else default_letter

    av = enc("attack_location", "N")
    ac = enc("attack_conditions", "L")
    pr = enc("required_privileges", "N")
    ui = enc("user_interaction", "N")
    if facts.scope_change is None:
        s = "U"
    else:
        s = "C" if facts.scope_change else "U"
    c = enc("confidentiality_impact", "N")
    i = enc("integrity_impact", "N")
    a = enc("availability_impact", "N")
    return f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}"


def _unwrap_metric_field(val: Any) -> Tuple[Optional[str], str, str]:
    """Accept flat string or {value, confidence, evidence}. Reject uncertain as value."""
    conf, evid = "", ""
    if isinstance(val, dict):
        conf = str(val.get("confidence") or "").strip().lower()
        evid = str(val.get("evidence") or "").strip()
        raw = val.get("value", val.get("val", val.get("prediction")))
    else:
        raw = val
    if raw is None:
        return None, conf, evid
    s = str(raw).strip().lower()
    if s in {"uncertain", "unknown", "n/a", "na", "null", ""}:
        return None, conf or "low", evid
    return s, conf, evid


def parse_vsp_facts_json(raw: str) -> Optional[VspFacts]:
    if not raw:
        return None
    text = raw.strip()
    m = re.search(r"\{[\s\S]*\}", text)
    if not m:
        return None
    try:
        obj = json.loads(m.group(0))
    except json.JSONDecodeError:
        return None
    if not isinstance(obj, dict):
        return None

    # Nested metrics keyed by CVSS letters
    letter_alias = {
        "av": "attack_location",
        "ac": "attack_conditions",
        "pr": "required_privileges",
        "ui": "user_interaction",
        "s": "scope_change",
        "c": "confidentiality_impact",
        "i": "integrity_impact",
        "a": "availability_impact",
    }
    conf: Dict[str, str] = {}
    evid: Dict[str, str] = {}
    values: Dict[str, Any] = {}

    def take(attr: str, *keys: str) -> None:
        for k in keys:
            if k in obj and obj[k] is not None:
                v, c, e = _unwrap_metric_field(obj[k])
                values[attr] = v
                if c:
                    conf[attr] = c
                if e:
                    evid[attr] = e
                return
        values[attr] = None

    take("attack_location", "attack_location", "av", "AV")
    take("attack_conditions", "attack_conditions", "ac", "AC")
    take("required_privileges", "required_privileges", "pr", "PR")
    take("user_interaction", "user_interaction", "ui", "UI")
    take("scope_change", "scope_change", "scope", "s", "S")
    take("confidentiality_impact", "confidentiality_impact", "c", "C")
    take("integrity_impact", "integrity_impact", "i", "I")
    take("availability_impact", "availability_impact", "a", "A")

    # Also accept top-level metric-letter objects only
    for letter, attr in letter_alias.items():
        if values.get(attr) is None and letter.upper() in obj:
            v, c, e = _unwrap_metric_field(obj[letter.upper()])
            values[attr] = v
            if c:
                conf[attr] = c
            if e:
                evid[attr] = e

    scope_raw = values.get("scope_change")
    scope: Optional[bool]
    if scope_raw is None:
        scope = None
    elif isinstance(scope_raw, bool):
        scope = scope_raw
    else:
        s = str(scope_raw).strip().lower()
        if s in {"1", "true", "yes", "changed", "c"}:
            scope = True
        elif s in {"0", "false", "no", "unchanged", "u"}:
            scope = False
        else:
            scope = None

    facts = VspFacts(
        attack_location=values.get("attack_location") or _MISSING,
        attack_conditions=values.get("attack_conditions") or _MISSING,
        required_privileges=values.get("required_privileges") or _MISSING,
        user_interaction=values.get("user_interaction") or _MISSING,
        scope_change=scope,
        confidentiality_impact=values.get("confidentiality_impact") or _MISSING,
        integrity_impact=values.get("integrity_impact") or _MISSING,
        availability_impact=values.get("availability_impact") or _MISSING,
        confidence=conf,
        evidence=evid,
        uncertain=list(obj.get("uncertain") or []) if isinstance(obj.get("uncertain"), list) else [],
    )
    # Normalize synonyms / letter codes
    loc_map = {"n": "network", "a": "adjacent", "l": "local", "p": "physical"}
    if facts.attack_location in loc_map:
        facts.attack_location = loc_map[facts.attack_location]
    if facts.attack_conditions in {"l", "low"}:
        facts.attack_conditions = "no special condition"
    if facts.attack_conditions in {"h", "high"}:
        facts.attack_conditions = "special"
    for attr, amap in (
        ("required_privileges", {"n": "none", "l": "low", "h": "high"}),
        ("user_interaction", {"n": "none", "r": "required"}),
        ("confidentiality_impact", {"n": "none", "l": "low", "h": "high"}),
        ("integrity_impact", {"n": "none", "l": "low", "h": "high"}),
        ("availability_impact", {"n": "none", "l": "low", "h": "high"}),
    ):
        val = getattr(facts, attr)
        if val in amap:
            setattr(facts, attr, amap[val])
    # Mark low-confidence fields in uncertain for audit only (does not change values)
    for attr, c in conf.items():
        if c in {"low", "uncertain"} and attr not in facts.uncertain:
            facts.uncertain.append(attr)
    return facts


def decode_vsp_prediction(
    raw: str,
    *,
    description: str = "",
    gold_vector: str = "",
) -> Tuple[str, dict]:
    """Prefer structured JSON facts → fill gaps from description → consistency → vector."""
    meta: Dict = {"decoder": "none", "consistency_mode": vsp_consistency_mode()}
    facts = parse_vsp_facts_json(raw)
    if facts is not None:
        filled = fill_missing_from_rulebased(facts, description)
        facts2, clog = apply_vsp_consistency_logged(
            filled, description, gold_vector=gold_vector
        )
        vec = facts_to_cvss_vector(facts2)
        meta = {
            "decoder": "json_facts",
            "facts": facts2.to_json_dict(),
            "vector": vec,
            "filled_from_rulebased": facts2.filled_from_rulebased,
            **clog,
        }
        return vec, meta
    parsed = parse_cvss_vector(raw or "")
    if parsed:
        meta = {"decoder": "raw_vector", "vector": parsed}
        return parsed, meta
    rb = extract_vsp_facts_rulebased(description)
    rb2, clog = apply_vsp_consistency_logged(rb, description, gold_vector=gold_vector)
    vec = facts_to_cvss_vector(rb2)
    meta = {
        "decoder": "rulebased_fallback",
        "facts": rb2.to_json_dict(),
        "vector": vec,
        **clog,
    }
    return vec, meta


def build_vsp_structured_prompt(*, query_description: str, evidence_block: str = "") -> str:
    evidence = evidence_block.strip() or "(no metric-specific evidence — closed-book fact extraction)"
    return f"""ROLE:
You extract exploitation facts for CVSS v3.1 base metrics. Do NOT emit a CVSS vector.
Do NOT copy neighbour vectors. Decide each fact from the DESCRIPTION; use evidence only as hints.

DESCRIPTION:
{query_description}

METRIC-SPECIFIC EVIDENCE (analogies only; empty for closed-book):
{evidence}

FOCUS (highest error historically — decide carefully):
- required_privileges (PR): none vs low vs high — look for unauthenticated / admin / logged-in
- scope_change (S): true only if impact crosses a security authority/boundary; NOT merely because of RCE
- integrity_impact (I): high only with explicit modify/tamper/code-execution consequence evidence

AV / AC / UI are usually clear from surface cues; do not overthink them.

OUTPUT (STRICT JSON ONLY) — every metric MUST include a best-guess value:
{{
  "PR": {{"value": "N|L|H", "confidence": "high|medium|low", "evidence": "short quote or cue"}},
  "AV": {{"value": "N|A|L|P", "confidence": "high|medium|low", "evidence": "..."}},
  "AC": {{"value": "L|H", "confidence": "high|medium|low", "evidence": "..."}},
  "UI": {{"value": "N|R", "confidence": "high|medium|low", "evidence": "..."}},
  "S":  {{"value": "U|C", "confidence": "high|medium|low", "evidence": "..."}},
  "C":  {{"value": "N|L|H", "confidence": "high|medium|low", "evidence": "..."}},
  "I":  {{"value": "N|L|H", "confidence": "high|medium|low", "evidence": "..."}},
  "A":  {{"value": "N|L|H", "confidence": "high|medium|low", "evidence": "..."}}
}}

You may equivalently use long field names (required_privileges, attack_location, …) with the same
{{value, confidence, evidence}} objects.

RULES:
- NEVER set value to "uncertain". Always commit to the single best value; put doubt in confidence=low.
- "Unauthenticated remote attacker" → AV:N, PR:N
- "Victim opens a malicious file" → UI:R
- Do not set S:C merely from remote code execution
- Do not assign high C/I/A without consequence evidence; prefer N/L with confidence=low instead
"""


def build_vsp_metric_evidence_block(cases: Sequence, question: str) -> str:
    """Evidence snippets without full CVSS vectors — emphasizes PR/S/I cues."""
    if not cases:
        return "(no distinct reference cases retrieved)"
    lines = [
        "Use cases only for individual metric analogies. Never copy a full vector.",
        "Prefer analogies for Privileges Required, Scope, and Integrity impact.",
    ]
    for i, h in enumerate(list(cases)[:5], start=1):
        text = getattr(h, "text", None) or str(h)
        text = re.sub(r"CVSS:3\.\d/[^\s]+", "[vector redacted]", text)
        lines.append(f"Case {i}: {text[:500]}")
    lines.append("")
    lines.append("Decide independently for: AV, AC, PR, UI, S, C, I, A (focus PR/S/I).")
    return "\n".join(lines)


def metric_dict_from_vector(vector: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    if not vector:
        return out
    for part in vector.replace("CVSS:3.1/", "").split("/"):
        if ":" in part:
            k, v = part.split(":", 1)
            out[k.upper()] = v.upper()
    return out
