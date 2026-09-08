#!/usr/bin/env python3
"""Relation-Aware Option Retrieval for CTIBench MCQ.

Architecture:
  Question + options
    → detect relation type
    → extract anchors (T/M/G/S IDs + technique names)
    → structured ATT&CK STIX edge lookup (with edge descriptions)
    → disambiguate options as graph endpoints (question↔edge overlap)
    → deterministic answer when uniquely supported
    → else relation-specific semantic retrieval + specialist prompt

Source of truth: data/ctibench_taa/enterprise-attack.json
Freeze/report ATT&CK bundle metadata — benchmark answers may lag the catalogue.

Env:
  MCQ_RETRIEVAL=relation_aware
"""

from __future__ import annotations

import json
import re
import threading
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Set, Tuple

ROOT = Path(__file__).resolve().parent.parent
STIX_DIR = ROOT / "data" / "ctibench_taa"
STIX_PATH = STIX_DIR / "enterprise-attack.json"
DEFAULT_STIX_PATHS: Tuple[Path, ...] = (
    STIX_DIR / "enterprise-attack.json",
    STIX_DIR / "ics-attack.json",
    STIX_DIR / "mobile-attack.json",
)

RelationType = str  # mitigation|detection|datasource|software|group|platform|tactic|generic
DecisionSource = str  # STIX | semantic | fallback


@dataclass
class AttackBundleMeta:
    path: str
    domain: str
    n_relationships: int
    attack_spec_version: str
    matrix_version: str
    matrix_modified: str
    matrix_name: str = ""


@dataclass
class MultiAttackMeta:
    """Frozen catalogue stamp for multi-domain ATT&CK (deployment-oriented KB)."""

    bundles: List[AttackBundleMeta]
    n_relationships: int
    attack_spec_version: str
    note: str = (
        "Deployment-oriented multi-domain ATT&CK STIX (Enterprise+ICS+Mobile). "
        "Catalogue may post-date CTIBench construction — report as such."
    )

    def to_dict(self) -> dict:
        return {
            "bundles": [b.__dict__ for b in self.bundles],
            "n_relationships": self.n_relationships,
            "attack_spec_version": self.attack_spec_version,
            "note": self.note,
        }

    # Back-compat fields used by older callers
    @property
    def path(self) -> str:
        return ";".join(b.path for b in self.bundles)

    @property
    def matrix_version(self) -> str:
        return ",".join(f"{b.domain}:{b.matrix_version}" for b in self.bundles)

    @property
    def matrix_modified(self) -> str:
        return ",".join(f"{b.domain}:{b.matrix_modified}" for b in self.bundles)


@dataclass
class EdgeHit:
    """One structured relation endpoint with optional STIX edge description."""

    endpoint_id: str = ""
    endpoint_name: str = ""
    edge_description: str = ""
    aliases: Tuple[str, ...] = ()


@dataclass
class OptionSupport:
    letter: str
    option_text: str
    supported: bool
    matched_ids: List[str] = field(default_factory=list)
    matched_names: List[str] = field(default_factory=list)
    match_score: float = 0.0
    edge_overlap: float = 0.0


@dataclass
class RelationLookupResult:
    relation: RelationType
    anchors: Dict[str, List[str]]
    endpoint_ids: List[str]
    endpoint_names: List[str]
    option_supports: List[OptionSupport]
    supported_letters: List[str]
    unique_supported: Optional[str]
    deterministic: bool
    method: str  # stix_edge|stix_disambiguated|semantic_pending|none
    notes: str = ""
    evidence_snippets: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def _norm(s: str) -> str:
    s = (s or "").lower()
    s = re.sub(r"[^a-z0-9.+-]+", " ", s)
    return re.sub(r"\s+", " ", s).strip()


def _tokens(s: str) -> Set[str]:
    return {t for t in re.findall(r"[a-z0-9]+", (s or "").lower()) if len(t) > 2}


def _jaccard(a: Set[str], b: Set[str]) -> float:
    if not a or not b:
        return 0.0
    inter = len(a & b)
    return inter / max(1, len(a | b))


def _attack_ext_id(obj: dict) -> str:
    for ref in obj.get("external_references") or []:
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            return str(ref["external_id"]).upper()
    return ""


def _is_revoked(obj: dict) -> bool:
    return bool(obj.get("revoked") or obj.get("x_mitre_deprecated"))


def _strip_md_links(text: str) -> str:
    return re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", text or "")


class AttackRelationIndex:
    """In-memory multi-domain ATT&CK relationship index (Enterprise + ICS + Mobile)."""

    _lock = threading.Lock()
    _instance: Optional["AttackRelationIndex"] = None

    def __init__(self, stix_paths: Optional[Sequence[Path]] = None) -> None:
        self.paths = [Path(p) for p in (stix_paths or DEFAULT_STIX_PATHS)]
        self.meta = MultiAttackMeta(bundles=[], n_relationships=0, attack_spec_version="")
        self.by_stix: Dict[str, dict] = {}
        self.id_to_stix: Dict[str, str] = {}
        self.id_to_name: Dict[str, str] = {}
        self.id_to_description: Dict[str, str] = {}
        self.id_to_domain: Dict[str, str] = {}
        self.name_to_ids: Dict[str, Set[str]] = defaultdict(set)
        self.tech_mitigations: Dict[str, List[EdgeHit]] = defaultdict(list)
        self.tech_detections: Dict[str, List[EdgeHit]] = defaultdict(list)
        self.tech_data_components: Dict[str, List[EdgeHit]] = defaultdict(list)
        self.tech_groups: Dict[str, List[EdgeHit]] = defaultdict(list)
        self.tech_software: Dict[str, List[EdgeHit]] = defaultdict(list)
        self.group_software: Dict[str, List[EdgeHit]] = defaultdict(list)
        self.software_groups: Dict[str, List[EdgeHit]] = defaultdict(list)
        self.tech_platforms: Dict[str, Set[str]] = defaultdict(set)
        self.tech_tactics: Dict[str, Set[str]] = defaultdict(set)
        self.software_blobs: Dict[str, str] = {}
        self._load()

    @classmethod
    def get(cls, stix_paths: Optional[Sequence[Path]] = None) -> "AttackRelationIndex":
        with cls._lock:
            # Always use multi-domain defaults once constructed
            if cls._instance is None:
                cls._instance = cls(stix_paths)
            return cls._instance

    @classmethod
    def reset(cls) -> None:
        with cls._lock:
            cls._instance = None

    def _domain_for_path(self, path: Path) -> str:
        name = path.name.lower()
        if "ics" in name:
            return "ics"
        if "mobile" in name:
            return "mobile"
        return "enterprise"

    def _register_obj(self, obj: dict, domain: str) -> None:
        if _is_revoked(obj):
            return
        sid = obj.get("id") or ""
        eid = _attack_ext_id(obj)
        if not sid:
            return
        self.by_stix[sid] = obj
        name = (obj.get("name") or "").strip()
        desc = _strip_md_links(obj.get("description") or "")
        if eid:
            self.id_to_stix[eid] = sid
            self.id_to_name[eid] = name
            self.id_to_description[eid] = desc
            self.id_to_domain[eid] = domain
            if name:
                self.name_to_ids[_norm(name)].add(eid)
            for al in obj.get("aliases") or obj.get("x_mitre_aliases") or []:
                if al:
                    self.name_to_ids[_norm(str(al))].add(eid)
            if obj.get("type") in {"malware", "tool"} and eid.startswith("S"):
                self.software_blobs[eid] = f"{name}\n{desc}"
        elif name:
            self.name_to_ids[_norm(name)].add(sid)

    def _load(self) -> None:
        bundles_meta: List[AttackBundleMeta] = []
        all_relationships: List[dict] = []
        spec_versions: Set[str] = set()
        existing = [p for p in self.paths if p.exists()]
        if not existing:
            raise FileNotFoundError(f"No ATT&CK STIX bundles found in {self.paths}")

        for path in existing:
            domain = self._domain_for_path(path)
            bundle = json.loads(path.read_text(encoding="utf-8"))
            objects = bundle.get("objects") or []
            matrix_version = matrix_modified = matrix_name = ""
            n_rel = 0
            for obj in objects:
                if obj.get("type") == "x-mitre-matrix":
                    # Prefer primary Mobile / Enterprise / ICS matrix names
                    nm = str(obj.get("name") or "")
                    if domain == "mobile" and "Network-Based" in nm and matrix_name:
                        pass
                    else:
                        matrix_version = str(obj.get("x_mitre_version") or matrix_version)
                        matrix_modified = str(obj.get("modified") or matrix_modified)
                        matrix_name = nm or matrix_name
                sv = obj.get("x_mitre_attack_spec_version")
                if sv:
                    spec_versions.add(str(sv))
                if obj.get("type") == "relationship":
                    if not _is_revoked(obj):
                        n_rel += 1
                        all_relationships.append(obj)
                else:
                    self._register_obj(obj, domain)
            bundles_meta.append(
                AttackBundleMeta(
                    path=str(path),
                    domain=domain,
                    n_relationships=n_rel,
                    attack_spec_version=sorted(spec_versions)[-1] if spec_versions else "",
                    matrix_version=matrix_version,
                    matrix_modified=matrix_modified,
                    matrix_name=matrix_name,
                )
            )

        for _sid, obj in self.by_stix.items():
            if obj.get("type") != "attack-pattern":
                continue
            eid = _attack_ext_id(obj)
            if not eid:
                continue
            for p in obj.get("x_mitre_platforms") or []:
                self.tech_platforms[eid].add(str(p))
            for ph in obj.get("kill_chain_phases") or []:
                if ph.get("kill_chain_name") in {
                    "mitre-attack",
                    "mitre-mobile-attack",
                    "mitre-ics-attack",
                }:
                    phase = str(ph.get("phase_name") or "").replace("-", " ").title()
                    if phase:
                        self.tech_tactics[eid].add(phase)

        analytic_to_dc: Dict[str, List[EdgeHit]] = defaultdict(list)
        for sid, obj in self.by_stix.items():
            if obj.get("type") != "x-mitre-analytic":
                continue
            for ref in obj.get("x_mitre_log_source_references") or []:
                dc_ref = ref.get("x_mitre_data_component_ref")
                dc = self.by_stix.get(dc_ref or "") or {}
                nm = (dc.get("name") or "").strip()
                if not nm:
                    continue
                dc_eid = _attack_ext_id(dc)
                analytic_to_dc[sid].append(
                    EdgeHit(endpoint_id=dc_eid, endpoint_name=nm, edge_description=nm)
                )
                ds_ref = dc.get("x_mitre_data_source_ref")
                if ds_ref and ds_ref in self.by_stix:
                    ds = self.by_stix[ds_ref]
                    dsn = (ds.get("name") or "").strip()
                    if dsn:
                        analytic_to_dc[sid].append(
                            EdgeHit(
                                endpoint_id=_attack_ext_id(ds),
                                endpoint_name=dsn,
                                edge_description=dsn,
                            )
                        )

        strategy_to_hits: Dict[str, List[EdgeHit]] = defaultdict(list)
        for sid, obj in self.by_stix.items():
            if obj.get("type") != "x-mitre-detection-strategy":
                continue
            nm = (obj.get("name") or "").strip()
            if nm:
                strategy_to_hits[sid].append(EdgeHit(endpoint_name=nm, edge_description=nm))
            for aref in obj.get("x_mitre_analytic_refs") or []:
                aid = aref if isinstance(aref, str) else ""
                if aid:
                    strategy_to_hits[sid].extend(analytic_to_dc.get(aid) or [])

        for obj in all_relationships:
            rtype = (obj.get("relationship_type") or "").lower()
            src = self.by_stix.get(obj.get("source_ref") or "")
            tgt = self.by_stix.get(obj.get("target_ref") or "")
            if not src or not tgt:
                continue
            s_eid, t_eid = _attack_ext_id(src), _attack_ext_id(tgt)
            s_type, t_type = src.get("type"), tgt.get("type")
            edge_desc = _strip_md_links(obj.get("description") or "")

            if rtype == "mitigates" and s_type == "course-of-action" and t_type == "attack-pattern" and t_eid:
                self.tech_mitigations[t_eid].append(
                    EdgeHit(
                        endpoint_id=s_eid,
                        endpoint_name=(src.get("name") or "").strip(),
                        edge_description=edge_desc or (src.get("description") or "")[:500],
                    )
                )

            elif rtype == "detects" and t_type == "attack-pattern" and t_eid:
                src_ref = obj.get("source_ref") or ""
                hits = list(strategy_to_hits.get(src_ref) or [])
                if not hits:
                    nm = (src.get("name") or "").strip()
                    if nm:
                        hits = [EdgeHit(endpoint_name=nm, edge_description=edge_desc or nm)]
                for h in hits:
                    if not h.edge_description and edge_desc:
                        h = EdgeHit(h.endpoint_id, h.endpoint_name, edge_desc, h.aliases)
                    self.tech_detections[t_eid].append(h)
                    low = (h.endpoint_name or "").lower()
                    if h.endpoint_name and (
                        (h.endpoint_id or "").startswith("DS")
                        or " " in h.endpoint_name
                        or "log" in low
                        or "traffic" in low
                        or "execution" in low
                        or "access" in low
                    ):
                        self.tech_data_components[t_eid].append(h)

            elif rtype == "uses":
                if t_type == "attack-pattern" and t_eid:
                    aliases = tuple(
                        str(a) for a in (src.get("aliases") or src.get("x_mitre_aliases") or []) if a
                    )
                    if s_type == "intrusion-set" and s_eid:
                        self.tech_groups[t_eid].append(
                            EdgeHit(
                                endpoint_id=s_eid,
                                endpoint_name=(src.get("name") or "").strip(),
                                edge_description=edge_desc,
                                aliases=aliases,
                            )
                        )
                    if s_type in {"malware", "tool"} and s_eid:
                        self.tech_software[t_eid].append(
                            EdgeHit(
                                endpoint_id=s_eid,
                                endpoint_name=(src.get("name") or "").strip(),
                                edge_description=edge_desc,
                                aliases=aliases,
                            )
                        )
                if s_type == "intrusion-set" and s_eid and t_type in {"malware", "tool"} and t_eid:
                    self.group_software[s_eid].append(
                        EdgeHit(
                            endpoint_id=t_eid,
                            endpoint_name=(tgt.get("name") or "").strip(),
                            edge_description=edge_desc,
                        )
                    )
                    self.software_groups[t_eid].append(
                        EdgeHit(
                            endpoint_id=s_eid,
                            endpoint_name=(src.get("name") or "").strip(),
                            edge_description=edge_desc,
                        )
                    )

        self.meta = MultiAttackMeta(
            bundles=bundles_meta,
            n_relationships=sum(b.n_relationships for b in bundles_meta),
            attack_spec_version=sorted(spec_versions)[-1] if spec_versions else "",
        )

    def matrices_for_anchors(self, anchors: Dict[str, List[str]]) -> List[str]:
        domains: List[str] = []
        for tid in anchors.get("techniques") or []:
            d = self.id_to_domain.get(tid.upper())
            if d and d not in domains:
                domains.append(d)
        if not domains:
            # Heuristic from ID ranges when not yet in index
            for tid in anchors.get("techniques") or []:
                m = re.match(r"T(\d{4})", tid.upper())
                if not m:
                    continue
                n = int(m.group(1))
                if 800 <= n <= 899 or 8000 <= n <= 8999:
                    d = "ics"
                elif n >= 1400:
                    d = "mobile"
                else:
                    d = "enterprise"
                if d not in domains:
                    domains.append(d)
        return domains or ["enterprise"]

    def resolve_name(self, text: str, *, prefer_tech: bool = False) -> Set[str]:
        n = _norm(text)
        if not n:
            return set()
        hits = set(self.name_to_ids.get(n) or [])
        if not hits and len(n) > 3:
            for key, ids in self.name_to_ids.items():
                if key == n:
                    hits |= ids
                elif key.startswith(n + " ") or n.startswith(key + " "):
                    hits |= ids
                elif len(n) >= 10 and (n in key or key in n):
                    hits |= ids
        out = {
            h
            for h in hits
            if re.match(r"^[TMGSD]\d", h) or h.startswith("M") or h.startswith("DS")
        }
        if prefer_tech:
            tech = {h for h in out if h.startswith("T")}
            if tech:
                return tech
        return out

    def mitigation_description_hits(self, question: str, limit: int = 8) -> List[EdgeHit]:
        qtok = _tokens(question)
        if len(qtok) < 4:
            return []
        scored: List[Tuple[float, EdgeHit]] = []
        for eid, desc in self.id_to_description.items():
            if not eid.startswith("M"):
                continue
            name = self.id_to_name.get(eid, "")
            dtok = _tokens(desc) | _tokens(name)
            j = _jaccard(qtok, dtok)
            bonus = _phrase_hits(question, desc)
            dl = desc.lower()
            for kw in (
                "application control",
                "legitimate",
                "repositor",
                "execution prevention",
                "software restriction",
                "allowlist",
                "whitelist",
            ):
                if kw in dl and any(k in question.lower() for k in kw.split()[:1]):
                    bonus += 0.15
            if "execution prevention" in name.lower() and (
                "prevent" in question.lower() or "running" in question.lower()
            ):
                bonus += 0.25
            score = j + bonus
            if score < 0.18:
                continue
            scored.append(
                (
                    score,
                    EdgeHit(
                        endpoint_id=eid,
                        endpoint_name=name,
                        edge_description=desc[:500],
                    ),
                )
            )
        scored.sort(key=lambda x: -x[0])
        return [e for _, e in scored[:limit]]

    def software_keyword_hits(self, question: str, limit: int = 12) -> List[EdgeHit]:
        """Lexical scan of malware/tool descriptions for software-relation questions."""
        qtok = _tokens(question)
        rare = {t for t in qtok if len(t) >= 6 or any(c.isupper() for c in t)}
        scored: List[Tuple[float, EdgeHit]] = []
        for sid, blob in self.software_blobs.items():
            btok = _tokens(blob)
            if not btok:
                continue
            inter_rare = rare & btok if rare else set()
            if len(inter_rare) < 1 and len(qtok & btok) < 4:
                continue
            score = 2.0 * len(inter_rare) + _jaccard(qtok, btok)
            if score < 1.5:
                continue
            scored.append(
                (
                    score,
                    EdgeHit(
                        endpoint_id=sid,
                        endpoint_name=self.id_to_name.get(sid, ""),
                        edge_description=blob[:400],
                    ),
                )
            )
        scored.sort(key=lambda x: -x[0])
        return [e for _, e in scored[:limit]]


_RELATION_RULES: Tuple[Tuple[re.Pattern[str], RelationType, int], ...] = (
    (re.compile(r"\bmitigat\w*\b|\bcountermeasur\w*\b", re.I), "mitigation", 10),
    (re.compile(r"\bdata\s*(?:source|component)s?\b|\blog\s*source\b|\btelemetry\b", re.I), "datasource", 12),
    (re.compile(r"\bdetect\w*\b|\banalytics?\b", re.I), "detection", 9),
    (re.compile(r"\bmalware\b|\bwhich\s+(?:tool|software|malware)\b|\bassociated software\b|\bwhich\s+tool\b", re.I), "software", 8),
    (re.compile(r"\bthreat\s*group\b|\badversary\s*group\b|\bwhich\s+(?:group|adversar)|APT\d+\b|\bintrusion\s*set\b|\badversar(?:y|ies)\b", re.I), "group", 8),
    (re.compile(r"\bplatform\b|\boperates on\b|\bsupported on\b|\btargeting which systems\b", re.I), "platform", 7),
    (re.compile(r"\btactics?\b|\bkill\s*chain\b|\bachieve by creating\b", re.I), "tactic", 11),
)


def detect_relation_type(question: str) -> Tuple[RelationType, float]:
    text = question or ""
    best: RelationType = "generic"
    best_score = 0
    for pat, rel, score in _RELATION_RULES:
        if pat.search(text):
            if score > best_score:
                best, best_score = rel, score
    conf = min(1.0, best_score / 12.0) if best != "generic" else 0.2
    return best, conf


def extract_mcq_anchors(question: str, index: Optional[AttackRelationIndex] = None) -> Dict[str, List[str]]:
    # CRITICAL: use question stem only — option lines contain distractor ATT&CK IDs.
    text = _question_stem(question)
    tech = [m.group(0).upper() for m in re.finditer(r"\bT\d{4}(?:\.\d{3})?\b", text, re.I)]
    groups = [re.sub(r"\s+", "", m.group(0).upper()) for m in re.finditer(r"\bAPT\s*-?\d+\b", text, re.I)]
    groups += [m.group(0).upper() for m in re.finditer(r"\bG\d{4}\b", text)]
    software = [m.group(0).upper() for m in re.finditer(r"\bS\d{4}\b", text)]
    # Mitigation IDs only from stem (e.g. "What does mitigation ID M1028 suggest")
    mitigations = [m.group(0).upper() for m in re.finditer(r"\bM\d{4}\b", text, re.I)]

    if index is not None:
        for qn in re.findall(r'"([^"]{3,80})"', text):
            resolved = index.resolve_name(qn, prefer_tech=True)
            tech += [x for x in resolved if x.startswith("T")]
            software += [x for x in resolved if x.startswith("S")]
            groups += [x for x in resolved if x.startswith("G")]
        # Name cues without requiring quotes
        for pat in (
            r"(?:technique|sub-technique)\s+[\"']?([A-Za-z][^\"'\n]{4,90}?)[\"']?(?:\s+is\b|\s+from\b|\(|$)",
            r"\babuse of\s+([a-z0-9 /-]{6,60}?)\s+bits\b",
            r"\b(setuid(?:\s+and\s+|\s*/\s*)setgid)\b",
            r"counteract the abuse of\s+([a-z0-9 /-]{6,60})",
        ):
            m = re.search(pat, text, re.I)
            if m:
                raw = m.group(1).strip(" .:,")
                resolved = index.resolve_name(raw, prefer_tech=True)
                if not resolved and " or " in raw.lower():
                    resolved = index.resolve_name(raw.lower().replace(" or ", " and "), prefer_tech=True)
                tech += [x for x in resolved if x.startswith("T")]

    return {
        "techniques": list(dict.fromkeys(tech)),
        "groups": list(dict.fromkeys(groups)),
        "software": list(dict.fromkeys(software)),
        "mitigations": list(dict.fromkeys(mitigations)),
    }


def _question_stem(question: str) -> str:
    """Strip MCQ boilerplate; keep the actual question sentence."""
    q = question or ""
    m = re.search(r"\*\*Question:\*\*\s*(.+?)(?:\*\*Options:\*\*|$)", q, re.S | re.I)
    if m:
        return m.group(1).strip()
    return q


def endpoints_for_relation(
    index: AttackRelationIndex,
    relation: RelationType,
    anchors: Dict[str, List[str]],
    question: str = "",
) -> Tuple[List[EdgeHit], str]:
    edges: List[EdgeHit] = []
    note = ""
    techs = [t.upper() for t in anchors.get("techniques") or []]
    groups = [g.upper().replace(" ", "") for g in anchors.get("groups") or []]
    mitigations = [m.upper() for m in anchors.get("mitigations") or []]

    for g in list(groups):
        if g.startswith("APT"):
            groups.extend(sorted(x for x in index.resolve_name(g) if x.startswith("G")))

    if relation == "mitigation":
        for t in techs:
            edges.extend(index.tech_mitigations.get(t) or [])
        # Mitigation-ID → description as synthetic endpoint for option matching
        for mid in mitigations:
            desc = index.id_to_description.get(mid) or ""
            name = index.id_to_name.get(mid) or mid
            edges.append(EdgeHit(endpoint_id=mid, endpoint_name=name, edge_description=desc))
        if not edges and question:
            edges.extend(index.mitigation_description_hits(question))
            note = "mitigation description scan"
        else:
            note = f"mitigates edges for {techs or mitigations}"
    elif relation == "detection":
        for t in techs:
            edges.extend(index.tech_detections.get(t) or [])
        note = f"detects for {techs}"
    elif relation == "datasource":
        for t in techs:
            edges.extend(index.tech_data_components.get(t) or [])
        note = f"data components for {techs}"
    elif relation == "software":
        for t in techs:
            edges.extend(index.tech_software.get(t) or [])
        for g in groups:
            gid = g if g.startswith("G") else None
            if not gid:
                for gid in [x for x in index.resolve_name(g) if x.startswith("G")]:
                    edges.extend(index.group_software.get(gid) or [])
            else:
                edges.extend(index.group_software.get(gid) or [])
        if not edges and question:
            edges.extend(index.software_keyword_hits(question))
            note = "software keyword scan"
        else:
            note = f"software uses for tech={techs} groups={groups}"
    elif relation == "group":
        for t in techs:
            edges.extend(index.tech_groups.get(t) or [])
        soft = [s.upper() for s in anchors.get("software") or []]
        for s in soft:
            edges.extend(index.software_groups.get(s) or [])
        note = f"groups using tech={techs}"
    elif relation == "platform":
        for t in techs:
            for p in index.tech_platforms.get(t) or []:
                edges.append(EdgeHit(endpoint_name=p, edge_description=p))
        note = f"platforms for {techs}"
    elif relation == "tactic":
        for t in techs:
            for tac in index.tech_tactics.get(t) or []:
                edges.append(EdgeHit(endpoint_name=tac, edge_description=tac))
        note = f"tactics for {techs}"
    else:
        note = "generic — no structured endpoints"
    return edges, note


def _phrase_hits(stem: str, haystack: str) -> float:
    """Score multi-word / distinctive phrase overlap between question stem and edge text."""
    if not stem or not haystack:
        return 0.0
    s = re.sub(r"[^a-z0-9]+", " ", stem.lower())
    h = re.sub(r"[^a-z0-9]+", " ", haystack.lower())
    st = s.split()
    best = 0.0
    # Sliding windows of 3–6 tokens from the stem
    for n in (6, 5, 4, 3):
        if len(st) < n:
            continue
        for i in range(0, len(st) - n + 1):
            phr = " ".join(st[i : i + n])
            if phr in h:
                best = max(best, 0.55 + 0.08 * n)
    # Title-case multiword entities from original stem
    for phr in re.findall(r"\b[A-Z][a-zA-Z0-9+._-]*(?:\s+[A-Z][a-zA-Z0-9+._-]*)+\b", stem):
        pn = re.sub(r"[^a-z0-9]+", " ", phr.lower()).strip()
        if len(pn) >= 8 and pn in h:
            best = max(best, 0.95)
    return best


def _option_edge_scores(
    option_text: str,
    edges: Sequence[EdgeHit],
    index: AttackRelationIndex,
    question_stem: str,
) -> Tuple[float, float, List[str], List[str], List[str]]:
    """Return (id/name match score, best edge↔question overlap, ids, names, evidence)."""
    opt = option_text or ""
    on = _norm(opt)
    if not on or on in {"none of the above", "n/a", "unknown"}:
        return 0.0, 0.0, [], [], []

    cand_ids = {e.endpoint_id for e in edges if e.endpoint_id}
    cand_names = {e.endpoint_name for e in edges if e.endpoint_name}
    for e in edges:
        for al in e.aliases:
            cand_names.add(al)

    matched_ids: List[str] = []
    matched_names: List[str] = []
    evidence: List[str] = []
    score = 0.0

    # Option may be "M1042: Name" — verify ID against candidates AND name against catalogue
    opt_id = ""
    m_id = re.match(r"^\s*([MGSDT]\d{4}(?:\.\d{3})?)\s*[:\-]", opt, re.I)
    if m_id:
        opt_id = m_id.group(1).upper()
        if opt_id in cand_ids:
            matched_ids.append(opt_id)
            score = max(score, 1.0)
            # Prefer correct official name after the ID
            official = _norm(index.id_to_name.get(opt_id) or "")
            rest = _norm(opt[m_id.end() :])
            if official and rest:
                if official == rest or official in rest or rest in official:
                    score = max(score, 1.0)
                    matched_names.append(index.id_to_name.get(opt_id) or "")
                else:
                    # Wrong label attached to a real ID (e.g. M1028 - Ensure disk encryption)
                    score = min(score, 0.4)
        else:
            # ID not an endpoint for this relation — do not treat as support
            pass

    for m in re.finditer(r"\b(M\d{4}|S\d{4}|G\d{4}|DS\d{4}|T\d{4}(?:\.\d{3})?)\b", opt, re.I):
        cid = m.group(1).upper()
        if cid in cand_ids and cid not in matched_ids:
            matched_ids.append(cid)
            score = max(score, 1.0)

    for name in cand_names:
        nn = _norm(name)
        if not nn:
            continue
        if on == nn or nn in on or on in nn:
            matched_names.append(name)
            score = max(score, 0.95 if on == nn else 0.85)
        else:
            ot, nt = set(on.split()), set(nn.split())
            if ot and nt:
                j = len(ot & nt) / max(1, len(ot | nt))
                if j >= 0.5 and len(ot & nt) >= 1:
                    matched_names.append(name)
                    score = max(score, 0.65 + 0.3 * j)

    resolved = index.resolve_name(opt)
    inter = resolved & cand_ids
    if inter:
        matched_ids.extend(sorted(inter))
        score = max(score, 0.98)

    for e in edges:
        for al in list(e.aliases) + ([e.endpoint_name] if e.endpoint_name else []):
            if _norm(al) and (_norm(al) in on or on in _norm(al) or _norm(al) == on):
                matched_names.append(al)
                if e.endpoint_id:
                    matched_ids.append(e.endpoint_id)
                score = max(score, 0.92)

    qtok = _tokens(question_stem)
    otok = _tokens(opt)
    best_edge_ov = 0.0
    for e in edges:
        if matched_ids or matched_names:
            en = _norm(e.endpoint_name)
            eid_ok = e.endpoint_id and e.endpoint_id in matched_ids
            name_ok = en and (en in on or on in en or e.endpoint_name in matched_names)
            alias_ok = any(_norm(a) in on or on in _norm(a) for a in e.aliases)
            if not (eid_ok or name_ok or alias_ok):
                continue
        # Edge↔question only (not option↔name self-match)
        ov = _jaccard(qtok, _tokens(e.edge_description))
        ov = max(ov, _phrase_hits(question_stem, e.edge_description))
        if ov > best_edge_ov:
            best_edge_ov = ov
            if e.edge_description:
                evidence = [f"{e.endpoint_id or e.endpoint_name}: {e.edge_description[:220]}"]

    for mid in cand_ids:
        if not mid.startswith("M"):
            continue
        desc = index.id_to_description.get(mid) or ""
        if not desc:
            continue
        dtok = _tokens(desc)
        j = _jaccard(otok, dtok)
        if j >= 0.25 and len(otok & dtok) >= 3:
            score = max(score, 0.75 + 0.2 * j)
            matched_ids.append(mid)
            evidence.append(f"{mid} desc overlap")
        # also score mid's edge when this option carries that mid
        if mid in matched_ids or (opt_id and opt_id == mid):
            best_edge_ov = max(best_edge_ov, _phrase_hits(question_stem, desc), _jaccard(qtok, dtok))

    opt_core = re.sub(r"^[A-Z0-9.]{1,10}\s*[:\-]\s*", "", opt).strip()
    stem_l = (question_stem or "").lower()
    if opt_core and len(opt_core) >= 6 and opt_core.lower() in stem_l:
        score = max(score, 0.9)
        best_edge_ov = max(best_edge_ov, 0.9)
        evidence.append(f"option text in stem: {opt_core}")
    else:
        if otok and len(otok & qtok) == len(otok) and len(otok) >= 2:
            score = max(score, 0.88)
            best_edge_ov = max(best_edge_ov, 0.88)
        else:
            stem_opt = _jaccard(qtok, otok)
            if stem_opt >= 0.35 and len(qtok & otok) >= 2:
                score = max(score, 0.72)
                best_edge_ov = max(best_edge_ov, stem_opt)

    # Penalize wrong ID+label pairs so they don't count as supported
    if m_id and opt_id in cand_ids:
        official = _norm(index.id_to_name.get(opt_id) or "")
        rest = _norm(opt[m_id.end() :])
        if official and rest and not (official == rest or official in rest or rest in official):
            score = min(score, 0.45)

    return (
        score,
        best_edge_ov,
        list(dict.fromkeys(matched_ids)),
        list(dict.fromkeys(matched_names)),
        evidence,
    )


def lookup_relation_options(
    question: str,
    options: Dict[str, str],
    *,
    index: Optional[AttackRelationIndex] = None,
    relation: Optional[RelationType] = None,
) -> RelationLookupResult:
    index = index or AttackRelationIndex.get()
    rel, _conf = (relation, 1.0) if relation else detect_relation_type(question)
    anchors = extract_mcq_anchors(question, index=index)
    stem = _question_stem(question)

    for tok in re.findall(r"\b[A-Z][A-Za-z0-9][A-Za-z0-9+._-]{1,40}\b", stem):
        ids = index.resolve_name(tok)
        soft = [x for x in ids if x.startswith("S")]
        if soft:
            anchors.setdefault("software", [])
            anchors["software"] = list(dict.fromkeys(anchors["software"] + soft))

    edges, note = endpoints_for_relation(index, rel, anchors, question=stem)
    supports: List[OptionSupport] = []
    evidence_all: List[str] = []

    scored_rows: List[Tuple[str, float, float, OptionSupport]] = []
    for letter in "ABCD":
        text = options.get(letter) or ""
        if re.search(r"none of the above", text, re.I):
            supports.append(OptionSupport(letter, text, False))
            scored_rows.append((letter, 0.0, 0.0, supports[-1]))
            continue
        score, edge_ov, mids, mnames, evid = _option_edge_scores(text, edges, index, stem)
        evidence_all.extend(evid)
        # Support if strong ID/name match OR strong edge↔question disambiguation
        ok = score >= 0.7 or (score >= 0.55 and edge_ov >= 0.45)
        os_ = OptionSupport(
            letter=letter,
            option_text=text,
            supported=ok,
            matched_ids=mids,
            matched_names=mnames,
            match_score=round(score, 3),
            edge_overlap=round(edge_ov, 3),
        )
        supports.append(os_)
        scored_rows.append((letter, score, edge_ov, os_))

    supported = [s.letter for s in supports if s.supported]
    unique: Optional[str] = supported[0] if len(supported) == 1 else None
    method = "stix_edge" if edges else "none"

    # Disambiguate multiple supports via edge↔question / combined score
    if len(supported) > 1:
        ranked = sorted(
            [(L, sc + 1.6 * ov, sc, ov) for L, sc, ov, _ in scored_rows if L in supported],
            key=lambda x: -x[1],
        )
        clear = False
        if ranked:
            gap = ranked[0][1] - ranked[1][1]
            ov0, ov1 = ranked[0][3], ranked[1][3]
            clear = gap >= 0.15 or (ov0 >= 0.55 and ov0 >= ov1 + 0.12) or (ov0 >= 0.85 and ov0 > ov1)
        if clear:
            unique = ranked[0][0]
            supported = [unique]
            method = "stix_disambiguated"
            for s in supports:
                s.supported = s.letter == unique

    # Guard: do not claim deterministic uniqueness on weak name-only matches
    # for relation types where many catalogue endpoints are co-listed (esp. DS/detection).
    if unique and edges:
        u_row = next((r for r in scored_rows if r[0] == unique), None)
        u_ov = u_row[2] if u_row else 0.0
        u_sc = u_row[1] if u_row else 0.0
        n_end = len({e.endpoint_id or e.endpoint_name for e in edges})
        needs_overlap = rel in {"datasource", "detection", "tactic"}
        if n_end >= 3 and u_ov < 0.35 and (needs_overlap or u_sc < 0.95):
            unique = None
            method = "stix_ambiguous"

    none_letter = next(
        (L for L, t in options.items() if re.search(r"none of the above", t or "", re.I)),
        None,
    )
    if (not supported) and none_letter and edges:
        # Conservative: do not auto-select "none of the above" deterministically —
        # too many false uniques on group/software questions.
        pass

    # Confidence gate for deterministic answers (protect rescues / avoid catalogue noise)
    if unique and edges:
        u_row = next((r for r in scored_rows if r[0] == unique), None)
        u_ov = u_row[2] if u_row else 0.0
        u_sc = u_row[1] if u_row else 0.0
        scan_like = "scan" in (note or "").lower() or "keyword" in (note or "").lower()
        allow = False
        if rel == "group":
            # Require procedure-description phrase overlap (e.g. "Google Drive", "hijacked…")
            allow = u_ov >= 0.7
        elif rel in {"datasource", "detection"}:
            allow = u_ov >= 0.55
        elif rel == "mitigation":
            allow = (u_sc >= 0.95 and not scan_like) or u_ov >= 0.55
        elif rel in {"software", "platform", "tactic"}:
            allow = (u_sc >= 0.95 and u_ov >= 0.4) or u_ov >= 0.7
            if scan_like:
                allow = u_ov >= 0.7
        else:
            allow = u_ov >= 0.7
        if not allow:
            unique = None
            if method.startswith("stix"):
                method = "stix_ambiguous"

    deterministic = unique is not None and bool(edges)
    if edges and not deterministic:
        method = "stix_ambiguous" if supported else method

    return RelationLookupResult(
        relation=rel,
        anchors=anchors,
        endpoint_ids=sorted({e.endpoint_id for e in edges if e.endpoint_id})[:50],
        endpoint_names=sorted({e.endpoint_name for e in edges if e.endpoint_name})[:50],
        option_supports=supports,
        supported_letters=supported,
        unique_supported=unique,
        deterministic=deterministic,
        method=method,
        notes=note,
        evidence_snippets=list(dict.fromkeys(evidence_all))[:8],
    )


def best_relation_supporting_gold(
    question: str,
    options: Dict[str, str],
    gold: str,
    *,
    index: Optional[AttackRelationIndex] = None,
) -> Tuple[Optional[RelationType], RelationLookupResult]:
    index = index or AttackRelationIndex.get()
    gold = (gold or "").strip().upper()
    best: Optional[RelationType] = None
    best_res: Optional[RelationLookupResult] = None
    for rel in ("mitigation", "detection", "datasource", "software", "group", "platform", "tactic"):
        res = lookup_relation_options(question, options, index=index, relation=rel)
        if gold in res.supported_letters:
            if res.unique_supported == gold:
                return rel, res
            if best is None:
                best, best_res = rel, res
    return best, best_res or lookup_relation_options(question, options, index=index)


def relation_semantic_queries(question: str, options: Dict[str, str], relation: RelationType) -> List[Tuple[str, str]]:
    """Build relation-typed retrieval queries (label, query) for unresolved items."""
    stem = _question_stem(question)
    anchors = extract_mcq_anchors(question)
    tech = " ".join(anchors.get("techniques") or [])
    labeled: List[Tuple[str, str]] = []
    rel_hint = {
        "mitigation": "ATT&CK mitigations mitigated-by",
        "detection": "ATT&CK detection strategy detects",
        "datasource": "ATT&CK data source data component",
        "software": "ATT&CK software malware tool uses",
        "group": "ATT&CK intrusion set threat group uses",
        "platform": "ATT&CK platforms",
        "tactic": "ATT&CK tactics kill chain",
        "generic": "MITRE ATT&CK",
    }.get(relation, "MITRE ATT&CK")
    labeled.append(("Q", f"{rel_hint} {tech} {stem}".strip()))
    for letter, text in options.items():
        labeled.append((letter, f"{rel_hint} {tech} {stem} {text}".strip()))
    return labeled


@dataclass
class McqV3PathDecision:
    decision_source: DecisionSource  # STIX | semantic | fallback
    relation: RelationType
    evidence_changed: bool
    matrices: List[str]
    stix: RelationLookupResult

    def to_dict(self) -> dict:
        return {
            "decision_source": self.decision_source,
            "relation": self.relation,
            "evidence_changed": self.evidence_changed,
            "matrices": self.matrices,
            "stix_method": self.stix.method,
            "stix_deterministic": self.stix.deterministic,
            "stix_unique": self.stix.unique_supported,
            "stix_supported": list(self.stix.supported_letters),
            "n_endpoints": len(self.stix.endpoint_ids) + len(self.stix.endpoint_names),
        }


def classify_mcq_v3_path(
    question: str,
    options: Optional[Dict[str, str]] = None,
    *,
    index: Optional[AttackRelationIndex] = None,
) -> McqV3PathDecision:
    """Decide STIX / semantic / fallback path without calling the LLM or retriever."""
    from tcar.specialist_retrieval import parse_mcq_options

    index = index or AttackRelationIndex.get()
    opts = options if options is not None else parse_mcq_options(question)
    rel, _ = detect_relation_type(question)
    stix = lookup_relation_options(question, opts, index=index, relation=rel)
    matrices = index.matrices_for_anchors(stix.anchors)
    has_edges = bool(stix.endpoint_ids or stix.endpoint_names)
    if stix.deterministic and stix.unique_supported:
        return McqV3PathDecision("STIX", rel, True, matrices, stix)
    if has_edges or rel != "generic":
        return McqV3PathDecision("semantic", rel, True, matrices, stix)
    return McqV3PathDecision("fallback", rel, False, matrices, stix)


def format_stix_evidence_block(result: RelationLookupResult) -> str:
    lines = [
        f"Relation type: {result.relation}",
        f"Method: {result.method}",
        f"Anchors: {result.anchors}",
    ]
    if result.endpoint_ids:
        lines.append("Endpoint IDs: " + ", ".join(result.endpoint_ids[:20]))
    if result.endpoint_names:
        lines.append("Endpoint names: " + ", ".join(result.endpoint_names[:20]))
    if result.supported_letters:
        lines.append("STIX-supported options: " + ", ".join(result.supported_letters))
    for snip in result.evidence_snippets:
        lines.append(f"- {snip}")
    for s in result.option_supports:
        if s.supported or s.match_score >= 0.5:
            lines.append(
                f"  Option {s.letter}: score={s.match_score} edge_ov={s.edge_overlap} "
                f"ids={s.matched_ids} names={s.matched_names}"
            )
    return "\n".join(lines)


def build_mcq_relation_prompt(
    *,
    question: str,
    context: str,
    relation: RelationType,
    stix_block: str = "",
    catalogue: str = "",
) -> str:
    return f"""You are a Cyber Threat Intelligence (CTI) assistant answering a multiple-choice question.

PRIMARY — QUESTION:
{question}

TARGET ATT&CK RELATION (retrieve/verify only this relation type): {relation}

STRUCTURED ATT&CK EDGE EVIDENCE (prefer when conclusive):
{stix_block or "(none)"}

RELATION-SPECIFIC PASSAGES:
{context}
{f'''
ADVISORY CATALOGUE:
{catalogue}
''' if catalogue else ""}
RULES:
- Prefer structured edge evidence over passages when they uniquely support one option.
- Ignore passages that discuss a different relation type (e.g. ignore detection text on a mitigation question).
- Keep named entities from the question; do not swap actors/malware just because they appear in passages.
- Choose exactly one of A, B, C, or D.
- Brief reasoning, then last line exactly: Final Answer: <A|B|C|D>
"""
