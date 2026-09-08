"""Behaviour-Grounded ATA retrieval for CTIConnect.

Pipeline (ATA_RETRIEVAL=grounded):
  report → rule-based multi-behaviour split
        → retrieve top-k per behaviour
        → RRF fuse
        → soft evidence link
        → JSON-only generation {"predicted_ids": [...]}
        → deterministic ID cleanup (full IDs; parent/sub policy)

Meta diagnostics:
  gold_in_raw_union / gold_in_rrf / gold_in_grounded
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

from eval.cticonnect_kb import KBHit
from tcar.specialist_retrieval import dedupe_parent_sub_techniques, env_flag

_ACTION_CUES = (
    "used ",
    "using ",
    "executed",
    "execute ",
    "ran ",
    "running ",
    "download",
    "downloaded",
    "uploaded",
    "exfiltrat",
    "encrypt",
    "decrypt",
    "inject",
    "created ",
    "create ",
    "scheduled",
    "schedule ",
    "persistence",
    "registry",
    "powershell",
    "cmd.exe",
    "command line",
    "lateral",
    "credential",
    "phishing",
    "spearphish",
    "c2",
    "command and control",
    "beacon",
    "implant",
    "dropped ",
    "dropper",
    "payload",
    "bypass",
    "privilege",
    "escalat",
    "compromis",
    "bruteforce",
    "brute-force",
    "rdp",
    "ssh ",
    "wmi",
    "dll ",
    "macro",
    "obfuscat",
    "tunnel",
    "proxy",
    "steal",
    "harvest",
    "keylog",
    "screenshot",
    "accessed",
    "modified",
    "installed",
    "deployed",
    "sent ",
    "spoof",
    "impersonat",
    "microphone",
    "webcam",
)

_IDENTITY_ONLY = (
    "apt",
    "threat actor",
    "nation-state",
    "campaign",
    "targeting",
    "targeted",
    "victim",
    "industry",
    "sector",
)

_ACTION_VERBS = (
    "downloaded",
    "download",
    "uploaded",
    "executed",
    "execute",
    "created",
    "create",
    "modified",
    "modify",
    "accessed",
    "access",
    "encrypted",
    "encrypt",
    "injected",
    "inject",
    "installed",
    "install",
    "scheduled",
    "schedule",
    "exfiltrated",
    "exfiltrate",
    "stole",
    "steal",
    "sent",
    "send",
    "used",
    "use",
    "ran",
    "run",
    "dropped",
    "drop",
    "bypassed",
    "bypass",
    "compromised",
    "harvested",
    "deployed",
)

_TID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)


@dataclass
class GroundedCandidate:
    technique_id: str
    title: str
    supporting_text: str
    rrf_score: float
    behavior: str
    hit: KBHit
    evidence_level: str = "strong"  # strong | provisional


def ata_grounded_enabled() -> bool:
    raw = (env_flag("ATA_RETRIEVAL", "behavior") or "").strip().lower()
    return raw in {"grounded", "behavior_grounded", "bg", "rrf"}


def reciprocal_rank_fusion(
    ranked_id_lists: Sequence[Sequence[str]],
    *,
    k: int = 60,
) -> List[Tuple[str, float]]:
    scores: Dict[str, float] = {}
    for ranks in ranked_id_lists:
        for i, cid in enumerate(ranks, start=1):
            cid = (cid or "").strip().upper()
            if not cid:
                continue
            scores[cid] = scores.get(cid, 0.0) + 1.0 / (k + i)
    return sorted(scores.items(), key=lambda x: x[1], reverse=True)


def parse_full_technique_ids(text: str) -> List[str]:
    """Full ATT&CK IDs including sub-techniques (CTIConnect needs .xxx)."""
    if not text:
        return []
    # Singular predicted_id (v3)
    try:
        m1 = re.search(
            r"\{[^{}]*\"predicted_id\"\s*:\s*\"(T\d{4}(?:\.\d{3})?)\"[^{}]*\}",
            text,
            flags=re.S | re.I,
        )
        if m1:
            return [m1.group(1).upper()]
    except Exception:
        pass
    try:
        m = re.search(r"\{[^{}]*\"predicted_ids\"\s*:\s*\[[^\]]*\][^{}]*\}", text, flags=re.S)
        if m:
            obj = json.loads(m.group(0))
            ids = obj.get("predicted_ids") or []
            # also accept singular key mistaken in list form
            if not ids and obj.get("predicted_id"):
                ids = [obj.get("predicted_id")]
            out = []
            for x in ids:
                tid = str(x).strip().upper()
                if _TID_RE.fullmatch(tid):
                    out.append(tid)
            if out:
                return list(dict.fromkeys(out))
    except Exception:
        pass
    answer_line = None
    m = re.search(r"(?im)^\s*answer\s*:\s*(.+)$", text)
    if m:
        answer_line = m.group(1)
    else:
        m2 = re.search(r"(?im)predicted_ids?\s*[:=]\s*\[?([^\]\n]*)", text)
        if m2:
            answer_line = m2.group(1)
    blob = answer_line if answer_line is not None else text
    found = [t.upper() for t in _TID_RE.findall(blob or "")]
    return list(dict.fromkeys(found))


def classify_evidence(
    behavior: str,
    hit: KBHit,
    *,
    rank_in_behavior: int,
    rrf_rank: int,
    final_k: int,
) -> Tuple[str, Optional[str], float]:
    """Return (level, supporting_text, overlap) with level in strong|provisional|rejected."""
    tid = (hit.doc_id or "").strip().upper()
    if not tid.startswith("T"):
        return "rejected", None, 0.0
    ov = evidence_overlap(behavior, hit)
    shared = len(_tokset(behavior) & _tokset(f"{hit.title} {hit.text}"))
    title_overlap = bool(_tokset(hit.title or "") & _tokset(behavior))
    # Strong lexical / top-rank
    if rank_in_behavior <= 3 or (ov >= 0.04 and shared >= 1):
        return "strong", behavior.strip(), ov
    if ov >= 0.02 and shared >= 1:
        return "strong", behavior.strip(), ov
    if title_overlap and rank_in_behavior <= 10:
        return "strong", behavior.strip(), ov
    # Provisional: weak link OR RRF rescue (do not hard-delete high-RRF gold)
    if ov >= 0.01 or title_overlap or shared >= 1:
        return "provisional", behavior.strip(), ov
    rescue_k = max(final_k, 12)
    if rrf_rank <= rescue_k:
        return "provisional", behavior.strip(), ov
    if rrf_rank <= 20 and rank_in_behavior <= 20:
        return "provisional", behavior.strip(), ov
    return "rejected", None, ov


def _clause_split(sentence: str) -> List[str]:
    s = (sentence or "").strip()
    if not s:
        return []
    chunks = re.split(r"\s*;\s*", s)
    out: List[str] = []
    # Do NOT embed spaces inside alternatives — outer \s+ handles them.
    coord = re.compile(
        r"\s+(?:and\s+then|and\s+also|and|then|before|after|while|,)\s+",
        flags=re.I,
    )
    for ch in chunks:
        pieces = [p.strip(" ,") for p in coord.split(ch) if p.strip(" ,")]
        if len(pieces) <= 1:
            out.append(ch.strip())
            continue
        for p in pieces:
            low = p.lower()
            if any(v in low for v in _ACTION_VERBS) or any(c.strip() in low for c in _ACTION_CUES):
                out.append(p)
            elif out:
                out[-1] = (out[-1] + " " + p).strip()
            else:
                out.append(p)
    return [x for x in out if x]


def segment_behaviors_rulebased(report: str, *, max_behaviors: int = 8) -> List[str]:
    """Sentence/clause/bullet split + cyber-action filter; no LLM."""
    text = re.sub(r"\s+", " ", (report or "").strip())
    if not text:
        return []
    m = re.search(r'"([^"]{40,})"', text)
    if m:
        text = m.group(1)

    parts: List[str] = []
    for chunk in re.split(r"(?:^|\s)(?:[-*]|\d+[.)])\s+", text):
        parts.extend(re.split(r"(?<=[.!?])\s+|\n+", chunk))

    refined: List[str] = []
    for p in parts:
        refined.extend(_clause_split(p))

    behaviors: List[str] = []
    seen: Set[str] = set()
    for p in refined:
        s = p.strip(" -\t\"'")
        if len(s) < 18:
            continue
        low = s.lower()
        if not any(c in low for c in _ACTION_CUES) and not any(v in low for v in _ACTION_VERBS):
            continue
        key = low[:120]
        if key in seen:
            continue
        seen.add(key)
        behaviors.append(s)
        if len(behaviors) >= max_behaviors:
            break

    if len(behaviors) >= 2:
        return behaviors

    seed = behaviors[0] if behaviors else text
    forced: List[str] = []
    for p in _clause_split(seed):
        s = p.strip(" -\t\"'")
        if len(s) >= 18:
            forced.append(s)
    forced = list(dict.fromkeys(forced))[:max_behaviors]
    if len(forced) >= 2:
        return forced
    if behaviors:
        return behaviors
    if len(text) > 400:
        mid = len(text) // 2
        cut = text.rfind(". ", 0, mid)
        if cut < 80:
            cut = mid
        return [text[: cut + 1].strip(), text[cut + 1 :].strip()][:max_behaviors]
    return [text] if text else []


def _tokset(text: str) -> Set[str]:
    return {t for t in re.findall(r"[a-z0-9]+", (text or "").lower()) if len(t) > 2}


def evidence_overlap(behavior: str, hit: KBHit) -> float:
    b = (behavior or "").lower()
    blob = f"{hit.title or ''} {hit.text or ''}".lower()
    if not b or not blob:
        return 0.0
    bt, ht = _tokset(b), _tokset(blob)
    if not bt or not ht:
        return 0.0
    jacc = len(bt & ht) / max(1, len(bt | ht))
    action_hit = sum(1 for c in _ACTION_CUES if c.strip() in b and c.strip() in blob)
    identity = sum(1 for w in _IDENTITY_ONLY if w in b and w in blob)
    title_hit = 1.0 if _tokset(hit.title or "") & bt else 0.0
    return jacc + 0.08 * action_hit + 0.05 * title_hit - 0.04 * identity


def verify_and_ground(
    behavior: str,
    hit: KBHit,
    *,
    rank_in_behavior: int = 99,
    min_overlap: float = 0.02,
) -> Optional[str]:
    """Soft grounding: keep top-ranked retrieves even with weak lexical overlap."""
    tid = (hit.doc_id or "").strip().upper()
    if not tid.startswith("T"):
        return None
    score = evidence_overlap(behavior, hit)
    shared = len(_tokset(behavior) & _tokset(f"{hit.title} {hit.text}"))
    if rank_in_behavior <= 3:
        return behavior.strip()
    if score >= min_overlap and shared >= 1:
        return behavior.strip()
    if _tokset(hit.title or "") & _tokset(behavior) and rank_in_behavior <= 10:
        return behavior.strip()
    return None


def prefer_subtechnique_when_grounded(
    predicted: Sequence[str],
    allowed: Set[str],
) -> List[str]:
    """Prefer explicit grounded sub over parent when uniquely determined."""
    pred = [p.strip().upper() for p in predicted if p]
    pred = dedupe_parent_sub_techniques(pred)
    out: List[str] = []
    for tid in pred:
        if "." in tid:
            if tid not in out:
                out.append(tid)
            continue
        subs = sorted(a for a in allowed if a.startswith(tid + "."))
        if len(subs) == 1:
            if subs[0] not in out:
                out.append(subs[0])
        else:
            if tid not in out:
                out.append(tid)
    return out


# Near-miss technique families that frequently damage CB on Connect ATA.
_NEIGHBOUR_PAIRS: Tuple[Tuple[str, str], ...] = (
    ("T1606", "T1558"),  # SAML/web forge vs Kerberos tickets
    ("T1203", "T1204"),  # Exploitation for client exec vs User Execution
    ("T1190", "T1588"),  # Exploit Public-Facing vs Obtain Capabilities
    ("T1190", "T1486"),  # Exploit vs Data Encrypted for Impact
    ("T1190", "T1221"),  # Exploit vs Template Injection
    ("T1078", "T1552"),  # Valid Accounts vs Unsecured Credentials
)


def _family(tid: str) -> str:
    return (tid or "").strip().upper().split(".")[0]


def should_abstain_ata_v4(
    predicted_id: str,
    *,
    question: str,
    behaviors: Sequence[str],
    grounded_ids: Sequence[str],
    evidence_levels: Optional[Dict[str, str]] = None,
    n_strong: int = 0,
) -> Tuple[bool, str]:
    """Damage-aware selective fallback: keep rescues, reverse weak RAG overwrites.

    Uses only RAG-side signals (no gold). Calibrated against v3 damage audit;
    prefer CB when evidence is inconsistent with the predicted neighbour.
    """
    pid = (predicted_id or "").strip().upper()
    if not pid:
        return True, "empty_pred"
    levels = {str(k).upper(): str(v).lower() for k, v in (evidence_levels or {}).items()}
    gset = {str(x).strip().upper() for x in grounded_ids if x}
    if pid not in gset and _family(pid) not in gset:
        return True, "pred_not_grounded"

    beh_text = " ".join(behaviors or [])
    text = f"{beh_text}\n{question or ''}"
    level = levels.get(pid) or levels.get(_family(pid)) or ""

    if int(n_strong or 0) <= 0:
        return True, "no_strong_evidence"
    if level == "provisional" and int(n_strong or 0) >= 1:
        return True, "provisional_while_strong_exists"

    exploit_cues = bool(
        re.search(
            r"\b(cve-\d{4}-\d+|vulnerabilit|weakness|flaw|exploit|zero-?day|rce|remote code)\b",
            text,
            re.I,
        )
    )
    if exploit_cues and _family(pid) in {"T1588", "T1486", "T1221", "T1495", "T1199"}:
        return True, "exploit_cue_vs_capability_neighbour"

    if _family(pid) == "T1190" and re.search(
        r"\b(chrome|firefox|browser|wps office|office for windows|client(?:-|\s)?side)\b",
        text,
        re.I,
    ):
        return True, "client_vuln_vs_public_facing"

    if re.search(r"\bstolen sign-?in|buy from online marketplaces\b", text, re.I):
        if _family(pid) in {"T1552", "T1110"}:
            return True, "stolen_creds_vs_unsecured"

    if re.search(r"\bsaml\b", text, re.I) and _family(pid) == "T1558":
        return True, "saml_vs_kerberos_ticket"

    if re.search(r"\b(office|document).{0,40}(remote code|rce|code execution)\b", text, re.I):
        if _family(pid) == "T1204":
            return True, "office_rce_vs_user_execution"

    if _family(pid) == "T1199" and not re.search(
        r"\b(trusted relationship|partner access|third-?party|msp|supply.?chain partner)\b",
        text,
        re.I,
    ):
        return True, "trusted_rel_without_evidence"

    return False, "keep"


def _gold_in_pool(gold: Set[str], pool: Iterable[str]) -> bool:
    if not gold:
        return False
    ps = {str(x).upper() for x in pool}
    for g in gold:
        if g in ps or g.split(".")[0] in ps:
            return True
        if any(x.startswith(g.split(".")[0] + ".") for x in ps):
            return True
    return False


def retrieve_grounded_ata(
    report: str,
    retriever,
    *,
    per_behavior_k: int = 20,
    final_k: int = 20,
    rrf_k: int = 60,
    gold_ids: Optional[Sequence[str]] = None,
) -> Tuple[List[GroundedCandidate], List[str], dict]:
    """v3: RRF unchanged; soft evidence labels (no hard lexical deletion)."""
    behaviors = segment_behaviors_rulebased(report)
    gold = {str(g).strip().upper() for g in (gold_ids or []) if g}
    meta: dict = {
        "ata_pipeline": "behavior_grounded_v4",
        "n_behaviors": len(behaviors),
        "behaviors": behaviors,
        "per_behavior_k": per_behavior_k,
        "rrf_k": rrf_k,
        "final_k": final_k,
    }
    if not behaviors:
        meta.update(
            {
                "gold_in_raw_union": False,
                "gold_in_rrf": False,
                "gold_in_grounded": False,
                "n_grounded": 0,
            }
        )
        return [], [], meta

    rank_lists: List[List[str]] = []
    per_b_hits: List[Tuple[str, List[KBHit]]] = []
    by_id: Dict[str, KBHit] = {}
    raw_union: Set[str] = set()

    for b in behaviors:
        hits = retriever.retrieve_for_task(b, "ata", k=per_behavior_k)
        per_b_hits.append((b, hits))
        ids = [(h.doc_id or "").strip().upper() for h in hits]
        rank_lists.append(ids)
        raw_union.update(x for x in ids if x)
        for h in hits:
            cid = (h.doc_id or "").strip().upper()
            prev = by_id.get(cid)
            if prev is None or float(h.score or 0) > float(prev.score or 0):
                by_id[cid] = h

    fused = reciprocal_rank_fusion(rank_lists, k=rrf_k)
    shortlist_n = max(final_k * 3, 24)
    rrf_short = [cid for cid, _ in fused[:shortlist_n]]
    rrf_rank_of = {cid: i for i, (cid, _) in enumerate(fused[:shortlist_n], start=1)}

    meta["gold_in_raw_union"] = _gold_in_pool(gold, raw_union)
    meta["gold_in_rrf"] = _gold_in_pool(gold, rrf_short)
    meta["rrf_pool"] = len(fused)
    meta["raw_union_n"] = len(raw_union)

    scored: List[Tuple[str, float, str, str, float, KBHit]] = []
    # (cid, rrf, level, support, ov, hit)
    n_strong = n_prov = n_rej = 0
    for cid, rrf in fused[:shortlist_n]:
        hit = by_id.get(cid)
        if hit is None:
            continue
        best_level = "rejected"
        best_sup: Optional[str] = None
        best_b = ""
        best_ov = -1.0
        rrf_rank = rrf_rank_of.get(cid, 99)
        for b, hits in per_b_hits:
            rank = 99
            for i, h in enumerate(hits, start=1):
                if (h.doc_id or "").upper() == cid:
                    rank = i
                    break
            if rank == 99:
                continue
            level, sup, ov = classify_evidence(
                b, hit, rank_in_behavior=rank, rrf_rank=rrf_rank, final_k=final_k
            )
            rank_level = {"strong": 2, "provisional": 1, "rejected": 0}[level]
            best_rank_level = {"strong": 2, "provisional": 1, "rejected": 0}[best_level]
            if rank_level > best_rank_level or (rank_level == best_rank_level and ov > best_ov):
                best_level = level
                best_sup = (sup or b).strip()
                best_b = b
                best_ov = ov
        if best_level == "rejected" or not best_sup:
            n_rej += 1
            continue
        if best_level == "strong":
            n_strong += 1
        else:
            n_prov += 1
        scored.append((cid, float(rrf), best_level, best_sup, best_ov, hit))

    # Select by RRF among non-rejected; prefer strong on ties. This preserves
    # high-RRF provisional gold that hard lexical deletion used to drop.
    scored.sort(key=lambda x: (-x[1], 0 if x[2] == "strong" else 1))
    selected: List[Tuple[str, float, str, str, float, KBHit]] = []
    selected_ids: Set[str] = set()

    def _add(row: Tuple[str, float, str, str, float, KBHit]) -> None:
        cid = row[0]
        if cid in selected_ids:
            return
        selected.append(row)
        selected_ids.add(cid)

    for row in scored:
        if len(selected) >= final_k:
            break
        _add(row)

    # Ensure at most one explicit parent/sub contrast pair when both exist in scored
    for cid, rrf, level, sup, ov, hit in scored:
        if cid in selected_ids:
            continue
        main = cid.split(".")[0]
        if "." in cid and main in selected_ids:
            _add((cid, rrf, level, sup, ov, hit))
            break
        if "." not in cid and any(s.startswith(cid + ".") for s in selected_ids):
            _add((cid, rrf, level, sup, ov, hit))
            break

    grounded: List[GroundedCandidate] = []
    for cid, rrf, level, sup, ov, hit in selected[: max(final_k + 2, final_k)]:
        grounded.append(
            GroundedCandidate(
                technique_id=cid,
                title=(hit.title or "").strip(),
                supporting_text=sup,
                rrf_score=float(rrf),
                behavior=sup,
                hit=hit,
                evidence_level=level,
            )
        )

    meta["n_grounded"] = len(grounded)
    meta["n_strong"] = n_strong
    meta["n_provisional"] = n_prov
    meta["n_rejected_ungrounded"] = n_rej
    meta["grounded_ids"] = [g.technique_id for g in grounded]
    meta["evidence_levels"] = {g.technique_id: g.evidence_level for g in grounded}
    meta["gold_in_grounded"] = _gold_in_pool(gold, [g.technique_id for g in grounded])
    return grounded, behaviors, meta


def format_grounded_candidates(cands: Sequence[GroundedCandidate]) -> str:
    if not cands:
        return "(no grounded candidates)"
    # Group parent/sub for contrast blocks
    by_main: Dict[str, List[GroundedCandidate]] = {}
    for g in cands:
        by_main.setdefault(g.technique_id.split(".")[0], []).append(g)

    families_present = {_family(g.technique_id) for g in cands}

    blocks: List[str] = []
    seen: Set[str] = set()
    neighbour_shown: Set[Tuple[str, str]] = set()

    # Neighbour-family contrasts (sibling / near-miss, not only parent/sub)
    for a, b in _NEIGHBOUR_PAIRS:
        if a in families_present and b in families_present:
            key = (a, b)
            if key in neighbour_shown:
                continue
            neighbour_shown.add(key)
            left = [g for g in cands if _family(g.technique_id) == a]
            right = [g for g in cands if _family(g.technique_id) == b]
            lines = [
                f"NEAR-MISS CONTRAST ({a} vs {b}) — choose only if behaviour explicitly matches:"
            ]
            for c in left + right:
                lines.append(
                    f"- {c.technique_id} — {c.title or c.technique_id} [{c.evidence_level}]\n"
                    f"  Observed behaviour: \"{c.supporting_text}\""
                )
            lines.append(
                "Decision: pick the ID whose distinguishing behaviour is explicit; "
                "if evidence is mixed or only loosely related, prefer predicted_id=\"\"."
            )
            blocks.append("\n".join(lines))

    for g in cands:
        main = g.technique_id.split(".")[0]
        group = by_main.get(main) or [g]
        if main in seen:
            continue
        seen.add(main)
        if len(group) >= 2:
            lines = ["PARENT/SUB CONTRAST (choose the most specific ID supported):"]
            for c in sorted(group, key=lambda x: (0 if "." in x.technique_id else 1, x.technique_id)):
                kind = "Sub-technique" if "." in c.technique_id else "Parent"
                lines.append(
                    f"{kind}: {c.technique_id} — {c.title or c.technique_id} "
                    f"[{c.evidence_level}]\n"
                    f"Observed behaviour: \"{c.supporting_text}\""
                )
            lines.append(
                "Decision rule: if the distinguishing sub-technique behaviour is explicit, "
                "choose the sub-technique; otherwise choose the parent. "
                "Example: PowerShell execution → T1059.001 not generic T1059."
            )
            blocks.append("\n".join(lines))
        else:
            c = group[0]
            # Skip if already covered by a neighbour block for this family? Still show once.
            blocks.append(
                f"Candidate: {c.technique_id} — {c.title or c.technique_id} [{c.evidence_level}]\n"
                f"Supporting sentence: \"{c.supporting_text}\""
            )
    return "\n\n".join(blocks)


def cleanup_ata_prediction(
    raw: str,
    *,
    allowed_ids: Sequence[str],
) -> Tuple[str, List[str], dict]:
    """Allow-list + parent/sub; emit exactly one JSON predicted_id (Connect exact-set)."""
    allowed = {(a or "").strip().upper() for a in allowed_ids if a}
    # Preserve grounded order as preference for single-ID pick
    allowed_order = [a for a in allowed_ids if (a or "").strip().upper() in allowed]
    preds = parse_full_technique_ids(raw or "")
    kept = [p for p in preds if p in allowed]
    if not kept:
        for p in preds:
            main = p.split(".")[0]
            if p in allowed:
                kept.append(p)
            elif any(a.startswith(main + ".") for a in allowed) or main in allowed:
                kept.append(p if p in allowed else main)
    kept = prefer_subtechnique_when_grounded(kept, allowed)
    kept = [k for k in kept if k in allowed]
    kept = list(dict.fromkeys(kept))
    # Exactly one ID: prefer first predicted that is allowed; else first grounded
    single: List[str] = []
    if kept:
        single = [kept[0]]
    elif allowed_order:
        # empty model output but we still should not invent — leave empty for abstain
        single = []
    meta = {
        "n_parsed": len(preds),
        "n_kept": len(single),
        "dropped": [p for p in preds if p not in single],
        "format": "json_predicted_id",
        "forced_single": len(kept) > 1,
    }
    if not single:
        return raw, [], {**meta, "emptied": True}
    new_raw = json.dumps({"predicted_id": single[0]}, ensure_ascii=False)
    return new_raw, single, {**meta, "emptied": False}
