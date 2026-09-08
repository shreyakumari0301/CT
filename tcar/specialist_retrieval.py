"""Task-specialist retrieval helpers (RCM/ATA/MCQ/VSP) — not one global policy.

Env flags (default off except where noted):
  ATE_PROMPT=cta              — CTA-RAG fidelity prompt/order for ATE
  ATE_RETRIEVAL=exploitation|dense
      dense = whole-description mem retrieve (default; strong ~0.905 F1 baseline)
      exploitation = ablation: exploitation-stage queries → RRF (keep only if > baseline)
  RCM_POOL=top20              — dense CWE/mem pool size before select (default 20 when rerank/oracle on)
  RCM_RERANK=taxonomy|learned|off — taxonomy or trained pairwise → diversify top-k
  RCM_ORACLE=gold_pin|gold_at20_log|off
      gold_pin: if gold ∈ top-20, pin as rank-1 then take top-5 (headroom upper bound)
      gold_at20_log: only log whether gold@20 (no pin)
  ATA_ABSTAIN=1               — drop unsupported IDs; fall back to CB if none evidenced
  ATA_RETRIEVAL=grounded|behavior|dense
      grounded = rule-based behaviours → RRF → evidence-linked candidates (recommended ATA)
  MCQ_RETRIEVAL=option_aware|default
  MCQ_ABSTAIN=1               — prefer CB when RAG disagrees and passages look contaminated
  VSP_RETRIEVAL=metric_wise|default
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

from eval.cticonnect_kb import KBHit
from eval.scoring import parse_ate_ids, parse_cwe_answer

# Mechanism / root-cause lexemes for lightweight taxonomy-aware RCM scoring.
_RCM_MECH_TERMS = (
    "injection",
    "overflow",
    "buffer",
    "xss",
    "cross-site",
    "csrf",
    "authentication",
    "authorization",
    "privilege",
    "path traversal",
    "directory traversal",
    "deserialization",
    "sql",
    "command injection",
    "race condition",
    "integer overflow",
    "null pointer",
    "use after free",
    "memory corruption",
    "cryptograph",
    "plaintext",
    "hardcoded",
    "ssrf",
    "xxe",
    "xml",
    "redirect",
    "open redirect",
    "improper input",
    "validation",
    "sanitiz",
    "access control",
    "exposure",
    "information disclosure",
    "resource exhaustion",
    "denial of service",
)


def env_flag(name: str, default: str = "off") -> str:
    return (os.getenv(name) or default).strip().lower()


def ate_prompt_mode() -> str:
    """cta = original CTA-RAG reasoning_ate prompt; else modern Forced-RAG prompt."""
    raw = (os.getenv("ATE_PROMPT") or "").strip().lower()
    if raw in {"cta", "fidelity", "paper"}:
        return "cta"
    return "default"


def rcm_rerank_mode() -> str:
    raw = env_flag("RCM_RERANK", "off")
    if raw in {"1", "true", "yes", "on", "taxonomy"}:
        return "taxonomy"
    if raw in {"learned", "pairwise", "specialist"}:
        return "learned"
    if raw in {"off", "0", "false", "no", ""}:
        return "off"
    return raw


_LEARNED_RERANKER = None


def load_learned_rcm_reranker(path: Optional[str] = None):
    """Lazy-load pickle from RCM_RERANKER_PATH or default eval_results path."""
    global _LEARNED_RERANKER
    if _LEARNED_RERANKER is not None:
        return _LEARNED_RERANKER
    import pickle
    from pathlib import Path

    default = (
        Path(__file__).resolve().parent / "eval_results" / "rcm_specialist_reranker.pkl"
    )
    p = Path(path or os.getenv("RCM_RERANKER_PATH") or default)
    if not p.exists():
        raise FileNotFoundError(
            f"Learned RCM reranker not found at {p}. "
            "Train with: python -m tcar.eval.train_rcm_specialist_reranker"
        )
    with p.open("rb") as f:
        _LEARNED_RERANKER = pickle.load(f)
    return _LEARNED_RERANKER


def rerank_cwe_learned(
    query: str,
    hits: Sequence[KBHit],
    *,
    top_k: int = 5,
    diversify: bool | None = None,
    lookup_docs=None,
) -> List[KBHit]:
    from tcar.eval.train_rcm_specialist_reranker import apply_learned

    model = load_learned_rcm_reranker()
    scored = apply_learned(query, hits, model)
    if diversify is None:
        env_d = env_flag("RCM_DIVERSIFY", "")
        if env_d in {"1", "true", "yes", "on"}:
            diversify = True
        elif env_d in {"0", "false", "no", "off"}:
            diversify = False
        else:
            diversify = top_k > 5
    if not diversify:
        return scored[:top_k]
    try:
        from eval.cta_rag_port import diversify_cwe_hits
    except Exception:
        return scored[:top_k]
    prompt_hits, _meta = diversify_cwe_hits(
        list(scored),
        lookup_docs=lookup_docs,
        prompt_k=top_k,
        seed_n=min(5, top_k),
        max_per_cluster=1 if top_k <= 5 else 3,
        audit_k=max(20, len(scored)),
    )
    return prompt_hits[:top_k]


def rcm_oracle_mode() -> str:
    raw = env_flag("RCM_ORACLE", "off")
    if raw in {"pin", "gold_pin", "oracle"}:
        return "gold_pin"
    if raw in {"log", "gold_at20", "gold_at20_log", "at20"}:
        return "gold_at20_log"
    return "off"


def ata_abstain_enabled() -> bool:
    return env_flag("ATA_ABSTAIN", "off") in {"1", "true", "yes", "on"}


def mcq_retrieval_mode() -> str:
    raw = env_flag("MCQ_RETRIEVAL", "default")
    if raw in {"option", "option_aware", "per_option"}:
        return "option_aware"
    if raw in {"relation", "relation_aware", "stix", "typed_relation"}:
        return "relation_aware"
    return "default"


def mcq_abstain_enabled() -> bool:
    return env_flag("MCQ_ABSTAIN", "off") in {"1", "true", "yes", "on"}


def vsp_retrieval_mode() -> str:
    raw = env_flag("VSP_RETRIEVAL", "default")
    if raw in {"metric", "metric_wise", "per_metric"}:
        return "metric_wise"
    if raw in {"structured", "facts", "decoder", "fact_decode"}:
        return "structured"
    return "default"


def _norm_cwe(cid: str) -> str:
    s = (cid or "").strip().upper()
    if not s:
        return ""
    if not s.startswith("CWE-"):
        m = re.search(r"(\d+)", s)
        return f"CWE-{m.group(1)}" if m else s
    return s


def _tokset(text: str) -> Set[str]:
    return {t for t in re.findall(r"[a-z0-9]+", (text or "").lower()) if len(t) > 2}


def taxonomy_score_cwe(query: str, hit: KBHit) -> float:
    """Lightweight specialist score: dense score + mechanism overlap (not pure lexical)."""
    q = (query or "").lower()
    blob = f"{hit.title or ''} {hit.text or ''}".lower()
    base = float(hit.score or 0.0)
    mech = 0.0
    for term in _RCM_MECH_TERMS:
        if term in q and term in blob:
            mech += 0.15
        elif term in q:
            # query mentions mechanism but candidate does not — mild penalty
            mech -= 0.02
    # Shared content words (root-cause language)
    qt, ht = _tokset(query), _tokset(blob)
    if qt and ht:
        jacc = len(qt & ht) / max(1, len(qt | ht))
        mech += 0.25 * jacc
    return base + mech


def rerank_cwe_taxonomy(
    query: str,
    hits: Sequence[KBHit],
    *,
    top_k: int = 5,
    diversify: bool | None = None,
    lookup_docs=None,
) -> List[KBHit]:
    """Taxonomy-aware score reorder; optional graph-diversified select.

    Default: diversify off when top_k<=5 (oracle: diversify@5 *hurts* gold recall);
    diversify on for larger Soft-GAD catalogues. Override with RCM_DIVERSIFY=1/0.
    """
    if diversify is None:
        env_d = env_flag("RCM_DIVERSIFY", "")
        if env_d in {"1", "true", "yes", "on"}:
            diversify = True
        elif env_d in {"0", "false", "no", "off"}:
            diversify = False
        else:
            diversify = top_k > 5
    scored = sorted(hits, key=lambda h: taxonomy_score_cwe(query, h), reverse=True)
    # Keep full pool order for diversify; only truncate when diversify is off.
    if not diversify:
        out: List[KBHit] = []
        seen: Set[str] = set()
        for h in scored:
            cid = _norm_cwe(h.doc_id)
            if not cid or cid in seen:
                continue
            seen.add(cid)
            out.append(h)
            if len(out) >= top_k:
                break
        return out

    try:
        from eval.cta_rag_port import diversify_cwe_hits  # noqa: WPS433
    except Exception:
        # Fallback: score-only top_k
        return rerank_cwe_taxonomy(query, hits, top_k=top_k, diversify=False)

    prompt_hits, _meta = diversify_cwe_hits(
        list(scored),
        lookup_docs=lookup_docs,
        prompt_k=top_k,
        seed_n=min(5, top_k),
        max_per_cluster=1 if top_k <= 5 else 3,
        audit_k=max(20, len(scored)),
    )
    return prompt_hits[:top_k]


def apply_rcm_oracle_pin(
    hits: Sequence[KBHit],
    gold_ids: Sequence[str],
    *,
    lookup_docs,
    top_k: int = 5,
) -> Tuple[List[KBHit], dict]:
    """If gold is in the pool (or look-up-able), pin it as rank-1 then fill to top_k."""
    golds = [_norm_cwe(g) for g in gold_ids if g]
    golds = [g for g in golds if g]
    meta = {"oracle": "gold_pin", "gold_ids": golds, "gold_in_pool": False, "pinned": False}
    if not golds:
        return list(hits)[:top_k], meta
    gold = golds[0]
    pool = list(hits)
    by_id = {_norm_cwe(h.doc_id): h for h in pool}
    meta["gold_in_pool"] = gold in by_id
    gold_hit = by_id.get(gold)
    if gold_hit is None and lookup_docs is not None:
        looked = lookup_docs([gold]) or []
        if looked:
            gold_hit = looked[0]
            meta["gold_looked_up"] = True
    if gold_hit is None:
        return pool[:top_k], meta
    meta["pinned"] = True
    out = [gold_hit]
    for h in pool:
        if _norm_cwe(h.doc_id) == gold:
            continue
        out.append(h)
        if len(out) >= top_k:
            break
    return out[:top_k], meta


def gold_in_top_n(hits: Sequence[KBHit], gold_ids: Sequence[str], n: int = 20) -> dict:
    golds = {_norm_cwe(g) for g in gold_ids if g}
    ids = [_norm_cwe(h.doc_id) for h in hits[:n]]
    rank = None
    for i, cid in enumerate(ids, start=1):
        if cid in golds:
            rank = i
            break
    return {
        "gold_ids": sorted(golds),
        "gold_at_n": rank is not None,
        "gold_rank": rank,
        "n": n,
        "pool_ids": ids,
    }


def format_cwe_hits_for_prompt(hits: Sequence[KBHit]) -> str:
    if not hits:
        return "No CWE context available."
    lines = []
    for h in hits:
        cid = _norm_cwe(h.doc_id) or h.doc_id
        name = h.title or ""
        text = (h.text or "")[:500]
        lines.append(f"{cid}: {name}\n{text}")
    return "\n\n".join(lines)


def dedupe_parent_sub_techniques(ids: Iterable[str]) -> List[str]:
    """Prefer sub-technique over parent when both present."""
    raw = [str(t).strip().upper() for t in ids if t]
    raw = [t for t in raw if t.startswith("T")]
    s = set(raw)
    out: List[str] = []
    for tid in raw:
        parent = tid.split(".")[0]
        if "." not in tid and any(x.startswith(parent + ".") for x in s):
            continue
        if tid not in out:
            out.append(tid)
    return out


def filter_ata_to_evidence(raw: str, allowed_ids: Sequence[str]) -> Tuple[str, List[str], bool]:
    """Keep only technique IDs that appear in retrieved candidates. Returns (new_raw, kept, emptied)."""
    allowed = {str(a).strip().upper() for a in allowed_ids if a}
    # Also allow parents of allowed subs and exact matches
    expanded = set(allowed)
    for a in list(allowed):
        expanded.add(a.split(".")[0])
    preds = sorted(parse_ate_ids(raw or ""))
    kept = [p for p in preds if p in expanded or any(a.startswith(p + ".") for a in allowed)]
    kept = dedupe_parent_sub_techniques(kept)
    emptied = len(kept) == 0
    if emptied:
        return raw, [], True
    # Rewrite answer line while preserving reasoning if present
    if re.search(r"(?im)^answer\s*:", raw or ""):
        new_raw = re.sub(
            r"(?im)^answer\s*:.*$",
            "answer: " + ", ".join(kept),
            raw or "",
            count=1,
        )
    else:
        new_raw = (raw or "").rstrip() + "\nanswer: " + ", ".join(kept)
    return new_raw, kept, False


def parse_mcq_options(prompt: str) -> Dict[str, str]:
    """Extract A/B/C/D option texts from a CTIBench Prompt field.

    CTIBench uses inline forms such as:
      **Options:** A) Audit B) Execution Prevention C) ... D) ...
    Legacy newline-separated A./A) lines are also supported.
    """
    text = prompt or ""
    opts: Dict[str, str] = {}

    # 1) Inline after Options: / **Options:**
    inline = re.search(
        r"(?:\*\*\s*Options\s*:\s*\*\*|Options\s*:)\s*"
        r"A\s*[.\)]\s*(.+?)\s+"
        r"B\s*[.\)]\s*(.+?)\s+"
        r"C\s*[.\)]\s*(.+?)\s+"
        r"D\s*[.\)]\s*(.+?)"
        r"(?=\s+\*\*|\s+Important\b|\s+Return\b|\Z)",
        text,
        flags=re.S | re.I,
    )
    if not inline:
        # 2) Bare inline A)…B)…C)…D)… (no Options: header)
        inline = re.search(
            r"\bA\s*[.\)]\s*(.+?)\s+"
            r"B\s*[.\)]\s*(.+?)\s+"
            r"C\s*[.\)]\s*(.+?)\s+"
            r"D\s*[.\)]\s*(.+?)"
            r"(?=\s+\*\*|\s+Important\b|\s+Return\b|\Z)",
            text,
            flags=re.S | re.I,
        )
    if inline:
        for letter, g in zip("ABCD", inline.groups()):
            opts[letter] = re.sub(r"\s+", " ", (g or "")).strip(" \t-;")
        if len(opts) == 4 and all(opts[L] for L in "ABCD"):
            return opts

    # 3) Newline-separated A. / A)
    for letter in "ABCD":
        m = re.search(
            rf"(?:^|\n)\s*{letter}[\.\)]\s*(.+?)(?=(?:\n\s*[ABCD][\.\)]|\Z))",
            text,
            flags=re.S | re.I,
        )
        if m:
            opts[letter] = re.sub(r"\s+", " ", m.group(1)).strip()
    return opts


def mcq_option_queries(full_prompt: str) -> List[Tuple[str, str]]:
    """Return (label, query) pairs for option-aware retrieval."""
    opts = parse_mcq_options(full_prompt)
    stem = full_prompt
    m = re.search(r"(?:\*\*\s*Options\s*:\s*\*\*|Options\s*:)", full_prompt, flags=re.I)
    if m:
        stem = full_prompt[: m.start()].strip()
    else:
        m2 = re.search(r"(?:^|\n)\s*A\s*[.\)]\s*", full_prompt)
        if m2:
            stem = full_prompt[: m2.start()].strip()
        else:
            m3 = re.search(r"\bA\s*[.\)]\s*", full_prompt)
            if m3:
                stem = full_prompt[: m3.start()].strip()
    # Prefer the **Question:** span when present (cleaner retrieval stem).
    qm = re.search(
        r"\*\*\s*Question\s*:\s*\*\*\s*(.+?)(?=\*\*\s*Options|\bOptions\s*:|\Z)",
        full_prompt,
        flags=re.S | re.I,
    )
    if qm:
        stem = re.sub(r"\s+", " ", qm.group(1)).strip() or stem
    if not opts:
        return [("ALL", full_prompt)]
    return [(lab, f"{stem}\nOption {lab}: {txt}") for lab, txt in opts.items()]


def _mcq_named_entities(text: str) -> Set[str]:
    """Lightweight CTI entity tokens for contamination checks."""
    t = text or ""
    ents: Set[str] = set()
    for m in re.finditer(r"\bCVE-\d{4}-\d+\b", t, flags=re.I):
        ents.add(m.group(0).upper())
    for m in re.finditer(r"\bAPT\s?-?\d+\b", t, flags=re.I):
        ents.add(re.sub(r"\s+", "", m.group(0).upper()))
    for m in re.finditer(r"\bT\d{4}(?:\.\d{3})?\b", t, flags=re.I):
        ents.add(m.group(0).upper())
    # CamelCase / multi-word Title Case tool & malware names
    for m in re.finditer(r"\b[A-Z][a-z]+(?:[A-Z][a-zA-Z0-9]+)+\b", t):
        ents.add(m.group(0).lower())
    for m in re.finditer(r"\b[A-Z][a-z]{2,}(?:\s+[A-Z][a-z]{2,}){1,3}\b", t):
        ents.add(m.group(0).lower())
    return ents


def mcq_should_prefer_closed_book(
    question: str,
    *,
    cb_raw: str,
    rag_raw: str,
    context: str,
) -> bool:
    """True when RAG likely swapped to a passage entity not named in the question."""
    from eval.scoring import parse_mcq_answer

    cb = parse_mcq_answer(cb_raw or "")
    rag = parse_mcq_answer(rag_raw or "")
    if not cb or not rag or cb == rag:
        return False
    q_ents = _mcq_named_entities(question)
    ctx_ents = _mcq_named_entities(context)
    foreign = {e for e in ctx_ents if e not in q_ents}
    if not foreign:
        return False
    # Strong signal: foreign entities in passages while answers disagree.
    if len(foreign) >= 1 and q_ents:
        # Extra: RAG option text itself introduces a foreign entity
        opts = parse_mcq_options(question)
        rag_opt = (opts.get(rag.upper()) or "").lower()
        if any(str(e).lower() in rag_opt for e in foreign if isinstance(e, str)):
            return True
        # Or context is dominated by foreign names vs question entities
        q_in_ctx = sum(1 for e in q_ents if str(e).lower() in (context or "").lower())
        if q_in_ctx == 0 and len(foreign) >= 1:
            return True
    return False


def merge_option_hits(
    labeled_hits: Sequence[Tuple[str, Sequence[KBHit]]],
    *,
    top_k: int = 5,
) -> List[KBHit]:
    """Take best hit per option then fill by score; tag title with option label."""
    merged: List[KBHit] = []
    seen: Set[str] = set()
    # First pass: best per option
    for lab, hits in labeled_hits:
        if not hits:
            continue
        h = hits[0]
        key = h.doc_id or h.text[:80]
        if key in seen:
            continue
        seen.add(key)
        merged.append(
            KBHit(
                doc_id=h.doc_id,
                title=f"[opt {lab}] {h.title or ''}".strip(),
                text=h.text,
                score=h.score,
            )
        )
    # Second pass: remaining by score
    rest: List[KBHit] = []
    for lab, hits in labeled_hits:
        for h in hits[1:]:
            key = h.doc_id or h.text[:80]
            if key in seen:
                continue
            seen.add(key)
            rest.append(h)
    rest.sort(key=lambda x: float(x.score or 0.0), reverse=True)
    for h in rest:
        if len(merged) >= top_k:
            break
        merged.append(h)
    return merged[:top_k]


_VSP_METRICS = (
    ("AV", "Attack Vector", "network adjacent local physical remote"),
    ("AC", "Attack Complexity", "low high complex conditions"),
    ("PR", "Privileges Required", "none low high privilege authentication"),
    ("UI", "User Interaction", "none required user click"),
    ("S", "Scope", "unchanged changed component"),
    ("C", "Confidentiality", "none low high information disclosure"),
    ("I", "Integrity", "none low high modify"),
    ("A", "Availability", "none low high denial of service crash"),
)


def vsp_metric_case_block(cases: Sequence[KBHit], query: str) -> str:
    """Build metric-wise guidance from reference cases (no full-vector copy)."""
    if not cases:
        return (
            "Below are descriptions of similar historical CVEs:\n\n"
            "(no distinct reference cases retrieved)\n"
        )
    lines = [
        "Below are reference CVE cases. For EACH CVSS metric, choose the value "
        "supported by the QUERY description; use cases only as analogies for that "
        "metric — do NOT copy an entire neighbour vector.\n"
    ]
    for i, h in enumerate(cases[:5], start=1):
        lines.append(f"Case {i}:")
        lines.append(f"Description: {h.text}\n")
    lines.append("Metric checklist (decide independently from the QUERY):")
    for code, name, hints in _VSP_METRICS:
        lines.append(f"- {code} ({name}): consider {hints}")
    lines.append("")
    return "\n".join(lines)


def parse_predicted_cwe_from_raw(raw: str) -> Optional[str]:
    return parse_cwe_answer(raw or "")


@dataclass
class RcmRerankModel:
    """Picklable pairwise specialist reranker (avoid __main__ pickle breaks)."""

    weights: List[float]
    bias: float
    feature_names: List[str]

    def score(self, feats: Sequence[float]) -> float:
        return float(self.bias + sum(w * f for w, f in zip(self.weights, feats)))


RCM_RERANK_FEATURE_NAMES = (
    "dense_score",
    "taxonomy_score",
    "mech_overlap",
    "jaccard",
)
