#!/usr/bin/env python3
"""Export MCQ v2 audit CSV + stratified groups for v3 planning.

Outputs under tcar/eval_results/mcq_v2_audit/:
  mcq_v2_audit_all_groups.csv     — damages + rescues + 100 both-wrong + 100 neutral-correct
  damages.csv / rescues.csv / both_wrong_100.csv / neutral_correct_100.csv
  damages_brief.md                — readable 50-damage audit
  both_wrong_100_brief.md         — readable both-wrong sample
  summary.json                    — counts + oracle ceiling
"""
from __future__ import annotations

import csv
import json
import random
import re
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from eval.scoring import parse_mcq_answer
from tcar.ctibench_kb import CTIBenchKBRetriever
from tcar.specialist_retrieval import (
    _mcq_named_entities,
    mcq_option_queries,
    parse_mcq_options,
)

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "tcar/eval_results/counterfactual_ctibench_mcq_20260907Tturbo_mcq_option_aware_v2.jsonl"
OUT_DIR = ROOT / "tcar/eval_results/mcq_v2_audit"
SEED = 20260908

_RELATION_PATTERNS = (
    (re.compile(r"\bmitigat", re.I), "mitigation"),
    (re.compile(r"\bdetect", re.I), "detection"),
    (re.compile(r"\bdata\s*source", re.I), "datasource"),
    (re.compile(r"\bassociated with\b|\bused by\b|\battributed", re.I), "association"),
    (re.compile(r"\bsoftware\b|\bmalware\b|\btool\b", re.I), "software"),
    (re.compile(r"\bgroup\b|\bAPT\b|\bactor\b|\bthreat\s*actor", re.I), "group"),
    (re.compile(r"\bplatform\b|\boperat(?:es|ing)\s+on\b", re.I), "platform"),
)


def extract_anchors(question: str) -> Dict[str, object]:
    ents = sorted(_mcq_named_entities(question))
    tids = [e for e in ents if re.fullmatch(r"T\d{4}(?:\.\d{3})?", str(e), flags=re.I)]
    cves = [e for e in ents if str(e).upper().startswith("CVE-")]
    apts = [e for e in ents if re.fullmatch(r"APT-?\d+", str(e).replace(" ", ""), flags=re.I)]
    relations = [name for pat, name in _RELATION_PATTERNS if pat.search(question or "")]
    # Platform cues
    platforms = []
    for p in ("windows", "linux", "macos", "android", "ios", "network", "containers"):
        if re.search(rf"\b{p}\b", question or "", re.I):
            platforms.append(p)
    return {
        "entities": ents,
        "technique_ids": tids,
        "cves": cves,
        "actors": apts,
        "relations": relations,
        "platforms": platforms,
    }


def effect_of(r: dict) -> str:
    cb, rag = bool(r.get("closed_book_correct")), bool(r.get("retrieval_correct"))
    if (not cb) and rag:
        return "rescue"
    if cb and (not rag):
        return "damage"
    if cb and rag:
        return "neutral_correct"
    return "neutral_wrong"


def _passage_contaminated(question: str, passage: str, anchors: dict) -> Tuple[bool, str]:
    """True if passage shares topic but conflicts on main entity (actor/tech)."""
    q_ents = set(anchors.get("entities") or [])
    p_ents = _mcq_named_entities(passage)
    if not q_ents or not p_ents:
        return False, ""
    # Technique overlap but actor conflict
    q_tech = {e.upper() for e in q_ents if re.fullmatch(r"T\d{4}(?:\.\d{3})?", str(e), flags=re.I)}
    p_tech = {e.upper() for e in p_ents if re.fullmatch(r"T\d{4}(?:\.\d{3})?", str(e), flags=re.I)}
    q_apt = {re.sub(r"\s+", "", str(e).upper()) for e in q_ents if "APT" in str(e).upper()}
    p_apt = {re.sub(r"\s+", "", str(e).upper()) for e in p_ents if "APT" in str(e).upper()}
    if q_tech & p_tech and q_apt and p_apt and not (q_apt & p_apt):
        return True, f"technique_overlap_actor_conflict q={sorted(q_apt)} p={sorted(p_apt)}"
    # Foreign APT/CVE while question names a different one
    foreign_apt = p_apt - q_apt
    if q_apt and foreign_apt and not (p_apt & q_apt):
        return True, f"foreign_actor {sorted(foreign_apt)}"
    foreign_cve = {
        e.upper() for e in p_ents if str(e).upper().startswith("CVE-")
    } - {e.upper() for e in q_ents if str(e).upper().startswith("CVE-")}
    q_cve = {e.upper() for e in q_ents if str(e).upper().startswith("CVE-")}
    if q_cve and foreign_cve and not (
        {e.upper() for e in p_ents if str(e).upper().startswith("CVE-")} & q_cve
    ):
        return True, f"foreign_cve {sorted(foreign_cve)}"
    return False, ""


def retrieve_per_option(retriever: CTIBenchKBRetriever, question: str, k: int = 3) -> dict:
    out = {}
    for lab, q in mcq_option_queries(question):
        hits = retriever.retrieve_for_task(q, "mcq", k=k)
        rows = []
        for rank, h in enumerate(hits, start=1):
            rows.append(
                {
                    "rank": rank,
                    "doc_id": h.doc_id,
                    "score": float(h.score or 0),
                    "title": h.title or "",
                    "text": (h.text or "")[:500],
                }
            )
        out[lab] = rows
    return out


def build_row(r: dict, *, per_option: Optional[dict] = None) -> dict:
    q = r.get("question") or ""
    opts = parse_mcq_options(q)
    anchors = extract_anchors(q)
    cb_raw = r.get("closed_book_prediction") or ""
    rag_raw = r.get("retrieval_prediction") or ""
    parsed_cb = parse_mcq_answer(cb_raw) or ""
    parsed_rag = parse_mcq_answer(rag_raw) or ""
    meta = r.get("tcar_meta") or {}
    effect = r.get("retrieval_effect") or effect_of(r)

    # Contamination over per-option evidence
    contam_flags = []
    selected_bits = []
    if per_option:
        for lab, hits in per_option.items():
            for h in hits[:1]:
                bad, reason = _passage_contaminated(q, h.get("text") or "", anchors)
                if bad:
                    contam_flags.append(f"{lab}:{reason}")
                selected_bits.append(
                    f"[{lab}#{h.get('rank')}|{h.get('doc_id')}|{h.get('score'):.3f}] "
                    f"{(h.get('text') or '')[:180]}"
                )

    return {
        "id": r.get("id"),
        "question": q,
        "options": json.dumps(opts, ensure_ascii=False),
        "option_A": opts.get("A", ""),
        "option_B": opts.get("B", ""),
        "option_C": opts.get("C", ""),
        "option_D": opts.get("D", ""),
        "gold": (r.get("gold") or "").strip().upper(),
        "cb_answer": parsed_cb,
        "rag_answer": parsed_rag,
        "effect": effect,
        "cb_correct": bool(r.get("closed_book_correct")),
        "rag_correct": bool(r.get("retrieval_correct")),
        "retrieved_evidence_per_option": json.dumps(per_option or {}, ensure_ascii=False),
        "retrieval_scores_or_ranks": json.dumps(
            {
                lab: [{"rank": h["rank"], "doc_id": h["doc_id"], "score": h["score"]} for h in hits]
                for lab, hits in (per_option or {}).items()
            },
            ensure_ascii=False,
        ),
        "selected_evidence": " || ".join(selected_bits),
        "seed_ids": json.dumps(meta.get("seed_ids") or []),
        "retrieved_ids_audit": json.dumps(r.get("retrieved_ids") or []),
        "raw_cb_response": cb_raw,
        "raw_rag_response": rag_raw,
        "parsed_cb": parsed_cb,
        "parsed_rag": parsed_rag,
        "abstain": bool(meta.get("mcq_abstain")),
        "abstain_to_cb": bool(meta.get("mcq_abstain_to_cb")),
        "anchors": json.dumps(anchors, ensure_ascii=False),
        "contamination_flags": "; ".join(contam_flags),
        "has_contamination": bool(contam_flags),
        "none_of_the_above_option": any(
            re.search(r"none of the above", opts.get(L, ""), re.I) for L in "ABCD"
        ),
    }


def write_csv(path: Path, rows: List[dict]) -> None:
    if not rows:
        path.write_text("")
        return
    fields = list(rows[0].keys())
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for row in rows:
            w.writerow(row)


def brief_md(path: Path, rows: List[dict], title: str) -> None:
    lines = [f"# {title}", "", f"n={len(rows)}", ""]
    for i, row in enumerate(rows, 1):
        opts = json.loads(row["options"] or "{}")
        lines.append(f"## {i}. {row['id']}  effect={row['effect']}")
        lines.append(f"- gold={row['gold']}  cb={row['cb_answer']}  rag={row['rag_answer']}")
        lines.append(f"- abstain={row['abstain']}  contamination={row['contamination_flags'] or 'none'}")
        lines.append(f"- anchors={row['anchors']}")
        q = row["question"]
        qm = re.search(r"\*\*\s*Question\s*:\s*\*\*\s*(.+?)(?=\*\*\s*Options|\bOptions\s*:|\Z)", q, re.S | re.I)
        stem = (qm.group(1).strip() if qm else q)[:300]
        lines.append(f"- question: {stem}")
        lines.append(
            f"- options: A) {opts.get('A','')} | B) {opts.get('B','')} | "
            f"C) {opts.get('C','')} | D) {opts.get('D','')}"
        )
        lines.append(f"- selected_evidence: {row['selected_evidence'][:600]}")
        lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    rows = [json.loads(l) for l in SRC.read_text(encoding="utf-8").splitlines() if l.strip()]
    by_effect: Dict[str, List[dict]] = {
        "damage": [],
        "rescue": [],
        "neutral_wrong": [],
        "neutral_correct": [],
    }
    for r in rows:
        by_effect[effect_of(r)].append(r)

    rng = random.Random(SEED)
    damages = by_effect["damage"]
    rescues = by_effect["rescue"]
    both_wrong = by_effect["neutral_wrong"][:]
    neutral_ok = by_effect["neutral_correct"][:]
    rng.shuffle(both_wrong)
    rng.shuffle(neutral_ok)
    both_wrong_100 = both_wrong[:100]
    neutral_100 = neutral_ok[:100]

    n = len(rows)
    rag_ok = sum(1 for r in rows if r.get("retrieval_correct"))
    cb_ok = sum(1 for r in rows if r.get("closed_book_correct"))
    oracle = sum(
        1 for r in rows if r.get("closed_book_correct") or r.get("retrieval_correct")
    )
    summary = {
        "n": n,
        "cb_acc": cb_ok / n,
        "rag_acc": rag_ok / n,
        "delta": (rag_ok - cb_ok) / n,
        "rescues": len(rescues),
        "damages": len(damages),
        "both_wrong": len(by_effect["neutral_wrong"]),
        "neutral_correct": len(by_effect["neutral_correct"]),
        "branch_oracle_acc": oracle / n,
        "rag_correct_count": rag_ok,
        "to_reach_80pct_need": max(0, int(0.80 * n) - rag_ok),
        "seed": SEED,
        "groups_exported": {
            "damages": len(damages),
            "rescues": len(rescues),
            "both_wrong_100": len(both_wrong_100),
            "neutral_correct_100": len(neutral_100),
        },
    }
    (OUT_DIR / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2), flush=True)

    # Offline re-retrieve for exported groups only
    print("loading retriever...", flush=True)
    t0 = time.time()
    retriever = CTIBenchKBRetriever()
    _ = retriever.retrieve_for_task("ATT&CK phishing", "mcq", k=2)
    print(f"retriever ready in {time.time()-t0:.1f}s", flush=True)

    def enrich(subset: List[dict], label: str) -> List[dict]:
        out = []
        for i, r in enumerate(subset):
            per = retrieve_per_option(retriever, r.get("question") or "", k=3)
            out.append(build_row(r, per_option=per))
            if (i + 1) % 25 == 0 or (i + 1) == len(subset):
                print(f"  {label}: {i+1}/{len(subset)}", flush=True)
        return out

    print("enriching damages...", flush=True)
    d_rows = enrich(damages, "damages")
    print("enriching rescues...", flush=True)
    r_rows = enrich(rescues, "rescues")
    print("enriching both_wrong_100...", flush=True)
    bw_rows = enrich(both_wrong_100, "both_wrong")
    print("enriching neutral_correct_100...", flush=True)
    nc_rows = enrich(neutral_100, "neutral_correct")

    write_csv(OUT_DIR / "damages.csv", d_rows)
    write_csv(OUT_DIR / "rescues.csv", r_rows)
    write_csv(OUT_DIR / "both_wrong_100.csv", bw_rows)
    write_csv(OUT_DIR / "neutral_correct_100.csv", nc_rows)
    all_rows = d_rows + r_rows + bw_rows + nc_rows
    write_csv(OUT_DIR / "mcq_v2_audit_all_groups.csv", all_rows)
    brief_md(OUT_DIR / "damages_brief.md", d_rows, "MCQ v2 — 50 damages")
    brief_md(OUT_DIR / "both_wrong_100_brief.md", bw_rows, "MCQ v2 — 100 both-wrong sample")

    # Contamination rates
    contam = {
        "damages_contam_rate": sum(1 for x in d_rows if x["has_contamination"]) / max(1, len(d_rows)),
        "rescues_contam_rate": sum(1 for x in r_rows if x["has_contamination"]) / max(1, len(r_rows)),
        "both_wrong_contam_rate": sum(1 for x in bw_rows if x["has_contamination"]) / max(1, len(bw_rows)),
        "damages_none_option": sum(1 for x in d_rows if x["none_of_the_above_option"]),
        "both_wrong_none_option": sum(1 for x in bw_rows if x["none_of_the_above_option"]),
    }
    summary["contamination"] = contam
    (OUT_DIR / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(contam, indent=2))
    print(f"wrote {OUT_DIR}")


if __name__ == "__main__":
    main()
