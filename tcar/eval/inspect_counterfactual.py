"""
Inspect counterfactual JSONL: retrieval → forced-RAG label vs gold vs closed-book.

Examples:
  python -m tcar.eval.inspect_counterfactual tcar/eval_results/counterfactual_cticonnect_rcm_20260901Tcf_cc.jsonl --limit 10
  python -m tcar.eval.inspect_counterfactual ... --effect damage --limit 20
  python -m tcar.eval.inspect_counterfactual ... --csv out.csv
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))

from eval.cticonnect_metrics import extract_ids, score_id_item  # noqa: E402
from eval.scoring import parse_ate_ids, parse_cwe_answer, parse_gold_ate  # noqa: E402


def _parse_labels(row: Dict[str, Any]) -> Dict[str, Any]:
    task = row.get("task", "")
    benchmark = row.get("benchmark", "")
    gold = row.get("gold")

    if benchmark == "cticonnect":
        gt = gold if isinstance(gold, dict) else {}
        kind = gt.get("target_type", "cwe")
        if gt.get("target_id"):
            gold_set = {str(gt["target_id"]).upper()}
        else:
            gold_set = {str(x).upper() for x in (gt.get("target_ids") or [])}
        cb_ids = extract_ids(row.get("closed_book_prediction") or "", kind)
        rag_ids = extract_ids(row.get("retrieval_prediction") or "", kind)
        return {
            "gold_label": ", ".join(sorted(gold_set)),
            "cb_label": ", ".join(sorted(cb_ids)) or "—",
            "rag_label": ", ".join(sorted(rag_ids)) or "—",
        }

    gold_str = str(gold or "")
    if task in ("rcm", "rcm2021"):
        g = parse_cwe_answer(gold_str) or gold_str
        cb = parse_cwe_answer(row.get("closed_book_prediction") or "") or "—"
        rag = parse_cwe_answer(row.get("retrieval_prediction") or "") or "—"
        return {"gold_label": g, "cb_label": cb, "rag_label": rag}
    if task == "ate":
        g = ", ".join(sorted(parse_gold_ate(gold_str)))
        cb = ", ".join(sorted(parse_ate_ids(row.get("closed_book_prediction") or ""))) or "—"
        rag = ", ".join(sorted(parse_ate_ids(row.get("retrieval_prediction") or ""))) or "—"
        return {"gold_label": g, "cb_label": cb, "rag_label": rag}
    if task == "mcq":
        return {"gold_label": gold_str, "cb_label": "—", "rag_label": "—"}
    return {"gold_label": gold_str, "cb_label": "—", "rag_label": "—"}


def _retrieval_summary(row: Dict[str, Any]) -> str:
    meta = row.get("tcar_meta") or {}
    parts: List[str] = []
    seed = meta.get("seed_ids") or row.get("retrieved_ids", [])[:5]
    if seed:
        parts.append(f"top5={seed}")
    candidates = meta.get("candidate_ids")
    if candidates and candidates != seed:
        parts.append(f"candidates={candidates}")
    scored = meta.get("scored_top") or []
    if scored:
        tops = [f"{s['id']}({s.get('total', 0):.2f})" for s in scored[:3]]
        parts.append(f"scored={tops}")
    rank = row.get("gold_rank")
    if rank is not None:
        parts.append(f"gold_rank={rank}")
    recall5 = (row.get("recall_at") or {}).get(5)
    if recall5 is not None:
        parts.append(f"recall@5={recall5}")
    return " | ".join(parts) if parts else "—"


def flatten_row(row: Dict[str, Any]) -> Dict[str, Any]:
    labels = _parse_labels(row)
    meta = row.get("tcar_meta") or {}
    retrieved = row.get("retrieved_ids") or []
    return {
        "id": row.get("id"),
        "task": row.get("task"),
        "effect": row.get("retrieval_effect"),
        "gold_label": labels["gold_label"],
        "cb_label": labels["cb_label"],
        "rag_label": labels["rag_label"],
        "cb_ok": row.get("closed_book_correct"),
        "rag_ok": row.get("retrieval_correct"),
        "gate": row.get("gate_decision"),
        "retrieved_top5": ", ".join(str(x) for x in retrieved[:5]),
        "retrieved_top20": ", ".join(str(x) for x in retrieved[:20]),
        "seed_ids": ", ".join(str(x) for x in (meta.get("seed_ids") or [])),
        "candidate_ids": ", ".join(str(x) for x in (meta.get("candidate_ids") or [])),
        "retrieval_summary": _retrieval_summary(row),
        "question": (row.get("question") or row.get("question_preview") or "")[:200],
    }


def load_jsonl(path: Path) -> List[Dict[str, Any]]:
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


def print_table(rows: List[Dict[str, Any]], *, verbose: bool) -> None:
    for r in rows:
        print("=" * 100)
        print(f"ID: {r['id']}  task={r['task']}  effect={r['effect']}  gate={r['gate']}")
        print(f"GOLD:     {r['gold_label']}")
        print(f"CB pred:  {r['cb_label']}  ({'✓' if r['cb_ok'] else '✗'})")
        print(f"RAG pred: {r['rag_label']}  ({'✓' if r['rag_ok'] else '✗'})")
        print(f"Retrieved top-5:  {r['retrieved_top5']}")
        if verbose:
            print(f"Retrieved top-20: {r['retrieved_top20']}")
            print(f"Seed IDs:         {r['seed_ids']}")
            print(f"Candidates:       {r['candidate_ids']}")
            print(f"Summary:          {r['retrieval_summary']}")
            print(f"Q: {r['question']}…")


def write_csv(rows: List[Dict[str, Any]], path: Path) -> None:
    if not rows:
        return
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)


def main() -> None:
    ap = argparse.ArgumentParser(description="Inspect counterfactual retrieval vs labels")
    ap.add_argument("jsonl", type=Path)
    ap.add_argument("--effect", default="", help="Filter: rescue|damage|neutral_correct|neutral_wrong")
    ap.add_argument("--differ", action="store_true", help="Only CB≠RAG label")
    ap.add_argument("--wrong-rag", action="store_true", help="Only forced-RAG wrong")
    ap.add_argument("--gold-missed", action="store_true", help="Gold not in retrieved top-5")
    ap.add_argument("--limit", type=int, default=15)
    ap.add_argument("--csv", type=Path, default=None)
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    raw = load_jsonl(args.jsonl)
    flat = [flatten_row(r) for r in raw if not r.get("error")]

    if args.effect:
        flat = [r for r in flat if r["effect"] == args.effect]
    if args.differ:
        flat = [r for r in flat if r["cb_label"] != r["rag_label"]]
    if args.wrong_rag:
        flat = [r for r in flat if not r["rag_ok"]]
    if args.gold_missed:
        raw_by_id = {r["id"]: r for r in raw}
        flat = [
            r
            for r in flat
            if not (raw_by_id.get(r["id"], {}).get("recall_at") or {}).get(5, False)
        ]

    flat = flat[: args.limit]

    if args.csv:
        write_csv(flat, args.csv)
        print(f"Wrote {len(flat)} rows -> {args.csv}")
    else:
        print_table(flat, verbose=args.verbose)
        print(f"\n({len(flat)} items shown from {args.jsonl.name})")


if __name__ == "__main__":
    main()
