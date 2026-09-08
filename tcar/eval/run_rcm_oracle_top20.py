#!/usr/bin/env python3
"""RCM headroom: dense top-20 gold recall + optional oracle-pin / taxonomy-rerank CF.

Retrieval-only stats (no LLM) answer: "Is reranking worth building?"
  If gold@20 is low, reranking cannot help much.
  If gold@20 is high but gold@5 is low, ranking has headroom.

Usage:
  PYTHONPATH=. python -m tcar.eval.run_rcm_oracle_top20 --limit 0
  PYTHONPATH=. python -m tcar.eval.run_rcm_oracle_top20 --generate --mode gold_pin --limit 100
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from dotenv import load_dotenv

load_dotenv(ROOT / ".env")

from tcar.ctibench_kb import CTIBenchKBRetriever  # noqa: E402
from tcar.specialist_retrieval import (  # noqa: E402
    apply_rcm_oracle_pin,
    gold_in_top_n,
    rerank_cwe_taxonomy,
)


def _norm(cid: str) -> str:
    s = (cid or "").strip().upper()
    if not s:
        return ""
    if not s.startswith("CWE-"):
        import re

        m = re.search(r"(\d+)", s)
        return f"CWE-{m.group(1)}" if m else s
    return s


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=0, help="0 = full CTIBench RCM")
    ap.add_argument("--pool", type=int, default=20)
    ap.add_argument("--top-k", type=int, default=5)
    ap.add_argument(
        "--mode",
        choices=["stats", "dense5", "taxonomy", "gold_pin"],
        default="stats",
        help="stats=retrieval only; others run generator CF via run_counterfactual env",
    )
    ap.add_argument("--generate", action="store_true", help="Also launch CF generate for --mode")
    ap.add_argument("--workers", type=int, default=2)
    ap.add_argument("--model", default="")
    ap.add_argument("--out-dir", type=Path, default=ROOT / "tcar" / "eval_results")
    args = ap.parse_args()

    data = ROOT / "data" / "cti-rcm.tsv"
    rows = list(csv.DictReader(data.open(encoding="utf-8", errors="replace"), delimiter="\t"))
    if args.limit and args.limit > 0:
        rows = rows[: args.limit]

    retriever = CTIBenchKBRetriever()
    n = len(rows)
    at20 = at5 = at5_tax = at5_tax_div = 0
    ranks = []
    for row in rows:
        q = (row.get("Description") or "").strip()
        gold = _norm(row.get("GT") or "")
        pool = retriever.retrieve(q, "cwe", k=args.pool)
        st = gold_in_top_n(pool, [gold], n=args.pool)
        if st["gold_at_n"]:
            at20 += 1
            ranks.append(st["gold_rank"])
        top5 = pool[: args.top_k]
        if any(_norm(h.doc_id) == gold for h in top5):
            at5 += 1
        tax5 = rerank_cwe_taxonomy(q, pool, top_k=args.top_k, diversify=False)
        if any(_norm(h.doc_id) == gold for h in tax5):
            at5_tax += 1
        tax5_div = rerank_cwe_taxonomy(
            q, pool, top_k=args.top_k, diversify=True, lookup_docs=retriever.get_docs_cwe
        )
        if any(_norm(h.doc_id) == gold for h in tax5_div):
            at5_tax_div += 1

    summary = {
        "n": n,
        "pool": args.pool,
        "top_k": args.top_k,
        "gold_at_20": at20 / n if n else 0.0,
        "gold_at_5_dense": at5 / n if n else 0.0,
        "gold_at_5_taxonomy": at5_tax / n if n else 0.0,
        "gold_at_5_taxonomy_diversify": at5_tax_div / n if n else 0.0,
        "mean_gold_rank_when_in_20": (sum(ranks) / len(ranks)) if ranks else None,
        "rerank_headroom_pp": (at20 - at5) / n if n else 0.0,
        "note": (
            "If gold_at_20 - gold_at_5_dense is small, ranking cannot unlock much. "
            "If large, specialist rerank / Soft GAD+rerank is justified. "
            "gold_at_20 is the oracle ceiling for any reranker over this pool."
        ),
    }
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    args.out_dir.mkdir(parents=True, exist_ok=True)
    out = args.out_dir / f"rcm_oracle_top20_{stamp}.json"
    out.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))
    print(f"wrote {out}")

    if args.generate and args.mode != "stats":
        model = (args.model or os.getenv("GENERATION_MODEL") or "gpt-5.6-sol").strip()
        os.environ["RCM_GAD"] = "off"
        os.environ["GAD_MODE"] = "off"
        os.environ["RCM_CWE_RETRIEVAL"] = "on"
        if args.mode == "taxonomy":
            os.environ["RCM_RERANK"] = "taxonomy"
            os.environ["RCM_ORACLE"] = "off"
            stamp_cf = f"{stamp}_taxonomy"
        elif args.mode == "gold_pin":
            os.environ["RCM_RERANK"] = "off"
            os.environ["RCM_ORACLE"] = "gold_pin"
            stamp_cf = f"{stamp}_gold_pin"
        else:
            os.environ["RCM_RERANK"] = "off"
            os.environ["RCM_ORACLE"] = "off"
            stamp_cf = f"{stamp}_dense5"
        print(f"Launching CF generate mode={args.mode} stamp={stamp_cf} model={model}")
        from tcar.eval import run_counterfactual as rc  # noqa: WPS433

        # Prefer CLI subprocess for resume stamps
        import subprocess

        cmd = [
            sys.executable,
            "-m",
            "tcar.eval.run_counterfactual",
            "--benchmark",
            "ctibench",
            "--tasks",
            "rcm",
            "--limit",
            str(args.limit),
            "--workers",
            str(args.workers),
            "--model",
            model,
            "--variant",
            "no_confusion",
            "--stamp",
            stamp_cf,
        ]
        print(" ".join(cmd))
        subprocess.check_call(cmd, cwd=str(ROOT), env=os.environ.copy())


if __name__ == "__main__":
    main()
