"""Constrained CTA-RAG TAA pick on CombSUM shortlists.

Primary fusion is gold-blind rank-normalised CombSUM over the saved Qwen
ranking and two hypothesis lists. This script does not refit weights.
Set TAA_N (default 10) to limit how many checkpoint items are scored.
"""
from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from eval.controlled_benchmark.select_taa_qwen_top3_llm import call_model, load_env  # noqa: E402
from eval.controlled_benchmark.taa_constrained import (  # noqa: E402
    build_selection_prompt,
    candidate_card,
    candidate_k,
    parse_choice,
    rerank_by_evidence_overlap,
    resolve_prediction,
)
from eval.taa_protocol import benchmark_alias_match  # noqa: E402

AUDIT = ROOT / "eval_results/controlled_benchmark/full/taa_qwen4b_evidence_query_audit"
PROFILES = (
    ROOT
    / "eval_results/controlled_benchmark/taa20_20260918"
    / "actor_retrieval_study_v2/actor_profiles.json"
)
FUSION = AUDIT / "published_rank_fusion/rows.json"


def main() -> None:
    load_env()
    api_key = os.environ.get("OPENAI_API_KEY", "")
    model = os.environ.get("GENERATION_MODEL", "gpt-4-turbo")
    if not api_key or api_key.startswith("sk-your-key"):
        raise SystemExit("OPENAI_API_KEY is missing from .env")
    n = int(os.environ.get("TAA_N", "10"))
    offset = int(os.environ.get("TAA_OFFSET", "0"))
    k = candidate_k()
    checkpoint = json.loads((AUDIT / "checkpoint.json").read_text(encoding="utf-8"))[
        offset : offset + n
    ]
    fusion = {row["id"]: row for row in json.loads(FUSION.read_text(encoding="utf-8"))}
    profiles = {
        profile["canonical_actor"]: profile
        for profile in json.loads(PROFILES.read_text(encoding="utf-8"))
    }
    out = AUDIT / f"llm_combsum_overlap_top{k}_offset{offset}_n{n}"
    out.mkdir(parents=True, exist_ok=True)
    cache_path = out / "calls.jsonl"
    done: dict[str, dict] = {}
    if cache_path.exists():
        for line in cache_path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                saved = json.loads(line)
                done[saved["id"]] = saved
    print(
        f"[cta-combsum] offset={offset} n={n} k={k} remaining={len(checkpoint) - len(done)}",
        flush=True,
    )
    for item in checkpoint:
        if item["id"] in done:
            continue
        fused = [name for name in fusion[item["id"]]["combsum_normalised_rank"] if name in profiles][:k]
        names, overlap = rerank_by_evidence_overlap(
            item["evidence_query"], fused, profiles
        )
        cards = [
            candidate_card(rank, name, profiles[name])
            + (
                f"\nOverlap score: {overlap[name]['overlap_score']}; "
                f"hits: {', '.join(overlap[name]['overlap_hits'][:8]) or 'none'}"
            )
            for rank, name in enumerate(names, 1)
        ]
        result = call_model(
            api_key,
            model,
            build_selection_prompt(item["evidence_query"], cards, k),
        )
        choice = parse_choice(result["raw"], k)
        predicted = resolve_prediction(names, choice) or ""
        gold_in_top3 = any(benchmark_alias_match(name, item["gold"]) for name in names)
        record = {
            "id": item["id"],
            "gold": item["gold"],
            "method": "cta_combsum_constrained",
            "top3": names,
            "combsum_top3": fused,
            "overlap": overlap,
            "gold_in_top3": gold_in_top3,
            "created_utc": datetime.now(timezone.utc).isoformat(),
            **choice,
            "predicted_actor": predicted,
            "correct": bool(predicted) and benchmark_alias_match(predicted, item["gold"]),
            "input_tokens": result["input_tokens"],
            "output_tokens": result["output_tokens"],
            "raw_response": result["raw"],
        }
        with cache_path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(record) + "\n")
        done[item["id"]] = record
        print(
            f"[cta-combsum] {item['id']} gold={item['gold']!r} "
            f"shortlist={names} pick={choice['selected_candidate']} "
            f"{predicted or choice['status']} correct={record['correct']}",
            flush=True,
        )
    ordered = [done[item["id"]] for item in checkpoint]
    summary = {
        "system": "CTA-RAG",
        "fusion": "rank-normalised CombSUM, equal source weights, gold-blind",
        "rerank": "lexical overlap of aliases/malware/tools/campaigns with evidence_query",
        "protocol": "constrained pick from overlap-reranked fused top-k",
        "n": len(ordered),
        "offset": offset,
        "ids": [row["id"] for row in ordered],
        "k": k,
        "model": model,
        "gold_in_top3": sum(row["gold_in_top3"] for row in ordered),
        "llm_correct": sum(row["correct"] for row in ordered),
        "no_match": sum(row["status"] == "NO_MATCH" for row in ordered),
        "input_tokens": sum(row.get("input_tokens") or 0 for row in ordered),
        "output_tokens": sum(row.get("output_tokens") or 0 for row in ordered),
        "items": [
            {
                "id": row["id"],
                "gold": row["gold"],
                "shortlist": row["top3"],
                "predicted": row["predicted_actor"],
                "gold_in_top3": row["gold_in_top3"],
                "correct": row["correct"],
            }
            for row in ordered
        ],
    }
    (out / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
