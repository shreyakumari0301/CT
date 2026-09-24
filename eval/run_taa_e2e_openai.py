"""Run the existing reasoning_taa specialist end to end on 50 TAA reports."""
from __future__ import annotations

import argparse
import csv
import json
import os
import re
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[1]
OUTPUT_DEFAULT = ROOT / "eval_results/controlled_benchmark/full/taa_reasoning_e2e_openai"
LABELS = ROOT / "eval_results/controlled_benchmark/full/taa_external_protocol/ctibench_frozen_retrieval/ft_idf_rrf_summary.json"
REPORTS = ROOT / "data/cti-taa.tsv"


def parse_actor(text: str) -> str | None:
    match = re.search(r"<ThreatActor>\s*(.*?)\s*</ThreatActor>", text or "", re.I | re.S)
    if match:
        return re.sub(r"\s+", " ", match.group(1)).strip() or None
    return None


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--n", type=int, default=50)
    parser.add_argument("--output", type=Path, default=OUTPUT_DEFAULT)
    parser.add_argument("--no-resume", action="store_true")
    args = parser.parse_args()
    load_dotenv(ROOT / ".env", override=False)
    if not os.getenv("OPENAI_API_KEY"):
        raise SystemExit("OPENAI_API_KEY is not set")

    from eval.taa_protocol import benchmark_alias_match
    from pipelines.reasoning_taa_pipeline import ReasoningTAAPipeline

    labels = json.loads(LABELS.read_text(encoding="utf-8"))["rows"][: args.n]
    reports = list(csv.DictReader(REPORTS.open(encoding="utf-8"), delimiter="\t"))[: args.n]
    args.output.mkdir(parents=True, exist_ok=True)
    checkpoint = args.output / "checkpoint.json"
    saved = [] if args.no_resume or not checkpoint.exists() else json.loads(checkpoint.read_text(encoding="utf-8"))
    by_id = {row["id"]: row for row in saved}
    pipeline = ReasoningTAAPipeline()
    for index, (label, report) in enumerate(zip(labels, reports)):
        item_id = label["id"]
        if item_id in by_id and by_id[item_id].get("raw_output"):
            continue
        try:
            raw_output = pipeline.run(report["Text"])
            error = None
        except Exception as exc:  # Preserve the case and continue resumably.
            raw_output = ""
            error = f"{type(exc).__name__}: {exc}"
        predicted = parse_actor(raw_output)
        by_id[item_id] = {
            "id": item_id,
            "gold": label["gold"],
            "predicted_actor": predicted,
            "raw_output": raw_output,
            "error": error,
            "model": os.getenv("GENERATION_MODEL", "gpt-4-turbo"),
        }
        checkpoint.write_text(json.dumps(sorted(by_id.values(), key=lambda row: row["id"]), indent=2), encoding="utf-8")
        print(f"completed {index + 1}/{len(labels)} {item_id}", flush=True)

    rows = sorted(by_id.values(), key=lambda row: row["id"])
    valid = [row for row in rows if row.get("predicted_actor")]
    ranks = [
        next((position for position, row in enumerate(valid, 1) if benchmark_alias_match(row["predicted_actor"], row["gold"])), None)
    ]
    correct = sum(benchmark_alias_match(row["predicted_actor"], row["gold"]) for row in valid)
    summary = {
        "method": "existing reasoning_taa specialist with OpenAI generation",
        "model": os.getenv("GENERATION_MODEL", "gpt-4-turbo"),
        "n_requested": len(labels),
        "n_completed": len(rows),
        "n_parsed": len(valid),
        "errors": sum(bool(row.get("error")) for row in rows),
        "accuracy": correct / len(rows) if rows else 0.0,
        "canonical_matches": correct,
        "output": "checkpoint.json contains each report, raw output, parsed actor, and error.",
    }
    (args.output / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()