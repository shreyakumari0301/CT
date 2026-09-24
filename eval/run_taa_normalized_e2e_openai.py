"""Run normalized CTA/BM25 TAA retrieval followed by OpenAI selection."""
from __future__ import annotations

import argparse
import csv
import json
import os
import re
from pathlib import Path

from dotenv import load_dotenv

from eval.controlled_benchmark.audit_taa_qwen3_union import (
    CTA,
    PROFILES,
    REPORTS,
    SHARED,
    normalized_actor_ranking,
)

ROOT = Path(__file__).resolve().parents[1]
LABELS = ROOT / "eval_results/controlled_benchmark/full/taa_external_protocol/ctibench_frozen_retrieval/ft_idf_rrf_summary.json"
REPORT_FILE = ROOT / "data/cti-taa.tsv"
DEFAULT_OUTPUT = ROOT / "eval_results/controlled_benchmark/full/taa_normalized_e2e_openai"


def profile_document(profile: dict) -> str:
    fields = ("aliases", "malware", "tools", "infrastructure", "target_regions", "target_sectors", "techniques", "campaigns")
    return "\n".join(
        [f"Actor: {profile['canonical_actor']}", profile.get("profile_text", "")]
        + [f"{field}: {', '.join(map(str, profile.get(field, [])))}" for field in fields]
    )


def parse_actor(text: str) -> str | None:
    match = re.search(r"<ThreatActor>\s*(.*?)\s*</ThreatActor>", text or "", re.I | re.S)
    if match:
        return re.sub(r"\s+", " ", match.group(1)).strip() or None
    return None


def selection_prompt(report: str, normalized_ranking: list[dict], profiles_by_name: dict[str, dict]) -> str:
    candidates = []
    for rank, entry in enumerate(normalized_ranking[:20], 1):
        profile = profiles_by_name[entry["actor"]]
        candidates.append(
            f"Candidate {rank}: {entry['actor']}\n"
            f"Normalized score: {entry['score']:.6f}\n"
            f"Evidence channels: {json.dumps(entry['channel_scores'], sort_keys=True)}\n"
            f"Actor profile:\n{profile_document(profile)}"
        )
    return f"""You are a CTI threat-actor attribution analyst.

Select the best-supported actor only from the candidate profiles below. Compare
the original report against explicit profile evidence. Do not choose an actor
because of generic techniques, frequency, or one common malware/tool. Do not
invent evidence. Preserve uncertainty if the report does not distinguish the
candidates, but still return the strongest candidate in the required tag.

Original CTI report:
{report}

Candidates ranked by normalized CTA/BM25 evidence:
{chr(10).join(candidates)}

Return exactly:
<Reasoning>Brief evidence comparison grounded in the report and profiles.</Reasoning>
<ThreatActor>One candidate actor name exactly as listed above.</ThreatActor>
"""


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--n", type=int, default=50)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--no-resume", action="store_true")
    args = parser.parse_args()
    load_dotenv(ROOT / ".env", override=False)
    if not os.getenv("OPENAI_API_KEY"):
        raise SystemExit("OPENAI_API_KEY is not set")

    from openai import OpenAI
    from eval.taa_protocol import benchmark_alias_match

    labels = json.loads(LABELS.read_text(encoding="utf-8"))["rows"][: args.n]
    reports = list(csv.DictReader(REPORT_FILE.open(encoding="utf-8"), delimiter="\t"))[: args.n]
    args.output.mkdir(parents=True, exist_ok=True)
    checkpoint = args.output / "checkpoint.json"
    saved = [] if args.no_resume or not checkpoint.exists() else json.loads(checkpoint.read_text(encoding="utf-8"))
    by_id = {row["id"]: row for row in saved}
    profiles_by_name = {profile["canonical_actor"]: profile for profile in PROFILES}
    client = OpenAI()
    model = os.getenv("GENERATION_MODEL", "gpt-4-turbo")

    for index, (label, report_row, cta_row, bm25_row) in enumerate(zip(labels, reports, CTA, SHARED), 1):
        item_id = label["id"]
        if item_id in by_id and by_id[item_id].get("raw_output"):
            continue
        report = report_row["Text"]
        cta_candidates = cta_row["ranking"][:15]
        bm25_candidates = bm25_row["bm25"][:25]
        pool = list(dict.fromkeys(cta_candidates + bm25_candidates))
        normalized = normalized_actor_ranking(report, pool, cta_candidates, bm25_candidates, PROFILES)
        frozen_pool = [entry["actor"] for entry in normalized[:20]]
        try:
            response = client.chat.completions.create(
                model=model,
                messages=[{"role": "user", "content": selection_prompt(report, normalized, profiles_by_name)}],
                temperature=0,
                max_tokens=900,
            )
            raw_output = response.choices[0].message.content or ""
            error = None
        except Exception as exc:
            raw_output = ""
            error = f"{type(exc).__name__}: {exc}"
        predicted = parse_actor(raw_output)
        by_id[item_id] = {
            "id": item_id,
            "gold": label["gold"],
            "cta_candidates": cta_candidates,
            "bm25_candidates": bm25_candidates,
            "candidate_pool": pool,
            "normalized_ranking": normalized,
            "frozen_candidate_pool": frozen_pool,
            "predicted_actor": predicted,
            "raw_output": raw_output,
            "error": error,
            "model": model,
        }
        checkpoint.write_text(json.dumps(sorted(by_id.values(), key=lambda row: row["id"]), indent=2), encoding="utf-8")
        print(f"completed {index}/{len(labels)} {item_id}", flush=True)

    rows = sorted(by_id.values(), key=lambda row: row["id"])
    complete = [row for row in rows if row.get("predicted_actor")]
    correct = sum(benchmark_alias_match(row["predicted_actor"], row["gold"]) for row in complete)
    retrieval_coverage = sum(any(benchmark_alias_match(actor, row["gold"]) for actor in row["candidate_pool"]) for row in rows) / len(rows)
    frozen_coverage = sum(any(benchmark_alias_match(actor, row["gold"]) for actor in row["frozen_candidate_pool"]) for row in rows) / len(rows)
    summary = {
        "method": "CTA15 + BM2525 normalized seven-channel ranking + OpenAI selection",
        "model": model,
        "n_requested": len(labels),
        "n_completed": len(rows),
        "n_parsed": len(complete),
        "errors": sum(bool(row.get("error")) for row in rows),
        "candidate_pool_coverage": retrieval_coverage,
        "frozen_top20_coverage": frozen_coverage,
        "openai_accuracy": correct / len(rows) if rows else 0.0,
        "canonical_matches": correct,
        "output": "checkpoint.json contains normalized rankings, frozen pools, raw OpenAI outputs, and parsed actors.",
    }
    (args.output / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()