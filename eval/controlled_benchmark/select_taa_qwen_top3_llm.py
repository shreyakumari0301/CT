"""Ask gpt-4-turbo to choose among the saved Qwen top-3 actors.

One call per report. The prompt contains the evidence query and the three
candidate profiles. It does not contain the gold label. The saved choice is
the prediction, including candidate 2 or 3.
"""
from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
AUDIT = ROOT / "eval_results/controlled_benchmark/full/taa_qwen4b_evidence_query_audit"
OUT = AUDIT / "llm_top3_selection"
PROFILES = ROOT / "eval_results/controlled_benchmark/taa20_20260918/actor_retrieval_study_v2/actor_profiles.json"

from eval.controlled_benchmark.taa_constrained import (  # noqa: E402
    build_selection_prompt,
    candidate_card,
    candidate_k,
    parse_choice,
    resolve_prediction,
)


def load_env() -> None:
    for line in (ROOT / ".env").read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip())


def call_model(api_key: str, model: str, prompt: str) -> dict:
    body = json.dumps({
        "model": model,
        "temperature": 0,
        "max_tokens": 180,
        "response_format": {"type": "json_object"},
        "messages": [{"role": "user", "content": prompt}],
    }).encode("utf-8")
    request = urllib.request.Request(
        "https://api.openai.com/v1/chat/completions",
        data=body,
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        method="POST",
    )
    for attempt in range(4):
        try:
            with urllib.request.urlopen(request, timeout=90) as response:
                payload = json.loads(response.read().decode("utf-8"))
            usage = payload.get("usage") or {}
            return {
                "raw": payload["choices"][0]["message"]["content"],
                "input_tokens": usage.get("prompt_tokens"),
                "output_tokens": usage.get("completion_tokens"),
            }
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:300]
            if exc.code in (429, 500, 502, 503) and attempt < 3:
                time.sleep(2 ** attempt * 3)
                continue
            raise RuntimeError(f"HTTP {exc.code}: {detail}") from exc
    raise RuntimeError("unreachable")


def main() -> None:
    from eval.taa_protocol import benchmark_alias_match

    load_env()
    api_key = os.environ.get("OPENAI_API_KEY", "")
    model = os.environ.get("GENERATION_MODEL", "gpt-4-turbo")
    if not api_key or api_key.startswith("sk-your-key"):
        raise SystemExit("OPENAI_API_KEY is missing from .env")
    OUT.mkdir(parents=True, exist_ok=True)
    cache_path = OUT / "calls.jsonl"
    done = {}
    if cache_path.exists():
        for line in cache_path.read_text(encoding="utf-8").splitlines():
            row = json.loads(line)
            done[row["id"]] = row
    k = candidate_k()
    profiles = {profile["canonical_actor"]: profile for profile in json.loads(PROFILES.read_text(encoding="utf-8"))}
    rows = json.loads((AUDIT / "checkpoint.json").read_text(encoding="utf-8"))
    print(f"[select] k={k} {len(rows) - len(done)} calls to make, {len(done)} cached", flush=True)
    for row in rows:
        if row["id"] in done:
            continue
        names = [entry["actor"] for entry in row["ranking"][:k]]
        cards = [candidate_card(rank, name, profiles[name]) for rank, name in enumerate(names, 1)]
        result = call_model(
            api_key,
            model,
            build_selection_prompt(row["evidence_query"], cards, k),
        )
        choice = parse_choice(result["raw"], k)
        predicted = resolve_prediction(names, choice) or ""
        record = {
            "id": row["id"],
            "gold": row["gold"],
            "top3": names,
            "qwen_rank1": names[0],
            "created_utc": datetime.now(timezone.utc).isoformat(),
            **choice,
            "predicted_actor": predicted,
            "correct": bool(predicted) and benchmark_alias_match(predicted, row["gold"]),
            "qwen_rank1_correct": benchmark_alias_match(names[0], row["gold"]),
            "input_tokens": result["input_tokens"],
            "output_tokens": result["output_tokens"],
        }
        with cache_path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(record) + "\n")
        done[row["id"]] = record
        print(f"[select] {row['id']} candidate {choice['selected_candidate']} {choice['status']}", flush=True)
    ordered = [done[row["id"]] for row in rows]
    summary = {
        "n": len(ordered),
        "model": model,
        "temperature": 0,
        "llm_correct": sum(row["correct"] for row in ordered),
        "qwen_rank1_correct": sum(row["qwen_rank1_correct"] for row in ordered),
        "selected_candidate_2_or_3": sum(row["selected_candidate"] in (2, 3) for row in ordered),
        "no_match": sum(row["status"] == "NO_MATCH" for row in ordered),
        "input_tokens": sum(row.get("input_tokens") or 0 for row in ordered),
        "output_tokens": sum(row.get("output_tokens") or 0 for row in ordered),
    }
    (OUT / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
