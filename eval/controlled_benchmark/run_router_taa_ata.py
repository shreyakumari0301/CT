"""Router-only diagnostic for TAA (n=50) and ATA (n=160). No generation."""
from __future__ import annotations

import csv
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from classifier.llm_classifier import classify_query_debug  # noqa: E402
from eval.cticonnect_loader import load_task  # noqa: E402

TAA_PATH = ROOT / "data" / "cti-taa.tsv"
TAA_INSTRUCTION = (
    "Attribute the anonymized threat report to one threat actor."
)
ATE_INSTRUCTION = (
    "Extract all MITRE ATT&CK technique IDs from the threat description. "
    "Return main technique IDs only (no subtechniques)."
)
OUT = ROOT / "eval_results" / "controlled_benchmark" / "full" / "router_taa_ata"
GOLD = {"taa": "reasoning_taa", "ata": "reasoning_ata", "ate": "reasoning_ate"}


def _summarise(rows: list[dict], gold: str) -> dict:
    n = len(rows)
    correct = sum(1 for row in rows if row["label"] == gold)
    paths = Counter(row["path"] for row in rows)
    labels = Counter(row["label"] for row in rows)
    return {
        "n": n,
        "gold": gold,
        "correct": correct,
        "accuracy": round(correct / n, 4) if n else 0.0,
        "paths": dict(paths),
        "predicted": dict(labels),
        "errors": [row for row in rows if row["label"] != gold][:20],
    }


def route_taa() -> list[dict]:
    rows_out: list[dict] = []
    with TAA_PATH.open(encoding="utf-8", errors="replace", newline="") as handle:
        reader = list(csv.DictReader(handle, delimiter="\t"))
    for index, row in enumerate(reader[:50]):
        task, context = TAA_INSTRUCTION, (row.get("Text") or "")[:8000]
        debug = classify_query_debug(task, context)
        rows_out.append({"id": f"taa-{index}", **debug, "gold": GOLD["taa"]})
    return rows_out


def route_ata() -> list[dict]:
    rows_out: list[dict] = []
    for qa in load_task("ata", limit=160):
        debug = classify_query_debug("", qa.question)
        rows_out.append({"id": qa.id, **debug, "gold": GOLD["ata"]})
    return rows_out


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    taa = route_taa()
    ata = route_ata()
    summary = {
        "taa": _summarise(taa, GOLD["taa"]),
        "ata": _summarise(ata, GOLD["ata"]),
        "note": (
            "Router-only. TAA uses the Prompt/instruction plus report text. "
            "ATA uses the CTIConnect question. No answer generation."
        ),
    }
    (OUT / "taa.json").write_text(json.dumps(taa, indent=2), encoding="utf-8")
    (OUT / "ata.json").write_text(json.dumps(ata, indent=2), encoding="utf-8")
    (OUT / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
