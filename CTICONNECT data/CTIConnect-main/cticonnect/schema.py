"""Public dataclasses for QA records and model predictions.

A canonical CTIConnect record on disk is a single JSONL line:

    {
        "id": "rcm-001",
        "task": "rcm",
        "category": "entity_linking",
        "eval_type": "single_id_match",
        "question": "...",
        "answer": "...",                          # reference answer (gold)
        "ground_truth": {...},                    # structured form, used for scoring
        "source": {...}                           # provenance for the record
    }

For leaderboard submission, a prediction is a JSONL line:

    {
        "id": "rcm-001",
        "prediction": "...the model's free-form answer..."
    }
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

__all__ = [
    "QA",
    "GroundTruth",
    "Source",
    "Prediction",
    "read_predictions",
    "write_predictions",
]


@dataclass(frozen=True)
class GroundTruth:
    """Structured ground truth. Fields populated depend on ``eval_type``."""

    target_type: str
    target_id: str | None = None       # for single_id_match (EL): canonical gold
    target_ids: list[str] | None = None  # for id_set_match (EA)
    # Some single_id_match items have a source that authoritatively links to
    # several targets (e.g. one CAPEC maps to multiple ATT&CK techniques, one
    # CWE to multiple CAPECs). Such items list every valid target here; a
    # prediction matching any of them is scored correct (see
    # evaluation/metrics.py). `target_id` stays the canonical gold.
    valid_target_ids: list[str] | None = None
    reference_answer: str | None = None  # for judge (MDS)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "GroundTruth":
        return cls(
            target_type=d["target_type"],
            target_id=d.get("target_id"),
            target_ids=d.get("target_ids"),
            valid_target_ids=d.get("valid_target_ids"),
            reference_answer=d.get("reference_answer"),
        )


@dataclass(frozen=True)
class Source:
    """Provenance for a QA record."""

    source_type: str
    source_id: str | None = None              # for EL/EA (single source)
    blog_ids: list[str] | None = None         # for MDS (cluster)
    aspect: str | None = None                 # MDS analytical aspect
    construction_file: str | None = None      # link back into dataset_generation/

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Source":
        return cls(
            source_type=d["source_type"],
            source_id=d.get("source_id"),
            blog_ids=d.get("blog_ids"),
            aspect=d.get("aspect"),
            construction_file=d.get("construction_file"),
        )


@dataclass(frozen=True)
class QA:
    """A single benchmark QA record."""

    id: str
    task: str
    category: str
    eval_type: str
    question: str
    answer: str
    ground_truth: GroundTruth
    source: Source

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "QA":
        return cls(
            id=d["id"],
            task=d["task"],
            category=d["category"],
            eval_type=d["eval_type"],
            question=d["question"],
            answer=d["answer"],
            ground_truth=GroundTruth.from_dict(d["ground_truth"]),
            source=Source.from_dict(d["source"]),
        )


@dataclass
class Prediction:
    """A model's prediction for a single QA record.

    The leaderboard requires only ``id`` and ``prediction``. Additional fields
    are optional and ignored by the scorer; they are useful for ablation
    studies (e.g., logging retrieved context).
    """

    id: str
    prediction: str
    retrieved_context: list[dict[str, Any]] | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Prediction":
        return cls(
            id=d["id"],
            prediction=d.get("prediction", ""),
            retrieved_context=d.get("retrieved_context"),
            extra={k: v for k, v in d.items()
                   if k not in {"id", "prediction", "retrieved_context"}},
        )

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"id": self.id, "prediction": self.prediction}
        if self.retrieved_context is not None:
            out["retrieved_context"] = self.retrieved_context
        out.update(self.extra)
        return out


def read_predictions(path: str | Path) -> list[Prediction]:
    """Load a JSONL predictions file into ``Prediction`` records."""
    p = Path(path)
    out: list[Prediction] = []
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        out.append(Prediction.from_dict(json.loads(line)))
    return out


def write_predictions(preds: Iterable[Prediction], path: str | Path) -> None:
    """Write ``Prediction`` records to a JSONL file."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", encoding="utf-8") as f:
        for pred in preds:
            f.write(json.dumps(pred.to_dict(), ensure_ascii=False) + "\n")
