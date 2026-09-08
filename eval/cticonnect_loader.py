"""Load CTIConnect QA records from CTICONNECT data/."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DATA_DIR = ROOT / "CTICONNECT data" / "data"

TASK_CATEGORY = {
    "rcm": "entity_linking",
    "wim": "entity_linking",
    "atd": "entity_linking",
    "esd": "entity_linking",
    "ata": "entity_attribution",
    "vca": "entity_attribution",
}

# Overlap with CTIBench defended tasks
OVERLAP_TASKS = ["rcm", "ata"]


@dataclass(frozen=True)
class QARecord:
    id: str
    task: str
    category: str
    eval_type: str
    question: str
    answer: str
    ground_truth: Dict[str, Any]
    source: Dict[str, Any]

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "QARecord":
        return cls(
            id=d["id"],
            task=d["task"],
            category=d["category"],
            eval_type=d["eval_type"],
            question=d["question"],
            answer=d["answer"],
            ground_truth=dict(d["ground_truth"]),
            source=dict(d.get("source") or {}),
        )


def load_task(
    task: str,
    *,
    data_dir: Optional[Path] = None,
    limit: Optional[int] = None,
) -> List[QARecord]:
    if task not in TASK_CATEGORY:
        raise ValueError(f"Unknown task {task!r}; valid: {sorted(TASK_CATEGORY)}")
    base = Path(data_dir) if data_dir else DEFAULT_DATA_DIR
    path = base / TASK_CATEGORY[task] / f"{task}.jsonl"
    if not path.exists():
        raise FileNotFoundError(f"Missing {path}")
    rows: List[QARecord] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        rows.append(QARecord.from_dict(json.loads(line)))
        if limit and len(rows) >= limit:
            break
    return rows


def load_tasks(
    tasks: List[str],
    *,
    data_dir: Optional[Path] = None,
    limit: Optional[int] = None,
) -> List[QARecord]:
    out: List[QARecord] = []
    for task in tasks:
        out.extend(load_task(task, data_dir=data_dir, limit=limit))
    return out
