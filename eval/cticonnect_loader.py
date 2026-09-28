"""Load CTIConnect QA records."""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parent.parent
_DATA_CANDIDATES = (
    ROOT / "CTICONNECT data" / "data",
    ROOT / "CTICONNECT data" / "CTIConnect-main" / "data",
)

TASK_CATEGORY = {
    "rcm": "entity_linking",
    "wim": "entity_linking",
    "atd": "entity_linking",
    "esd": "entity_linking",
    "ata": "entity_attribution",
    "vca": "entity_attribution",
}


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


def _data_dir(data_dir: Optional[Path] = None) -> Path:
    if data_dir is not None:
        return Path(data_dir)
    for candidate in _DATA_CANDIDATES:
        if (candidate / "entity_attribution" / "ata.jsonl").exists():
            return candidate
    return _DATA_CANDIDATES[0]


def load_task(
    task: str,
    *,
    data_dir: Optional[Path] = None,
    limit: Optional[int] = None,
) -> List[QARecord]:
    if task not in TASK_CATEGORY:
        raise ValueError(f"Unknown task {task!r}; valid: {sorted(TASK_CATEGORY)}")
    path = _data_dir(data_dir) / TASK_CATEGORY[task] / f"{task}.jsonl"
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
