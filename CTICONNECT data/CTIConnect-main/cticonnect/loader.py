"""Data-loading API for the CTIConnect benchmark.

Typical usage:

    from cticonnect import load_task, list_tasks
    qa_list = load_task("rcm")
    print(qa_list[0].question)
    print(qa_list[0].ground_truth.target_id)

Tasks are organised into three categories:

    - entity_linking:        rcm, wim, atd, esd
    - entity_attribution:    ata, vca
    - multi_doc_synthesis:   csc, tap, mla

For batch evaluation, ``load_all()`` returns ``{task_name: [QA, ...]}``.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

from cticonnect.schema import QA

# Default data directory: the ``data/`` folder shipped with the release.
# Override with the ``CTICONNECT_DATA_DIR`` env var or by passing ``data_dir=``
# explicitly to any loader.
DATA_DIR: Path = Path(__file__).resolve().parent.parent / "data"

_CATEGORIES = {
    "entity_linking":      ["rcm", "wim", "atd", "esd"],
    "entity_attribution":  ["ata", "vca"],
    "multi_doc_synthesis": ["csc", "tap", "mla"],
}

# Reverse index: task -> category. Built once.
_TASK_CATEGORY = {t: c for c, ts in _CATEGORIES.items() for t in ts}


def _resolve_data_dir(data_dir: str | Path | None) -> Path:
    import os
    if data_dir is not None:
        return Path(data_dir)
    env = os.environ.get("CTICONNECT_DATA_DIR")
    if env:
        return Path(env)
    return DATA_DIR


def list_tasks() -> list[str]:
    """All nine task names in canonical order."""
    return [t for ts in _CATEGORIES.values() for t in ts]


def list_categories() -> list[str]:
    """The three task categories."""
    return list(_CATEGORIES)


@lru_cache(maxsize=16)
def _load_jsonl(path: Path) -> tuple[QA, ...]:
    if not path.exists():
        raise FileNotFoundError(
            f"CTIConnect data file not found: {path}. "
            "Did you run `python scripts/build_release.py`?"
        )
    records: list[QA] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        records.append(QA.from_dict(json.loads(line)))
    return tuple(records)


def load_task(task: str, *, data_dir: str | Path | None = None) -> list[QA]:
    """Load the QA records for one task.

    Parameters
    ----------
    task : one of ``list_tasks()``
    data_dir : optional override of the default ``data/`` directory.
    """
    if task not in _TASK_CATEGORY:
        raise ValueError(
            f"Unknown task {task!r}. Valid: {', '.join(list_tasks())}."
        )
    base = _resolve_data_dir(data_dir)
    category = _TASK_CATEGORY[task]
    return list(_load_jsonl(base / category / f"{task}.jsonl"))


def load_category(category: str, *, data_dir: str | Path | None = None) -> dict[str, list[QA]]:
    """Load all tasks in a category, returning ``{task: [QA, ...]}``."""
    if category not in _CATEGORIES:
        raise ValueError(
            f"Unknown category {category!r}. Valid: {', '.join(list_categories())}."
        )
    return {t: load_task(t, data_dir=data_dir) for t in _CATEGORIES[category]}


def load_all(*, data_dir: str | Path | None = None) -> dict[str, list[QA]]:
    """Load every task. Returns ``{task: [QA, ...]}`` for all 9 tasks."""
    return {t: load_task(t, data_dir=data_dir) for t in list_tasks()}


def get_manifest(*, data_dir: str | Path | None = None) -> dict:
    """Return the parsed ``data/manifest.json`` (release version, counts, SHAs)."""
    base = _resolve_data_dir(data_dir)
    return json.loads((base / "manifest.json").read_text(encoding="utf-8"))
