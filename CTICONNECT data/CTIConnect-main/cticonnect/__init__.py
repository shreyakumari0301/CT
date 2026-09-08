"""CTIConnect: a benchmark for retrieval-augmented LLMs over heterogeneous CTI."""

from cticonnect._version import __version__
from cticonnect.loader import (
    list_tasks,
    list_categories,
    load_task,
    load_category,
    load_all,
    get_manifest,
    DATA_DIR,
)
from cticonnect.schema import QA, GroundTruth, Source, Prediction, read_predictions, write_predictions

__all__ = [
    "__version__",
    "list_tasks",
    "list_categories",
    "load_task",
    "load_category",
    "load_all",
    "get_manifest",
    "DATA_DIR",
    "QA",
    "GroundTruth",
    "Source",
    "Prediction",
    "read_predictions",
    "write_predictions",
]
