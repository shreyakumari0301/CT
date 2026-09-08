"""CTIConnect evaluation harness.

Public API:

    from evaluation import score_predictions, normalize_id, extract_ids

`score_predictions` takes a list of model predictions and the gold QA records
and returns per-task and aggregate metrics, routing by `eval_type`:

  - single_id_match (Entity Linking)   -> identifier P/R/F1
  - id_set_match    (Entity Attribution) -> identifier-set P/R/F1
  - judge           (Multi-Doc Synthesis) -> requires the LLM judge (see judge/)
"""

from evaluation.metrics import (
    normalize_id,
    extract_ids,
    prf1,
    score_id_item,
    aggregate_scores,
    score_predictions,
    ID_PATTERNS,
)

__all__ = [
    "normalize_id",
    "extract_ids",
    "prf1",
    "score_id_item",
    "aggregate_scores",
    "score_predictions",
    "ID_PATTERNS",
]
