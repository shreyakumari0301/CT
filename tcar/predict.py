"""Thin adapter for CTIConnect-style eval (no changes to existing predictors)."""

from __future__ import annotations

from typing import Any, Callable, Dict, Optional

from eval.cticonnect_loader import QARecord

from tcar.config import TCARConfig
from tcar.pipeline import TCARPipeline

_PIPELINES: Dict[str, TCARPipeline] = {}


def get_pipeline(variant: str = "full", cfg: Optional[TCARConfig] = None) -> TCARPipeline:
    key = variant
    if key not in _PIPELINES:
        base = cfg or TCARConfig()
        base.variant = variant
        _PIPELINES[key] = TCARPipeline(base)
    return _PIPELINES[key]


def predict(
    qa: QARecord,
    ctx: Dict[str, Any],
    *,
    variant: str = "full",
    chat: Optional[Callable[..., str]] = None,
) -> str:
    """Return model text for scoring by eval/cticonnect_metrics."""
    pipe = get_pipeline(variant)
    if ctx.get("cti_kb") and pipe.retriever is not ctx["cti_kb"]:
        pipe.retriever = ctx["cti_kb"]
    chat_fn = chat or ctx.get("chat")
    result = pipe.predict(
        qa.task,
        qa.question,
        chat=chat_fn,
        ground_truth=qa.ground_truth,
    )
    # stash meta on ctx for optional logging (per-thread unsafe; eval uses jsonl only)
    ctx.setdefault("_tcar_meta", {})[qa.id] = result.meta
    return result.prediction


def predict_with_meta(
    qa: QARecord,
    ctx: Dict[str, Any],
    *,
    variant: str = "full",
) -> tuple[str, dict]:
    pipe = get_pipeline(variant)
    if ctx.get("cti_kb"):
        pipe.retriever = ctx["cti_kb"]
    chat_fn = ctx.get("chat")
    result = pipe.predict(
        qa.task,
        qa.question,
        chat=chat_fn,
        ground_truth=qa.ground_truth,
    )
    return result.prediction, result.meta
