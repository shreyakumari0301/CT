"""Claim-level LLM judge for Multi-Doc Synthesis (CSC / TAP / MLA).

Free-form synthesis answers cannot be graded by identifier matching. Following
the paper (App. eval_judge), we use an LLM to decompose both the reference and
predicted answers into atomic claims, match them pairwise, and report counts —
then we compute Precision / Recall / F1 in code (so the arithmetic is
verifiable and not left to the model).

    Precision = n_matched / n_prediction_claims   (are the model's claims correct?)
    Recall    = n_matched / n_reference_claims     (did the model cover the gold?)

The judge LLM defaults to the same OpenAI-backed client used by the baselines
(`baselines.ctinexus_lite.llm.LLMClient`), so the only dependency is an
`OPENAI_API_KEY`. The model is configurable via `CTICONNECT_JUDGE_MODEL`
(default falls back to the client default).
"""

from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass
from pathlib import Path

PROMPT_PATH = Path(__file__).parent / "mds_rubric.jinja"


@dataclass
class JudgeResult:
    id: str
    task: str
    precision: float
    recall: float
    f1: float
    n_reference_claims: int
    n_prediction_claims: int
    n_matched: int


def claim_prf1(n_ref: int, n_pred: int, n_matched: int) -> tuple[float, float, float]:
    """Precision / Recall / F1 from claim counts.

    n_matched is clamped to <= min(n_ref, n_pred) defensively (the judge does
    one-to-one matching, but we guard against an over-eager response).
    """
    n_matched = max(0, min(n_matched, n_ref, n_pred))
    if n_ref == 0 and n_pred == 0:
        return 1.0, 1.0, 1.0
    precision = n_matched / n_pred if n_pred else 0.0
    recall = n_matched / n_ref if n_ref else 0.0
    f1 = (2 * precision * recall / (precision + recall)
          if (precision + recall) > 0 else 0.0)
    return precision, recall, f1


def _render_prompt(question: str, reference: str, prediction: str) -> str:
    tmpl = PROMPT_PATH.read_text(encoding="utf-8")
    return (tmpl
            .replace("{{ QUESTION }}", question or "")
            .replace("{{ REFERENCE }}", reference or "")
            .replace("{{ PREDICTION }}", prediction or ""))


async def judge_one(question: str, reference: str, prediction: str,
                    *, llm=None, item_id: str = "", task: str = "") -> JudgeResult:
    """Judge a single (reference, prediction) pair."""
    if llm is None:
        from baselines.ctinexus_lite.llm import LLMClient
        model = os.environ.get("CTICONNECT_JUDGE_MODEL", "gpt-4o")
        llm = LLMClient(model=model)

    # Empty prediction -> zero credit without an API call.
    if not prediction or not prediction.strip():
        return JudgeResult(item_id, task, 0.0, 0.0, 0.0, 0, 0, 0)

    prompt = _render_prompt(question, reference, prediction)
    obj, _ = await llm.aask_json(prompt, max_tokens=4000)

    n_ref = int(obj.get("n_reference_claims")
                or len(obj.get("reference_claims", []) or []))
    n_pred = int(obj.get("n_prediction_claims")
                 or len(obj.get("prediction_claims", []) or []))
    n_match = int(obj.get("n_matched")
                  or len(obj.get("matched_pairs", []) or []))
    p, r, f1 = claim_prf1(n_ref, n_pred, n_match)
    return JudgeResult(item_id, task, p, r, f1, n_ref, n_pred, n_match)


def judge_mds_items(predictions: dict[str, str], qa_records: list, *,
                    only_ids: set[str] | None = None,
                    concurrency: int = 8) -> dict:
    """Judge all Multi-Doc Synthesis items and aggregate claim-level P/R/F1."""
    from baselines.ctinexus_lite.llm import LLMClient, gather_bounded
    model = os.environ.get("CTICONNECT_JUDGE_MODEL", "gpt-4o")
    llm = LLMClient(model=model)

    targets = [qa for qa in qa_records
               if qa.eval_type == "judge"
               and (only_ids is None or qa.id in only_ids)]

    async def _run():
        coros = []
        for qa in targets:
            gt = qa.ground_truth
            ref = (gt.get("reference_answer") if isinstance(gt, dict)
                   else gt.reference_answer) or qa.answer
            pred = predictions.get(qa.id, "")
            coros.append(judge_one(qa.question, ref, pred,
                                   llm=llm, item_id=qa.id, task=qa.task))
        return await gather_bounded(coros, concurrency=concurrency)

    results: list[JudgeResult] = asyncio.run(_run())

    def _mean(xs):
        return sum(xs) / len(xs) if xs else 0.0

    by_task: dict[str, list[JudgeResult]] = {}
    for r in results:
        by_task.setdefault(r.task, []).append(r)
    per_task = {}
    for task, rs in sorted(by_task.items()):
        per_task[task] = {
            "n": len(rs),
            "precision": _mean([x.precision for x in rs]),
            "recall": _mean([x.recall for x in rs]),
            "f1": _mean([x.f1 for x in rs]),
        }
    overall = {
        "n": len(results),
        "precision": _mean([x.precision for x in results]),
        "recall": _mean([x.recall for x in results]),
        "f1": _mean([x.f1 for x in results]),
    }
    return {"overall": overall, "per_task": per_task}
