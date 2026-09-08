#!/usr/bin/env python3
"""Decompose-then-Retrieve (DtR) — domain-specific strategy for Entity
Attribution.

Three stages (paper App. ds_details):
  1. Decompose the input passage into atomic behaviors.
  2. Retrieve top-k candidates per behavior from the target taxonomy.
  3. Validate each behavior-candidate pairing and aggregate the surviving
     identifiers into the final answer set.

    python -m baselines.dtr.run --out preds_dtr.jsonl --tasks ata vca --limit 5
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from baselines._shared import baseline_cli  # noqa: E402
from baselines._shared.llm import ChatLLM  # noqa: E402
from baselines._shared.retriever import KBRetriever, format_candidates  # noqa: E402

DECOMPOSE_PROMPT = """You are a CTI analyst. Decompose the security report
passage in the question below into its distinct atomic behaviors (each a single
actionable security event). Output one behavior per line, no numbering, 2-5
behaviors total. Do not answer the question.

{question}

Atomic behaviors:"""

VALIDATE_SYSTEM = ("You are a CTI expert mapping report behaviors to taxonomy "
                   "entries. Use only the retrieved candidates. State the exact "
                   "identifier(s) (CWE-/T-) explicitly.")

VALIDATE_PROMPT = """Original question:
{question}

For each atomic behavior below, the most similar taxonomy candidates were
retrieved. Select the single best-matching identifier per behavior (or none if
no candidate fits), then present the final consolidated answer to the original
question with all selected identifiers stated explicitly.

{behavior_blocks}"""


def predict(qa, ctx) -> str:
    llm = ctx["llm"]
    # Stage 1: decompose.
    raw = llm.chat(DECOMPOSE_PROMPT.format(question=qa.question), max_tokens=256)
    behaviors = [b.strip("-* \t") for b in raw.splitlines() if b.strip()][:5]
    if not behaviors:
        behaviors = [qa.question]

    # Stage 2: retrieve per behavior.
    blocks = []
    for b in behaviors:
        hits = ctx["retriever"].retrieve_for_task(b, qa.task, k=ctx["k"])
        blocks.append(f"Behavior: {b}\nCandidates:\n{format_candidates(hits, max_chars=300)}")
    behavior_blocks = "\n\n---\n\n".join(blocks)

    # Stage 3: validate + aggregate.
    prompt = VALIDATE_PROMPT.format(question=qa.question, behavior_blocks=behavior_blocks)
    return llm.chat(prompt, system=VALIDATE_SYSTEM, max_tokens=700)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Decompose-then-Retrieve (Entity Attribution)")
    baseline_cli.add_common_args(ap)
    args = ap.parse_args(argv)
    # DtR targets EA tasks by default.
    if args.tasks == baseline_cli.ID_TASKS:
        args.tasks = ["ata", "vca"]
    ctx = {
        "llm": ChatLLM(model=args.model) if args.model else ChatLLM(),
        "retriever": KBRetriever(),
        "k": args.top_k,
    }
    baseline_cli.run(predict, args, ctx)


if __name__ == "__main__":
    main()
