#!/usr/bin/env python3
"""Vanilla RAG baseline: embed the raw query, retrieve top-k from the target
knowledge base, answer conditioned on the retrieved candidates.

Isolates the contribution of retrieval itself (CB -> VR). Applies to Entity
Linking and Entity Attribution.

    python -m baselines.vanilla_rag.run --out preds_vr.jsonl --tasks rcm --limit 5
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

SYSTEM = ("You are a Cyber Threat Intelligence expert. Use the retrieved "
          "knowledge-base candidates to answer. State the exact identifier "
          "(CWE-/CVE-/CAPEC-/T-) explicitly in your answer.")

PROMPT = """Question:
{question}

Retrieved knowledge-base candidates:
{candidates}

Based on the candidates above, answer the question. Cite the single best-matching
identifier explicitly."""


def predict(qa, ctx) -> str:
    hits = ctx["retriever"].retrieve_for_task(qa.question, qa.task, k=ctx["k"])
    prompt = PROMPT.format(question=qa.question,
                           candidates=format_candidates(hits))
    return ctx["llm"].chat(prompt, system=SYSTEM, max_tokens=512)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Vanilla RAG baseline")
    baseline_cli.add_common_args(ap)
    args = ap.parse_args(argv)
    ctx = {
        "llm": ChatLLM(model=args.model) if args.model else ChatLLM(),
        "retriever": KBRetriever(),
        "k": args.top_k,
    }
    baseline_cli.run(predict, args, ctx)


if __name__ == "__main__":
    main()
