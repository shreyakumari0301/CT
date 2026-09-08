#!/usr/bin/env python3
"""Closed-Book baseline: answer from parametric knowledge only, no retrieval.

This is the performance floor — it measures how much CTI knowledge the model
encoded during pretraining. Applies to Entity Linking and Entity Attribution
(Multi-Doc Synthesis inherently requires retrieval and is handled by
cskg_guided).

    python -m baselines.closed_book.run --out preds_cb.jsonl --tasks rcm --limit 5
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

SYSTEM = ("You are a Cyber Threat Intelligence expert. Answer the question "
          "directly and concisely. When the question asks for a CWE, CVE, "
          "CAPEC, or MITRE ATT&CK identifier, state the exact identifier "
          "(e.g., CWE-79, T1059.001) explicitly in your answer.")


def predict(qa, ctx) -> str:
    return ctx["llm"].chat(qa.question, system=SYSTEM, max_tokens=512)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Closed-Book baseline")
    baseline_cli.add_common_args(ap)
    args = ap.parse_args(argv)
    ctx = {"llm": ChatLLM(model=args.model) if args.model else ChatLLM()}
    baseline_cli.run(predict, args, ctx)


if __name__ == "__main__":
    main()
