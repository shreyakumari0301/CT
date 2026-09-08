"""Quick import / prompt-mode smoke test for specialist plan."""
from __future__ import annotations

import os

from tcar.pipeline_prompts import build_ate_prompt
from tcar.specialist_retrieval import ate_prompt_mode


def main() -> None:
    print("default_mode", ate_prompt_mode())
    p = build_ate_prompt(description="x", similar_context="y")
    print("default_has_PRIMARY", "PRIMARY" in p)
    os.environ["ATE_PROMPT"] = "cta"
    # rebuild path reads env at call time via ate_prompt_mode
    from importlib import reload

    import tcar.pipeline_prompts as pp
    import tcar.specialist_retrieval as sr

    reload(sr)
    reload(pp)
    p2 = pp.build_ate_prompt(description="x", similar_context="y")
    print("cta_mode", sr.ate_prompt_mode())
    print("cta_has_Relevant", "Relevant context" in p2)
    print("imports_ok")


if __name__ == "__main__":
    main()
