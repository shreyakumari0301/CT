#!/usr/bin/env python3
"""Start RCM hybrid turbo n=200 only if offline shortlist quality clears strengthened gate.

Requires:
  hybrid / RRF Recall@20 >= 60%
  hybrid→taxonomy Recall@5  > 45.5%
"""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
AUDIT = ROOT / "tcar/eval_results/rcm_hybrid_offline_audit.json"
LOG = ROOT / "tcar/eval_results/logs/rcm_hybrid_turbo_n200.log"

MIN_HYBRID_R20 = 0.60
MIN_TAX5 = 0.455


def main() -> None:
    if not AUDIT.exists():
        print("no offline audit; skip pilot")
        return
    s = json.loads(AUDIT.read_text(encoding="utf-8"))
    stages = s.get("stages") or {}
    g20 = float(stages.get("rrf_recall@20") or s.get("hybrid_gold@20") or 0)
    tax5 = float(
        stages.get("hybrid_then_taxonomy_recall@5")
        or s.get("hybrid_then_taxonomy_gold@5")
        or 0
    )
    union20 = float(stages.get("dense_union_bm25_recall@20") or s.get("union_gold@20") or 0)
    lost = float(s.get("gold_in_union_lost_by_rrf_rate") or 0)
    print(
        f"dense∪bm25@20={union20:.3f} rrf/hybrid@20={g20:.3f} "
        f"hyb_tax@5={tax5:.3f} union_lost_rrf={lost:.3f}"
    )
    print(f"gate: hybrid@20>={MIN_HYBRID_R20} and tax@5>{MIN_TAX5}")

    if g20 < MIN_HYBRID_R20:
        print(f"SKIP RCM pilot: hybrid/RRF@20={g20:.3f} < {MIN_HYBRID_R20}")
        return
    if tax5 <= MIN_TAX5:
        print(f"SKIP RCM pilot: taxonomy@5={tax5:.3f} does not exceed {MIN_TAX5}")
        return
    # Soft warning only — RRF should not wipe the union ceiling
    if union20 - g20 > 0.05:
        print(
            f"WARN: RRF drops {union20-g20:.1%} absolute vs union ceiling; "
            "pilot still allowed because shortlist tax@5 cleared."
        )

    print("START RCM hybrid turbo n=200 (strengthened gate passed)")
    env = os.environ.copy()
    env.update(
        {
            "RCM_GAD": "off",
            "RCM_PIPELINE": "hybrid",
            "RCM_RERANK": "taxonomy",
            "RCM_PROMPT": "soft",
            "RCM_DIVERSIFY": "0",
            "RCM_TOP_K": "3",
            "RCM_POOL": "20",
            "RCM_CWE_RETRIEVAL": "on",
            "GAD_MODE": "off",
            "GENERATION_MODEL": "gpt-4-turbo",
            "MODEL": "gpt-4-turbo",
            "USE_OPENROUTER": "0",
        }
    )
    LOG.parent.mkdir(parents=True, exist_ok=True)
    with LOG.open("w", encoding="utf-8") as log:
        subprocess.Popen(
            [
                "bash",
                "-lc",
                "cd /mnt/c/Users/SK/CTI-Chatbot && source .venv/bin/activate && "
                "PYTHONPATH=. python -m tcar.eval.run_counterfactual "
                "--benchmark ctibench --tasks rcm --limit 200 --workers 1 "
                "--model gpt-4-turbo --variant no_confusion "
                "--stamp 20260908Tturbo_rcm_hybrid_n200",
            ],
            env=env,
            stdout=log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    print(f"RCM pilot log -> {LOG}")


if __name__ == "__main__":
    main()
