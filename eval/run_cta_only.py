#!/usr/bin/env python3
"""Run CTA-RAG only on one dataset/task.

Examples (from repo root, venv active, .env loaded):

  python -m eval.run_cta_only --task rcm --n 50
  python -m eval.run_cta_only --task mcq --n 0          # full split
  python -m eval.run_cta_only --task cticonnect_rcm
  python -m eval.run_cta_only --task ate --oracle       # oracle pipeline (diagnostic)

Tasks: mcq | rcm | vsp | ate | cticonnect_rcm | cticonnect_ata
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

TASK_N = {
    "ate": 60,
    "rcm": 1000,
    "vsp": 1000,
    "mcq": 2500,
    "cticonnect_rcm": 290,
    "cticonnect_ata": 160,
}

CTA_E2E = "cta_rag_original_e2e"
CTA_ORACLE = "cta_rag_oracle"


def main() -> None:
    ap = argparse.ArgumentParser(description="Run CTA-RAG only on one task/dataset")
    ap.add_argument(
        "--task",
        required=True,
        choices=list(TASK_N),
        help="Dataset/task to evaluate (e.g. rcm, mcq, cticonnect_rcm)",
    )
    ap.add_argument(
        "--n",
        type=int,
        default=0,
        help="Number of items (0 = full split for that task)",
    )
    ap.add_argument("--model", default=os.getenv("CONTROLLED_MODEL") or "gpt-4-turbo")
    ap.add_argument("--k", type=int, default=5)
    ap.add_argument("--budget-usd", type=float, default=900.0)
    ap.add_argument(
        "--oracle",
        action="store_true",
        help="Use oracle pipeline selection (diagnostic), not end-to-end router",
    )
    ap.add_argument("--no-resume", action="store_true")
    args = ap.parse_args()

    n = TASK_N[args.task] if args.n <= 0 else args.n
    system = CTA_ORACLE if args.oracle else CTA_E2E

    env = os.environ.copy()
    env.setdefault("PYTHONPATH", str(ROOT))
    env.setdefault("PYTHONUNBUFFERED", "1")
    env.setdefault("USE_OPENROUTER", "0")
    env.setdefault("CONTROLLED_TEMPERATURE", "0")
    env.setdefault("CONTROLLED_TOP_P", "1")
    env.setdefault("CONTROLLED_AUTO_STAR_SKIP", "1")
    env.setdefault("CONTROLLED_PARSE_FLOOR", "0.98")
    env.setdefault("CONTROLLED_MODEL", args.model)
    env.setdefault("GENERATION_MODEL", args.model)

    cmd = [
        sys.executable,
        "-u",
        str(ROOT / "tcar/eval/controlled_benchmark/run_controlled_staged.py"),
        "--task-worker",
        "--task",
        args.task,
        "--n",
        str(n),
        "--systems",
        system,
        "--model",
        args.model,
        "--k",
        str(args.k),
        "--budget-usd",
        str(args.budget_usd),
    ]
    if args.no_resume:
        cmd.append("--no-resume")

    print(f"[run_cta_only] task={args.task} n={n} system={system} model={args.model}", flush=True)
    raise SystemExit(subprocess.call(cmd, cwd=str(ROOT), env=env))


if __name__ == "__main__":
    main()
