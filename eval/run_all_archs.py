#!/usr/bin/env python3
"""Run all main-table architectures on one dataset/task.

Use this when you want a head-to-head for a single dataset, e.g. RCM:

  python -m eval.run_all_archs --task rcm --n 50
  python -m eval.run_all_archs --task rcm              # full 1000
  python -m eval.run_all_archs --task mcq --n 100
  python -m eval.run_all_archs --task cticonnect_rcm

Systems (default main table):
  closed_book, unified_rag, self_rag_inspired, graphrag_local,
  adaptive_rag_adapted, tadarag_inspired, cta_rag_original_e2e

Omit CTA with --no-cta; omit Closed Book with --rag-only.
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

MAIN_SYSTEMS = [
    "closed_book",
    "unified_rag",
    "self_rag_inspired",
    "graphrag_local",
    "adaptive_rag_adapted",
    "tadarag_inspired",
    "cta_rag_original_e2e",
]


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Run all architectures on one task/dataset (controlled protocol)"
    )
    ap.add_argument(
        "--task",
        required=True,
        choices=list(TASK_N),
        help="Dataset/task (e.g. rcm for CTIBench RCM)",
    )
    ap.add_argument(
        "--n",
        type=int,
        default=0,
        help="Number of items (0 = full split)",
    )
    ap.add_argument("--model", default=os.getenv("CONTROLLED_MODEL") or "gpt-4-turbo")
    ap.add_argument("--k", type=int, default=5)
    ap.add_argument("--budget-usd", type=float, default=900.0)
    ap.add_argument(
        "--systems",
        default=None,
        help="Comma-separated override (default: full main table)",
    )
    ap.add_argument("--no-cta", action="store_true", help="Drop CTA-E2E from the list")
    ap.add_argument("--rag-only", action="store_true", help="Drop closed_book")
    ap.add_argument("--no-resume", action="store_true")
    args = ap.parse_args()

    n = TASK_N[args.task] if args.n <= 0 else args.n
    if args.systems:
        systems = [s.strip() for s in args.systems.split(",") if s.strip()]
    else:
        systems = list(MAIN_SYSTEMS)
        if args.no_cta:
            systems = [s for s in systems if s != "cta_rag_original_e2e"]
        if args.rag_only:
            systems = [s for s in systems if s != "closed_book"]

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
        ",".join(systems),
        "--model",
        args.model,
        "--k",
        str(args.k),
        "--budget-usd",
        str(args.budget_usd),
    ]
    if args.no_resume:
        cmd.append("--no-resume")

    print(
        f"[run_all_archs] task={args.task} n={n} systems={','.join(systems)} "
        f"model={args.model}",
        flush=True,
    )
    raise SystemExit(subprocess.call(cmd, cwd=str(ROOT), env=env))


if __name__ == "__main__":
    main()
