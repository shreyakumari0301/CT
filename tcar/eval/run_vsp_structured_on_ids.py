#!/usr/bin/env python3
"""Run VSP structured decoder CF on the same IDs as sol metric_wise successes (n≈75)."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "tcar/eval_results/counterfactual_ctibench_vsp_20260907Tsol_vsp_metric_wise.jsonl"
STAMP = "20260908Tturbo_vsp_structured_n75"
IDS_FILE = ROOT / "tcar/eval_results/_vsp_structured_pilot_ids.txt"


def main() -> None:
    ids: list[str] = []
    if SRC.exists():
        for line in SRC.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            r = json.loads(line)
            if r.get("error"):
                continue
            ids.append(r["id"])
    IDS_FILE.parent.mkdir(parents=True, exist_ok=True)
    IDS_FILE.write_text("\n".join(ids) + ("\n" if ids else ""))
    print(f"pilot ids: {len(ids)} -> {IDS_FILE}")

    env = os.environ.copy()
    env.update(
        {
            "GAD_MODE": "off",
            "VSP_RETRIEVAL": "structured",
            "GENERATION_MODEL": "gpt-4-turbo",
            "MODEL": "gpt-4-turbo",
            "USE_OPENROUTER": "0",
        }
    )
    cmd = [
        sys.executable,
        "-m",
        "tcar.eval.run_counterfactual",
        "--benchmark",
        "ctibench",
        "--tasks",
        "vsp",
        "--workers",
        "1",
        "--model",
        "gpt-4-turbo",
        "--variant",
        "no_confusion",
        "--stamp",
        STAMP,
    ]
    if ids:
        cmd.extend(["--ids-file", str(IDS_FILE), "--limit", "0"])
    else:
        cmd.extend(["--limit", "75"])
    subprocess.check_call(cmd, cwd=str(ROOT), env=env)


if __name__ == "__main__":
    main()
