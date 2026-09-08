#!/usr/bin/env bash
set -euo pipefail
cd /mnt/c/Users/SK/CTI-Chatbot
mkdir -p data/ctibench_taa
BASE=https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master
curl -fsSL -o data/ctibench_taa/ics-attack.json "$BASE/ics-attack/ics-attack.json"
curl -fsSL -o data/ctibench_taa/mobile-attack.json "$BASE/mobile-attack/mobile-attack.json"
ls -lh data/ctibench_taa/*attack*.json
python3 <<'PY'
import json
from pathlib import Path
for p in sorted(Path("data/ctibench_taa").glob("*attack*.json")):
    o = json.loads(p.read_text(encoding="utf-8"))["objects"]
    m = [x for x in o if x.get("type") == "x-mitre-matrix"]
    print(p.name, "objs", len(o), "matrix", [(x.get("name"), x.get("x_mitre_version"), x.get("modified")) for x in m])
PY
