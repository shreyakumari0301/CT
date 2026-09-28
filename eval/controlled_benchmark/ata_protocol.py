"""Parse constrained ATA JSON answers."""
from __future__ import annotations

import json
import re

TECHNIQUE_ID = re.compile(r"T\d{4}(?:\.\d{3})?", re.I)


def parse_ata_answer(raw: str) -> list[str]:
    text = (raw or "").strip()
    if not text:
        return []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return [m.group(0).upper() for m in TECHNIQUE_ID.finditer(text)][:1]
    ids = data.get("technique_ids") if isinstance(data, dict) else data
    if isinstance(ids, str):
        ids = [ids]
    if not isinstance(ids, list):
        return []
    out: list[str] = []
    for value in ids:
        match = TECHNIQUE_ID.search(str(value or ""))
        if match:
            tid = match.group(0).upper()
            if tid not in out:
                out.append(tid)
    return out
