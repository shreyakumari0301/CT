"""CWE taxonomy graph from CTIConnect cwe_xrefs (ChildOf / siblings)."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Dict, List, Set


def _norm(cwe_id: str) -> str:
    cwe_id = str(cwe_id).strip().upper()
    if not cwe_id.startswith("CWE-"):
        cwe_id = f"CWE-{cwe_id}"
    return cwe_id


class CWEGraph:
    def __init__(self, xrefs_path: Path) -> None:
        self.parent_of: Dict[str, str] = {}
        self.children_of: Dict[str, Set[str]] = {}
        self._load(xrefs_path)

    def _load(self, path: Path) -> None:
        if not path.exists():
            return
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            child = _norm(row["cwe_id"])
            for rel in row.get("correlated_cwe") or []:
                schema = rel.get("correlation_schema") or []
                if "ChildOf" not in schema:
                    continue
                parent = _norm(rel["cwe_id"])
                self.parent_of[child] = parent
                self.children_of.setdefault(parent, set()).add(child)

    def siblings(self, cwe_id: str) -> Set[str]:
        cwe_id = _norm(cwe_id)
        parent = self.parent_of.get(cwe_id)
        if not parent:
            return set()
        return {s for s in self.children_of.get(parent, set()) if s != cwe_id}

    def confusion_set(self, seed_ids: List[str], *, max_size: int = 6) -> List[str]:
        """Expand seeds with parent, children, siblings (deduped, capped)."""
        out: List[str] = []
        seen: Set[str] = set()

        def add(cid: str) -> None:
            cid = _norm(cid)
            if cid in seen:
                return
            seen.add(cid)
            out.append(cid)

        for sid in seed_ids:
            add(sid)
            sid = _norm(sid)
            if sid in self.parent_of:
                add(self.parent_of[sid])
            for ch in self.children_of.get(sid, ()):
                add(ch)
            for sib in self.siblings(sid):
                add(sib)
            if len(out) >= max_size:
                break

        # Same-hundreds neighbours (weak sibling heuristic when graph sparse)
        for sid in list(seed_ids):
            m = re.match(r"CWE-(\d+)", _norm(sid))
            if not m:
                continue
            base = int(m.group(1))
            for delta in (-3, -2, -1, 1, 2, 3):
                add(f"CWE-{base + delta}")
            if len(out) >= max_size:
                break

        return out[:max_size]
