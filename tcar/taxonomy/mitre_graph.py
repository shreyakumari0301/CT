"""MITRE ATT&CK hierarchy helpers (parent / sub-technique / siblings)."""

from __future__ import annotations

import re
from typing import Dict, List, Set


_TID = re.compile(r"^(T\d{4})(?:\.(\d{3}))?$", re.I)


def _norm(tid: str) -> str:
    tid = tid.strip().upper()
    if not tid.startswith("T"):
        tid = f"T{tid}"
    return tid


class MitreGraph:
    """Lightweight hierarchy from technique ID structure (no STIX file required)."""

    def parent_of(self, tid: str) -> str | None:
        tid = _norm(tid)
        m = _TID.match(tid)
        if not m or not m.group(2):
            return None
        return m.group(1).upper()

    def is_subtechnique(self, tid: str) -> bool:
        return "." in _norm(tid)

    def siblings(self, tid: str) -> Set[str]:
        """Other sub-techniques under the same parent (IDs only; populated externally)."""
        parent = self.parent_of(tid)
        if not parent:
            return set()
        return set()  # filled via registry when corpus loaded

    def confusion_set(
        self,
        seed_ids: List[str],
        subtechniques_by_parent: Dict[str, Set[str]],
        *,
        max_size: int = 6,
    ) -> List[str]:
        out: List[str] = []
        seen: Set[str] = set()

        def add(tid: str) -> None:
            tid = _norm(tid)
            if tid in seen:
                return
            seen.add(tid)
            out.append(tid)

        for sid in seed_ids:
            add(sid)
            sid = _norm(sid)
            par = self.parent_of(sid)
            if par:
                add(par)
                for sub in sorted(subtechniques_by_parent.get(par, ()))[:4]:
                    add(sub)
            else:
                for sub in sorted(subtechniques_by_parent.get(sid, ()))[:4]:
                    add(sub)
            if len(out) >= max_size:
                break
        return out[:max_size]
