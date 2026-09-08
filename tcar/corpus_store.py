"""Load CWE / MITRE catalogue rows by ID for contrast cards."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Optional


class CorpusStore:
    def __init__(self, corpus_dir: Path) -> None:
        self.corpus_dir = corpus_dir
        self._cwe: Dict[str, dict] = {}
        self._mitre: Dict[str, dict] = {}
        self._mitre_subs: Dict[str, set[str]] = {}

    def _load_cwe(self) -> None:
        if self._cwe:
            return
        path = self.corpus_dir / "cwe.jsonl"
        if not path.exists():
            return
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            row = json.loads(line)
            raw = str(row.get("cwe_id") or row.get("id") or "")
            num = raw.replace("CWE-", "").replace("cwe-", "")
            cid = f"CWE-{num}".upper()
            self._cwe[cid] = row

    def _load_mitre(self) -> None:
        if self._mitre:
            return
        path = self.corpus_dir / "mitre.jsonl"
        if not path.exists():
            return
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            row = json.loads(line)
            tid = str(row.get("mitre_id", "")).upper()
            if not tid.startswith("T"):
                tid = f"T{tid}"
            self._mitre[tid] = row
            if "." in tid:
                parent = tid.split(".")[0]
                self._mitre_subs.setdefault(parent, set()).add(tid)

    def cwe(self, cwe_id: str) -> Optional[dict]:
        self._load_cwe()
        key = cwe_id.upper()
        if not key.startswith("CWE-"):
            key = f"CWE-{key}"
        return self._cwe.get(key)

    def mitre(self, tid: str) -> Optional[dict]:
        self._load_mitre()
        key = tid.upper()
        if not key.startswith("T"):
            key = f"T{key}"
        return self._mitre.get(key)

    def mitre_subtechniques(self, parent: str) -> set[str]:
        self._load_mitre()
        parent = parent.upper().split(".")[0]
        return set(self._mitre_subs.get(parent, set()))

    def short_label(self, kind: str, doc_id: str) -> str:
        if kind == "cwe":
            row = self.cwe(doc_id)
            if row:
                return f"{doc_id}: {row.get('title', '')[:80]}"
        else:
            row = self.mitre(doc_id)
            if row:
                return f"{doc_id}: {row.get('title', '')[:80]}"
        return doc_id
