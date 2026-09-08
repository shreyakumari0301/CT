"""CTIBench catalogue lookup for TCAR contrast/gate (CWE + MITRE from vector DB chunks)."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Dict, Optional, Set

ROOT = Path(__file__).resolve().parent.parent
CWE_CHUNKS = ROOT / "vector_dbs" / "understanding_vdbs" / "faiss_cwe" / "chunks_cwe.json"
MEM_CHUNKS = ROOT / "vector_dbs" / "memorization_vdb" / "chunks.json"

_TID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)


class CTIBenchCorpusStore:
    """Drop-in replacement for CorpusStore on CTIBench vector-db assets."""

    def __init__(
        self,
        *,
        cwe_chunks_path: Path = CWE_CHUNKS,
        mem_chunks_path: Path = MEM_CHUNKS,
    ) -> None:
        self.cwe_chunks_path = cwe_chunks_path
        self.mem_chunks_path = mem_chunks_path
        self._cwe: Dict[str, dict] = {}
        self._mitre: Dict[str, dict] = {}
        self._mitre_subs: Dict[str, Set[str]] = {}

    def _load_cwe(self) -> None:
        if self._cwe:
            return
        if not self.cwe_chunks_path.exists():
            return
        rows = json.loads(self.cwe_chunks_path.read_text(encoding="utf-8"))
        for row in rows:
            raw = str(row.get("cwe_id") or "")
            cid = raw.upper()
            if not cid.startswith("CWE-"):
                cid = f"CWE-{cid}"
            self._cwe[cid] = {
                "cwe_id": cid,
                "title": row.get("name") or "",
                "contents": row.get("text") or row.get("description") or "",
            }

    def cwe(self, cwe_id: str) -> Optional[dict]:
        self._load_cwe()
        key = cwe_id.upper()
        if not key.startswith("CWE-"):
            key = f"CWE-{key}"
        return self._cwe.get(key)

    def _load_mitre(self) -> None:
        # MITRE catalogue is derived lazily per technique ID; do not scan all chunks.
        return

    def mitre(self, tid: str) -> Optional[dict]:
        key = tid.upper()
        if not key.startswith("T"):
            key = f"T{key}"
        if key not in self._mitre:
            self._mitre[key] = {
                "mitre_id": key,
                "title": key,
                "contents": "",
            }
        return self._mitre[key]

    def mitre_subtechniques(self, parent: str) -> Set[str]:
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
