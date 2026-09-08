"""Load the structured knowledge bases from corpus_kb/ into IndexedDocs and
build dense vector indexes over them.

Each corpus_kb/*.jsonl row is `{id, <kind>_id, title, contents, metadata}`.
The embedded text is `title + contents` (contents is a JSON-serialized blob of
the full KB entry — descriptions, mitigations, etc.).
"""

from __future__ import annotations

import json
from pathlib import Path

from baselines._shared.vector_index import IndexedDoc, VectorIndex

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent

KB_FILES = {
    "cve":   _REPO_ROOT / "corpus_kb/cve.jsonl",
    "cwe":   _REPO_ROOT / "corpus_kb/cwe.jsonl",
    "capec": _REPO_ROOT / "corpus_kb/capec.jsonl",
    "mitre": _REPO_ROOT / "corpus_kb/mitre.jsonl",
}

_ID_FIELD = {"cve": "cve_id", "cwe": "cwe_id", "capec": "capec_id", "mitre": "mitre_id"}
_ID_PREFIX = {"cwe": "CWE-", "capec": "CAPEC-"}  # cve/mitre ids already prefixed/bare


def _canonical_id(kind: str, raw: str) -> str:
    raw = str(raw)
    if kind == "cve":
        return raw if raw.upper().startswith("CVE-") else f"CVE-{raw}"
    if kind == "mitre":
        return raw if raw.upper().startswith("T") else f"T{raw}"
    prefix = _ID_PREFIX[kind]
    return raw if raw.upper().startswith(prefix) else f"{prefix}{raw}"


def load_kb(kind: str, *, max_entries: int | None = None) -> list[IndexedDoc]:
    """Load one knowledge base as a list of IndexedDoc (doc_id is canonical)."""
    if kind not in KB_FILES:
        raise ValueError(f"unknown KB {kind!r}; valid: {list(KB_FILES)}")
    path = KB_FILES[kind]
    id_field = _ID_FIELD[kind]
    docs: list[IndexedDoc] = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            d = json.loads(line)
            raw_id = d.get(id_field) or d.get("id")
            doc_id = _canonical_id(kind, raw_id)
            title = d.get("title", "") or ""
            contents = d.get("contents", "") or ""
            # contents is a JSON string; keep it as text (the embedder sees prose-ish).
            docs.append(IndexedDoc(doc_id=doc_id, title=title, text=str(contents)))
            if max_entries and len(docs) >= max_entries:
                break
    return docs


def build_kb_index(kind: str, embedder, *, out_dir: str | Path | None = None,
                   max_entries: int | None = None,
                   show_progress: bool = True) -> VectorIndex:
    """Build (and optionally persist) a dense index over one KB."""
    docs = load_kb(kind, max_entries=max_entries)
    if show_progress:
        print(f"[{kind}] embedding {len(docs)} entries...")
    index = VectorIndex.build(docs, embedder, show_progress=show_progress)
    if out_dir:
        out = Path(out_dir) / f"kb_{kind}"
        index.save(out)
        if show_progress:
            print(f"[{kind}] saved -> {out}.npz")
    return index
