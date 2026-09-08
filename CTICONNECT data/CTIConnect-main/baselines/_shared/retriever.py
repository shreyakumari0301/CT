"""Lazy, cached KB retriever shared by the vanilla_rag / etr / dtr baselines.

The first time a knowledge base is needed, its dense index is built (embedding
every entry once) and cached to ``baselines/_shared/.index_cache/``. Subsequent
runs load the cached index instantly. The embedder also caches per-text
embeddings, so query embedding of repeated inputs is free.
"""

from __future__ import annotations

import threading
from pathlib import Path

from baselines._shared.embedder import Embedder
from baselines._shared.kb import build_kb_index
from baselines._shared.vector_index import VectorIndex, SearchHit

_CACHE_DIR = Path(__file__).resolve().parent / ".index_cache"
_INDEX_BUILD_LOCKS: dict[str, threading.Lock] = {}
_INDEX_BUILD_GUARD = threading.Lock()


def _index_build_lock(kind: str) -> threading.Lock:
    with _INDEX_BUILD_GUARD:
        lock = _INDEX_BUILD_LOCKS.get(kind)
        if lock is None:
            lock = threading.Lock()
            _INDEX_BUILD_LOCKS[kind] = lock
        return lock

# Which KB each task retrieves against (== ground_truth.target_type).
TASK_TARGET_KB = {
    "rcm": "cwe", "wim": "cve", "atd": "mitre", "esd": "capec",
    "ata": "mitre", "vca": "cwe",
}


class KBRetriever:
    """Holds one shared Embedder + lazily-built per-KB vector indexes."""

    def __init__(self, *, cache_dir: Path | None = None):
        self.cache_dir = Path(cache_dir) if cache_dir else _CACHE_DIR
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.embedder = Embedder(cache_dir=self.cache_dir / "emb")
        self._indexes: dict[str, VectorIndex] = {}
        self._indexes_lock = threading.Lock()

    def index_for(self, kind: str) -> VectorIndex:
        with self._indexes_lock:
            if kind in self._indexes:
                return self._indexes[kind]

        with _index_build_lock(kind):
            with self._indexes_lock:
                if kind in self._indexes:
                    return self._indexes[kind]

            cached = self.cache_dir / f"kb_{kind}"
            npz = cached.with_suffix(".npz")
            if npz.exists():
                try:
                    idx = VectorIndex.load(cached)
                except (EOFError, OSError, ValueError) as e:
                    print(f"[{kind}] corrupt index cache ({e}); rebuilding...")
                    npz.unlink(missing_ok=True)
                    idx = build_kb_index(
                        kind, self.embedder, out_dir=self.cache_dir, show_progress=True
                    )
            else:
                idx = build_kb_index(
                    kind, self.embedder, out_dir=self.cache_dir, show_progress=True
                )

            with self._indexes_lock:
                self._indexes[kind] = idx
                return idx

    def retrieve(self, query: str, kind: str, k: int = 5) -> list[SearchHit]:
        idx = self.index_for(kind)
        qv = self.embedder.embed_one(query)
        return idx.search(qv, k=k)

    def retrieve_for_task(self, query: str, task: str, k: int = 5) -> list[SearchHit]:
        return self.retrieve(query, TASK_TARGET_KB[task], k=k)


def format_candidates(hits: list[SearchHit], *, max_chars: int = 600) -> str:
    """Render retrieved KB entries into a compact context block for the prompt."""
    lines = []
    for h in hits:
        body = h.text[:max_chars]
        lines.append(f"[{h.doc_id}] {h.title}\n{body}")
    return "\n\n".join(lines)
