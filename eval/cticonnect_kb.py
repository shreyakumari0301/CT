"""CTIConnect KB retriever — matches official baselines/_shared stack.

Embedding: OpenAI ``text-embedding-3-large`` (3072-d, L2-normalized).
Similarity: cosine via inner product on unit vectors (``VectorIndex``).
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

import numpy as np

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CORPUS = ROOT / "CTICONNECT data" / "CTIConnect-main" / "corpus_kb"
DEFAULT_CACHE = ROOT / "CTICONNECT data" / ".index_cache" / "te3large"

EMBED_MODEL = "text-embedding-3-large"
EMBED_DIM = 3072

# Shared across threads when eval runs with workers > 1.
_EMB_CACHE_LOCK = threading.RLock()
_INDEX_BUILD_LOCKS: Dict[str, threading.Lock] = {}
_INDEX_BUILD_GUARD = threading.Lock()


def _index_build_lock(kind: str) -> threading.Lock:
    with _INDEX_BUILD_GUARD:
        lock = _INDEX_BUILD_LOCKS.get(kind)
        if lock is None:
            lock = threading.Lock()
            _INDEX_BUILD_LOCKS[kind] = lock
        return lock

TASK_TARGET_KB = {
    "rcm": "cwe",
    "wim": "cve",
    "atd": "mitre",
    "esd": "capec",
    "ata": "mitre",
    "vca": "cwe",
}

_ID_FIELD = {"cve": "cve_id", "cwe": "cwe_id", "capec": "capec_id", "mitre": "mitre_id"}
_ID_PREFIX = {"cwe": "CWE-", "capec": "CAPEC-"}


def _canonical_id(kind: str, raw: str) -> str:
    raw = str(raw)
    if kind == "cve":
        return raw if raw.upper().startswith("CVE-") else f"CVE-{raw}"
    if kind == "mitre":
        return raw if raw.upper().startswith("T") else f"T{raw}"
    prefix = _ID_PREFIX[kind]
    return raw if raw.upper().startswith(prefix) else f"{prefix}{raw}"


@dataclass(frozen=True)
class IndexedDoc:
    doc_id: str
    title: str
    text: str


@dataclass(frozen=True)
class SearchHit:
    doc_id: str
    score: float
    title: str
    text: str


@dataclass
class KBHit:
    doc_id: str
    title: str
    text: str
    score: float

    @property
    def distance(self) -> float:
        return 1.0 - self.score


class Embedder:
    """OpenAI text-embedding-3-large with per-text disk cache and L2 norm."""

    def __init__(
        self,
        model: str = EMBED_MODEL,
        *,
        api_key: str | None = None,
        cache_dir: str | Path | None = None,
        batch_size: int = 64,
    ) -> None:
        from openai import OpenAI  # noqa: WPS433

        self.model = model
        self.batch_size = batch_size
        self._client = OpenAI(api_key=api_key or os.environ.get("OPENAI_API_KEY"))
        self._cache_dir = Path(cache_dir) if cache_dir else None
        if self._cache_dir:
            self._cache_dir.mkdir(parents=True, exist_ok=True)

    def _key(self, text: str) -> str:
        return hashlib.sha1(f"{self.model}\x00{text}".encode("utf-8")).hexdigest()

    def _cache_path(self, key: str) -> Path | None:
        return self._cache_dir / f"{key}.npy" if self._cache_dir else None

    def _load_cached(self, text: str) -> np.ndarray | None:
        if not self._cache_dir:
            return None
        p = self._cache_path(self._key(text))
        if not p:
            return None
        with _EMB_CACHE_LOCK:
            if not p.exists():
                return None
            try:
                vec = np.load(p)
                if vec.size == 0:
                    raise EOFError("empty cache file")
                return vec
            except (EOFError, OSError, ValueError):
                try:
                    p.unlink(missing_ok=True)
                    p.with_name(f"{p.stem}.tmp.npy").unlink(missing_ok=True)
                    p.with_suffix(".npy.tmp").unlink(missing_ok=True)
                except OSError:
                    pass
                return None

    def _store_cached(self, text: str, vec: np.ndarray) -> None:
        if not self._cache_dir:
            return
        p = self._cache_path(self._key(text))
        if not p:
            return
        # np.save appends ".npy" unless the path already ends with ".npy".
        tmp = p.with_name(f"{p.stem}.tmp.npy")
        with _EMB_CACHE_LOCK:
            p.parent.mkdir(parents=True, exist_ok=True)
            try:
                np.save(tmp, vec)
                os.replace(tmp, p)
            except Exception:
                tmp.unlink(missing_ok=True)
                raise

    @staticmethod
    def _l2_normalize(m: np.ndarray) -> np.ndarray:
        norms = np.linalg.norm(m, axis=1, keepdims=True)
        norms[norms == 0] = 1.0
        return m / norms

    def embed(self, texts: list[str], *, show_progress: bool = False) -> np.ndarray:
        out: list[np.ndarray | None] = [None] * len(texts)
        to_fetch: list[int] = []
        for i, t in enumerate(texts):
            cached = self._load_cached(t)
            if cached is not None:
                out[i] = cached
            else:
                to_fetch.append(i)

        for start in range(0, len(to_fetch), self.batch_size):
            batch_idx = to_fetch[start : start + self.batch_size]
            batch_texts = [texts[i] or " " for i in batch_idx]
            vecs = self._embed_batch(batch_texts)
            for j, i in enumerate(batch_idx):
                v = vecs[j].astype(np.float32)
                out[i] = v
                self._store_cached(texts[i], v)
            if show_progress:
                done = min(start + self.batch_size, len(to_fetch))
                print(
                    f"  embedded {done}/{len(to_fetch)} "
                    f"(cache hits: {len(texts) - len(to_fetch)})",
                    end="\r",
                )
        if show_progress and to_fetch:
            print()

        mat = np.vstack([o for o in out]).astype(np.float32)
        return self._l2_normalize(mat)

    def embed_one(self, text: str) -> np.ndarray:
        return self.embed([text])[0]

    def _embed_batch(self, texts: list[str], max_retries: int = 4) -> np.ndarray:
        last: Exception | None = None
        for attempt in range(max_retries):
            try:
                resp = self._client.embeddings.create(model=self.model, input=texts)
                return np.array([d.embedding for d in resp.data], dtype=np.float32)
            except Exception as e:  # noqa: BLE001
                last = e
                time.sleep(2**attempt)
        raise RuntimeError(f"embedding failed after {max_retries} retries: {last}")


class VectorIndex:
    """Dense retrieval over L2-normalized embeddings (cosine = inner product)."""

    def __init__(self) -> None:
        self._docs: list[IndexedDoc] = []
        self._matrix: np.ndarray | None = None

    @property
    def n_documents(self) -> int:
        return len(self._docs)

    @classmethod
    def build(
        cls, docs: list[IndexedDoc], embedder: Embedder, *, show_progress: bool = False
    ) -> "VectorIndex":
        idx = cls()
        idx._docs = list(docs)
        texts = [f"{d.title}. {d.text}".strip() for d in docs]
        idx._matrix = embedder.embed(texts, show_progress=show_progress)
        return idx

    def search(self, query_vec: np.ndarray, k: int = 5) -> list[SearchHit]:
        if self._matrix is None or not self._docs:
            return []
        q = query_vec.astype(np.float32).reshape(-1)
        scores = self._matrix @ q
        k = min(k, len(self._docs))
        top = np.argpartition(-scores, k - 1)[:k]
        top = top[np.argsort(-scores[top])]
        return [
            SearchHit(self._docs[i].doc_id, float(scores[i]), self._docs[i].title, self._docs[i].text)
            for i in top
        ]

    def get_by_ids(self, doc_ids: list[str]) -> list[IndexedDoc]:
        """Return catalogue docs for the given IDs (order preserved; missing skipped)."""
        if not self._docs or not doc_ids:
            return []
        by_id = {d.doc_id.upper(): d for d in self._docs}
        out: list[IndexedDoc] = []
        for raw in doc_ids:
            key = str(raw).strip().upper()
            doc = by_id.get(key)
            if doc is not None:
                out.append(doc)
        return out

    def save(self, path: str | Path) -> None:
        p = Path(path).with_suffix(".npz")
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_name(f"{p.stem}.tmp.npz")
        np.savez_compressed(
            tmp,
            matrix=self._matrix,
            doc_ids=np.array([d.doc_id for d in self._docs], dtype=object),
            titles=np.array([d.title for d in self._docs], dtype=object),
            texts=np.array([d.text for d in self._docs], dtype=object),
        )
        os.replace(tmp, p)

    @classmethod
    def load(cls, path: str | Path) -> "VectorIndex":
        p = Path(path).with_suffix(".npz")
        try:
            data = np.load(p, allow_pickle=True)
        except (EOFError, OSError, ValueError) as e:
            raise EOFError(f"corrupt vector index: {p}") from e
        idx = cls()
        idx._matrix = data["matrix"]
        idx._docs = [
            IndexedDoc(str(i), str(t), str(x))
            for i, t, x in zip(data["doc_ids"], data["titles"], data["texts"])
        ]
        return idx


def _load_kb_docs(kind: str, corpus_dir: Path) -> list[IndexedDoc]:
    path = corpus_dir / f"{kind}.jsonl"
    if not path.exists():
        raise FileNotFoundError(path)
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
            title = d.get("title") or ""
            contents = d.get("contents") or ""
            docs.append(IndexedDoc(doc_id=doc_id, title=title, text=str(contents)))
    return docs


def _build_kb_index(
    kind: str,
    corpus_dir: Path,
    embedder: Embedder,
    *,
    out_dir: Path,
    show_progress: bool = True,
) -> VectorIndex:
    docs = _load_kb_docs(kind, corpus_dir)
    if show_progress:
        print(f"[cticonnect-kb] embedding {len(docs)} {kind} entries ({EMBED_MODEL})...")
    index = VectorIndex.build(docs, embedder, show_progress=show_progress)
    out = out_dir / f"kb_{kind}"
    index.save(out)
    if show_progress:
        print(f"[cticonnect-kb] saved -> {out}.npz")
    return index


def format_candidates(hits: List[KBHit] | List[SearchHit], *, max_chars: int = 600) -> str:
    lines = []
    for h in hits:
        body = h.text[:max_chars]
        lines.append(f"[{h.doc_id}] {h.title}\n{body}")
    return "\n\n".join(lines)


class CTIConnectKBRetriever:
    """Shared retriever for vanilla_rag / etr / dtr / cta_rag_cticonnect."""

    def __init__(
        self,
        *,
        corpus_dir: Optional[Path] = None,
        cache_dir: Optional[Path] = None,
        embed_model: str = EMBED_MODEL,
    ) -> None:
        self.corpus_dir = Path(corpus_dir) if corpus_dir else DEFAULT_CORPUS
        self.cache_dir = Path(cache_dir) if cache_dir else DEFAULT_CACHE
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.embed_model = embed_model
        self.embedder = Embedder(model=embed_model, cache_dir=self.cache_dir / "emb")
        self._indexes: Dict[str, VectorIndex] = {}
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
                except EOFError:
                    npz.unlink(missing_ok=True)
                    idx = _build_kb_index(
                        kind,
                        self.corpus_dir,
                        self.embedder,
                        out_dir=self.cache_dir,
                        show_progress=True,
                    )
            else:
                idx = _build_kb_index(
                    kind,
                    self.corpus_dir,
                    self.embedder,
                    out_dir=self.cache_dir,
                    show_progress=True,
                )

            with self._indexes_lock:
                self._indexes[kind] = idx
                return idx

    def retrieve(self, query: str, kind: str, k: int = 5) -> List[KBHit]:
        idx = self.index_for(kind)
        qv = self.embedder.embed_one(query)
        return [
            KBHit(doc_id=h.doc_id, title=h.title, text=h.text, score=h.score)
            for h in idx.search(qv, k=k)
        ]

    def get_docs(self, kind: str, doc_ids: list[str]) -> List[KBHit]:
        """Lookup catalogue entries by ID (score=0 for injected neighbours)."""
        docs = self.index_for(kind).get_by_ids(doc_ids)
        return [KBHit(doc_id=d.doc_id, title=d.title, text=d.text, score=0.0) for d in docs]

    def retrieve_for_task(self, query: str, task: str, k: int = 5) -> List[KBHit]:
        kind = TASK_TARGET_KB[task]
        return self.retrieve(query, kind, k=k)
