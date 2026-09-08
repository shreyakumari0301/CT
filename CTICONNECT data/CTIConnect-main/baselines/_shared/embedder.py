"""OpenAI text-embedding-3-large embedder with batching, L2-normalization,
and an on-disk cache.

The cache is keyed by sha1(model + text) so repeated builds (and the query-time
embedding of inputs already seen) are free.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from pathlib import Path

import numpy as np

DEFAULT_MODEL = "text-embedding-3-large"
EMBED_DIM = 3072

# baseline_cli runs predict() with ThreadPoolExecutor; guard disk cache I/O.
_EMB_CACHE_LOCK = threading.RLock()


class Embedder:
    def __init__(self, model: str = DEFAULT_MODEL, *, api_key: str | None = None,
                 cache_dir: str | Path | None = None, batch_size: int = 64):
        from openai import OpenAI
        self.model = model
        self.batch_size = batch_size
        self._client = OpenAI(api_key=api_key or os.environ.get("OPENAI_API_KEY"))
        self._cache_dir = Path(cache_dir) if cache_dir else None
        if self._cache_dir:
            self._cache_dir.mkdir(parents=True, exist_ok=True)

    # ------------- cache helpers -------------
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
        tmp = p.with_name(f"{p.stem}.tmp.npy")
        with _EMB_CACHE_LOCK:
            p.parent.mkdir(parents=True, exist_ok=True)
            try:
                np.save(tmp, vec)
                os.replace(tmp, p)
            except Exception:
                tmp.unlink(missing_ok=True)
                raise

    # ------------- public -------------
    @staticmethod
    def _l2_normalize(m: np.ndarray) -> np.ndarray:
        norms = np.linalg.norm(m, axis=1, keepdims=True)
        norms[norms == 0] = 1.0
        return m / norms

    def embed(self, texts: list[str], *, show_progress: bool = False) -> np.ndarray:
        """Embed a list of texts -> (N, 3072) L2-normalized float32 matrix."""
        out: list[np.ndarray | None] = [None] * len(texts)
        to_fetch: list[int] = []
        for i, t in enumerate(texts):
            cached = self._load_cached(t)
            if cached is not None:
                out[i] = cached
            else:
                to_fetch.append(i)

        for start in range(0, len(to_fetch), self.batch_size):
            batch_idx = to_fetch[start:start + self.batch_size]
            batch_texts = [texts[i] or " " for i in batch_idx]  # API rejects empty
            vecs = self._embed_batch(batch_texts)
            for j, i in enumerate(batch_idx):
                v = vecs[j].astype(np.float32)
                out[i] = v
                self._store_cached(texts[i], v)
            if show_progress:
                done = min(start + self.batch_size, len(to_fetch))
                print(f"  embedded {done}/{len(to_fetch)} (cache hits: "
                      f"{len(texts) - len(to_fetch)})", end="\r")
        if show_progress and to_fetch:
            print()

        mat = np.vstack([o for o in out]).astype(np.float32)
        return self._l2_normalize(mat)

    def embed_one(self, text: str) -> np.ndarray:
        return self.embed([text])[0]

    def _embed_batch(self, texts: list[str], max_retries: int = 4) -> np.ndarray:
        last = None
        for attempt in range(max_retries):
            try:
                resp = self._client.embeddings.create(model=self.model, input=texts)
                return np.array([d.embedding for d in resp.data], dtype=np.float32)
            except Exception as e:  # noqa: BLE001
                last = e
                time.sleep(2 ** attempt)
        raise RuntimeError(f"embedding failed after {max_retries} retries: {last}")
