"""Inner-product vector index over L2-normalized embeddings (numpy).

The index stacks document embeddings into a single ``(N, D)`` matrix and
ranks candidates by ``matrix @ query`` (equivalent to cosine similarity on
unit vectors). Top-k selection uses ``np.argpartition`` followed by a
partial sort over the retained k indices. Indices serialise to ``.npz``
archives alongside parallel ``doc_ids``/``titles``/``texts`` arrays.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import numpy as np


@dataclass(frozen=True)
class IndexedDoc:
    doc_id: str        # canonical identifier, e.g. "CWE-79"
    title: str
    text: str          # the embedded text


@dataclass(frozen=True)
class SearchHit:
    doc_id: str
    score: float
    title: str
    text: str


class VectorIndex:
    """Dense retrieval over a fixed document set."""

    def __init__(self) -> None:
        self._docs: list[IndexedDoc] = []
        self._matrix: np.ndarray | None = None   # (N, D), L2-normalized

    @property
    def n_documents(self) -> int:
        return len(self._docs)

    @classmethod
    def build(cls, docs: list[IndexedDoc], embedder, *,
              show_progress: bool = False) -> "VectorIndex":
        idx = cls()
        idx._docs = list(docs)
        texts = [f"{d.title}. {d.text}".strip() for d in docs]
        idx._matrix = embedder.embed(texts, show_progress=show_progress)
        return idx

    def search(self, query_vec: np.ndarray, k: int = 5) -> list[SearchHit]:
        if self._matrix is None or not self._docs:
            return []
        q = query_vec.astype(np.float32).reshape(-1)
        # vectors are L2-normalized, so inner product == cosine
        scores = self._matrix @ q
        k = min(k, len(self._docs))
        # argpartition for top-k then sort those k
        top = np.argpartition(-scores, k - 1)[:k]
        top = top[np.argsort(-scores[top])]
        return [
            SearchHit(self._docs[i].doc_id, float(scores[i]),
                      self._docs[i].title, self._docs[i].text)
            for i in top
        ]

    # ------------- persistence -------------
    def save(self, path: str | Path) -> None:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        np.savez_compressed(
            p.with_suffix(".npz"),
            matrix=self._matrix,
            doc_ids=np.array([d.doc_id for d in self._docs], dtype=object),
            titles=np.array([d.title for d in self._docs], dtype=object),
            texts=np.array([d.text for d in self._docs], dtype=object),
        )

    @classmethod
    def load(cls, path: str | Path) -> "VectorIndex":
        p = Path(path).with_suffix(".npz")
        data = np.load(p, allow_pickle=True)
        idx = cls()
        idx._matrix = data["matrix"]
        idx._docs = [
            IndexedDoc(str(i), str(t), str(x))
            for i, t, x in zip(data["doc_ids"], data["titles"], data["texts"])
        ]
        return idx
