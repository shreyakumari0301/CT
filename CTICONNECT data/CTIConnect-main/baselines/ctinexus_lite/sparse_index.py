"""BM25 sparse index over per-document entity vocabularies.

Each indexed document is represented purely by the surface forms (canonical
names + aliases) of the entities extracted from it. This is the
``CSKG-Guided RAG`` retrieval signal: at query time we extract entities
from the input (anchor) report and rank corpus reports by BM25 score over
the entity-only vocabulary.

Why this works
--------------
The questions in the multi-document synthesis tasks (CSC / TAP / MLA) are
*generic* — they ask "what is the storyline", "who is the threat actor",
"how did the malware evolve" without naming specific entities. The
retrieval input is the anchor *report*, which has ~23 entities on average
(see paper §3.2.3). BM25 over an entity vocabulary gives us:

* IDF weighting that down-ranks ubiquitous terms ("Windows", "Linux") and
  up-weights distinctive identifiers ("APT29", "EleKtra-Leak", a specific
  CVE);
* lexical match (no embedding API call at query time) so the query is fast
  and reproducible.

The relation set is intentionally NOT used in the index — only entity
occurrences matter for retrieval.
"""

from __future__ import annotations

import json
import pickle
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from rank_bm25 import BM25Okapi


# ---------------------------------------------------------------------------
# Tokeniser
# ---------------------------------------------------------------------------

_WORD_RE = re.compile(r"[a-z0-9]+")


def tokenize_entity_vocab(surfaces: Iterable[str]) -> list[str]:
    """Lower-case, alphanumeric-only tokeniser for entity surface forms.

    Each surface (canonical name or alias) contributes one or more tokens
    once it is split on non-alphanumeric boundaries — so ``"APT29"`` becomes
    ``["apt29"]`` and ``"Cozy Bear"`` becomes ``["cozy", "bear"]``. The
    same tokeniser is used for both indexed docs and queries.
    """
    out: list[str] = []
    for surf in surfaces:
        if not surf:
            continue
        out.extend(_WORD_RE.findall(surf.lower()))
    return out


# ---------------------------------------------------------------------------
# Index
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class RetrievalHit:
    doc_id: str
    score: float
    matched_tokens: tuple[str, ...]


class BM25EntityIndex:
    """BM25 over the entity vocabulary of each indexed document.

    Usage
    -----

    >>> index = BM25EntityIndex.build({
    ...     "REPORT-1": ["APT29", "Cozy Bear", "WellMess", "CVE-2020-5902"],
    ...     "REPORT-2": ["APT29", "Sliver", "CVE-2024-3400"],
    ...     "REPORT-3": ["Lazarus Group", "TrickBot"],
    ... })
    >>> hits = index.search(["APT29", "WellMess"], k=2)
    >>> [h.doc_id for h in hits]
    ['REPORT-1', 'REPORT-2']
    """

    def __init__(self) -> None:
        self._doc_ids: list[str] = []
        self._docs: list[list[str]] = []     # tokenised entity vocab per doc
        self._raw_surfaces: list[tuple[str, ...]] = []  # original surface forms
        self._bm25: BM25Okapi | None = None
        self._built = False

    # ------------------- build -------------------

    @classmethod
    def build(cls, doc_surfaces: dict[str, Iterable[str]]) -> "BM25EntityIndex":
        """Build an index from ``{doc_id: [surface, ...]}``."""
        idx = cls()
        for doc_id, surfaces in doc_surfaces.items():
            idx.add(doc_id, surfaces)
        idx.finalise()
        return idx

    def add(self, doc_id: str, surfaces: Iterable[str]) -> None:
        """Add one document. Must call :meth:`finalise` before searching."""
        if self._built:
            raise RuntimeError("cannot add documents after finalise(); rebuild instead")
        surfaces_tuple = tuple(s for s in surfaces if s)
        tokens = tokenize_entity_vocab(surfaces_tuple)
        # Empty token lists confuse BM25 (zero-length docs). Inject a dummy
        # so the doc is still ranked but never matches anything meaningfully.
        if not tokens:
            tokens = ["__empty__"]
        self._doc_ids.append(doc_id)
        self._docs.append(tokens)
        self._raw_surfaces.append(surfaces_tuple)

    def finalise(self) -> None:
        """Fit the BM25 model. Required before :meth:`search`."""
        if not self._docs:
            # Trivial empty index — still allow search() (returns []).
            self._built = True
            return
        self._bm25 = BM25Okapi(self._docs)
        self._built = True

    # ------------------- query -------------------

    def search(
        self,
        query_surfaces: Iterable[str],
        *,
        k: int = 10,
        exclude_doc_ids: Iterable[str] = (),
    ) -> list[RetrievalHit]:
        """Return the top-``k`` document IDs by BM25 score.

        Parameters
        ----------
        query_surfaces
            Surface forms of entities extracted from the query (anchor) input.
            Tokenised with the same rules as the indexed docs.
        k
            How many hits to return (after exclusions).
        exclude_doc_ids
            Doc IDs that must not appear in the result — typically the
            anchor doc itself.
        """
        if not self._built:
            raise RuntimeError("call finalise() before search()")
        if not self._bm25 or not self._doc_ids:
            return []
        q_tokens = tokenize_entity_vocab(query_surfaces)
        if not q_tokens:
            return []

        scores = self._bm25.get_scores(q_tokens)
        exclude = set(exclude_doc_ids)
        # Argsort descending, skipping zero scores and excluded docs.
        order = sorted(range(len(scores)),
                       key=lambda i: scores[i],
                       reverse=True)
        out: list[RetrievalHit] = []
        q_token_set = set(q_tokens)
        for i in order:
            if scores[i] <= 0:
                break
            doc_id = self._doc_ids[i]
            if doc_id in exclude:
                continue
            matched = tuple(t for t in self._docs[i] if t in q_token_set)
            out.append(RetrievalHit(
                doc_id=doc_id,
                score=float(scores[i]),
                matched_tokens=matched,
            ))
            if len(out) >= k:
                break
        return out

    # ------------------- introspection -------------------

    @property
    def n_documents(self) -> int:
        return len(self._doc_ids)

    def doc_ids(self) -> list[str]:
        return list(self._doc_ids)

    def surfaces_for(self, doc_id: str) -> tuple[str, ...]:
        try:
            i = self._doc_ids.index(doc_id)
        except ValueError:
            return ()
        return self._raw_surfaces[i]

    # ------------------- persistence -------------------

    def save(self, path: str | Path) -> None:
        """Pickle the index to ``path``."""
        if not self._built:
            self.finalise()
        p = Path(path); p.parent.mkdir(parents=True, exist_ok=True)
        state = {
            "doc_ids": self._doc_ids,
            "docs": self._docs,
            "raw_surfaces": self._raw_surfaces,
        }
        with p.open("wb") as f:
            pickle.dump(state, f)

    @classmethod
    def load(cls, path: str | Path) -> "BM25EntityIndex":
        with Path(path).open("rb") as f:
            state = pickle.load(f)
        idx = cls()
        idx._doc_ids = list(state["doc_ids"])
        idx._docs = list(state["docs"])
        idx._raw_surfaces = list(state["raw_surfaces"])
        idx.finalise()
        return idx

    def to_jsonl_for_debug(self, path: str | Path) -> None:
        """Dump the per-doc surface lists (human-inspectable)."""
        p = Path(path); p.parent.mkdir(parents=True, exist_ok=True)
        with p.open("w", encoding="utf-8") as f:
            for doc_id, surfaces in zip(self._doc_ids, self._raw_surfaces):
                f.write(json.dumps(
                    {"doc_id": doc_id, "entity_surfaces": list(surfaces)},
                    ensure_ascii=False,
                ) + "\n")
