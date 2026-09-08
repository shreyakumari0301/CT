"""Token-aware recursive character splitter for CTI reports.

Mirrors the chunking used by the paper's Vanilla RAG configuration
(``app:vanilla_rag``): 1024-token chunks with a 128-token overlap, computed
against ``tiktoken``'s ``cl100k_base`` encoding so the counts match what the
OpenAI embedding API will see.

The splitter is *recursive*: it tries to split on the most semantic boundary
first (paragraph), and only falls back to finer-grained separators if a chunk
still exceeds the target size. This preserves narrative structure better than
fixed-width sliding windows.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

import tiktoken


# Order matters: try the most semantic boundary first.
DEFAULT_SEPARATORS: tuple[str, ...] = (
    "\n\n",   # paragraph
    "\n",     # line
    ". ",     # sentence
    "? ",
    "! ",
    "; ",
    ", ",
    " ",      # word
    "",       # character (last resort)
)


@dataclass(frozen=True)
class Chunk:
    """A single chunk of a document with positional + token metadata."""

    chunk_id: str            # e.g. "BLOG-42::ch3"
    doc_id: str              # parent document identifier (e.g. "BLOG-42")
    chunk_index: int         # 0-based position within the document
    text: str
    token_count: int


# -------------------------------- internal --------------------------------

def _encoder():
    return tiktoken.get_encoding("cl100k_base")


def _count_tokens(text: str, enc=None) -> int:
    enc = enc or _encoder()
    return len(enc.encode(text, disallowed_special=()))


def _split_with_separator(text: str, sep: str) -> list[str]:
    if sep == "":
        return list(text)
    parts = text.split(sep)
    # Re-attach the separator to the *end* of each part except the last so
    # joining the parts later reproduces the original text.
    if len(parts) == 1:
        return parts
    return [p + sep for p in parts[:-1]] + [parts[-1]]


def _recursive_split(
    text: str,
    chunk_size: int,
    separators: tuple[str, ...],
    enc,
) -> list[str]:
    """Split ``text`` so no piece exceeds ``chunk_size`` tokens.

    Tries separators in order; each separator is only used to break up the
    pieces that are still too large after the previous round.
    """
    if _count_tokens(text, enc) <= chunk_size:
        return [text] if text else []

    for i, sep in enumerate(separators):
        pieces = _split_with_separator(text, sep)
        if len(pieces) == 1:
            continue  # this separator didn't split anything; try a finer one
        out: list[str] = []
        remaining = separators[i + 1:]
        for p in pieces:
            if _count_tokens(p, enc) <= chunk_size:
                out.append(p)
            else:
                out.extend(_recursive_split(p, chunk_size, remaining, enc))
        return out

    # Should not reach here because the empty-string separator always splits.
    return [text]


def _merge_with_overlap(
    pieces: Iterable[str],
    chunk_size: int,
    overlap: int,
    enc,
) -> list[str]:
    """Greedy-pack pieces into chunks of ~``chunk_size`` tokens.

    A trailing window of ``overlap`` tokens from the last produced chunk is
    prepended to the next chunk so each chunk shares context with its
    neighbours.
    """
    chunks: list[str] = []
    current: list[str] = []
    current_tokens = 0

    pieces = [p for p in pieces if p]

    for piece in pieces:
        n = _count_tokens(piece, enc)
        if current_tokens + n <= chunk_size or not current:
            current.append(piece)
            current_tokens += n
            continue

        # Close out the current chunk.
        chunks.append("".join(current))

        # Build the overlap prefix from the tail of the last chunk.
        if overlap > 0:
            tail_text = "".join(current)
            tail_tokens = enc.encode(tail_text, disallowed_special=())
            overlap_tokens = tail_tokens[-overlap:]
            overlap_text = enc.decode(overlap_tokens)
            current = [overlap_text, piece]
            current_tokens = len(overlap_tokens) + n
        else:
            current = [piece]
            current_tokens = n

    if current:
        chunks.append("".join(current))
    return chunks


# --------------------------------- public ---------------------------------

def chunk_document(
    text: str,
    doc_id: str,
    *,
    chunk_size: int = 1024,
    overlap: int = 128,
    separators: tuple[str, ...] = DEFAULT_SEPARATORS,
) -> list[Chunk]:
    """Split ``text`` into overlapping token-bounded chunks.

    Parameters
    ----------
    text : str
        The document body.
    doc_id : str
        A stable identifier for the parent document (e.g. ``"BLOG-42"``).
        Chunk IDs are formed as ``f"{doc_id}::ch{i}"``.
    chunk_size : int
        Maximum tokens per chunk (default 1024 to match the paper).
    overlap : int
        Token overlap between consecutive chunks (default 128).
    separators : tuple[str, ...]
        Boundaries to try in order. Defaults to paragraph -> sentence -> word
        -> character.
    """
    if chunk_size <= 0:
        raise ValueError("chunk_size must be positive")
    if overlap < 0 or overlap >= chunk_size:
        raise ValueError("overlap must be in [0, chunk_size)")
    if not text or not text.strip():
        return []

    enc = _encoder()
    pieces = _recursive_split(text, chunk_size, separators, enc)
    merged = _merge_with_overlap(pieces, chunk_size, overlap, enc)

    chunks: list[Chunk] = []
    for i, body in enumerate(merged):
        body = body.strip("\n")
        if not body:
            continue
        chunks.append(Chunk(
            chunk_id=f"{doc_id}::ch{i}",
            doc_id=doc_id,
            chunk_index=i,
            text=body,
            token_count=_count_tokens(body, enc),
        ))
    return chunks
