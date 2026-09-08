"""CTIBench FAISS retriever — raw faiss indices + chunk metadata (no LangChain pickle)."""

from __future__ import annotations

import json
import os
import pickle
import re
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

from eval.cticonnect_kb import KBHit

ROOT = Path(__file__).resolve().parent.parent
EMBED_MODEL = "sentence-transformers/all-MiniLM-L6-v2"

_TID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)

TASK_TARGET = {
    "rcm": "cwe",
    "rcm2021": "cwe",
    "ate": "mem",
    "ata": "mem",
    "mcq": "mem",
    "vsp": "vsp",
}


@dataclass
class _IndexBundle:
    index: Any
    rows: List[dict]
    kind: str
    metadatas: Optional[List[Any]] = None


class CTIBenchKBRetriever:
    """Dense retrieval over CTIBench FAISS stores (MiniLM, same as CTA-RAG pipelines)."""

    def __init__(self) -> None:
        self._bundles: Dict[str, _IndexBundle] = {}
        self._embedder = None
        self._lock = threading.Lock()

    def _embedder_model(self):
        if self._embedder is None:
            try:
                from sentence_transformers import SentenceTransformer  # noqa: WPS433

                self._embedder = SentenceTransformer(EMBED_MODEL)
                self._embedder_kind = "st"
            except ImportError:
                from langchain_huggingface import HuggingFaceEmbeddings  # noqa: WPS433

                self._embedder = HuggingFaceEmbeddings(model_name=EMBED_MODEL)
                self._embedder_kind = "lc"
        return self._embedder

    def _embed_query(self, query: str) -> np.ndarray:
        model = self._embedder_model()
        if getattr(self, "_embedder_kind", "lc") == "st":
            vec = model.encode(query, normalize_embeddings=False)
            return np.array([vec], dtype=np.float32)
        vec = model.embed_query(query)
        return np.array([vec], dtype=np.float32)

    def _load_cwe_bundle(self) -> _IndexBundle:
        import faiss  # noqa: WPS433

        rebuilt = ROOT / "vector_dbs" / "understanding_vdbs" / "faiss_cwe_rebuilt"
        legacy = ROOT / "vector_dbs" / "understanding_vdbs" / "faiss_cwe"
        chunks_path = legacy / "chunks_cwe.json"

        if rebuilt.exists() and (rebuilt / "index.faiss").exists():
            index_path = rebuilt / "index.faiss"
            # Rebuilt store order matches chunks_cwe.json
            rows = json.loads(chunks_path.read_text(encoding="utf-8"))
        else:
            # Build in-memory from chunks (one-time, cached on disk under rebuilt if missing)
            rows = json.loads(chunks_path.read_text(encoding="utf-8"))
            texts = []
            for entry in rows:
                cwe_id = str(entry.get("cwe_id") or "")
                name = str(entry.get("name") or "")
                desc = str(entry.get("description") or "")
                ext = str(entry.get("extended_description") or "")
                body = f"{cwe_id}: {name}\n{desc}"
                if ext:
                    body += f"\n{ext}"
                texts.append(body.strip())
            emb = self._embedder_model().embed_documents(texts)
            mat = np.array(emb, dtype=np.float32)
            index = faiss.IndexFlatL2(mat.shape[1])
            index.add(mat)
            rebuilt.mkdir(parents=True, exist_ok=True)
            faiss.write_index(index, str(rebuilt / "index.faiss"))
            index_path = rebuilt / "index.faiss"

        index = faiss.read_index(str(index_path))
        bundle = _IndexBundle(index=index, rows=rows, kind="cwe")
        return bundle

    def _load_vsp_bundle(self) -> _IndexBundle:
        import faiss  # noqa: WPS433

        vsp_dir = ROOT / "vector_dbs" / "problem_solving_vdb"
        index = faiss.read_index(str(vsp_dir / "vsp_faiss_index.faiss"))
        with open(vsp_dir / "vsp_metadata.pickle", "rb") as f:
            metadatas = pickle.load(f)
        with open(vsp_dir / "vsp_chunks.pickle", "rb") as f:
            chunks = pickle.load(f)
        rows = [{"chunk": c, "metadata": m} for c, m in zip(chunks, metadatas)]
        return _IndexBundle(index=index, rows=rows, kind="vsp", metadatas=metadatas)

    def _load_mem_bundle(self) -> _IndexBundle:
        import faiss  # noqa: WPS433

        mem_dir = ROOT / "vector_dbs" / "memorization_vdb"
        rows = json.loads((mem_dir / "chunks.json").read_text(encoding="utf-8"))
        index = faiss.read_index(str(mem_dir / "index.faiss"))
        return _IndexBundle(index=index, rows=rows, kind="mem")

    def _bundle(self, kind: str) -> _IndexBundle:
        with self._lock:
            if kind in self._bundles:
                return self._bundles[kind]
        if kind == "cwe":
            b = self._load_cwe_bundle()
        elif kind == "mem":
            b = self._load_mem_bundle()
        elif kind == "vsp":
            b = self._load_vsp_bundle()
        else:
            raise ValueError(kind)
        with self._lock:
            self._bundles[kind] = b
        return b

    def _search(self, kind: str, query: str, k: int) -> List[Tuple[int, float]]:
        bundle = self._bundle(kind)
        qv = self._embed_query(query)
        k = min(k, bundle.index.ntotal)
        dists, idxs = bundle.index.search(qv, k)
        out: List[Tuple[int, float]] = []
        for i, d in zip(idxs[0], dists[0]):
            if i < 0:
                continue
            score = 1.0 / (1.0 + float(d))
            out.append((int(i), score))
        return out

    def _hits_from_cwe(self, query: str, k: int) -> List[KBHit]:
        bundle = self._bundle("cwe")
        hits: List[KBHit] = []
        for idx, score in self._search("cwe", query, k):
            if idx >= len(bundle.rows):
                continue
            row = bundle.rows[idx]
            cid = str(row.get("cwe_id") or "UNKNOWN").upper()
            if not cid.startswith("CWE-"):
                cid = f"CWE-{cid}"
            name = row.get("name") or ""
            text = (row.get("text") or row.get("description") or "")[:600]
            hits.append(KBHit(doc_id=cid, title=name, text=text, score=score))
        return hits

    def _hits_from_mem(self, query: str, k: int) -> List[KBHit]:
        bundle = self._bundle("mem")
        seen: set[str] = set()
        hits: List[KBHit] = []
        for idx, score in self._search("mem", query, max(k * 3, k)):
            if idx >= len(bundle.rows):
                continue
            content = bundle.rows[idx].get("content") or ""
            for tid in _TID_RE.findall(content):
                key = tid.upper()
                if key in seen:
                    continue
                seen.add(key)
                hits.append(KBHit(doc_id=key, title=key, text=content[:600], score=score))
                if len(hits) >= k:
                    return hits
        return hits[:k]

    def _hits_from_mem_chunks(self, query: str, k: int, *, as_techniques: bool) -> List[KBHit]:
        if as_techniques:
            return self._hits_from_mem(query, k)
        bundle = self._bundle("mem")
        hits: List[KBHit] = []
        for idx, score in self._search("mem", query, k):
            if idx >= len(bundle.rows):
                continue
            row = bundle.rows[idx]
            content = row.get("content") or ""
            hits.append(
                KBHit(
                    doc_id=str(idx),
                    title=str(row.get("url") or idx),
                    text=content[:600],
                    score=score,
                )
            )
        return hits

    def _hits_from_vsp(self, query: str, k: int) -> List[KBHit]:
        bundle = self._bundle("vsp")
        hits: List[KBHit] = []
        for idx, score in self._search("vsp", query, max(k, 8)):
            if idx >= len(bundle.rows):
                continue
            chunk = bundle.rows[idx].get("chunk") or ""
            hits.append(KBHit(doc_id=str(idx), title=f"case-{idx}", text=chunk[:600], score=score))
            if len(hits) >= k:
                break
        return hits

    def retrieve(self, query: str, kind: str, k: int = 5) -> List[KBHit]:
        if kind == "cwe":
            return self._hits_from_cwe(query, k)
        if kind == "mem":
            return self._hits_from_mem(query, k)
        if kind == "vsp":
            return self._hits_from_vsp(query, k)
        raise ValueError(f"Unknown kind {kind!r}")

    def retrieve_mem_chunks(self, query: str, k: int = 5) -> List[KBHit]:
        """Full memorization chunks (same as reasoning_ate FAISS hits)."""
        return self._hits_from_mem_chunks(query, k, as_techniques=False)

    def retrieve_for_task(self, query: str, task: str, k: int = 5) -> List[KBHit]:
        kind = TASK_TARGET.get(task)
        if not kind:
            raise ValueError(f"CTIBench retriever unsupported task {task!r}")
        if task == "mcq":
            return self._hits_from_mem_chunks(query, k, as_techniques=False)
        if task == "ate":
            # CTA-RAG reasoning_ate uses full mem chunks, not technique-ID dedup.
            return self.retrieve_mem_chunks(query, k=k)
        return self.retrieve(query, kind, k=k)

    @staticmethod
    def _cwe_retrieval_enabled() -> bool:
        return (os.getenv("RCM_CWE_RETRIEVAL", "off") or "off").strip().lower() not in {
            "off",
            "0",
            "false",
            "no",
        }

    @staticmethod
    def _format_cwe_hit(hit: KBHit) -> str:
        """Compact catalogue line (mirrors understanding_pipeline._format_cwe_hit)."""
        cwe_id = hit.doc_id or "Unknown"
        name = hit.title or ""
        body = re.sub(r"\s+", " ", (hit.text or "").strip())
        if name and body.lower().startswith(str(cwe_id).lower()):
            parts = body.split(" ", 2)
            if len(parts) >= 3:
                body = parts[2]
        if len(body) > 280:
            body = body[:277].rsplit(" ", 1)[0] + "..."
        return f"{cwe_id}: {name}. {body}".strip()

    def get_docs_cwe(self, doc_ids: List[str]) -> List[KBHit]:
        """Lookup CWE catalogue rows by ID (for confusion-set injection)."""
        if not doc_ids:
            return []
        bundle = self._bundle("cwe")
        if not hasattr(self, "_cwe_by_id"):
            by_id: Dict[str, dict] = {}
            for row in bundle.rows:
                cid = str(row.get("cwe_id") or "").strip().upper()
                if not cid:
                    continue
                if not cid.startswith("CWE-"):
                    cid = f"CWE-{cid}"
                by_id[cid] = row
            self._cwe_by_id = by_id
        out: List[KBHit] = []
        for raw in doc_ids:
            key = str(raw).strip().upper()
            if not key.startswith("CWE-"):
                key = f"CWE-{key}"
            row = self._cwe_by_id.get(key)
            if not row:
                continue
            name = row.get("name") or ""
            text = (row.get("text") or row.get("description") or "")[:600]
            out.append(KBHit(doc_id=key, title=name, text=text, score=0.0))
        return out

    def retrieve_rcm_context(
        self,
        query: str,
        *,
        k_kb: int = 3,
        k_cwe: int = 3,
    ) -> Tuple[str, str, List[KBHit], List[KBHit]]:
        """KB + optional CWE strings for understanding_pipeline-style RCM."""
        kb_hits = self.retrieve_mem_chunks(query, k=k_kb)
        if kb_hits:
            kb_context = "\n\n".join(
                f"Source: {h.title or 'Unknown'}\nContent: {h.text}" for h in kb_hits
            )
        else:
            kb_context = "No knowledge base context available."

        cwe_hits: List[KBHit] = []
        if self._cwe_retrieval_enabled():
            cwe_hits = self._hits_from_cwe(query, k_cwe)
            if cwe_hits:
                cwe_context = "\n".join(self._format_cwe_hit(h) for h in cwe_hits)
            else:
                cwe_context = "No CWE context available."
        else:
            cwe_context = "No CWE context available."

        return kb_context, cwe_context, kb_hits, cwe_hits

    def retrieve_rcm_context_diversified(
        self,
        query: str,
        *,
        k_kb: int = 5,
        k_cwe_audit: int = 20,
        prompt_k: int = 12,
    ) -> Tuple[str, str, List[KBHit], List[KBHit], Any]:
        """
        Same as retrieve_rcm_context but CWE catalogue uses graph-aware
        diversification (eval/cta_rag_port.diversify_cwe_hits). Always retrieves
        CWE (on) for this path so CTIBench matches the CTIConnect GAD setup.
        """
        from eval.cta_rag_port import diversify_cwe_hits  # noqa: WPS433
        from eval.rcm_diversify import DiversifyMeta  # noqa: WPS433

        kb_hits = self.retrieve_mem_chunks(query, k=k_kb)
        if kb_hits:
            kb_context = "\n\n".join(
                f"Source: {h.title or 'Unknown'}\nContent: {h.text}" for h in kb_hits
            )
        else:
            kb_context = "No knowledge base context available."

        dense = self._hits_from_cwe(query, k_cwe_audit)
        prompt_hits, div_meta = diversify_cwe_hits(
            dense,
            lookup_docs=self.get_docs_cwe,
            prompt_k=prompt_k,
            seed_n=5,
            max_per_cluster=3,
            audit_k=k_cwe_audit,
        )
        if prompt_hits:
            cwe_context = "\n".join(self._format_cwe_hit(h) for h in prompt_hits)
        else:
            cwe_context = "No CWE context available."
            div_meta = DiversifyMeta()

        return kb_context, cwe_context, kb_hits, dense, div_meta
