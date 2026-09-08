"""TCAR pipeline: confusion set -> contrast score -> gate -> LLM."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from eval.cticonnect_kb import CTIConnectKBRetriever, KBHit

from tcar.ata_matcher import constrained_ata_select
from tcar.config import TCARConfig
from tcar.contrast import (
    build_contrast_card,
    score_ata_candidates,
    score_rcm_candidates,
)
from tcar.corpus_store import CorpusStore
from tcar.gate import GateDecision, evaluate_gate
from tcar.prompts import (
    ATA_CLOSED_BOOK,
    ATA_CONTRAST,
    RCM_CLOSED_BOOK,
    RCM_CONTRAST,
)
from tcar.taxonomy.cwe_graph import CWEGraph
from tcar.taxonomy.mitre_graph import MitreGraph

ROOT = Path(__file__).resolve().parent.parent


@dataclass
class TCARResult:
    prediction: str
    meta: Dict[str, Any] = field(default_factory=dict)


class TCARPipeline:
    def __init__(
        self,
        cfg: Optional[TCARConfig] = None,
        *,
        retriever: Optional[CTIConnectKBRetriever] = None,
        chat: Optional[Callable[..., str]] = None,
        store: Optional[CorpusStore] = None,
    ) -> None:
        self.cfg = (cfg or TCARConfig()).apply_variant()
        corpus = ROOT / self.cfg.corpus_kb
        self.retriever = retriever or CTIConnectKBRetriever(corpus_dir=corpus)
        self.store = store or CorpusStore(corpus)
        self.cwe_graph = CWEGraph(ROOT / self.cfg.cwe_xrefs)
        self.mitre_graph = MitreGraph()
        self._chat = chat

    def _ensure_chat(self, chat: Optional[Callable[..., str]]) -> Callable[..., str]:
        if chat:
            return chat
        if self._chat:
            return self._chat
        from eval.run_cticonnect import _cticonnect_chat  # noqa: WPS433

        return _cticonnect_chat

    def _retrieve(self, question: str, task: str) -> List[KBHit]:
        return self.retriever.retrieve_for_task(question, task, k=self.cfg.k_retrieve)

    def _hits_to_ids(self, hits: List[KBHit], kind: str) -> List[str]:
        ids: List[str] = []
        for h in hits:
            if kind == "cwe":
                cid = h.doc_id.upper()
                if not cid.startswith("CWE-"):
                    cid = f"CWE-{cid}"
                ids.append(cid)
            else:
                tid = h.doc_id.upper()
                if not tid.startswith("T"):
                    tid = f"T{tid}"
                ids.append(tid)
        return ids

    def _similarity_map(self, hits: List[KBHit], kind: str) -> Dict[str, float]:
        sim: Dict[str, float] = {}
        for h in hits:
            key = h.doc_id.upper()
            if kind == "cwe" and not key.startswith("CWE-"):
                key = f"CWE-{key}"
            if kind == "mitre" and not key.startswith("T"):
                key = f"T{key}"
            sim[key] = float(h.score)
        return sim

    def _store_text_blob(self, kind: str, doc_id: str) -> str:
        if kind == "cwe":
            row = self.store.cwe(doc_id)
        else:
            row = self.store.mitre(doc_id)
        if not row:
            return doc_id
        return f"{row.get('title', '')} {row.get('contents', '')[:1500]}"

    def predict_rcm(
        self,
        question: str,
        *,
        chat: Optional[Callable[..., str]] = None,
        gold_id: Optional[str] = None,
    ) -> TCARResult:
        chat_fn = self._ensure_chat(chat)
        hits = self._retrieve(question, "rcm")
        seed_ids = self._hits_to_ids(hits, "cwe")
        sim = self._similarity_map(hits, "cwe")

        if self.cfg.use_confusion_set:
            expanded: List[str] = []
            for sid in seed_ids[:3]:
                for cid in self.cwe_graph.confusion_set([sid], max_size=self.cfg.max_confusion):
                    expanded.append(cid)
            if self.cfg.oracle_confusion and gold_id:
                expanded = list(dict.fromkeys([gold_id.upper()] + expanded))
            candidate_ids = list(dict.fromkeys(expanded))[: self.cfg.max_confusion]
        else:
            candidate_ids = seed_ids[: self.cfg.k_retrieve]

        scored = score_rcm_candidates(question, candidate_ids, sim, self.store, self.cfg)
        store_text = {cid: self._store_text_blob("cwe", cid) for cid in candidate_ids}
        gate = evaluate_gate(question, scored, store_text, self.cfg)

        meta: Dict[str, Any] = {
            "task": "rcm",
            "seed_ids": seed_ids,
            "candidate_ids": candidate_ids,
            "gate": gate.__dict__,
            "scored": [
                {
                    "id": s.doc_id,
                    "total": round(s.total, 4),
                    "support": round(s.support, 3),
                    "contradiction": round(s.contradiction, 3),
                }
                for s in scored[:5]
            ],
        }

        if gate.admit_retrieval and self.cfg.use_contrast_cards:
            card = build_contrast_card(scored, self.store, "cwe")
            prompt = RCM_CONTRAST.format(contrast_card=card, question=question)
            raw = chat_fn(prompt, max_tokens=512)
            meta["mode"] = "contrast_retrieval"
        else:
            prompt = RCM_CLOSED_BOOK.format(question=question)
            raw = chat_fn(prompt, max_tokens=512)
            meta["mode"] = "closed_book_fallback"

        meta["raw"] = raw[:2000]
        return TCARResult(prediction=raw, meta=meta)

    def predict_ata(
        self,
        question: str,
        *,
        chat: Optional[Callable[..., str]] = None,
        gold_ids: Optional[List[str]] = None,
    ) -> TCARResult:
        chat_fn = self._ensure_chat(chat)
        hits = self._retrieve(question, "ata")
        seed_ids = self._hits_to_ids(hits, "mitre")
        sim = self._similarity_map(hits, "mitre")

        if self.cfg.use_confusion_set:
            expanded: List[str] = []
            subs = {p: self.store.mitre_subtechniques(p) for p in set(s.split(".")[0] for s in seed_ids)}
            for sid in seed_ids[:3]:
                for tid in self.mitre_graph.confusion_set(
                    [sid], subs, max_size=self.cfg.max_confusion
                ):
                    expanded.append(tid)
            if self.cfg.oracle_confusion and gold_ids:
                expanded = list(dict.fromkeys([g.upper() for g in gold_ids] + expanded))
            candidate_ids = list(dict.fromkeys(expanded))[: self.cfg.max_confusion]
        else:
            candidate_ids = seed_ids[: self.cfg.k_retrieve]

        scored = score_ata_candidates(question, candidate_ids, sim, self.store, self.cfg)
        store_text = {tid: self._store_text_blob("mitre", tid) for tid in candidate_ids}
        gate = evaluate_gate(question, scored, store_text, self.cfg)

        meta: Dict[str, Any] = {
            "task": "ata",
            "seed_ids": seed_ids,
            "candidate_ids": candidate_ids,
            "gate": gate.__dict__,
            "scored": [
                {
                    "id": s.doc_id,
                    "total": round(s.total, 4),
                    "support": round(s.support, 3),
                }
                for s in scored[:5]
            ],
        }

        if gate.admit_retrieval and self.cfg.use_contrast_cards:
            card = build_contrast_card(scored, self.store, "mitre")
            prompt = ATA_CONTRAST.format(contrast_card=card, question=question)
            raw = chat_fn(prompt, max_tokens=700)
            if self.cfg.use_ata_matcher:
                selected = constrained_ata_select(question, scored, self.store)
                meta["matcher_ids"] = selected
                # Rewrite answer line if model over-generated
                if selected:
                    raw = raw.split("answer:")[0] + "answer: " + ", ".join(selected)
            meta["mode"] = "contrast_retrieval"
        else:
            prompt = ATA_CLOSED_BOOK.format(question=question)
            raw = chat_fn(prompt, max_tokens=700)
            meta["mode"] = "closed_book_fallback"

        meta["raw"] = raw[:2000]
        return TCARResult(prediction=raw, meta=meta)

    def predict(
        self,
        task: str,
        question: str,
        *,
        chat: Optional[Callable[..., str]] = None,
        ground_truth: Optional[dict] = None,
    ) -> TCARResult:
        gt = ground_truth or {}
        if task == "rcm":
            gold = gt.get("target_id")
            return self.predict_rcm(question, chat=chat, gold_id=gold)
        if task == "ata":
            gids = gt.get("target_ids") or ([gt["target_id"]] if gt.get("target_id") else [])
            return self.predict_ata(question, chat=chat, gold_ids=gids)
        raise ValueError(f"TCAR supports rcm/ata only; got {task!r}")
