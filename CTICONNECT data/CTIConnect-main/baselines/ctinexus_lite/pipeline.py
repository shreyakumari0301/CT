"""End-to-end orchestrator: corpus JSONL → property graph → BM25 index.

Typical usage from the CLI:

    python -m baselines.cskg_guided.build_index \\
        --corpus corpus_reports/preprocessed_reports.jsonl \\
        --output cskg/v2 \\
        --concurrency 8

What gets written to ``output_dir``:

    cskg/v2/
    ├── manifest.json                  # version, parameters, stats
    ├── entities.jsonl                  # one canonical entity per line
    ├── relations.jsonl                 # one open-RE triple per line
    ├── graph.graphml                   # NetworkX graph for visualisation
    ├── bm25_index.pkl                  # the pickled BM25EntityIndex
    └── per_doc_entities.jsonl          # one row per doc, listing its entities

The pipeline is *resumable in spirit but not yet in implementation*: if
something fails midway, re-run with the same output directory and previously
written per-doc graphs will be skipped (see ``skip_existing``).
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from baselines.ctinexus_lite.alias_table import AliasTable
from baselines.ctinexus_lite.chunker import chunk_document
from baselines.ctinexus_lite.extractor import Extractor, ExtractionStats
from baselines.ctinexus_lite.graph import PropertyGraph
from baselines.ctinexus_lite.llm import LLMClient
from baselines.ctinexus_lite.ontology import Entity
from baselines.ctinexus_lite.sparse_index import BM25EntityIndex


log = logging.getLogger("ctinexus_lite.pipeline")


# ---------------------------------------------------------------------------
# Corpus loading
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CorpusReport:
    """One report loaded from the corpus JSONL."""
    doc_id: str              # e.g. "BLOG-0"
    title: str
    text: str
    publish_date: str | None = None
    link: str | None = None
    vendor: str | None = None


def load_corpus(corpus_path: str | Path) -> list[CorpusReport]:
    """Read ``corpus_reports/*.jsonl`` and normalise each row to a CorpusReport.

    The corpus file is expected to have rows with ``id``, ``title``,
    ``preprocessed`` (the entity-preserving summary), ``publish_date`` (optional),
    ``link`` (optional), and ``metadata.platform`` (optional, vendor name).
    """
    out: list[CorpusReport] = []
    with Path(corpus_path).open(encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except json.JSONDecodeError as e:
                log.warning("skipping malformed line %d: %s", line_num, e)
                continue
            raw_id = d.get("id")
            if raw_id is None:
                continue
            doc_id = f"BLOG-{raw_id}" if not str(raw_id).startswith("BLOG-") else str(raw_id)
            text = d.get("preprocessed") or d.get("body") or d.get("text") or ""
            if not text.strip():
                continue
            meta = d.get("metadata") or {}
            out.append(CorpusReport(
                doc_id=doc_id,
                title=d.get("title", "") or "",
                text=text,
                publish_date=d.get("publish_date"),
                link=d.get("link"),
                vendor=meta.get("platform") if isinstance(meta, dict) else None,
            ))
    return out


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------

@dataclass
class PipelineStats:
    n_reports_total: int = 0
    n_reports_processed: int = 0
    n_reports_skipped: int = 0
    n_chunks_total: int = 0
    extraction_usage: dict[str, int] = field(default_factory=lambda: {
        "prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0,
    })
    n_entities_global: int = 0
    n_relationships_global: int = 0
    elapsed_seconds: float = 0.0


@dataclass
class PipelineConfig:
    corpus_path: Path
    output_dir: Path
    chunk_size: int = 1024
    chunk_overlap: int = 128
    concurrency: int = 8                # in-flight LLM calls within a single report
    report_concurrency: int = 8         # concurrent reports processed in parallel
    model: str | None = None            # override LLMClient default
    max_reports: int | None = None      # for smoke tests
    skip_existing: bool = True

    def __post_init__(self) -> None:
        self.corpus_path = Path(self.corpus_path)
        self.output_dir = Path(self.output_dir)


async def build_cskg(config: PipelineConfig) -> PipelineStats:
    """Run extraction across the corpus and produce CSKG artifacts.

    Returns aggregate statistics. The function is async because the extractor
    fans out per-chunk LLM calls with bounded concurrency.
    """
    t0 = time.time()
    stats = PipelineStats()
    output_dir = config.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    reports = load_corpus(config.corpus_path)
    stats.n_reports_total = len(reports)
    if config.max_reports is not None:
        reports = reports[:config.max_reports]
    log.info("Loaded %d reports from %s (using %d)",
             stats.n_reports_total, config.corpus_path, len(reports))

    # Initialise extractor (also instantiates the LLM client + alias table).
    llm_kwargs: dict[str, Any] = {}
    if config.model:
        llm_kwargs["model"] = config.model
    extractor = Extractor(
        llm=LLMClient(**llm_kwargs),
        concurrency=config.concurrency,
        alias_table=AliasTable(),
    )

    # Per-doc subgraphs (kept on disk so we can resume); plus a global graph
    # that accumulates every extraction.
    per_doc_dir = output_dir / "per_doc"
    per_doc_dir.mkdir(exist_ok=True)
    global_graph = PropertyGraph()
    per_doc_entity_vocab: dict[str, list[str]] = {}

    # Process reports in parallel with a semaphore. Each report still does
    # its NER + RE sequentially (one chunk in most cases), but we fan out
    # across reports so the corpus completes in O(N / report_concurrency).
    report_sem = asyncio.Semaphore(config.report_concurrency)
    progress = {"done": 0, "total": len(reports)}

    async def _one_report(idx: int, report: CorpusReport) -> tuple[CorpusReport, PropertyGraph, dict]:
        async with report_sem:
            per_doc_entities_file = per_doc_dir / f"{report.doc_id}.entities.jsonl"
            per_doc_rels_file = per_doc_dir / f"{report.doc_id}.relations.jsonl"

            if config.skip_existing and per_doc_entities_file.exists() and per_doc_rels_file.exists():
                progress["done"] += 1
                log.info("[%d/%d] %s: cached", progress["done"], progress["total"], report.doc_id)
                return (
                    report,
                    PropertyGraph.from_jsonl(per_doc_entities_file, per_doc_rels_file),
                    {"cached": True, "usage": {}, "n_chunks": 0},
                )

            chunks = chunk_document(
                report.text,
                doc_id=report.doc_id,
                chunk_size=config.chunk_size,
                overlap=config.chunk_overlap,
            )
            doc_graph = PropertyGraph()
            doc_stats = ExtractionStats()
            await extractor.extract_document(chunks, graph=doc_graph, stats=doc_stats)
            doc_graph.to_jsonl(per_doc_entities_file, per_doc_rels_file)

            progress["done"] += 1
            log.info("[%d/%d] %s: %d chunks, %d entities",
                     progress["done"], progress["total"], report.doc_id,
                     len(chunks), doc_graph.n_entities)
            return (
                report,
                doc_graph,
                {"cached": False, "usage": dict(doc_stats.usage), "n_chunks": len(chunks)},
            )

    results = await asyncio.gather(*[
        _one_report(i, r) for i, r in enumerate(reports, 1)
    ])

    # Merge results into the global graph sequentially (no async hazards).
    for report, doc_graph, meta in results:
        if meta["cached"]:
            stats.n_reports_skipped += 1
        else:
            stats.n_reports_processed += 1
            stats.n_chunks_total += meta["n_chunks"]
            for k in ("prompt_tokens", "completion_tokens", "total_tokens"):
                stats.extraction_usage[k] = (
                    stats.extraction_usage.get(k, 0)
                    + (meta["usage"].get(k, 0) if meta["usage"] else 0)
                )
        for e in doc_graph.entities():
            global_graph.add_entity(e)
        for r in doc_graph.relationships():
            global_graph.add_relationship(r)
        per_doc_entity_vocab[report.doc_id] = _collect_surface_forms(
            doc_graph.entities()
        )

    # ---- write top-level artifacts ----
    entities_path = output_dir / "entities.jsonl"
    relations_path = output_dir / "relations.jsonl"
    global_graph.to_jsonl(entities_path, relations_path)
    global_graph.to_graphml(output_dir / "graph.graphml")
    stats.n_entities_global = global_graph.n_entities
    stats.n_relationships_global = global_graph.n_relationships

    # ---- build BM25 index ----
    index = BM25EntityIndex.build(per_doc_entity_vocab)
    index.save(output_dir / "bm25_index.pkl")
    index.to_jsonl_for_debug(output_dir / "per_doc_entities.jsonl")

    # ---- write manifest ----
    stats.elapsed_seconds = time.time() - t0
    manifest = {
        "version": "v0.1.0",
        "model": config.model or "default",
        "chunk_size": config.chunk_size,
        "chunk_overlap": config.chunk_overlap,
        "concurrency": config.concurrency,
        "n_reports_total": stats.n_reports_total,
        "n_reports_processed_this_run": stats.n_reports_processed,
        "n_reports_skipped_cached": stats.n_reports_skipped,
        "n_chunks_total": stats.n_chunks_total,
        "n_entities_global": stats.n_entities_global,
        "n_relationships_global": stats.n_relationships_global,
        "entities_by_type": global_graph.stats()["entities_by_type"],
        "extraction_usage": stats.extraction_usage,
        "elapsed_seconds": round(stats.elapsed_seconds, 2),
    }
    (output_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return stats


def _collect_surface_forms(entities) -> list[str]:
    """Flatten an iterable of Entity objects into a deduplicated surface list."""
    seen: set[str] = set()
    out: list[str] = []
    for e in entities:
        for surf in e.vocab:
            if surf and surf not in seen:
                seen.add(surf)
                out.append(surf)
    return out


# ---------------------------------------------------------------------------
# Online retrieval helper
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class RetrievalResult:
    hits: list[Any]                  # list[RetrievalHit]
    anchor_entities: list[str]


async def retrieve_related_reports(
    anchor_text: str,
    *,
    anchor_doc_id: str | None = None,
    bm25_index: BM25EntityIndex,
    extractor: Extractor | None = None,
    k: int = 10,
) -> RetrievalResult:
    """Online CSKG-Guided retrieval.

    Extract entities from ``anchor_text``, then query the prebuilt BM25 index.
    """
    extractor = extractor or Extractor()
    chunks = chunk_document(anchor_text, doc_id=anchor_doc_id or "ANCHOR")
    g = PropertyGraph()
    await extractor.extract_document(chunks, graph=g)
    surfaces = _collect_surface_forms(g.entities())
    exclude: set[str] = {anchor_doc_id} if anchor_doc_id else set()
    hits = bm25_index.search(surfaces, k=k, exclude_doc_ids=exclude)
    return RetrievalResult(hits=hits, anchor_entities=surfaces)
