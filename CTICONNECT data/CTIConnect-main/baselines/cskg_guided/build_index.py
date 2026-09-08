#!/usr/bin/env python3
"""Offline CSKG construction CLI.

Run from the repository root:

    # Smoke test with 5 reports
    python -m baselines.cskg_guided.build_index \\
        --corpus corpus_reports/preprocessed_reports.jsonl \\
        --output cskg/v2_smoke \\
        --max-reports 5 \\
        --concurrency 4

    # Full corpus build
    python -m baselines.cskg_guided.build_index \\
        --corpus corpus_reports/preprocessed_reports.jsonl \\
        --output cskg/v2 \\
        --concurrency 8

Required env var: ``OPENAI_API_KEY``. The model defaults to whatever the
``CTINEXUS_MODEL`` env var points to, or ``gpt-4o`` if unset.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
from pathlib import Path

# Make the repo root importable when running this file directly.
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from baselines.ctinexus_lite import build_cskg, PipelineConfig


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build the CTIConnect CSKG (entities + relations + BM25 index).",
    )
    parser.add_argument(
        "--corpus", required=True, type=Path,
        help="Path to corpus_reports/*.jsonl (one row per report)",
    )
    parser.add_argument(
        "--output", required=True, type=Path,
        help="Output directory (e.g. cskg/v2). Created if missing.",
    )
    parser.add_argument(
        "--chunk-size", type=int, default=1024,
        help="Tokens per chunk (default 1024, matches paper Vanilla RAG)",
    )
    parser.add_argument(
        "--chunk-overlap", type=int, default=128,
        help="Token overlap between consecutive chunks (default 128)",
    )
    parser.add_argument(
        "--concurrency", type=int, default=8,
        help="In-flight LLM calls within a single report (default 8)",
    )
    parser.add_argument(
        "--report-concurrency", type=int, default=8,
        help="Number of reports processed in parallel (default 8)",
    )
    parser.add_argument(
        "--model", type=str, default=None,
        help="Override extractor LLM model (default: env CTINEXUS_MODEL or gpt-4o)",
    )
    parser.add_argument(
        "--max-reports", type=int, default=None,
        help="Limit processing to first N reports (for smoke tests)",
    )
    parser.add_argument(
        "--no-skip-existing", action="store_true",
        help="Force re-extraction even if per-doc results already exist",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Set log level to INFO",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    config = PipelineConfig(
        corpus_path=args.corpus,
        output_dir=args.output,
        chunk_size=args.chunk_size,
        chunk_overlap=args.chunk_overlap,
        concurrency=args.concurrency,
        report_concurrency=args.report_concurrency,
        model=args.model,
        max_reports=args.max_reports,
        skip_existing=not args.no_skip_existing,
    )

    print(f"Building CSKG from {config.corpus_path} -> {config.output_dir}")
    print(f"  chunk_size={config.chunk_size}, overlap={config.chunk_overlap}, "
          f"concurrency={config.concurrency}, model={config.model or 'default'}")
    if config.max_reports:
        print(f"  max_reports={config.max_reports} (smoke test)")

    stats = asyncio.run(build_cskg(config))

    print()
    print("Build complete:")
    print(f"  reports total          : {stats.n_reports_total}")
    print(f"  reports processed now  : {stats.n_reports_processed}")
    print(f"  reports skipped cached : {stats.n_reports_skipped}")
    print(f"  chunks total           : {stats.n_chunks_total}")
    print(f"  entities (global graph): {stats.n_entities_global}")
    print(f"  relations (global)     : {stats.n_relationships_global}")
    print(f"  LLM tokens             : {stats.extraction_usage['total_tokens']}")
    print(f"  elapsed                : {stats.elapsed_seconds:.1f}s")
    print(f"  manifest               : {config.output_dir / 'manifest.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
