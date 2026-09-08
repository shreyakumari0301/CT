"""ctinexus-lite: lean STIX-aligned property-graph extraction for CTI reports.

Public API:

    from baselines.ctinexus_lite import (
        ENTITY_TYPES, Entity, Relationship, PropertyGraph,
        chunk_document, BM25EntityIndex,
        extract_graph_from_text,  # available after Phase B
        build_cskg,                # available after Phase E
    )

The library is deliberately small (~700 LOC, 4 pip dependencies) so it is easy
to read, audit, and modify. It follows the two-step extraction pattern used by
HippoRAG / DIGIMON (NER then open relation extraction anchored on the NER
entities) but uses a STIX-aligned entity ontology tailored to CTI corpora and
keeps relation predicates open-vocabulary (we use entity occurrences, not the
relation set, for sparse retrieval).
"""

from baselines.ctinexus_lite.ontology import (
    ENTITY_TYPES,
    Entity,
    Relationship,
    canonical_predicate,
)
from baselines.ctinexus_lite.chunker import Chunk, chunk_document
from baselines.ctinexus_lite.graph import PropertyGraph
from baselines.ctinexus_lite.alias_table import AliasTable, AliasMatch, ALIAS_SEED
from baselines.ctinexus_lite.llm import LLMClient, parse_json_lenient, gather_bounded
from baselines.ctinexus_lite.extractor import Extractor, ExtractionStats
from baselines.ctinexus_lite.sparse_index import (
    BM25EntityIndex, RetrievalHit, tokenize_entity_vocab,
)
from baselines.ctinexus_lite.pipeline import (
    PipelineConfig, PipelineStats, CorpusReport,
    load_corpus, build_cskg, retrieve_related_reports,
)

__version__ = "0.1.0"

__all__ = [
    "__version__",
    "ENTITY_TYPES",
    "Entity",
    "Relationship",
    "canonical_predicate",
    "Chunk",
    "chunk_document",
    "PropertyGraph",
    "AliasTable",
    "AliasMatch",
    "ALIAS_SEED",
    "LLMClient",
    "parse_json_lenient",
    "gather_bounded",
    "Extractor",
    "ExtractionStats",
    "BM25EntityIndex",
    "RetrievalHit",
    "tokenize_entity_vocab",
    "PipelineConfig",
    "PipelineStats",
    "CorpusReport",
    "load_corpus",
    "build_cskg",
    "retrieve_related_reports",
]
