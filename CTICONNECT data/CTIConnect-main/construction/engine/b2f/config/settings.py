"""B2F global configuration."""

import os
from pathlib import Path

# Base paths
WORKSPACE_ROOT = Path(__file__).parent.parent.parent.parent.parent
CORRELATION_DIR = WORKSPACE_ROOT / "construction" / "seeds" / "correlations"
CORPUS_DIR = WORKSPACE_ROOT / "corpus_kb"

# Input corpus files
BLOG_INPUT_FILE = CORPUS_DIR / "blog.jsonl"
CWE_CORPUS_FILE = CORPUS_DIR / "cwe.jsonl"
MITRE_CORPUS_FILE = CORPUS_DIR / "mitre.jsonl"
CAPEC_CORPUS_FILE = CORPUS_DIR / "capec.jsonl"
CVE_CORPUS_FILE = CORPUS_DIR / "cve.jsonl"

# CWE output files
BLOG_CWE_OUTPUT = CORRELATION_DIR / "blog_cwe.jsonl"
BLOG_CWE_FILTERED = CORRELATION_DIR / "blog_cwe_filtered.jsonl"
BLOG_CWE_BEHAVIOR_ID = CORRELATION_DIR / "blog_cwe_behavior_id.jsonl"
BLOG_CWE_LLM_ENRICHED = CORRELATION_DIR / "b2f_cwe.jsonl"

# MITRE output files
BLOG_MITRE_OUTPUT = CORRELATION_DIR / "blog_mitre.jsonl"
BLOG_MITRE_FILTERED = CORRELATION_DIR / "blog_mitre_filtered.jsonl"
BLOG_MITRE_BEHAVIOR_ID = CORRELATION_DIR / "blog_mitre_behavior_id.jsonl"
BLOG_MITRE_LLM_ENRICHED = CORRELATION_DIR / "b2f_mitre.jsonl"

# CAPEC output files
BLOG_CAPEC_OUTPUT = CORRELATION_DIR / "blog_capec.jsonl"
BLOG_CAPEC_FILTERED = CORRELATION_DIR / "blog_capec_filtered.jsonl"
BLOG_CAPEC_BEHAVIOR_ID = CORRELATION_DIR / "blog_capec_behavior_id.jsonl"
BLOG_CAPEC_LLM_ENRICHED = CORRELATION_DIR / "b2f_capec.jsonl"

# CVE output files
BLOG_CVE_OUTPUT = CORRELATION_DIR / "blog_cve.jsonl"
BLOG_CVE_FILTERED = CORRELATION_DIR / "blog_cve_filtered.jsonl"
BLOG_CVE_BEHAVIOR_ID = CORRELATION_DIR / "blog_cve_behavior_id.jsonl"
BLOG_CVE_LLM_ENRICHED = CORRELATION_DIR / "b2f_cve.jsonl"

# LLM
LLM_MODEL = os.getenv("B2F_LLM_MODEL", "o3-mini")
MAX_INPUT_TOKENS = 32768
MAX_OUTPUT_TOKENS = 8000
LLM_TEMPERATURE = 0.1

# Vector retrieval
VECTOR_TOP_K = 10
SIMILARITY_THRESHOLD = 0.5
EMBEDDING_MODEL = "text-embedding-3-large"

# Only call the LLM for candidates above this similarity, and only the top-K.
LLM_SIMILARITY_THRESHOLD = 0.6
LLM_MAX_CANDIDATES = 5

# Batch / retry
BATCH_SIZE = 10
CHECKPOINT_INTERVAL = 100
MAX_RETRIES = 3

# Cache
CACHE_DIR = Path(__file__).parent.parent / "cache"
EMBEDDING_CACHE = CACHE_DIR / "embeddings"
CHECKPOINT_FILE = CACHE_DIR / "checkpoint.json"

CACHE_DIR.mkdir(parents=True, exist_ok=True)
EMBEDDING_CACHE.mkdir(parents=True, exist_ok=True)
