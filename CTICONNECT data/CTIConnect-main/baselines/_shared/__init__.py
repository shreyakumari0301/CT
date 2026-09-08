"""Shared retrieval + LLM infrastructure for the CTIConnect baselines.

Mirrors the paper's setup (App. retrieval_details):
  - Embedder: OpenAI text-embedding-3-large (3072-d, L2-normalized)
  - Vector index: exact inner-product search == FAISS IndexFlatIP over
    L2-normalized vectors (== cosine). Implemented in numpy (the corpora are a
    few thousand entries, so brute-force exact search is instant and identical
    to FAISS).
  - LLM client: OpenAI-compatible chat wrapper (works with the OPENAI_BASE_URL
    in the environment; swap in LiteLLM for other providers).
"""
