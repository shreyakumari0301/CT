"""CSKG-Guided RAG baseline for CTIConnect multi-document synthesis tasks.

The retrieval stage is implemented in ``ctinexus_lite``; this package wraps
it with two thin CLIs:

* ``build_index.py`` — offline pass: extract entities from every report and
  persist a BM25-indexable property graph under ``cskg/v2/``.
* ``run.py``         — online query: given an anchor report and a question,
  retrieve top-k related reports and prompt an answering LLM.
"""
