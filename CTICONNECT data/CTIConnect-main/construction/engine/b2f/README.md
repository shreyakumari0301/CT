# B2F (Blog to Framework)

Stage-1 module that extracts CWE / MITRE ATT&CK / CAPEC / CVE references from
threat-intelligence blog posts. The pipeline has three steps, run via `main.py`:

1. **Blog Digger** — LLM analysis of each blog post, emitting candidate
   framework references (`blog_<framework>.jsonl`).
2. **Behavior Annotator** — assigns a stable `behavior_id` to each emitted
   reference (`blog_<framework>_behavior_id.jsonl`).
3. **LLM Annotator** — for each behavior, runs a vector-retrieve-then-LLM
   filter to keep only well-grounded framework matches
   (`blog_<framework>_llm_filtered-enriched.jsonl`).

The outputs used by the rest of the construction pipeline are already
committed under `seeds/correlations/`, so re-running B2F is only needed to
rebuild from scratch or to swap in a different LLM / corpus.

## Layout

```
b2f/
├── main.py                  # entry point (see --help)
├── manage_checkpoints.py    # inspect / reset per-framework checkpoints
├── precompute_embeddings.py # build corpus embedding cache (one-time)
├── core/
│   ├── blog_digger.py
│   ├── behavior_annotator.py
│   └── llm_annotator.py
├── utils/                   # file / LLM / embedding helpers
├── config/settings.py       # paths, model name, retrieval thresholds
└── requirements.txt
```

## Usage

```bash
export OPENAI_API_KEY=...

# Full pipeline for one framework
python main.py --mode full --framework cwe          # or mitre / capec / cve

# Run a single stage
python main.py --mode blog     --framework mitre --limit 10
python main.py --mode behavior --framework mitre
python main.py --mode llm      --framework mitre --force-restart
```

Checkpoints are written to `cache/llm_annotator_<framework>.json` so long runs
can resume after an interrupt. Use `manage_checkpoints.py status|clear|reset|backup`
to inspect or reset them.

## Configuration

Model name and retrieval thresholds are in `config/settings.py`. The defaults
match the settings used in the paper:

- `LLM_MODEL` — reads `B2F_LLM_MODEL` env var (default `o3-mini`)
- `EMBEDDING_MODEL` — `text-embedding-3-large`
- `LLM_SIMILARITY_THRESHOLD` — `0.6` (skip LLM call below this cosine score)
- `LLM_MAX_CANDIDATES` — `5` (top-k candidates per atomic behavior)

## Per-framework strategy

- **MITRE / CAPEC** — decompose the blog text into 2–4 atomic behaviors, run
  vector retrieval per atom, then ask the LLM to confirm each (technique, atom)
  match. Decomposition improves recall on long compound sentences.
- **CWE** — same decomposition + retrieval, but keep at most one CWE per atom
  to favor precision (one root cause per weakness).
- **CVE** — direct match; CVEs are usually named verbatim in the text, so a
  single retrieval + LLM verification is enough.
