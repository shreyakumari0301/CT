# TCAR: Taxonomy-Contrastive Adaptive RAG

Isolated research implementation — **does not modify** `eval/run_cticonnect.py`, CTA-RAG pipelines, or `CTICONNECT benchmark/protocol.json`.

## Idea

Instead of feeding the LLM the top-*k* most similar CWE/ATT&CK catalogue passages, TCAR:

1. **Builds a taxonomy confusion set** (retrieved ID + parent/child/sibling neighbours from CWE xrefs or ATT&CK ID structure).
2. **Scores candidates** with support / contradiction / abstraction penalties using rule-based attributes (no extra LLM).
3. **Builds contrast cards** (“support vs against”) instead of long raw passages.
4. **Gates retrieval** — if evidence is ambiguous, **falls back to closed-book** (protects strong CB baseline).
5. **ATA matcher** — constrains output to techniques linked to explicit behaviours; reduces over-prediction.

## Layout

```
tcar/
  config.py           # hyperparameters + ablation variants
  taxonomy/           # CWE graph (cwe_xrefs), MITRE hierarchy
  attributes.py       # rule-based RCM/ATA attribute extraction
  corpus_store.py     # CWE/MITRE row lookup from corpus_kb
  contrast.py         # contrastive scoring + contrast cards
  gate.py             # reliability gate
  ata_matcher.py      # constrained behaviour→technique matching
  pipeline.py         # TCARPipeline (RCM + ATA)
  predict.py          # QARecord adapter
  prompts.py
  eval/
    run_benchmark.py  # standalone CTIConnect eval runner
  eval_results/       # outputs here (not CTICONNECT benchmark/)
```

## Run (smoke test)

From repo root with `OPENAI_API_KEY` and WSL venv:

```bash
source cti_env/bin/activate
python -m tcar.eval.run_benchmark --limit 5 --workers 1
```

Full overlap + ablations:

```bash
python -m tcar.eval.run_benchmark --limit 0 --workers 3 --compare
```

Single ablation:

```bash
python -m tcar.eval.run_benchmark --variant no_gate --limit 50
```

## Variants (experiments)

| `--variant`   | Meaning                                      |
|---------------|----------------------------------------------|
| `full`        | confusion set + contrast cards + gate        |
| `no_gate`     | always use contrast retrieval                |
| `no_confusion`| top-*k* only (no taxonomy expansion)         |
| `no_contrast` | (set in config; use with custom runner)      |
| `closed_book` | gate never admits retrieval                  |

## Outputs

- `tcar/eval_results/tcar_<stamp>.jsonl` — predictions + `tcar_meta` (gate, candidates, scores)
- `tcar/eval_results/tcar_<stamp>_summary.json` — CTIConnect P/R/F1
- `tcar/eval_results/scoreboard_<stamp>.json` — multi-variant comparison

## Compare to existing systems

Reuse prior closed-book / port jsonl from `CTICONNECT benchmark/eval_results/` for paper tables; TCAR results stay under `tcar/eval_results/` so nothing in the frozen protocol is overwritten.

## Next steps (research)

- Oracle ablations: `--variant` + set `oracle_confusion` / `oracle_gate` in `TCARConfig`
- Fixed-candidate eval (same top-*k* as vanilla; only contrast module differs)
- Hierarchical CWE parent/child credit in scorer
- Learned attribute extractor (optional; current design is LLM-free except final answer)
