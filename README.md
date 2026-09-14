# CTI-Chatbot (CTA-RAG)

Cognitive-Task-Aware RAG for cyber threat intelligence. This repo contains the
specialist pipelines, the cascade router, and a **controlled multi-system
benchmark** (CTA-RAG vs Closed Book / Unified / Self-RAG / GraphL / Adaptive / TAda).

---

## Setup

```bash
# From repo root
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt

cp .env.example .env               # put OPENAI_API_KEY in .env (never commit .env)
export PYTHONPATH=.
```

CTIBench TSVs live under `data/` (see [xashru/cti-bench](https://github.com/xashru/cti-bench)).  
FAISS indices live under `vector_dbs/`.

---

## Quick evaluation (what you usually want)

Two entry points wrap the controlled runner:

| Goal | Command |
|------|---------|
| **CTA-RAG only** on one dataset | `python -m eval.run_cta_only --task rcm` |
| **All architectures** on one dataset | `python -m eval.run_all_archs --task rcm` |

### 1) Run only CTA-RAG

```bash
# Smoke (50 items)
python -m eval.run_cta_only --task rcm --n 50

# Full CTIBench RCM (1000)
python -m eval.run_cta_only --task rcm

# Other tasks
python -m eval.run_cta_only --task mcq --n 100
python -m eval.run_cta_only --task vsp
python -m eval.run_cta_only --task ate
python -m eval.run_cta_only --task cticonnect_rcm

# Diagnostic: force gold pipeline (oracle), not the live router
python -m eval.run_cta_only --task rcm --n 50 --oracle
```

### 2) Run all architectures on one dataset

Example — compare every main-table system on **RCM**:

```bash
python -m eval.run_all_archs --task rcm --n 50     # smoke
python -m eval.run_all_archs --task rcm            # full 1000
```

Same pattern for other datasets:

```bash
python -m eval.run_all_archs --task mcq --n 100
python -m eval.run_all_archs --task vsp
python -m eval.run_all_archs --task ate
python -m eval.run_all_archs --task cticonnect_rcm
python -m eval.run_all_archs --task cticonnect_ata
```

Useful flags:

```bash
python -m eval.run_all_archs --task rcm --rag-only   # no Closed Book
python -m eval.run_all_archs --task rcm --no-cta     # peers only
python -m eval.run_all_archs --task rcm \
  --systems closed_book,unified_rag,cta_rag_original_e2e
```

### Tasks / full sizes

| `--task` | Benchmark | Full `n` | Metric |
|----------|-----------|----------|--------|
| `mcq` | CTIBench MCQ | 2500 | Acc ↑ |
| `rcm` | CTIBench RCM | 1000 | Acc ↑ |
| `vsp` | CTIBench VSP | 1000 | MAD ↓ |
| `ate` | CTIBench ATE | 60 | F1 ↑ |
| `cticonnect_rcm` | CTIConnect RCM | 290 | F1 ↑ |
| `cticonnect_ata` | CTIConnect ATA | 160 | F1 ↑ |

### Systems (main table)

`closed_book` · `unified_rag` · `self_rag_inspired` · `graphrag_local` ·  
`adaptive_rag_adapted` · `tadarag_inspired` · `cta_rag_original_e2e`

Protocol defaults: `gpt-4-turbo`, temperature `0`, `USE_OPENROUTER=0`, resume on.

---

## Where results go

```text
tcar/eval_results/controlled_benchmark/full/<system>/<task>.jsonl
```

Print a live scoreboard:

```bash
python tcar/eval/controlled_benchmark/print_results_table.py
```

---

## Lower-level runner (optional)

The wrappers call:

```bash
python -u tcar/eval/controlled_benchmark/run_controlled_staged.py \
  --task-worker --task rcm --n 1000 \
  --systems closed_book,unified_rag,...,cta_rag_original_e2e \
  --budget-usd 900
```

Legacy CTA-RAG oracle (older path):

```bash
python -m eval.run_ctibench --route_mode oracle --task rcm --limit 50
```

---

## Repo layout (code you care about)

```text
pipelines/          # CTA specialist pipelines
classifier/         # cascade router
eval/
  run_cta_only.py   # CTA-RAG only
  run_all_archs.py  # all architectures × one dataset
  run_ctibench.py   # legacy CTIBench runner
tcar/eval/controlled_benchmark/   # controlled multi-system protocol
vector_dbs/         # FAISS indices
data/               # CTIBench TSVs (local)
```

Eval dumps under `tcar/eval_results/` and `eval_results/` are **gitignored** — keep them local.

---

## Notes

- Do not commit `.env` or API keys.
- One OpenAI worker is safer under rate limits; parallelize only when quota allows.
- CTA-E2E uses the live router; `--oracle` is diagnostic only (not the main paper table).
