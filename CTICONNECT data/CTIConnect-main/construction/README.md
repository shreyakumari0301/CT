# CTIConnect — Data Construction Framework

This directory contains the open-source pipeline that produced the **691 expert-curated QA pairs** released under [`data/`](../data/). The framework implements the three-stage construction process described in paper §3.2.4 and on the [project page](../paper/) under *"Construction pipeline & data composition"*:

```
Stage 1: Seed annotation             → seeds/correlations/, seeds/b2f/, seeds/clusters/
Stage 2: Template-constrained QA     → engine/t2p (render) + engine/p2d (synthesize)
Stage 3: LLM-as-a-Judge curation     → ../evaluation/judge/run_judge.py
```

The **seed files** (Stage 1 output) are committed as authoritative ground truth. Stages 2–3 are fully automated and reproducible from the seeds using a single command.

---

## Reproduction

Stage 2 and Stage 3 are reproduced by running the per-task commands shown below
against the committed seeds in `seeds/`. The release packaging step
([`../scripts/build_release.py`](../scripts/build_release.py)) then consolidates
the per-task outputs into the canonical artifact in [`../data/`](../data/).

```bash
export OPENAI_API_KEY=...
# Render prompts and synthesize QA per task (see "Stage 2" below)
# Run LLM-as-a-Judge triage (see "Stage 3" below)
python ../scripts/build_release.py
```

---

## What's in each directory

| Path | Role |
|---|---|
| `templates/{task}/v*.jinja` | Stage-2 Jinja2 templates per task. Canonical versions pinned in [`templates/README.md`](templates/README.md). |
| `engine/t2p/` | Renders templates over the seed correlations into per-pair prompt files (`prompts/{task}/v*/batch_*/<SRC>-<TGT>.txt`). No API calls. |
| `engine/p2d/` | Reads prompt files, calls the LLM, writes per-pair QA JSON (`data/{task}/v*/batch_*/<SRC>-<TGT>.json`). |
| `engine/b2f/` | Stage-1 Blog-to-Framework extraction. Produces `seeds/correlations/blog_{mitre,cwe}_llm_filtered-enriched.jsonl`. **Optional — its outputs are already committed.** |
| `engine/report_preprocessing/` | Compresses long vendor reports into entity-preserving outputs (`../corpus_reports/preprocessed_reports.jsonl`, `preprocessed` field). |
| `engine/t2p/` | Renders templates over the seed correlations into per-pair prompt files. No API calls. |
| `engine/p2d/` | Reads prompt files, calls the LLM, writes per-pair QA JSON. |

---

## Stage 1 — Seed annotation (outputs committed)

Stage 1 establishes ground-truth correlations between heterogeneous CTI sources. Its outputs are committed in the repository root so users do not need to re-mine them.

| Task family | Seed files | Origin |
|---|---|---|
| **Entity Linking** (RCM, WIM, ATD, ESD) | `seeds/correlations/{cve,cwe,capec}_xrefs.jsonl` | Hard-coded traversal of official MITRE/NVD cross-references in [`../corpus_kb/`](../corpus_kb/). |
| **Entity Attribution** (ATA, VCA) | `seeds/b2f/B2F-cwe.jsonl`, `seeds/correlations/b2f_{cwe,mitre}.jsonl` | LLM-based blog-to-framework extraction (`engine/b2f/`) followed by dual expert annotation with senior adjudication (paper §3.2.2). |
| **Multi-Doc Synthesis** (CSC, TAP, MLA) | `seeds/clusters/cluster_*.json` | Manual clustering of related reports followed by metadata reconciliation (paper §3.2.3). |

> **Re-running Stage 1 from scratch** requires the original blog corpus (321 reports, ~50 MB of long-form text) which is **not redistributed** for copyright reasons — only its preprocessed outputs (in `corpus_reports/preprocessed_reports.jsonl`) and per-blog URLs (in `corpus_reports/`) are shipped. The seed outputs above are therefore treated as committed artifacts.

---

## Stage 2 — Template-constrained QA synthesis

Stage 2 is fully automated. Each task uses one canonical Jinja2 template and one engine route.

| Task | Template | Stage-2 input | Stage-2 output |
|---|---|---|---|
| RCM | `templates/rcm/v4.jinja` | `seeds/correlations/cve_xrefs.jsonl` | `data/rcm/v4/batch_*/<CVE>-<CWE>.json` |
| WIM | `templates/wim/v3.jinja` | `seeds/correlations/cwe_xrefs.jsonl` | `data/wim/v3/batch_*/<CWE>-<CVE>.json` |
| ATD | `templates/atd/v5.jinja` | `seeds/correlations/capec_xrefs.jsonl` | `data/atd/v5/batch_*/<CAPEC>-<T-ID>.json` |
| ESD | `templates/esd/v3.jinja` | `seeds/correlations/cwe_xrefs.jsonl` | `data/esd/v3/batch_*/<CWE>-<CAPEC>.json` |
| ATA | `templates/ata/v5.jinja` | `seeds/correlations/b2f_mitre.jsonl` | `data/ata/v5/batch_*/<BLOG>-<T-ID>.json` |
| VCA | `templates/vca/v4.jinja` | `seeds/correlations/b2f_cwe.jsonl` | `data/vca/v4/batch_*/<BLOG>-<CWE>.json` |
| CSC | `templates/csc/v6.jinja` | `seeds/clusters/cluster_*.json` | `data/csc/v6/batch_*/<cluster>-<aspect>.json` |
| TAP | `templates/tap/v2.jinja` | (same as CSC) | `data/tap/v2/batch_*/<cluster>-<aspect>.json` |
| MLA | `templates/mla/v2.jinja` | (same as CSC) | `data/mla/v2/batch_*/<cluster>-<aspect>.json` |

### Running Stage 2 for one task

```bash
# 1. Render prompts (no API cost)
python engine/t2p/run_generator.py \
    --corpus-dir ../corpus_kb --correlation-dir seeds/correlations \
    --task rcm --template-version v4 \
    --enable-batching --batch-size 25 --restart

# 2. Synthesize QA via LLM
python engine/p2d/run_generator.py \
    --task rcm --template-version v4 --batch-id batch_1 \
    --model gpt-4o --max-jobs 25 --no-timestamp --overwrite
```

The p2d generator is sequential by design (one API call at a time + 0 s delay). It reads the `OPENAI_API_KEY` environment variable.

### Key design choices in the templates

The canonical templates explicitly forbid the LLM from leaking source/target identifiers into the question text. This is critical for Entity Linking: a question like *"Which CWE does CVE-2024-1234 map to?"* trivialises retrieval to regex+dict lookup. The v3+/v4+/v5+ EL templates therefore include rules such as:

> **Must NOT contain the source CVE ID** (e.g., do not write "CVE-2020-36775"). The model under evaluation must infer the answer from the behavior alone.
> **Must NOT contain identifiers that uniquely fingerprint the specific CVE** — including vendor product names with version, exact internal function/method names, exact API endpoint paths, or exact file paths.

See [`templates/README.md`](templates/README.md) for the canonical-version policy.

---

## Stage 3 — LLM-as-a-Judge construction triage

Implements paper Appendix C.1 (`app:con_judge`): a GPT-class model scores each generated QA on a 1–5 scale across five rubric dimensions (factual correctness, relevance, clarity, task consistency, completeness). Items with score ≥ 3 are retained for optional expert second-stage review; items with score < 3 are discarded.

```bash
python ../evaluation/judge/run_judge.py \
    --input-dir data/rcm/v4/batch_1 \
    --model gpt-4o
```

This rewrites each QA JSON in-place, adding two fields:

```json
{
  "question": "...",
  "answer": "...",
  "triage_score": 5,
  "triage_assessment": "The answer correctly maps the described path traversal-enabled arbitrary file deletion to CWE-73 (External Control of File Name or Path)..."
}
```

Pass `--filter-out passed/` to additionally copy score-≥-3 items into a clean directory.

The judge prompt is in [`../evaluation/judge/mds_rubric.jinja`](../evaluation/judge/mds_rubric.jinja) — a verbatim port of the prompt shown in paper Appendix C.1.

---

## Release packaging (final stage)

After Stage 3 produces scored QAs, [`../scripts/build_release.py`](../scripts/build_release.py) does the final consolidation:

1. Walks each task's `data/{task}/v*/batch_*/` directory.
2. Validates each QA (no ID leakage in question, non-empty answer description, target ID actually appears in the answer).
3. Subsamples to the paper's per-task counts (`{rcm:100, wim:100, atd:100, esd:100, ata:60, vca:90, csc:51, tap:55, mla:35}`) using a fixed seed (`SEED=42`) for reproducibility.
4. Assigns stable IDs (`rcm-001`, `rcm-002`, ...) after final ordering.
5. Writes JSONL to `data/{category}/{task}.jsonl` and a SHA256-stamped `data/manifest.json`.

```bash
python ../scripts/build_release.py
# task   cand accept  ship  skip_nq  skip_fn  skip_idQ  skip_emp  skip_tgt
# rcm     120    120   100        0        0         0         0         0
# ...
# Total shipped: 691 (paper target: 691)
```

---

## Extending the framework

To add a new task or new CTI source:

1. Add a new Jinja2 template under `templates/<new_task>/v1.jinja` following the existing rules.
2. Add a `correlation_file` entry for `<new_task>` in [`engine/t2p/generator.py`](engine/t2p/generator.py) `load_correlation_data()`.
3. If the task introduces a new (source, target) type pair, add an `ID_PATTERNS[task]` entry in [`../scripts/build_release.py`](../scripts/build_release.py) covering the filename regex, source/target types, and eval type.
4. If the task is open-ended (free-text answer), set `eval_type = "judge"` so the leaderboard evaluator routes it through `evaluation/judge/mds_rubric.jinja` rather than regex matching.

---

## Reproducibility notes

- **Determinism.** Subsampling uses `random.Random(42)`. Re-running `build_release.py` is byte-identical.
- **LLM nondeterminism.** Stage 2 and Stage 3 use temperature defaults (model-dependent). Re-running these stages produces semantically equivalent but not byte-identical output. The canonical 691-QA release in `../data/` is the frozen reference.
- **Snapshot dates.** `../corpus_kb/MANIFEST.json` records the snapshot dates of each KB source so reviewers can confirm the framework targets the same versions used in the paper.

---

## Frequently asked questions

**Q: Can the framework regenerate all 691 QAs without my having the original blog corpus?**

Yes. The seeds — including the LLM-extracted blog ↔ framework correlations and the cluster manifests — are committed. Stage 1 modules (`engine/b2f/`) are shipped for transparency but are not required.

**Q: Why are there multiple template versions per task (e.g., `csc/v1` … `csc/v7`)?**

Each version corresponds to an iteration of the construction process. Only the canonical version per task is used by the release pipeline; older versions are kept for provenance and ablation. See [`templates/README.md`](templates/README.md).

**Q: What is the LLM judge protecting against?**

Hallucination (Stage-2 output that doesn't ground in the seed), under-specification (vague questions that have many correct answers), and identifier leakage that the template-level checks missed. The triage score is a recall-favoring filter — it keeps borderline cases for optional expert review (score = 3) and discards only clearly bad samples (score < 3).
