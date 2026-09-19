# CTA-RAG — Cognitive-Task-Aware Retrieval-Augmented Generation

CTA-RAG is a task-conditional retrieval-augmented generation system for cyber threat intelligence (CTI). It routes an unlabelled analyst request to a specialist pipeline whose evidence source, prompt, decoding, parser, and evaluation contract match the requested decision.

The repository contains the implementation, controlled benchmark runners, saved evaluation artifacts, and the paper manuscript.

## What CTA-RAG does

A single CTI queue may contain several different requests:

```text
MCQ question ──┐
CWE mapping  ──┤
CVSS scoring ──┼──▶ automatic router ──▶ one specialist ──▶ validated output
ATT&CK extraction ─┤
Actor attribution ─┘
```

The router selects one of five primary CTA-RAG specialists:

| Specialist | Task | Output contract |
|---|---|---|
| Memorization | CTIBench MCQ | One answer letter (A–D) |
| Understanding | CTIBench RCM | Primary CWE identifier |
| Problem-solving | CTIBench VSP | Complete CVSS v3.1 vector |
| Reasoning-ATE | CTIBench ATE | ATT&CK technique-ID set |
| Reasoning-TAA | CTIBench TAA | Threat actor or family |

The CTIConnect ATA experiment is an additional end-to-end attribution evaluation and is reported separately from the five-task primary router.

## Architecture

```text
raw analyst query
      │
      ▼
┌──────────────────────────────┐
│ Cascade router               │
│ regex → classifier → override│
└──────────────┬───────────────┘
               │ one task label
   ┌───────────┼───────────┬───────────────┬──────────────┐
   ▼           ▼           ▼               ▼              ▼
 MCQ        RCM          VSP             ATE            TAA
   │           │           │               │              │
 task index  CTI KB   sanitized CVEs  ATT&CK store  actor store
 task prompt CWE JSON CVSS rules      T-ID list     attribution
   │           │           │               │              │
   └───────────┴───────────┴───────────────┴──────────────┘
                         ▼
              schema parser + scorer
```

Only the selected specialist executes. Retrieval is task-scoped; output validation is deterministic where the contract permits it.

### TAA pipeline

The CTIBench threat-actor attribution specialist is the `reasoning_taa`
pipeline. It performs attribution in six observable steps:

```text
unlabelled report
      ↓
router selects reasoning_taa
      ↓
behavioural clue extraction
      ↓
report + clues form an enriched query
      ↓
top-3 retrieval from the intrusion-set / actor store
      ↓
actor or family attribution
      ↓
canonical actor parsing and TAA scoring
```

The generator receives the retrieved actor evidence and produces one actor or
family name. Evaluation records both benchmark-compatible matching and strict
canonical identity. The candidate-inclusion retrieval audit is exploratory and
does not replace the reported end-to-end CTA-RAG TAA result.

## Repository layout

```text
classifier/
  llm_classifier.py                 Router and fallback classifier
pipelines/
  memorization_pipeline.py          MCQ specialist
  understanding_pipeline.py         RCM specialist
  problem_solving_pipeline.py       VSP specialist
  reasoning_ate_pipeline.py         ATE specialist
  reasoning_taa_pipeline.py         TAA specialist
  errors.py                          Pipeline/API error handling
utils/
  llm_client.py                     Shared model client
  cve_sanitize.py                   CVE retrieval sanitization
  taa_actor_retrieval.py             TAA candidate retrieval utilities
eval/
  run_ctibench.py                   CTIBench loader and dispatch
  run_all_archs.py                  Controlled baseline runner
  run_cta_only.py                   CTA-RAG runner
  scoring.py                        Shared parsing and metrics
  cticonnect_loader.py              CTIConnect loader
  cticonnect_metrics.py             CTIConnect scoring
  controlled_benchmark/              Resumable controlled experiments
vector_dbs/                          Local FAISS indexes and metadata
data/                               CTIBench and CTIConnect inputs
eval_results/                        Saved predictions, manifests, and reports
paper_results/main.tex               Main manuscript
paper_results/references.bib         Bibliography
paper_results/statistical_appendix.tex Supplementary statistical tables
paper_results/figures/               Editable paper figures
```

Dataset files, vector indexes, API keys, and large run outputs are local assets and may be excluded from Git. Keep the exact dataset and index versions used for a run.

## Setup

### Requirements

- Python 3.10 or newer
- OpenAI-compatible model credentials used by the configured client
- FAISS and sentence-transformers for retrieval
- LaTeX/pdflatex plus the Springer Nature `sn-jnl.cls` and `sn-mathphys-num.bst` files to compile the manuscript

Create an environment and install dependencies:

```bash
git clone https://github.com/shreyakumari0301/CT.git
cd CT
python -m venv .venv
# Windows
.venv\Scripts\activate
# macOS/Linux
source .venv/bin/activate
pip install -r requirements.txt
```

Create `.env` from `.env.example` and add the model credentials required by the selected runner. Never commit `.env` or API keys.

## Data and retrieval assets

Place the CTIBench task files and CTIConnect records under `data/` using the paths expected by the loaders. Place the corresponding FAISS indexes and metadata under `vector_dbs/`. Retrieval assets are not generated automatically by installing the package; they must be provisioned from the same corpus versions used in the evaluation.

The primary controls use dense FAISS retrieval. The reported CTIConnect ATA run uses the frozen entity-guided configuration with its configured retrieval strategy. Hybrid retrieval is an orthogonal experiment and should not be assumed for the primary CTIBench tables.

## Running evaluations

Run a small smoke test before a full experiment:

```bash
python eval/controlled_benchmark/run_controlled_smoke.py
```

Run a selected CTIBench task or architecture through the controlled harness:

```bash
python eval/run_ctibench.py
python eval/run_all_archs.py
python eval/run_cta_only.py
```

Full runs can be resumed with the staged controlled runner in `eval/controlled_benchmark/`. Keep worker-state files and manifests with the saved predictions. Do not mix outputs from different prompts, model versions, scorer versions, or corpus snapshots.

## Reported evaluation results

The current manuscript reports the following end-to-end results. These values are descriptive point estimates; consult the manuscript and appendix for paired tests, confidence intervals, denominators, and limitations.

| Task | CTA-RAG result | Strongest reported comparator |
|---|---:|---:|
| CTIBench MCQ | 74.84% | Adaptive-RAG-adapted: 75.48% |
| CTIBench RCM | 73.40% | CTA-RAG: 73.40% |
| CTIBench VSP | MAD 1.0990 | CTA-RAG: 1.0990 |
| CTIBench ATE | F1 0.9554 | CTA-RAG: 0.9554 |
| CTIBench TAA | 25/50 benchmark-compatible | Entity-Guided Multi-Query RAG: 37/50 |
| CTIConnect ATA | 75/160 | Entity-Guided Multi-Query RAG: 79/160 |
| CTIConnect RCM | 149/290 | CTA-RAG: 149/290 |

Automatic routing selects the expected specialist for 4,550/4,560 primary CTIBench items (99.78%). This measures routing under benchmark instructions and does not establish robustness to paraphrased or unconstrained analyst requests. The existing TAA/ATA outputs stored under the internal `tadarag_inspired` directory correspond to the paper's Dual-Query RAG row; internal directory names are not paper method names.

## Manuscript

The main paper is `paper_results/main.tex`. The manuscript uses the Springer Nature class and bibliography style:

```text
paper_results/sn-jnl.cls
paper_results/sn-mathphys-num.bst
paper_results/references.bib
```

Compile with pdfLaTeX and BibTeX after placing the Springer template files beside `main.tex`:

```bash
cd paper_results
pdflatex main.tex
bibtex main
pdflatex main.tex
pdflatex main.tex
```

The editable CTA-RAG architecture figure is in `paper_results/figures/`. Paper diagrams should remain editable TikZ/SVG sources; use the installed `paper-figure-creation` skill for new figures and plots.

## Reproducibility

Saved runs should retain item-level predictions, normalized outputs, prompt versions, model identifiers, corpus/index fingerprints, route decisions, parser status, and analysis seeds. Statistics must be recomputed from frozen records rather than manually transcribed table values. API generation can vary across model revisions, so paired intervals describe item-sampling uncertainty rather than repeated-generation variability.

## Known limitations

- The primary benchmark is CTIBench; external transfer is evaluated on selected CTIConnect tasks.
- TAA and ATA use distinct attribution contracts and should not be read as uniform transfer evidence.
- Baselines are local mechanism adaptations, not necessarily full reproductions of upstream trained systems.
- Retrieval, prompting, routing, and parsing vary together in the complete-system comparison.
- Query-time sanitization does not prove index independence or resistance to poisoning and prompt injection.
- The candidate-inclusion TAA diagnostic is post-hoc and exploratory; it is not a replacement for the reported end-to-end CTA-RAG score.

## License and attribution

This repository is an internal research implementation. It uses FAISS, sentence-transformers, CTIBench, CTIConnect, MITRE ATT&CK, CWE/NVD content, and model-provider APIs. Respect the licenses and terms of each source when redistributing datasets, indexes, or reports.
