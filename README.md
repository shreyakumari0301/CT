# CTA-RAG

Code and manuscript for **Cognitive-Task-Aware Retrieval-Augmented Generation** for cyber threat intelligence.

CTA-RAG maps an analyst request to one of four cognitive modes (memorization, understanding, problem-solving, reasoning) implemented as six specialists. Each specialist uses its own index, prompt, and parser.

| Mode | Task | Output |
|---|---|---|
| Memorization | CTIBench MCQ | A–D letter |
| Understanding | CTIBench RCM | Primary CWE-ID |
| Problem-solving | CTIBench VSP | CVSS v3.1 vector |
| Reasoning | CTIBench ATE | ATT&CK technique-ID set |
| Reasoning | CTIBench TAA | Actor name (top-3 pick) |
| Reasoning | CTIConnect ATA | Single ATT&CK ID (open) |

Comparators: Closed Book, Unified RAG, Self-RAG, Graph RAG, Adaptive-RAG, TAdaRAG. CTIConnect supplies external RCM and ATA.

Numbers, paired tests, and limitations are in the paper, not in this README.

## Layout

```text
classifier/llm_classifier.py     Cascade router
pipelines/                       Six specialists
utils/                           LLM client, CVE sanitization, TAA retrieval
eval/run_all_archs.py            Shared-corpus peer systems
eval/run_cta_only.py             CTA-RAG runner
eval/cticonnect_*.py             CTIConnect loader and metrics
eval/controlled_benchmark/       TAA CombSUM and ATA hybrid / open generation
paper_results/main.tex           Manuscript (Elsevier elsarticle)
paper_results/references.bib
paper_results/figures/           Architecture SVG source
```

Indexes (`vector_dbs/`), datasets (`data/`), and run dumps (`eval_results/`) are local. They are not part of this repository.

## Setup

Python 3.10+, OpenAI-compatible credentials, FAISS, sentence-transformers.

```bash
git clone https://github.com/shreyakumari0301/CT.git
cd CT
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

Put CTIBench and CTIConnect files under `data/` and the matching FAISS stores under `vector_dbs/` (same snapshots used in the paper).

## Paper

`paper_results/main.tex` uses the Elsevier `elsarticle` class.

```bash
cd paper_results
pdflatex main.tex
bibtex main
pdflatex main.tex
pdflatex main.tex
```

## Evaluation (after data and indexes are in place)

```bash
python eval/run_cta_only.py
python eval/run_all_archs.py --task rcm --n 50
python eval/controlled_benchmark/run_ata_cta_open_v2.py
python eval/controlled_benchmark/run_taa_cta_combsum_constrained.py
```

Do not mix predictions from different prompt versions, models, or corpus snapshots.

## License

Research code. CTIBench, CTIConnect, MITRE ATT&CK, CWE/NVD, FAISS, and model APIs keep their own terms. Do not redistribute indexes or benchmark files unless those licenses allow it.
