# Tutorial: Evaluating Your LLM on CTIConnect

This walkthrough takes you from a fresh clone to a scored prediction file.

## 0. Install

```bash
git clone <repo-url> && cd cticonnect-benchmark-release
pip install -e .
# For the baselines (retrieval + LLM clients):
pip install -e ".[baselines]"
export OPENAI_API_KEY=...        # if you use the OpenAI-backed baselines
```

## 1. Load the benchmark

```python
from cticonnect import load_task, load_all, list_tasks

list_tasks()
# ['rcm', 'wim', 'atd', 'esd', 'ata', 'vca', 'csc', 'tap', 'mla']

qa = load_task("rcm")[0]
qa.question        # the prompt shown to the model
qa.answer          # the gold reference answer (human-readable)
qa.ground_truth    # structured gold used for automated scoring
qa.eval_type       # 'single_id_match' | 'id_set_match' | 'judge'
```

## 2. Run your model

Your job is to produce a `prediction` string per QA `id`. How you produce it is
up to you — closed-book, your own RAG stack, or one of the shipped baselines.

```python
from cticonnect import load_all, Prediction, write_predictions

def my_model(question: str) -> str:
    # Replace with your model call. Optionally retrieve from corpus_kb/ and
    # corpus_reports/ first.
    ...

preds = []
for task, items in load_all().items():
    for qa in items:
        preds.append(Prediction(id=qa.id, prediction=my_model(qa.question)))

write_predictions(preds, "predictions.jsonl")
```

`predictions.jsonl` is one JSON object per line:

```json
{"id": "rcm-001", "prediction": "CWE-384: the vulnerability allows session fixation ..."}
```

## 3. Retrieval (optional but recommended)

CTIConnect is a *retrieval-augmented* benchmark. The corpora are:

| Corpus | Path | Used by |
|---|---|---|
| Structured KBs | `corpus_kb/{cve,cwe,capec,mitre}.jsonl` | Entity Linking, Entity Attribution |
| Vendor reports | `corpus_reports/preprocessed_reports.jsonl` | Multi-Doc Synthesis, Entity Attribution |
| Knowledge graph | `cskg/` | CSKG-Guided RAG (Multi-Doc Synthesis) |

The paper's shared retrieval setup: `text-embedding-3-large`, FAISS
`IndexFlatIP`, top-k = 5 (EL/EA) or 10 (MDS), report chunks of 1024 tokens
with 128 overlap.

### Multi-Doc Synthesis: use the prebuilt CSKG

For CSC/TAP/MLA, retrieve related reports by entity-set overlap:

```python
import asyncio
from baselines.ctinexus_lite import BM25EntityIndex, Extractor
from baselines.ctinexus_lite.pipeline import retrieve_related_reports

index = BM25EntityIndex.load("cskg/bm25_index.pkl")

result = asyncio.run(retrieve_related_reports(
    anchor_text=anchor_report_text,   # the report given in the QA item
    anchor_doc_id="BLOG-112",
    bm25_index=index,
    k=10,
))
[h.doc_id for h in result.hits]       # related reports to feed your synthesizer
```

## 4. Score

Grading depends on `eval_type`:

- **Entity Linking** (`single_id_match`): normalize identifiers (CVE/CWE/CAPEC/T-ID)
  from your prediction, compare to `ground_truth.target_id` → Precision/Recall/F1.
- **Entity Attribution** (`id_set_match`): extract the *set* of taxonomy IDs from
  your prediction, compare to `ground_truth.target_ids` → set P/R/F1.
- **Multi-Doc Synthesis** (`judge`): an LLM judge decomposes both your prediction
  and `ground_truth.reference_answer` into atomic claims and matches them →
  claim-level P/R/F1.

All three are implemented in `evaluation/`: run
`python -m evaluation.run_eval --predictions preds.jsonl` for the ID-based
metrics, and add `--with-judge` to score the Multi-Doc Synthesis items with the
LLM judge (`evaluation/judge/`).

## 5. Reproduce the paper's baselines

The `baselines/` directory contains reference implementations. Swap the
answering model via config to compare your model against the paper's ten LLMs.
See [`../baselines/README.md`](../baselines/README.md).

## FAQ

**Q: Do I get the gold answer at inference time?**
No. Your model sees only `qa.question` (and whatever it retrieves). `qa.answer`
and `qa.ground_truth` are for scoring.

**Q: For Multi-Doc Synthesis, do I get all the cluster reports?**
No — you get one anchor report. Retrieving the rest from the corpus is the task.

**Q: Can I use a different embedding model / retriever?**
Yes. Report what you used. The benchmark grades the *answer*, not the retrieval
mechanism — though retrieval quality is what makes or breaks the score.
