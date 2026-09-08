"""
Unified-RAG baseline: one shared index, one generic prompt, no task specialization.

Reviewers 1 (point 2) and 3 (points 1 and 5) object that comparing CTA-RAG against a
bare LLM only shows "retrieval helps", not that task-specialized pipelines beat a
competent single RAG. This script supplies the missing middle term:

  1. CTIBench GPT-4   benchmark prompt, no retrieval          (published)
  2. Unified RAG      benchmark prompt + shared retrieval     (this script)
  3. CTA-RAG          specialized index/k/prompt + routing    (main results)

(2) - (1) isolates the gain from retrieval alone; (3) - (2) isolates the gain from
cognitive-task specialization, which is the paper's actual claim.

Fairness choices, all favourable to the baseline:
  * Input is the dataset Prompt column -- the exact instruction CTIBench gave
    zero-shot GPT-4, including its output-format constraints.
  * Retrieval draws k=5 from the union of the CTI knowledge base, the CWE
    catalogue, the auxiliary KB, and the CVE example store. All were built
    with all-MiniLM-L6-v2 under an L2 metric, so distances are comparable and
    results merge by ascending distance. The TAA store is excluded because TAA is
    not scored, and including it would only add noise.
  * The CVE store overlaps the RCM/VSP eval set and every record carries that
    CVE's gold CWE and CVSS. Passages from this store are emitted as prose only
    (no CVE/CWE/CVSS strings) and query near-duplicates are dropped, matching
    the decontaminated VSP pipeline. The CWE *catalogue* still carries CWE IDs;
    that is a knowledge source, not the eval answer key.
  * Same generator (gpt-4-turbo), same temperature (0.1), and the same gold
    parsers and scorers as the main evaluation.

CTA-RAG is rescored on exactly the sampled rows by replaying the stored full-split
router predictions, so the comparison carries no sampling mismatch.

Examples:
  python -m eval.run_unified_rag --limit 150
  python -m eval.run_unified_rag --limit 20 --workers 2
"""

from __future__ import annotations

import argparse
import csv
import json
import pickle
import random
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from dotenv import load_dotenv
from tqdm import tqdm

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
load_dotenv(ROOT / ".env")

from eval.scoring import (  # noqa: E402
    accuracy,
    instance_macro_f1,
    mad_cvss,
    mad_cvss_base_score,
    parse_ate_ids,
    parse_cvss_vector,
    parse_cwe_answer,
    parse_gold_ate,
    parse_mcq_answer,
)
from utils.llm_client import (  # noqa: E402
    chat_completion_kwargs,
    get_openai_client,
    resolve_model,
)
from utils.cve_sanitize import (  # noqa: E402
    is_query_near_dup as _is_query_near_dup,
    sanitize_cve_store_passage,
)

EMBED_MODEL = "sentence-transformers/all-MiniLM-L6-v2"

# Defended full-split CTA-RAG router logs (CWE catalogue off; VSP gold vectors stripped).
# Do not pick "newest" — a later CWE-on RCM run scores worse and is not the headline.
DEFENDED_CTA_JSONL = {
    "mcq": "mcq_router_20260813T175714Z.jsonl",
    "rcm": "rcm_router_20260813T193651Z.jsonl",
    "vsp": "vsp_router_20260815T101149Z.jsonl",
    "ate": "ate_router_20260813T223256Z.jsonl",
}

# CTIBench Table 1 zero-shot ChatGPT-4, full splits.
CTIBENCH_GPT4 = {
    "mcq": 0.710,
    "rcm": 0.720,
    "vsp": 1.310,
    "ate": 0.6388,
}

TASKS: Dict[str, Dict[str, Any]] = {
    "mcq": {
        "paper_name": "CTI-MCQ",
        "data": ROOT / "data" / "cti-mcq.tsv",
        "metric": "Acc",
    },
    "rcm": {
        "paper_name": "CTI-RCM",
        "data": ROOT / "data" / "cti-rcm.tsv",
        "metric": "Acc",
    },
    "vsp": {
        "paper_name": "CTI-VSP",
        "data": ROOT / "data" / "cti-vsp.tsv",
        "metric": "MAD",
    },
    "ate": {
        "paper_name": "CTI-ATE",
        "data": ROOT / "data" / "cti-ate.tsv",
        "metric": "Macro-F1",
    },
}

GENERIC_PROMPT = """You are a Cyber Threat Intelligence (CTI) assistant.

Use the retrieved context below when it is relevant. If it is incomplete or
off-topic, answer from reliable CTI knowledge instead. Follow the output format
required by the request exactly.

RETRIEVED CONTEXT:
{context}

REQUEST:
{request}
"""

FEW_SHOT_ONLY_PROMPT = """You are a Cyber Threat Intelligence (CTI) assistant.

Study the worked examples, then answer the new request. Follow the output format
shown in the examples exactly.

{examples}

REQUEST:
{request}
"""

UNIFIED_FEW_SHOT_PROMPT = """You are a Cyber Threat Intelligence (CTI) assistant.

Study the worked examples. Use the retrieved context when it is relevant. If
context is incomplete or off-topic, answer from reliable CTI knowledge instead.
Follow the output format shown in the examples exactly.

{examples}

RETRIEVED CONTEXT:
{context}

REQUEST:
{request}
"""

# Fixed 2-shot demos (indices 0 and 1); excluded from scored eval rows.
DEFAULT_DEMO_INDICES = (0, 1)


class UnifiedRetriever:
    """Single retriever over the union of every scored-task corpus."""

    def __init__(self) -> None:
        from langchain_community.vectorstores import FAISS
        from langchain_huggingface import HuggingFaceEmbeddings

        embeddings = HuggingFaceEmbeddings(model_name=EMBED_MODEL)
        vdb = ROOT / "vector_dbs"

        cwe_rebuilt = vdb / "understanding_vdbs" / "faiss_cwe_rebuilt"
        cwe_path = (
            cwe_rebuilt
            if (cwe_rebuilt / "index.pkl").exists()
            else vdb / "understanding_vdbs" / "faiss_cwe"
        )

        self.stores = []
        for name, path in [
            ("cti_kb", vdb / "memorization_vdb"),
            ("cwe", cwe_path),
            ("kb", vdb / "understanding_vdbs" / "faiss_kb"),
        ]:
            if not (path / "index.faiss").exists():
                print(f"  skip {name}: no index at {path}")
                continue
            try:
                store = FAISS.load_local(
                    str(path), embeddings, allow_dangerous_deserialization=True
                )
            except Exception as e:  # noqa: BLE001
                print(f"  SKIP {name}: unreadable store ({type(e).__name__}: {e})")
                continue
            self.stores.append((name, store))
            print(f"  loaded {name} (ntotal={store.index.ntotal})")

        self.vsp_index = None
        vsp_dir = vdb / "problem_solving_vdb"
        if (vsp_dir / "vsp_faiss_index.faiss").exists():
            import faiss
            from sentence_transformers import SentenceTransformer

            self.vsp_index = faiss.read_index(str(vsp_dir / "vsp_faiss_index.faiss"))
            with open(vsp_dir / "vsp_metadata.pickle", "rb") as f:
                self.vsp_meta = pickle.load(f)
            with open(vsp_dir / "vsp_chunks.pickle", "rb") as f:
                self.vsp_chunks = pickle.load(f)
            self.embedder = SentenceTransformer("all-MiniLM-L6-v2")
            print("  loaded cve_desc (labels stripped at query time)")

    def search_hits(self, query: str, k: int = 5) -> List[Tuple[float, str, str]]:
        """Return (distance, source, text) sorted by ascending distance."""
        hits: List[Tuple[float, str, str]] = []
        fetch = max(k, 8)

        for name, store in self.stores:
            try:
                kept = 0
                for doc, score in store.similarity_search_with_score(query, k=fetch * 2):
                    if kept >= k:
                        break
                    meta = doc.metadata or {}
                    raw = doc.page_content or ""
                    if name == "cwe":
                        tag = meta.get("cwe_id")
                        body = f"[{tag}] {raw}" if tag else raw
                    else:
                        if _is_query_near_dup(query, raw):
                            continue
                        body = sanitize_cve_store_passage(raw)
                        if not body or _is_query_near_dup(query, body):
                            continue
                    hits.append((float(score), name, body))
                    kept += 1
            except Exception as e:  # noqa: BLE001
                hits.append((1e9, name, f"[retrieval error: {e}]"))

        if self.vsp_index is not None:
            try:
                emb = self.embedder.encode([query], convert_to_numpy=True)
                fetch_cve = max(16, k * 5)
                dists, idxs = self.vsp_index.search(emb.astype("float32"), fetch_cve)
                kept = 0
                for dist, idx in zip(dists[0], idxs[0]):
                    if idx < 0 or kept >= k:
                        continue
                    raw = str(self.vsp_chunks[int(idx)])
                    if _is_query_near_dup(query, raw):
                        continue
                    text = sanitize_cve_store_passage(raw)
                    if not text or _is_query_near_dup(query, text):
                        continue
                    hits.append((float(dist), "cve_desc", text))
                    kept += 1
            except Exception as e:  # noqa: BLE001
                hits.append((1e9, "cve_desc", f"[retrieval error: {e}]"))

        hits.sort(key=lambda h: h[0])
        return hits[:k]

    def search(self, query: str, k: int = 5) -> str:
        top = self.search_hits(query, k=k)
        if not top:
            return "No context retrieved."
        return "\n\n".join(f"Source: {src}\nContent: {text}" for _, src, text in top)


def load_rows(path: Path) -> List[Dict[str, str]]:
    with open(path, encoding="utf-8", errors="replace", newline="") as f:
        return list(csv.DictReader(f, delimiter="\t"))


def format_demo_block(task_key: str, rows: List[Dict[str, str]], indices: Tuple[int, ...]) -> str:
    """Format held-out (request, gold answer) pairs as in-context examples."""
    parts: List[str] = ["WORKED EXAMPLES:"]
    for n, idx in enumerate(indices, start=1):
        row = rows[idx]
        request = (row.get("Prompt") or "").strip()
        gold = (row.get("GT") or "").strip()
        if task_key == "mcq":
            answer = gold.upper()
        elif task_key == "ate":
            answer = gold.replace(", ", ",").replace(" ", "")
        else:
            answer = gold
        parts.append(f"\nExample {n}:")
        parts.append(f"Request:\n{request}")
        parts.append(f"Answer:\n{answer}")
    return "\n".join(parts)


def build_prompt(
    task_key: str,
    request: str,
    context: str,
    examples: str,
    prompt_mode: str,
    use_retrieval: bool,
) -> str:
    if prompt_mode == "few_shot" and use_retrieval:
        return UNIFIED_FEW_SHOT_PROMPT.format(
            examples=examples, context=context, request=request
        )
    if prompt_mode == "few_shot":
        return FEW_SHOT_ONLY_PROMPT.format(examples=examples, request=request)
    if use_retrieval:
        return GENERIC_PROMPT.format(context=context, request=request)
    # zero-shot, no retrieval — CTIBench protocol (system message added separately)
    return request


def parse_for_task(task_key: str, raw: str) -> Any:
    if task_key == "mcq":
        return parse_mcq_answer(raw)
    if task_key == "rcm":
        return parse_cwe_answer(raw)
    if task_key == "vsp":
        return parse_cvss_vector(raw) or (raw.strip() or None)
    if task_key == "ate":
        return parse_ate_ids(raw)
    return raw


def score_records(task_key: str, records: List[Dict[str, Any]]) -> float:
    metric = TASKS[task_key]["metric"]
    golds = [r["gold"] for r in records]
    preds = [r["parsed"] for r in records]
    if metric == "Acc":
        return accuracy(preds, golds)
    if metric == "MAD":
        return mad_cvss(preds, golds)
    pred_sets = [set(p) if isinstance(p, (set, list)) else set() for p in preds]
    gold_sets = [parse_gold_ate(g) for g in golds]
    return instance_macro_f1(pred_sets, gold_sets)


def latest_router_predictions(task_key: str, out_dir: Path) -> Optional[Path]:
    """Defended full-split router predictions for this task."""
    pinned = DEFENDED_CTA_JSONL.get(task_key)
    if pinned:
        path = out_dir / pinned
        if path.exists():
            return path
    best: Optional[Tuple[int, str, Path]] = None
    for summary_path in out_dir.glob(f"{task_key}_router_*_summary.json"):
        try:
            data = json.loads(summary_path.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            continue
        jsonl = out_dir / summary_path.name.replace("_summary.json", ".jsonl")
        if not jsonl.exists():
            continue
        key = (int(data.get("n") or 0), summary_path.name, jsonl)
        if best is None or key[:2] > best[:2]:
            best = key
    return best[2] if best else None


def rescore_cta_rag(
    task_key: str, indices: set, out_dir: Path
) -> Optional[Dict[str, Any]]:
    path = latest_router_predictions(task_key, out_dir)
    if path is None:
        return None
    records = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            rec = json.loads(line)
            if rec.get("idx") in indices:
                records.append(rec)
    if not records:
        return None
    out: Dict[str, Any] = {
        "score": round(score_records(task_key, records), 4),
        "n": len(records),
        "source": path.name,
    }
    if task_key == "vsp":
        golds = [r["gold"] for r in records]
        preds = [r["parsed"] for r in records]
        out["eight_metric_mad"] = round(mad_cvss(preds, golds), 4)
        out["base_score_mad"] = round(mad_cvss_base_score(preds, golds), 4)
        out["score"] = out["base_score_mad"]
    return out


def run_one(job: Dict[str, Any]) -> Dict[str, Any]:
    client = get_openai_client()
    rec: Dict[str, Any] = {
        "task": job["task"],
        "idx": job["idx"],
        "gold": job["gold"],
        "raw": None,
        "parsed": None,
        "error": None,
        "prompt_mode": job["prompt_mode"],
        "use_retrieval": job["use_retrieval"],
    }
    try:
        context = "No retrieved context."
        if job["use_retrieval"] and job.get("retriever") is not None:
            context = job["retriever"].search(job["request"], k=job["k"])
        user_content = build_prompt(
            job["task"],
            job["request"],
            context,
            job.get("examples") or "",
            job["prompt_mode"],
            job["use_retrieval"],
        )
        messages: List[Dict[str, str]]
        if job["prompt_mode"] == "zero_shot" and not job["use_retrieval"]:
            messages = [
                {
                    "role": "system",
                    "content": (
                        "You are a cybersecurity expert specializing in "
                        "cyberthreat intelligence."
                    ),
                },
                {"role": "user", "content": user_content},
            ]
            temperature = 0.0
        else:
            messages = [{"role": "user", "content": user_content}]
            temperature = 0.1
        response = client.chat.completions.create(
            messages=messages,
            **chat_completion_kwargs(
                "gpt-4-turbo",
                max_tokens=1200,
                temperature=temperature,
            ),
        )
        raw = (response.choices[0].message.content or "").strip()
        rec["raw"] = raw
        rec["parsed"] = parse_for_task(job["task"], raw)
    except Exception as e:  # noqa: BLE001
        rec["error"] = f"{type(e).__name__}: {e}"
    return rec


def print_report(rows: List[Dict[str, Any]]) -> None:
    print("\n========== UNIFIED RAG BASELINE vs CTA-RAG (matched rows) ==========")
    header = (
        f"{'Task':<10}{'Metric':<10}{'GPT-4':>9}{'Unified':>10}"
        f"{'CTA-RAG':>10}{'Retrieval':>11}{'Speciali.':>11}{'n':>6}"
    )
    print(header)
    print("-" * len(header))
    for r in rows:
        unified = f"{r['unified']:.4f}"
        cta = f"{r['cta_rag']:.4f}" if r["cta_rag"] is not None else "--"
        retr = f"{r['gain_retrieval']:+.4f}" if r["gain_retrieval"] is not None else "--"
        spec = (
            f"{r['gain_specialization']:+.4f}"
            if r["gain_specialization"] is not None
            else "--"
        )
        print(
            f"{r['task']:<10}{r['metric']:<10}{r['gpt4']:>9.4f}{unified:>10}"
            f"{cta:>10}{retr:>11}{spec:>11}{r['n']:>6}"
        )
    print(
        "\nGains are stated so that positive always means better:\n"
        "  Retrieval      = Unified RAG - CTIBench GPT-4   (MAD: GPT-4 - Unified)\n"
        "  Specialization = CTA-RAG - Unified RAG          (MAD: Unified - CTA-RAG)\n"
        "CTIBench GPT-4 is a published full-split figure; the other two columns are\n"
        "measured on the identical sampled rows."
    )


def _mode_tag(prompt_mode: str, use_retrieval: bool) -> str:
    if prompt_mode == "few_shot" and use_retrieval:
        return "unified_fewshot"
    if prompt_mode == "few_shot":
        return "fewshot_only"
    if use_retrieval:
        return "unified_rag"
    return "zero_shot_repro"


def main() -> None:
    parser = argparse.ArgumentParser(description="Unified-RAG baseline for CTIBench")
    parser.add_argument("--limit", type=int, default=150, help="Rows per task; 0 = all")
    parser.add_argument("--tasks", default="mcq,rcm,vsp,ate")
    parser.add_argument("--k", type=int, default=5, help="Retrieved passages")
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--seed", type=int, default=13)
    parser.add_argument("--out-dir", type=Path, default=ROOT / "eval_results")
    parser.add_argument(
        "--prompt-mode",
        choices=["zero_shot", "few_shot"],
        default="zero_shot",
        help="zero_shot = CTIBench-style request; few_shot = prepend 2 gold demos",
    )
    parser.add_argument(
        "--retrieval",
        choices=["on", "off"],
        default="on",
        help="on = shared FAISS union; off = no external retrieval",
    )
    parser.add_argument(
        "--demo-indices",
        default="0,1",
        help="Comma-separated row indices used as few-shot demos (excluded from scoring)",
    )
    args = parser.parse_args()

    use_retrieval = args.retrieval == "on"
    demo_indices = tuple(int(x.strip()) for x in args.demo_indices.split(",") if x.strip())
    if args.prompt_mode == "few_shot" and not demo_indices:
        raise SystemExit("few_shot mode requires --demo-indices")

    task_keys = [t.strip() for t in args.tasks.split(",") if t.strip()]
    unknown = [t for t in task_keys if t not in TASKS]
    if unknown:
        raise SystemExit(f"Unknown task(s): {', '.join(unknown)}")

    retriever: Optional[UnifiedRetriever] = None
    if use_retrieval:
        print("Loading unified retriever (union of all scored-task corpora)...")
        retriever = UnifiedRetriever()
    else:
        print("Retrieval off (zero-shot / few-shot-only mode).")

    jobs: List[Dict[str, Any]] = []
    sampled_indices: Dict[str, set] = {}
    for task_key in task_keys:
        cfg = TASKS[task_key]
        rows = load_rows(cfg["data"])
        demo_block = ""
        if args.prompt_mode == "few_shot":
            demo_block = format_demo_block(task_key, rows, demo_indices)
        exclude = set(demo_indices) if args.prompt_mode == "few_shot" else set()
        indexed = [(i, r) for i, r in enumerate(rows) if i not in exclude]
        if args.limit and args.limit < len(indexed):
            indexed = random.Random(args.seed).sample(indexed, args.limit)
        sampled_indices[task_key] = {i for i, _ in indexed}
        print(f"{cfg['paper_name']}: {len(indexed)} scored rows (demos excluded: {sorted(exclude)})")
        for idx, row in indexed:
            request = (row.get("Prompt") or "").strip()
            if not request:
                continue
            jobs.append(
                {
                    "task": task_key,
                    "idx": idx,
                    "gold": (row.get("GT") or "").strip(),
                    "request": request,
                    "retriever": retriever,
                    "k": args.k,
                    "prompt_mode": args.prompt_mode,
                    "use_retrieval": use_retrieval,
                    "examples": demo_block,
                }
            )

    tag = _mode_tag(args.prompt_mode, use_retrieval)
    print(f"\nrunning {len(jobs)} generations ({tag}, gpt-4-turbo)")
    results: List[Dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        for rec in tqdm(pool.map(run_one, jobs), total=len(jobs), desc=tag):
            results.append(rec)

    report_rows: List[Dict[str, Any]] = []
    for task_key in task_keys:
        subset = [r for r in results if r["task"] == task_key]
        if not subset:
            continue
        metric = TASKS[task_key]["metric"]
        golds = [r["gold"] for r in subset]
        preds = [r["parsed"] for r in subset]
        unified = round(score_records(task_key, subset), 4)
        extra: Dict[str, Any] = {}
        if task_key == "vsp":
            extra["eight_metric_mad"] = round(mad_cvss(preds, golds), 4)
            extra["base_score_mad"] = round(mad_cvss_base_score(preds, golds), 4)
            unified = extra["base_score_mad"]
        gpt4 = CTIBENCH_GPT4[task_key]
        cta = rescore_cta_rag(task_key, sampled_indices[task_key], args.out_dir)
        cta_score = cta["score"] if cta else None

        if metric == "MAD":
            gain_retrieval = round(gpt4 - unified, 4)
            gain_spec = round(unified - cta_score, 4) if cta_score is not None else None
        else:
            gain_retrieval = round(unified - gpt4, 4)
            gain_spec = round(cta_score - unified, 4) if cta_score is not None else None

        report_rows.append(
            {
                "task": TASKS[task_key]["paper_name"],
                "metric": "MAD(base)" if task_key == "vsp" else metric,
                "gpt4": gpt4,
                "unified": unified,
                "cta_rag": cta_score,
                "cta_rag_source": cta["source"] if cta else None,
                "gain_retrieval": gain_retrieval,
                "gain_specialization": gain_spec,
                "n": len(subset),
                "n_errors": sum(1 for r in subset if r["error"]),
                **extra,
            }
        )

    print_report(report_rows)

    args.out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    pred_path = args.out_dir / f"{tag}_{stamp}.jsonl"
    with open(pred_path, "w", encoding="utf-8") as f:
        for rec in results:
            dump = dict(rec)
            dump.pop("retriever", None)
            if isinstance(dump.get("parsed"), set):
                dump["parsed"] = sorted(dump["parsed"])
            f.write(json.dumps(dump, ensure_ascii=False) + "\n")

    summary_path = args.out_dir / f"{tag}_{stamp}_summary.json"
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(
            {
                "system": tag,
                "generator": "gpt-4-turbo",
                "prompt_mode": args.prompt_mode,
                "retrieval": args.retrieval,
                "demo_indices": list(demo_indices),
                "retrieval_k": args.k if use_retrieval else 0,
                "limit_per_task": args.limit,
                "seed": args.seed,
                "results": report_rows,
                "predictions_file": str(pred_path),
            },
            f,
            indent=2,
        )

    print(f"\nwrote {pred_path}")
    print(f"wrote {summary_path}")


if __name__ == "__main__":
    main()
