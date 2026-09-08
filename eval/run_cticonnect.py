"""
Evaluate overlapping CTIConnect tasks (RCM, ATA) with CTIConnect baselines,
Unified RAG, strong RAG baselines, and CTA-RAG specialized pipelines.

Overlap with CTIBench:
  RCM (CVE -> CWE)     ~ CTI-RCM
  ATA (report -> ATT&CK set) ~ CTI-ATE

Scoring uses CTIConnect mean P/R/F1 over identifier sets (evaluation/metrics.py).

Examples:
  python -m eval.run_cticonnect --limit 10 --workers 2
  python -m eval.run_cticonnect --systems closed_book,vanilla_rag,cta_rag --tasks rcm,ata
  python -m eval.run_cticonnect --compare --limit 0 --workers 3
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import threading
import time
import traceback
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from dotenv import load_dotenv
from tqdm import tqdm

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
load_dotenv(ROOT / ".env")

from eval.cticonnect_kb import (  # noqa: E402
    CTIConnectKBRetriever,
    KBHit,
    format_candidates,
)
from eval.cticonnect_official_prompts import (  # noqa: E402
    DTR_DECOMPOSE,
    DTR_VALIDATE,
    DTR_VALIDATE_SYSTEM,
    ETR_ANSWER,
    ETR_ANSWER_SYSTEM,
    ETR_CANON_RCM,
    ETR_EXTRACT,
    VANILLA_RAG_PROMPT,
    VANILLA_RAG_SYSTEM,
)
from eval.cticonnect_loader import OVERLAP_TASKS, QARecord, load_tasks  # noqa: E402
from eval.cticonnect_metrics import ItemScore, aggregate_scores, score_id_item  # noqa: E402
from utils.llm_client import (  # noqa: E402
    chat_completion_kwargs,
    get_openai_client,
    resolve_classifier_model,
    resolve_model,
)

CTICONNECT_DATA = ROOT / "CTICONNECT data" / "data"
CTICONNECT_CORPUS = ROOT / "CTICONNECT data" / "CTIConnect-main" / "corpus_kb"
OUT_DEFAULT = ROOT / "CTICONNECT data" / "eval_results"

CLOSED_BOOK_SYSTEM = (
    "You are a Cyber Threat Intelligence expert. Answer the question "
    "directly and concisely. When the question asks for a CWE, CVE, "
    "CAPEC, or MITRE ATT&CK identifier, state the exact identifier "
    "(e.g., CWE-79, T1059.001) explicitly in your answer."
)

UNIFIED_PROMPT = """You are a Cyber Threat Intelligence (CTI) assistant.

Use the retrieved context below when it is relevant. If it is incomplete or
off-topic, answer from reliable CTI knowledge instead. Follow the output format
required by the request exactly.

RETRIEVED CONTEXT:
{context}

REQUEST:
{request}
"""

CRITIQUE_PROMPT = """You are a retrieval critic for a CTI question-answering system.
Decide whether the retrieved passages should be used to answer the request.

REQUEST:
{request}

RETRIEVED PASSAGES:
{context}

Reply with exactly one token: RELEVANT, PARTIAL, or IRRELEVANT."""

ENTITY_PROMPT = """Extract distinctive CTI entities from this request for graph-style retrieval.
Return a JSON list of short strings (max 8). Include CWE IDs, ATT&CK technique IDs (Txxxx),
CVE IDs, product names, malware names, and vulnerability classes.
Request:
{request}
JSON list only:"""

TADARAG_INTENT_PROMPT = """Detect the CTI output intent of this request for knowledge-graph extraction.
Reply with exactly one token:
RCM — map to CWE weakness ID
ATE — list MITRE ATT&CK technique IDs (entity attribution)
GENERAL — other CTI QA

REQUEST:
{request}
"""

TADARAG_KG_TEMPLATES = {
    "RCM": "Focus on vulnerability descriptions, weakness classes, and CWE-related entities.",
    "ATE": "Focus on attack procedures, techniques (Txxxx), tactics, and malware behaviours.",
    "GENERAL": "Focus on CTI entities: actors, malware, techniques, weaknesses, products.",
}

TADARAG_EXTRACT_KG_PROMPT = """Build a small task-adaptive knowledge graph from these CTI passages.
{template_hint}
Return JSON only:
{{"entities":[{{"name":"string","type":"technique|weakness|malware|product|other"}}],
 "relations":[{{"src":"name","rel":"short relation","dst":"name"}}]}}
Max 12 entities and 15 relations. No CVE IDs or CVSS vectors in names.

PASSAGES:
{passages}
"""

_TASK_TADARAG_INTENT = {"rcm": "RCM", "ata": "ATE"}

PIPELINE_FOR_TASK = {"rcm": "understanding", "ata": "reasoning_ate"}

_WRITE_LOCK = threading.Lock()
_RUNNER_CACHE: Dict[str, Callable[[str], str]] = {}


def _resolve_cticonnect_model() -> str:
    return resolve_model((os.environ.get("CTICONNECT_MODEL") or "gpt-4o").strip() or "gpt-4o")


def _chat(
    user: str,
    *,
    system: Optional[str] = None,
    temperature: float = 0.0,
    max_tokens: int = 800,
    model: Optional[str] = None,
) -> str:
    client = get_openai_client()
    messages: List[Dict[str, str]] = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": user})
    resp = client.chat.completions.create(
        messages=messages,
        **chat_completion_kwargs(
            model or "gpt-4-turbo",
            max_tokens=max_tokens,
            temperature=temperature,
        ),
    )
    return (resp.choices[0].message.content or "").strip()


def _cticonnect_chat(
    user: str,
    *,
    system: Optional[str] = None,
    temperature: float = 0.0,
    max_tokens: int = 800,
) -> str:
    return _chat(
        user,
        system=system,
        temperature=temperature,
        max_tokens=max_tokens,
        model=_resolve_cticonnect_model(),
    )


def _critique(context: str, request: str) -> str:
    client = get_openai_client()
    resp = client.chat.completions.create(
        messages=[
            {"role": "user", "content": CRITIQUE_PROMPT.format(context=context, request=request)},
        ],
        **chat_completion_kwargs(
            resolve_classifier_model("gpt-4o-mini"),
            max_tokens=16,
            temperature=0.0,
        ),
    )
    text = (resp.choices[0].message.content or "").strip().upper()
    for label in ("RELEVANT", "PARTIAL", "IRRELEVANT"):
        if label in text:
            return label
    return "PARTIAL"


def _extract_entities(request: str) -> List[str]:
    raw = _cticonnect_chat(ENTITY_PROMPT.format(request=request), temperature=0.0, max_tokens=200)
    m = re.search(r"\[[\s\S]*\]", raw)
    if not m:
        return []
    try:
        vals = json.loads(m.group(0))
        return [str(v).strip() for v in vals if str(v).strip()][:8]
    except json.JSONDecodeError:
        return []


def get_pipeline_runner(name: str) -> Callable[[str], str]:
    if name in _RUNNER_CACHE:
        return _RUNNER_CACHE[name]
    if name == "understanding":
        from pipelines import understanding_pipeline as mod
    elif name == "reasoning_ate":
        from pipelines import reasoning_ate_pipeline as mod
    else:
        raise ValueError(name)
    _RUNNER_CACHE[name] = mod.run
    return mod.run


def predict_closed_book(qa: QARecord, _ctx: Dict[str, Any]) -> str:
    return _cticonnect_chat(qa.question, system=CLOSED_BOOK_SYSTEM, max_tokens=512)


def predict_vanilla_rag(qa: QARecord, ctx: Dict[str, Any]) -> str:
    retriever: CTIConnectKBRetriever = ctx["cti_kb"]
    hits = retriever.retrieve_for_task(qa.question, qa.task, k=ctx["k"])
    prompt = VANILLA_RAG_PROMPT.format(
        question=qa.question,
        candidates=format_candidates(hits),
    )
    return _cticonnect_chat(prompt, system=VANILLA_RAG_SYSTEM, max_tokens=512)


def predict_etr(qa: QARecord, ctx: Dict[str, Any]) -> str:
    if qa.task != "rcm":
        return predict_vanilla_rag(qa, ctx)
    retriever: CTIConnectKBRetriever = ctx["cti_kb"]
    hint = ETR_CANON_RCM
    keys = _cticonnect_chat(
        ETR_EXTRACT.format(
            framework=hint["framework"],
            style=hint["style"],
            question=qa.question,
        ),
        max_tokens=128,
    ).strip()
    query = keys or qa.question
    hits = retriever.retrieve_for_task(query, qa.task, k=ctx["k"])
    prompt = ETR_ANSWER.format(
        question=qa.question,
        keys=keys,
        candidates=format_candidates(hits),
    )
    return _cticonnect_chat(prompt, system=ETR_ANSWER_SYSTEM, max_tokens=512)


def predict_dtr(qa: QARecord, ctx: Dict[str, Any]) -> str:
    if qa.task != "ata":
        return predict_vanilla_rag(qa, ctx)
    retriever: CTIConnectKBRetriever = ctx["cti_kb"]
    raw = _cticonnect_chat(DTR_DECOMPOSE.format(question=qa.question), max_tokens=256)
    behaviors = [b.strip("-* \t") for b in raw.splitlines() if b.strip()][:5]
    if not behaviors:
        behaviors = [qa.question]
    blocks = []
    for b in behaviors:
        hits = retriever.retrieve_for_task(b, qa.task, k=ctx["k"])
        blocks.append(f"Behavior: {b}\nCandidates:\n{format_candidates(hits, max_chars=300)}")
    prompt = DTR_VALIDATE.format(
        question=qa.question,
        behavior_blocks="\n\n---\n\n".join(blocks),
    )
    return _cticonnect_chat(prompt, system=DTR_VALIDATE_SYSTEM, max_tokens=700)


def _format_cti_context(hits: List[KBHit]) -> str:
    if not hits:
        return "(none)"
    return "\n\n".join(
        f"[{h.doc_id}] {h.title}\n{(h.text or '')[:600]}" for h in hits
    )


def _retrieve_cti_hits(qa: QARecord, ctx: Dict[str, Any], query: str, *, k: int | None = None) -> List[KBHit]:
    retriever: CTIConnectKBRetriever = ctx["cti_kb"]
    return retriever.retrieve_for_task(query, qa.task, k=k or ctx["k"])


def _classifier_one_line(prompt: str, max_tokens: int = 16) -> str:
    client = get_openai_client()
    resp = client.chat.completions.create(
        messages=[{"role": "user", "content": prompt}],
        **chat_completion_kwargs(
            resolve_classifier_model("gpt-4o-mini"),
            max_tokens=max_tokens,
            temperature=0.0,
        ),
    )
    return (resp.choices[0].message.content or "").strip()


def _merge_cti_hits(
    qa: QARecord,
    ctx: Dict[str, Any],
    queries: List[str],
    *,
    k: int | None = None,
) -> List[KBHit]:
    limit = k or ctx["k"]
    merged: Dict[str, Tuple[float, KBHit]] = {}
    per_q = max(3, limit)
    for q in queries:
        if not q.strip():
            continue
        for hit in _retrieve_cti_hits(qa, ctx, q, k=per_q):
            key = f"{hit.doc_id}:{(hit.text or '')[:400]}"
            prev = merged.get(key)
            if prev is None or hit.score > prev[0]:
                merged[key] = (hit.score, hit)
    ranked = sorted(merged.values(), key=lambda h: h[0], reverse=True)
    return [h for _, h in ranked[: limit + 2]]


def _detect_tadarag_intent(request: str, task: str) -> str:
    raw = _classifier_one_line(
        TADARAG_INTENT_PROMPT.format(request=request[:6000]),
        max_tokens=8,
    ).upper()
    for label in ("RCM", "ATE", "GENERAL"):
        if label in raw:
            return label
    return _TASK_TADARAG_INTENT.get(task, "GENERAL")


def _extract_tadarag_kg(passages: str, intent: str) -> str:
    hint = TADARAG_KG_TEMPLATES.get(intent, TADARAG_KG_TEMPLATES["GENERAL"])
    raw = _classifier_one_line(
        TADARAG_EXTRACT_KG_PROMPT.format(template_hint=hint, passages=passages[:8000]),
        max_tokens=700,
    )
    raw = re.sub(r"^```(?:json)?", "", raw).replace("```", "").strip()
    obj: Dict[str, Any] = {"entities": [], "relations": []}
    try:
        obj = json.loads(raw)
    except json.JSONDecodeError:
        m = re.search(r"\{.*\}", raw, re.S)
        if m:
            try:
                obj = json.loads(m.group(0))
            except json.JSONDecodeError:
                pass
    ents = obj.get("entities") or []
    rels = obj.get("relations") or []
    elines = [
        f"- {e.get('name', '')} ({e.get('type', '')})"
        for e in ents
        if isinstance(e, dict) and e.get("name")
    ][:12]
    rlines = [
        f"- {r.get('src', '')} --{r.get('rel', 'related')}--> {r.get('dst', '')}"
        for r in rels
        if isinstance(r, dict) and r.get("src") and r.get("dst")
    ][:15]
    parts = ["TASK-ADAPTIVE KNOWLEDGE GRAPH:"]
    if elines:
        parts.append("ENTITIES:\n" + "\n".join(elines))
    if rlines:
        parts.append("RELATIONS:\n" + "\n".join(rlines))
    if passages.strip():
        parts.append("SOURCE PASSAGES:\n" + passages[:6000])
    return "\n\n".join(parts) if len(parts) > 1 else passages


def predict_tadarag(qa: QARecord, ctx: Dict[str, Any]) -> str:
    intent = _detect_tadarag_intent(qa.question, qa.task)
    hits = _merge_cti_hits(qa, ctx, [qa.question], k=ctx["k"] + 2)
    passages = _format_cti_context(hits)
    kg_context = _extract_tadarag_kg(passages, intent)
    prompt = UNIFIED_PROMPT.format(context=kg_context, request=qa.question)
    return _cticonnect_chat(prompt, max_tokens=800)


def predict_unified_rag(qa: QARecord, ctx: Dict[str, Any]) -> str:
    hits = _retrieve_cti_hits(qa, ctx, qa.question)
    prompt = UNIFIED_PROMPT.format(context=_format_cti_context(hits), request=qa.question)
    return _cticonnect_chat(prompt, max_tokens=800)


def predict_selfrag(qa: QARecord, ctx: Dict[str, Any]) -> str:
    hits = _retrieve_cti_hits(qa, ctx, qa.question)
    context = _format_cti_context(hits)
    label = _critique(context, qa.question)
    used = context if label != "IRRELEVANT" else "(none)"
    prompt = UNIFIED_PROMPT.format(context=used, request=qa.question)
    return _cticonnect_chat(prompt, max_tokens=800)


def predict_graphrag(qa: QARecord, ctx: Dict[str, Any]) -> str:
    entities = _extract_entities(qa.question)
    merged: Dict[str, Tuple[float, KBHit]] = {}
    per_q = max(3, ctx["k"])
    for q in [qa.question] + entities:
        for hit in _retrieve_cti_hits(qa, ctx, q, k=per_q):
            key = f"{hit.doc_id}:{(hit.text or '')[:400]}"
            prev = merged.get(key)
            if prev is None or hit.score > prev[0]:
                merged[key] = (hit.score, hit)
    ranked = sorted(merged.values(), key=lambda h: h[0], reverse=True)[: ctx["k"] + 3]
    context = _format_cti_context([h for _, h in ranked])
    prompt = UNIFIED_PROMPT.format(context=context, request=qa.question)
    return _cticonnect_chat(prompt, max_tokens=800)


def predict_cta_rag(qa: QARecord, _ctx: Dict[str, Any]) -> str:
    pipe = PIPELINE_FOR_TASK[qa.task]
    return get_pipeline_runner(pipe)(qa.question)


def predict_cta_rag_cticonnect(qa: QARecord, ctx: Dict[str, Any]) -> str:
    from eval.cta_rag_cticonnect import predict as cta_cc_predict  # noqa: WPS433

    return cta_cc_predict(qa, ctx)


def predict_cta_rag_fair(qa: QARecord, ctx: Dict[str, Any]) -> str:
    from eval.cta_rag_fair import predict as cta_fair_predict  # noqa: WPS433

    return cta_fair_predict(qa, ctx, chat=_cticonnect_chat)


def predict_cta_rag_port(qa: QARecord, ctx: Dict[str, Any]) -> str:
    from eval.cta_rag_port import predict as cta_port_predict  # noqa: WPS433

    return cta_port_predict(qa, ctx, chat=_cticonnect_chat)


PREDICTORS: Dict[str, Callable[[QARecord, Dict[str, Any]], str]] = {
    "closed_book": predict_closed_book,
    "vanilla_rag": predict_vanilla_rag,
    "etr": predict_etr,
    "dtr": predict_dtr,
    "unified_rag": predict_unified_rag,
    "selfrag": predict_selfrag,
    "graphrag": predict_graphrag,
    "tadarag": predict_tadarag,
    "cta_rag": predict_cta_rag,
    "cta_rag_cticonnect": predict_cta_rag_cticonnect,
    "cta_rag_fair": predict_cta_rag_fair,
    "cta_rag_port": predict_cta_rag_port,
}

DEFAULT_COMPARE_SYSTEMS = [
    "closed_book",
    "vanilla_rag",
    "etr",
    "dtr",
    "cta_rag_port",
    "cta_rag_fair",
    "unified_rag",
    "selfrag",
    "graphrag",
    "tadarag",
    "cta_rag",
    "cta_rag_cticonnect",
]


def score_records(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    items: List[ItemScore] = []
    for r in records:
        if r.get("error"):
            continue
        gt = r["ground_truth"]
        items.append(
            score_id_item(
                r.get("prediction") or "",
                gt,
                task=r["task"],
                item_id=r["id"],
            )
        )
    return aggregate_scores(items)


def _load_jsonl_records(path: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    if not path.exists():
        return rows
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return rows


def load_reused_records(
    path: Path,
    system: str,
    wanted_ids: Set[str],
) -> List[Dict[str, Any]]:
    """Load prior predictions; keep latest good row per id."""
    latest: Dict[str, Dict[str, Any]] = {}
    for row in _load_jsonl_records(path):
        rid = row.get("id")
        if rid not in wanted_ids:
            continue
        prev = latest.get(rid)
        if prev is None or (prev.get("error") and not row.get("error")):
            row = dict(row)
            row["system"] = system
            latest[rid] = row
    return [latest[i] for i in sorted(latest) if i in wanted_ids]


def run_system(
    system: str,
    qas: List[QARecord],
    ctx: Dict[str, Any],
    workers: int,
    out_path: Path,
    *,
    resume: bool = True,
) -> List[Dict[str, Any]]:
    if system not in PREDICTORS:
        raise ValueError(f"Unknown system {system!r}")
    predict_fn = PREDICTORS[system]

    done: Dict[str, Dict[str, Any]] = {}
    if resume and out_path.exists():
        for row in _load_jsonl_records(out_path):
            rid = row.get("id")
            if not rid:
                continue
            prev = done.get(rid)
            if prev is None or (prev.get("error") and not row.get("error")):
                done[rid] = row
        print(f"  resume: {len(done)} already done in {out_path.name}")

    remaining = [qa for qa in qas if qa.id not in done or done[qa.id].get("error")]
    results: List[Dict[str, Any]] = [
        done[qa.id] for qa in qas if qa.id in done and not done[qa.id].get("error")
    ]

    def _one(qa: QARecord) -> Dict[str, Any]:
        t0 = time.time()
        err: Optional[str] = None
        pred = ""
        try:
            pred = predict_fn(qa, ctx)
        except Exception as exc:  # noqa: BLE001
            err = f"{type(exc).__name__}: {exc}"
            traceback.print_exc()
        row = {
            "system": system,
            "id": qa.id,
            "task": qa.task,
            "question": qa.question[:500],
            "ground_truth": qa.ground_truth,
            "prediction": pred,
            "raw": pred[:4000],
            "error": err,
            "elapsed_s": round(time.time() - t0, 2),
        }
        with _WRITE_LOCK:
            with open(out_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(row, ensure_ascii=False) + "\n")
        return row

    if remaining:
        print(f"  running {len(remaining)} remaining / {len(qas)}")
        with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
            for row in tqdm(pool.map(_one, remaining), total=len(remaining), desc=system):
                results.append(row)
    else:
        print(f"  all {len(qas)} items already present; skipping API calls")
    # Stable order matching qas
    by_id = {r["id"]: r for r in results}
    return [by_id[qa.id] for qa in qas if qa.id in by_id]


def print_summary(system: str, summary: Dict[str, Any]) -> None:
    print(f"\n========== {system} ==========")
    for task, block in summary.get("per_task", {}).items():
        print(
            f"  {task}: n={block['n']}  "
            f"F1={block['f1']*100:.1f}%  "
            f"P={block['precision']*100:.1f}%  "
            f"R={block['recall']*100:.1f}%  "
            f"EM={block['exact_match']*100:.1f}%"
        )
    ov = summary.get("overall", {})
    print(
        f"  OVERALL: n={ov.get('n',0)}  F1={ov.get('f1',0)*100:.1f}%  "
        f"EM={ov.get('exact_match',0)*100:.1f}%"
    )


def build_context(*, need_cti_kb: bool, k: int) -> Dict[str, Any]:
    ctx: Dict[str, Any] = {"k": k}
    if need_cti_kb:
        print("Loading CTIConnect corpus_kb retriever...")
        ctx["cti_kb"] = CTIConnectKBRetriever(corpus_dir=CTICONNECT_CORPUS)
    return ctx


def main() -> None:
    ap = argparse.ArgumentParser(description="CTIConnect overlap eval (RCM + ATA)")
    ap.add_argument("--tasks", default="rcm,ata", help="comma-separated (default overlap)")
    ap.add_argument("--limit", type=int, default=0, help="0 = full task splits")
    ap.add_argument("--workers", type=int, default=3)
    ap.add_argument(
        "--systems",
        default="",
        help=f"comma-separated; default all compare systems",
    )
    ap.add_argument(
        "--compare",
        action="store_true",
        help="Run full ladder and print scoreboard",
    )
    ap.add_argument("--k", type=int, default=5, help="retrieval depth")
    ap.add_argument("--out-dir", type=Path, default=OUT_DEFAULT)
    ap.add_argument("--data-dir", type=Path, default=CTICONNECT_DATA)
    ap.add_argument(
        "--stamp",
        default="",
        help="Fixed stamp so interrupted runs can resume into the same jsonl files",
    )
    ap.add_argument(
        "--reuse",
        action="append",
        default=[],
        metavar="SYSTEM=JSONL",
        help="Reuse prior predictions (e.g. --reuse closed_book=.../cticonnect_closed_book_....jsonl)",
    )
    ap.add_argument(
        "--no-resume",
        action="store_true",
        help="Do not append into existing stamp jsonl; overwrite",
    )
    ap.add_argument(
        "--protocol-json",
        type=Path,
        default=None,
        help="Optional protocol.json (embedded in scoreboard for fair-benchmark runs)",
    )
    args = ap.parse_args()

    tasks = [t.strip() for t in args.tasks.split(",") if t.strip()]
    bad = [t for t in tasks if t not in OVERLAP_TASKS]
    if bad:
        raise SystemExit(f"Only overlap tasks supported here: {OVERLAP_TASKS}; got {bad}")

    limit = None if args.limit == 0 else args.limit
    qas = load_tasks(tasks, data_dir=args.data_dir, limit=limit)
    wanted_ids = {qa.id for qa in qas}
    print(f"Loaded n={len(qas)} from {args.data_dir} tasks={tasks}")

    systems = (
        [s.strip() for s in args.systems.split(",") if s.strip()]
        if args.systems
        else (DEFAULT_COMPARE_SYSTEMS if args.compare else ["closed_book"])
    )
    for s in systems:
        if s not in PREDICTORS:
            raise SystemExit(f"Unknown system {s!r}; valid: {sorted(PREDICTORS)}")

    reuse_map: Dict[str, Path] = {}
    for item in args.reuse or []:
        if "=" not in item:
            raise SystemExit(f"--reuse expects SYSTEM=JSONL, got {item!r}")
        name, path_s = item.split("=", 1)
        reuse_map[name.strip()] = Path(path_s.strip())

    args.out_dir.mkdir(parents=True, exist_ok=True)
    stamp = args.stamp or datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    need_cti_kb = any(
        s
        in {
            "vanilla_rag",
            "etr",
            "dtr",
            "cta_rag_cticonnect",
            "cta_rag_fair",
            "cta_rag_port",
            "unified_rag",
            "selfrag",
            "graphrag",
            "tadarag",
        }
        and s not in reuse_map
        for s in systems
    )
    need_pipelines = "cta_rag" in systems and "cta_rag" not in reuse_map
    ctx = build_context(need_cti_kb=need_cti_kb, k=args.k)
    if need_pipelines:
        for pipe in set(PIPELINE_FOR_TASK[t] for t in tasks):
            print(f"Preloading CTA pipeline: {pipe}")
            get_pipeline_runner(pipe)

    scoreboard: Dict[str, Any] = {
        "stamp": stamp,
        "tasks": tasks,
        "n": len(qas),
        "generator": _resolve_cticonnect_model(),
        "ctibench_generator": resolve_model("gpt-4-turbo"),
        "retrieval_k": args.k,
        "data_dir": str(args.data_dir),
        "out_dir": str(args.out_dir),
        "systems": {},
    }
    if args.protocol_json:
        if not args.protocol_json.exists():
            raise SystemExit(f"--protocol-json not found: {args.protocol_json}")
        with open(args.protocol_json, encoding="utf-8") as f:
            scoreboard["protocol"] = json.load(f)
        scoreboard["benchmark"] = scoreboard["protocol"].get("name", "CTIConnect fair")

    for system in systems:
        out_path = args.out_dir / f"cticonnect_{system}_{stamp}.jsonl"
        if system in reuse_map:
            records = load_reused_records(reuse_map[system], system, wanted_ids)
            missing = wanted_ids - {r["id"] for r in records}
            print(
                f"\n>>> Reused {system}: {len(records)}/{len(qas)} "
                f"from {reuse_map[system]}"
            )
            if missing:
                raise SystemExit(
                    f"{system} reuse incomplete: missing {len(missing)} ids "
                    f"(e.g. {sorted(missing)[:3]})"
                )
            # Persist under this stamp for the scoreboard package
            with open(out_path, "w", encoding="utf-8") as f:
                for r in records:
                    f.write(json.dumps(r, ensure_ascii=False) + "\n")
        else:
            if args.no_resume and out_path.exists():
                out_path.unlink()
            print(f"\n>>> Running {system} on {len(qas)} items -> {out_path.name}")
            records = run_system(
                system,
                qas,
                ctx,
                args.workers,
                out_path,
                resume=not args.no_resume,
            )
        summary = score_records(records)
        summary_path = args.out_dir / f"cticonnect_{system}_{stamp}_summary.json"
        summary["system"] = system
        summary["pred_path"] = str(out_path)
        summary["n_errors"] = sum(1 for r in records if r.get("error"))
        if system in reuse_map:
            summary["reused_from"] = str(reuse_map[system])
        with open(summary_path, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2)
        scoreboard["systems"][system] = summary
        print_summary(system, summary)

    board_name = (
        f"scoreboard_{stamp}.json"
        if args.protocol_json
        else f"cticonnect_scoreboard_{stamp}.json"
    )
    board_path = args.out_dir / board_name
    with open(board_path, "w", encoding="utf-8") as f:
        json.dump(scoreboard, f, indent=2)

    if args.compare or len(systems) > 1:
        md_path = board_path.with_name(board_path.stem + "_per_task.md")
        lines = [
            f"# CTIConnect scoreboard `{stamp}` (per-task F1 / EM)",
            "",
            f"Items: {len(qas)} ({', '.join(tasks)})",
            "",
            "| System | RCM F1 | RCM EM | ATA F1 | ATA EM | Overall F1 | n |",
            "|--------|--------|--------|--------|--------|------------|---|",
        ]
        for system in systems:
            s = scoreboard["systems"][system]
            rcm = s.get("per_task", {}).get("rcm", {})
            ata = s.get("per_task", {}).get("ata", {})
            ov = s.get("overall", {})
            lines.append(
                f"| {system} "
                f"| {rcm.get('f1', 0) * 100:.1f}% "
                f"| {rcm.get('exact_match', 0) * 100:.1f}% "
                f"| {ata.get('f1', 0) * 100:.1f}% "
                f"| {ata.get('exact_match', 0) * 100:.1f}% "
                f"| {ov.get('f1', 0) * 100:.1f}% "
                f"| {ov.get('n', 0)} |"
            )
        md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    if args.compare or len(systems) > 1:
        print("\n========== CTICONNECT SCOREBOARD (mean F1 / EM) ==========")
        print(f"{'System':<16} {'RCM F1':>8} {'RCM EM':>8} {'ATA F1':>8} {'ATA EM':>8} {'ALL F1':>8}")
        print("-" * 64)
        for system in systems:
            s = scoreboard["systems"][system]
            rcm = s.get("per_task", {}).get("rcm", {})
            ata = s.get("per_task", {}).get("ata", {})
            ov = s.get("overall", {})
            print(
                f"{system:<16} "
                f"{rcm.get('f1', 0)*100:7.1f}% "
                f"{rcm.get('exact_match', 0)*100:7.1f}% "
                f"{ata.get('f1', 0)*100:7.1f}% "
                f"{ata.get('exact_match', 0)*100:7.1f}% "
                f"{ov.get('f1', 0)*100:7.1f}%"
            )
        print(f"\nWrote {board_path}")
        if args.compare or len(systems) > 1:
            print(f"Wrote {md_path}")


if __name__ == "__main__":
    main()
