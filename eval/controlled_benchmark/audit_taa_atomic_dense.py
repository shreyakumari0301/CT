"""Offline atomic field-chunk audit for TAA.

This experiment keeps the MiniLM dense-retrieval paradigm and does not use
graph traversal or gold labels for candidate generation. It builds actor-
explicit atomic records, retrieves a larger dense pool, aggregates by actor,
and reports Recall@1/3/10 and MRR@10. It makes no model calls.
"""
from __future__ import annotations

import csv
import hashlib
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
BASE = ROOT / "eval_results/controlled_benchmark/taa20_20260918"
RUN = BASE / "fresh_full50_20260918T053944Z"
OUT = ROOT / "eval_results/controlled_benchmark/full/taa_atomic_dense_audit"
OUT.mkdir(parents=True, exist_ok=True)

MODEL_NAME = "all-MiniLM-L6-v2"
FIELDS = ("aliases", "malware", "tools", "techniques", "sectors",
          "regions", "campaigns", "infrastructure", "description")


def norm(text: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (text or "").lower())


def load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def actor_documents(profiles):
    docs = []
    for actor_index, profile in enumerate(profiles):
        actor = profile["canonical_actor"]
        gid = profile.get("source_id", "")
        prefix = f"Threat actor {actor} ({gid})"
        values = {
            "aliases": profile.get("aliases", []),
            "malware": profile.get("malware", []),
            "tools": profile.get("tools", []),
            "techniques": profile.get("techniques", []),
            "sectors": profile.get("target_sectors", []),
            "regions": profile.get("target_regions", []),
            "campaigns": profile.get("campaigns", []),
            "infrastructure": profile.get("infrastructure", []),
            "description": [profile.get("profile_text", "")],
        }
        for field, entries in values.items():
            clean = [str(x).strip() for x in entries if str(x).strip()]
            if not clean:
                continue
            # Atomic records are used for distinctive entities. Descriptions
            # and technique lists remain compact field records.
            if field in {"malware", "tools", "campaigns", "infrastructure"}:
                for value in clean:
                    docs.append({"actor_index": actor_index, "actor": actor,
                                 "field": field,
                                 "text": f"{prefix} {field}: {value}"})
            else:
                docs.append({"actor_index": actor_index, "actor": actor,
                             "field": field,
                             "text": f"{prefix} {field}: {'; '.join(clean)}"})
    return docs


def metrics(rows, key):
    ranks = [row[key] for row in rows]
    return {
        f"recall_at_{k}": sum(r is not None and r <= k for r in ranks) / len(ranks)
        for k in (1, 3, 10)
    } | {"mrr_at_10": sum(1 / r if r and r <= 10 else 0 for r in ranks) / len(ranks)}


def main():
    import numpy as np
    from sentence_transformers import SentenceTransformer
    from eval.taa_protocol import benchmark_alias_match
    from utils.taa_actor_retrieval import ActorRetriever

    profiles = load_json(BASE / "actor_retrieval_study_v2/actor_profiles.json")
    reports = list(csv.DictReader((ROOT / "data/cti-taa.tsv").open(encoding="utf-8"), delimiter="\t"))
    labels = list(csv.DictReader((ROOT / "data/ctibench_taa/cti-taa-responses.tsv").open(encoding="utf-8"), delimiter="\t"))
    old_items = [load_json(p) for p in sorted((RUN / "items").glob("taa-*.json"), key=lambda p: int(p.stem.split("-")[1]))]
    model = SentenceTransformer(MODEL_NAME)
    docs = actor_documents(profiles)
    embeddings = model.encode([d["text"] for d in docs], normalize_embeddings=True, batch_size=64, show_progress_bar=True)
    retriever = ActorRetriever(model, profiles, BASE / "actor_retrieval_study/embedding_cache")
    rows = []
    for item, report_row, label in zip(old_items, reports, labels):
        report = report_row["Text"]
        queries, _ = retriever.queries(report)
        # Include the full clue query as a dense field query.
        queries["full"] = " ".join(queries.values()) or report[:2000]
        actor_scores = defaultdict(lambda: defaultdict(float))
        actor_hits = defaultdict(list)
        for field_query in queries.values():
            qv = model.encode([field_query], normalize_embeddings=True)[0]
            scores = np.asarray(embeddings) @ qv
            for idx in np.argsort(-scores)[:20]:
                doc = docs[int(idx)]
                actor = doc["actor"]
                actor_scores[actor][doc["field"]] = max(actor_scores[actor][doc["field"]], float(scores[idx]))
                actor_hits[actor].append({"field": doc["field"], "score": float(scores[idx]), "text": doc["text"]})
        ranked = []
        for actor, fields in actor_scores.items():
            vals = sorted(fields.values(), reverse=True)
            score = vals[0] + 0.5 * (vals[1] if len(vals) > 1 else 0) + 0.25 * (vals[2] if len(vals) > 2 else 0)
            ranked.append((score, actor, sorted(fields), actor_hits[actor]))
        ranked.sort(key=lambda x: (-x[0], x[1]))
        names = [x[1] for x in ranked]
        gold = label["GT"]
        rank = next((i for i, actor in enumerate(names, 1) if benchmark_alias_match(actor, gold)), None)
        rows.append({"id": item["id"], "gold": gold, "rank": rank,
                     "top10": names[:10], "actors_before_truncation": len(names),
                     "top3_fields": [{"actor": x[1], "score": x[0], "fields": x[2]} for x in ranked[:3]],
                     "gold_profile": next((p for p in profiles if benchmark_alias_match(p["canonical_actor"], gold)), None),
                     "gold_retrieved": rank is not None,
                     "candidate_evidence": {a: actor_hits[a] for a in names[:10]}})
    summary = {"model": MODEL_NAME, "documents": len(docs), "metrics": metrics(rows, "rank"),
               "mean_candidates": sum(x["actors_before_truncation"] for x in rows) / len(rows),
               "absent_top10": [x["id"] for x in rows if not x["rank"] or x["rank"] > 10],
               "rank4_10": [x["id"] for x in rows if x["rank"] and 4 <= x["rank"] <= 10],
               "gold_top3": [x["id"] for x in rows if x["rank"] and x["rank"] <= 3],
               "note": "Dense atomic field audit only; no graph traversal and no GPT calls.",
               "sha256": hashlib.sha256(json.dumps(docs, sort_keys=True).encode()).hexdigest()}
    (OUT / "atomic_rows.json").write_text(json.dumps(rows, indent=2), encoding="utf-8")
    (OUT / "atomic_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
