"""Evaluate Qwen3 4B with deterministic evidence-focused CTI report queries."""
from __future__ import annotations

import csv
import json
import os
import re
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
BASE = ROOT / "eval_results/controlled_benchmark/full/taa_external_protocol/offline_diagnostics"
CTA = json.loads((ROOT / "eval_results/controlled_benchmark/full/taa_external_protocol/ctibench_frozen_retrieval/ft_idf_rrf_summary.json").read_text())["rows"]
SHARED = json.loads((BASE / "passage_bm25_summary.json").read_text())["rows"]
PROFILES = json.loads((ROOT / "eval_results/controlled_benchmark/taa20_20260918/actor_retrieval_study_v2/actor_profiles.json").read_text())
OUT = ROOT / os.environ.get("EVIDENCE_QWEN_OUTPUT", "eval_results/controlled_benchmark/full/taa_qwen4b_evidence_query_audit")
MODEL_NAME = os.environ.get("EVIDENCE_QWEN_MODEL", "Qwen/Qwen3-Reranker-4B")
BATCH_SIZE = int(os.environ.get("EVIDENCE_QWEN_BATCH_SIZE", "8"))
QUERY_TOKEN_BUDGET = int(os.environ.get("EVIDENCE_QWEN_QUERY_TOKENS", "1100"))
OUT.mkdir(parents=True, exist_ok=True)
REPORTS = {f"taa-{i}": row["Text"] for i, row in enumerate(csv.DictReader((ROOT / "data/cti-taa.tsv").open(encoding="utf-8"), delimiter="\t"))}


def full_profile_passage(profile: dict) -> str:
    fields = ("aliases", "malware", "tools", "techniques", "campaigns", "target_regions", "target_sectors", "infrastructure")
    return "Actor: " + profile["canonical_actor"] + "\n" + profile.get("profile_text", "") + "\n" + "\n".join(
        f"{field}: " + ", ".join(map(str, profile.get(field, []))) for field in fields
    )


def profile_terms() -> tuple[list[tuple[str, str, float]], set[str]]:
    """Return report-matchable profile evidence with inverse-document-frequency weights."""
    terms_by_actor = []
    for profile in PROFILES:
        values = []
        for field in ("malware", "tools", "infrastructure", "campaigns", "techniques"):
            values.extend((value, field) for value in profile.get(field, []))
        terms_by_actor.append(values)
    df = Counter(value.casefold() for values in terms_by_actor for value, _ in set(values))
    weighted = []
    for value, field in sorted({item for values in terms_by_actor for item in values}, key=lambda item: (item[0].casefold(), item[1])):
        if len(value.strip()) >= 3:
            weighted.append((value, field, 1 / df[value.casefold()]))
    return weighted, set()


PROFILE_TERMS, _ = profile_terms()


def evidence_query(report: str, tokenizer) -> tuple[str, list[dict]]:
    """Select high-specificity report sentences under a fixed token budget."""
    from utils.taa_actor_retrieval import BEHAVIORS, REGIONS, SECTORS, contains, entity_mention, sentences

    candidates = []
    for index, sentence in enumerate(sentences(report)):
        score = 0.0
        signals = []
        cves = re.findall(r"\bCVE-\d{4}-\d{4,}\b", sentence, flags=re.I)
        attack_ids = re.findall(r"\bT\d{4}(?:\.\d{3})?\b", sentence)
        iocs = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b|\b[a-z0-9-]+(?:\[\.\]|\.)(?:com|net|org|info|biz)\b", sentence, flags=re.I)
        if cves:
            score += 4 * len(cves); signals.extend(cves)
        if attack_ids:
            score += 3 * len(attack_ids); signals.extend(attack_ids)
        if iocs:
            score += 3 * len(iocs); signals.extend(iocs)
        for term, field, idf in PROFILE_TERMS:
            field_for_match = "aliases_campaigns" if field == "campaigns" else ("infrastructure" if field == "infrastructure" else "malware_tools")
            matched = entity_mention(sentence, term, field_for_match)
            if field == "techniques" and (re.search(r"[\d._ -]", term) or re.search(r"[a-z][A-Z]", term)):
                matched = contains(sentence, term)
            if matched:
                score += 8 * idf
                signals.append(term)
        target_hits = [term for term in (*REGIONS, *SECTORS) if contains(sentence, term)]
        behavior_hits = [term for term in BEHAVIORS if contains(sentence, term)]
        if target_hits:
            score += 1 + 0.25 * len(target_hits); signals.extend(target_hits)
        if behavior_hits:
            score += 1 + 0.25 * len(behavior_hits); signals.extend(behavior_hits)
        if re.search(r"\b(?:target|victim|attribut|campaign|malware|tool|backdoor|ransomware|phish|side.load|inject|persist)\b", sentence, re.I):
            score += 0.5
        if score > 0:
            candidates.append({"index": index, "sentence": sentence, "score": score, "signals": list(dict.fromkeys(signals))[:12]})
    selected = []
    used = len(tokenizer.encode("Evidence-focused report excerpts:", add_special_tokens=False))
    for candidate in sorted(candidates, key=lambda item: (-item["score"], item["index"])):
        size = len(tokenizer.encode(candidate["sentence"], add_special_tokens=False))
        if used + size <= QUERY_TOKEN_BUDGET:
            selected.append(candidate); used += size
    if not selected:
        for index, sentence in enumerate(sentences(report)):
            size = len(tokenizer.encode(sentence, add_special_tokens=False))
            if used + size > QUERY_TOKEN_BUDGET:
                break
            selected.append({"index": index, "sentence": sentence, "score": 0.0, "signals": []}); used += size
    selected.sort(key=lambda item: item["index"])
    return "Evidence-focused report excerpts:\n" + "\n".join(item["sentence"] for item in selected), selected


def main() -> None:
    from sentence_transformers import CrossEncoder
    from eval.taa_protocol import benchmark_alias_match

    by_name = {profile["canonical_actor"]: profile for profile in PROFILES}
    model = CrossEncoder(MODEL_NAME, max_length=2048, device="cuda")
    checkpoint = OUT / "checkpoint.json"
    completed = json.loads(checkpoint.read_text()) if checkpoint.exists() else []
    rows_by_id = {row["id"]: row for row in completed if "ranking" in row and "evidence_sentences" in row}
    for cta_row, bm25_row in zip(CTA, SHARED):
        item_id = cta_row["id"]
        if item_id in rows_by_id:
            continue
        pool = list(dict.fromkeys(cta_row["ranking"][:10] + bm25_row["bm25"][:20]))
        query, selected = evidence_query(REPORTS[item_id], model.tokenizer)
        scores = model.predict([(query, full_profile_passage(by_name[name])) for name in pool], show_progress_bar=False, batch_size=BATCH_SIZE)
        ranking = [{"actor": name, "score": float(score)} for score, name in sorted(zip(scores, pool), key=lambda item: float(item[0]), reverse=True)]
        rank = next((position for position, entry in enumerate(ranking, 1) if benchmark_alias_match(entry["actor"], cta_row["gold"])), None)
        rows_by_id[item_id] = {
            "id": item_id, "gold": cta_row["gold"], "candidate_pool": pool,
            "evidence_query": query, "evidence_sentences": selected, "rank": rank, "ranking": ranking,
        }
        checkpoint.write_text(json.dumps(sorted(rows_by_id.values(), key=lambda row: int(row["id"].removeprefix("taa-"))), indent=2), encoding="utf-8")
    rows = sorted(rows_by_id.values(), key=lambda row: int(row["id"].removeprefix("taa-")))
    checkpoint.write_text(json.dumps(rows, indent=2), encoding="utf-8")
    ranks = [row["rank"] for row in rows]
    metrics = {f"Recall@{cutoff}": sum(bool(rank and rank <= cutoff) for rank in ranks) / len(ranks) for cutoff in (1, 3, 5, 10, 20)}
    metrics["MRR@10"] = sum(1 / rank if rank and rank <= 10 else 0 for rank in ranks) / len(ranks)
    summary = {
        "method": "frozen CTA top-10 + shared BM25 top-20 -> Qwen3 4B with deterministic evidence-focused report query",
        "query_token_budget": QUERY_TOKEN_BUDGET, "model": MODEL_NAME, "n": len(rows), "complete": len(rows) == 50,
        "metrics": metrics,
        "mean_selected_sentences": sum(len(row["evidence_sentences"]) for row in rows) / len(rows),
        "per_case_results": "checkpoint.json contains the selected report evidence, full candidate scores, and gold rank.",
    }
    (OUT / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
