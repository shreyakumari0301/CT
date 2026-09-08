"""Offline ATA v2 full (n=160) stage-wise diagnostics — no API."""
from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path

from eval.cticonnect_metrics import score_id_item
from tcar.ata_behavior_grounded import parse_full_technique_ids

SRC = Path("tcar/eval_results/counterfactual_cticonnect_ata_20260908Tturbo_ata_grounded_v2_full.jsonl")
rows = [json.loads(l) for l in SRC.read_text(encoding="utf-8").splitlines() if l.strip()]
by = {str(r["id"]): r for r in rows}
rows = sorted(by.values(), key=lambda r: r["id"])
n = len(rows)
print(f"n={n} stamp=20260908Tturbo_ata_grounded_v2_full\n")


def gold_set(r):
    return {str(x).upper() for x in (r.get("gold_ids") or [])}


def pred_set(r):
    return set(parse_full_technique_ids(r.get("retrieval_prediction") or ""))


def div(r):
    return (r.get("tcar_meta") or {}).get("diversify") or {}


# --- stage gold recall from stored meta ---
raw = rrf = grounded = 0
have_meta = 0
for r in rows:
    d = div(r)
    if "gold_in_raw_union" in d or "gold_in_rrf" in d or "gold_in_grounded" in d:
        have_meta += 1
    raw += int(bool(d.get("gold_in_raw_union")))
    rrf += int(bool(d.get("gold_in_rrf")))
    grounded += int(bool(d.get("gold_in_grounded")))

# fallback: retrieved_ids / seed as "final prompt"
final_prompt = sum(1 for r in rows if r.get("retrieval_contains_gold"))
# also check grounded_ids in meta vs gold
final_from_grounded = 0
for r in rows:
    g = gold_set(r)
    ids = set(str(x).upper() for x in (div(r).get("grounded_ids") or r.get("retrieved_ids") or []))
    if any(x in ids or x.split(".")[0] in ids or any(i.startswith(x.split(".")[0] + ".") for i in ids) for x in g):
        final_from_grounded += 1

print("=== STAGE-WISE GOLD RECALL (from stored meta) ===")
print(f"meta_present: {have_meta}/{n}")
print(f"Gold in raw per-behaviour top-20 union: {raw}/{n} = {raw/n:.1%}")
print(f"Gold after RRF shortlist:               {rrf}/{n} = {rrf/n:.1%}")
print(f"Gold after grounding (meta):            {grounded}/{n} = {grounded/n:.1%}")
print(f"Gold in audit retrieval_contains_gold:  {final_prompt}/{n} = {final_prompt/n:.1%}")
print(f"Gold in grounded_ids/retrieved_ids:     {final_from_grounded}/{n} = {final_from_grounded/n:.1%}")

# --- generator when all gold present ---
def gold_fully_in(pool, gold):
    if not gold:
        return False
    ps = {str(x).upper() for x in pool}
    for g in gold:
        ok = g in ps or g.split(".")[0] in ps or any(p.startswith(g.split(".")[0] + ".") for p in ps)
        # require exact or parent/sub link — for "all gold IDs present" prefer exact or sub-match
        if g in ps:
            continue
        # allow parent in pool if gold is sub? usually we need the gold id itself
        if any(p == g or p.startswith(g + ".") or (g.startswith(p + ".") if "." not in p else False) for p in ps):
            # stricter: gold exact in pool
            pass
        if g not in ps:
            # also accept if gold is sub and pool has exact gold only
            return False
    return True


def gold_exact_in(pool, gold):
    ps = {str(x).upper() for x in pool}
    return bool(gold) and gold <= ps


gen_when_present = []
for r in rows:
    g = gold_set(r)
    pool = set(str(x).upper() for x in (div(r).get("grounded_ids") or []))
    if not pool:
        pool = set(str(x).upper() for x in (r.get("retrieved_ids") or []))
    if gold_exact_in(pool, g):
        item = score_id_item(r.get("retrieval_prediction") or "", r["gold"], task="ata")
        gen_when_present.append(item.f1 >= 1.0 - 1e-9)

print("\n=== GENERATOR WHEN ALL GOLD IDs IN PROMPT ===")
print(f"items with all gold exact in grounded_ids: {len(gen_when_present)}")
if gen_when_present:
    print(f"exact Acc among those: {sum(gen_when_present)}/{len(gen_when_present)} = {sum(gen_when_present)/len(gen_when_present):.1%}")

# soft: gold_in_grounded meta True
soft = []
for r in rows:
    if div(r).get("gold_in_grounded"):
        soft.append(bool(r.get("retrieval_correct")))
print(f"items gold_in_grounded=True: {len(soft)}")
if soft:
    print(f"Acc among those: {sum(soft)}/{len(soft)} = {sum(soft)/len(soft):.1%}")

# --- set sizes ---
pred_sizes = []
gold_sizes = []
for r in rows:
    pred_sizes.append(len(pred_set(r)))
    gold_sizes.append(len(gold_set(r)))
print("\n=== PREDICTED vs GOLD SET SIZE ===")
print(f"mean |pred|={sum(pred_sizes)/n:.2f}  mean |gold|={sum(gold_sizes)/n:.2f}")
print(f"pred size hist: {Counter(pred_sizes)}")
print(f"gold size hist: {Counter(gold_sizes)}")
over = sum(1 for p, g in zip(pred_sizes, gold_sizes) if p > g)
under = sum(1 for p, g in zip(pred_sizes, gold_sizes) if p < g)
exact_n = sum(1 for p, g in zip(pred_sizes, gold_sizes) if p == g)
print(f"over-predict count={over} under={under} same_cardinality={exact_n}")

# --- parent/sub errors ---
parent_sub = 0
parent_sub_cases = []
for r in rows:
    g, p = gold_set(r), pred_set(r)
    if not g or not p:
        continue
    if g == p:
        continue
    hit = False
    for gid in g:
        main = gid.split(".")[0]
        if gid in p:
            continue
        if main in p or any(x.startswith(main + ".") for x in p):
            hit = True
            break
        # pred has sub, gold parent
        for pid in p:
            if pid.startswith(main + ".") or (gid.startswith(pid.split(".")[0] + ".") and "." not in pid):
                hit = True
                break
    if hit:
        parent_sub += 1
        if len(parent_sub_cases) < 8:
            parent_sub_cases.append((r["id"], sorted(g), sorted(p)))

print("\n=== PARENT/SUB-TECHNIQUE CONFUSION ===")
print(f"wrong items with parent/sub relation: {parent_sub}/{n} = {parent_sub/n:.1%}")
for c in parent_sub_cases:
    print(f"  {c[0]} gold={c[1]} pred={c[2]}")

# --- empty / invalid ---
empty = 0
invalid = 0
abstain_cb = 0
for r in rows:
    raw = r.get("retrieval_prediction") or ""
    meta = r.get("tcar_meta") or {}
    if meta.get("ata_abstain_to_cb"):
        abstain_cb += 1
    ids = parse_full_technique_ids(raw)
    if not (raw or "").strip():
        empty += 1
    elif not ids and not r.get("retrieval_correct"):
        # no parseable ids
        if "predicted_ids" in raw or raw.strip().startswith("{"):
            invalid += 1
        elif not ids:
            invalid += 1

print("\n=== EMPTY / INVALID / ABSTAIN ===")
print(f"empty responses: {empty}")
print(f"no-parseable-ID (approx invalid): {invalid}")
print(f"abstain_to_cb: {abstain_cb}/{n} = {abstain_cb/n:.1%}")

# --- overall Acc ---
cb = sum(1 for r in rows if r.get("closed_book_correct"))
rag = sum(1 for r in rows if r.get("retrieval_correct"))
print("\n=== HEADLINE ===")
print(f"CB={cb/n:.1%} RAG={rag/n:.1%} Δ={(rag-cb)/n:+.1%}")
print(f"effects: {Counter(r.get('retrieval_effect') for r in rows)}")

# bottleneck drop
print("\n=== WHERE GOLD DISAPPEARS (pp of items) ===")
print(f"raw→rrf loss:      {(raw-rrf)/n:+.1%} absolute ({raw}→{rrf})")
print(f"rrf→grounded loss: {(rrf-grounded)/n:+.1%} absolute ({rrf}→{grounded})")
print(f"grounded→Acc gap:  gold_grounded {grounded/n:.1%} vs Acc {rag/n:.1%} → gen/selection leaves {(grounded-rag)/n:.1%} on table (approx)")
