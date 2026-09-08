"""Explain MCQ 80% → ~76%: slice vs cumulative composition."""
import json
from pathlib import Path

p = Path("tcar/eval_results/counterfactual_ctibench_mcq_20260907Tturbo_mcq_option_aware_full.jsonl")
by = {}
for line in p.read_text(encoding="utf-8").splitlines():
    if not line.strip():
        continue
    r = json.loads(line)
    by[str(r["id"])] = r


def num_id(rid: str) -> int:
    # mcq-0 -> 0
    try:
        return int(str(rid).split("-")[-1])
    except Exception:
        return 10**9


rows = sorted(by.values(), key=lambda r: num_id(r["id"]))


def stats(slice_rows, label):
    n = len(slice_rows)
    if not n:
        print(f"{label}: empty")
        return
    cb = sum(1 for r in slice_rows if r.get("closed_book_correct")) / n
    rag = sum(1 for r in slice_rows if r.get("retrieval_correct")) / n
    print(
        f"{label}: n={n}  CB={cb:.1%}  RAG={rag:.1%}  Δ={rag-cb:+.1%}  "
        f"ids {slice_rows[0]['id']}..{slice_rows[-1]['id']}"
    )


first100 = [r for r in rows if num_id(r["id"]) < 100]
rest = [r for r in rows if num_id(r["id"]) >= 100]
print(f"unique_total={len(rows)}")
stats(first100, "first 100 (mcq-0..99) — same as finished pilot")
stats(rest, "NEW only (mcq-100+)")
stats(rows, "CUMULATIVE all done so far")
# rolling feel: last 32 of new
if len(rest) >= 20:
    stats(rest[:20], "new first 20 (mcq-100..119)")
    if len(rest) > 20:
        stats(rest[20:], f"new after that (n={len(rest)-20})")
