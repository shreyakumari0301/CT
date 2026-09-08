from pathlib import Path
import json
from tcar.specialist_retrieval import parse_mcq_options, mcq_option_queries

p = Path("tcar/eval_results/counterfactual_ctibench_mcq_20260907Tturbo_mcq_option_aware_full.jsonl")
row = json.loads(p.read_text(encoding="utf-8").splitlines()[0])
q = row["question"]
print("=== Q ===")
print(q[:600])
print("=== parsed ===", parse_mcq_options(q))
print("=== queries ===")
for a, x in mcq_option_queries(q):
    print(a, x[:100])
ok = 0
n = 0
for line in p.read_text(encoding="utf-8").splitlines()[:100]:
    if not line.strip():
        continue
    n += 1
    r = json.loads(line)
    if parse_mcq_options(r["question"]):
        ok += 1
print(f"parse_ok {ok}/{n}")
