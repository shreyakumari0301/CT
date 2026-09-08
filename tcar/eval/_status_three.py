"""Quick status: MCQ option-aware / ATA grounded / ATE exploitation."""
import json
from collections import Counter
from pathlib import Path

ROOT = Path("tcar/eval_results")


def score_cf(path: Path):
    rows = [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]
    if not rows:
        return {"n": 0}
    cb = sum(1 for r in rows if r.get("closed_book_correct"))
    rag = sum(1 for r in rows if r.get("retrieval_correct"))
    effects = Counter(r.get("retrieval_effect") for r in rows)
    return {
        "n": len(rows),
        "cb": cb / len(rows),
        "rag": rag / len(rows),
        "delta": (rag - cb) / len(rows),
        "rescues": effects.get("rescue", 0),
        "damages": effects.get("damage", 0),
        "pipeline": (rows[0].get("tcar_meta") or {}).get("prompt_style")
        or (rows[0].get("tcar_meta") or {}).get("ate_retrieval")
        or (rows[0].get("tcar_meta") or {}).get("ata_pipeline"),
        "retrieval_mode": (rows[0].get("tcar_meta") or {}).get("ate_retrieval")
        or (rows[0].get("tcar_meta") or {}).get("retrieval"),
    }


# 1 MCQ
mcq_sum = ROOT / "counterfactual_summary_20260907Tturbo_mcq_option_aware_n100.json"
mcq = json.loads(mcq_sum.read_text())["tasks"]["ctibench/mcq"] if mcq_sum.exists() else None

# 2 ATA grounded (partial)
ata_p = ROOT / "counterfactual_cticonnect_ata_20260907Tturbo_ata_grounded_n50.jsonl"
ata = score_cf(ata_p) if ata_p.exists() else None
if ata and ata_p.exists():
    row0 = json.loads(ata_p.read_text(encoding="utf-8").splitlines()[0])
    meta = row0.get("tcar_meta") or {}
    ata["prompt_style"] = meta.get("prompt_style")
    ata["diversify"] = (meta.get("diversify") or meta.get("retrieval"))

# 3 ATE exploitation — expect missing
ate_paths = list(ROOT.glob("*ate*exploit*")) + list(ROOT.glob("*ate_exploitation*"))
ate_cta = ROOT / "counterfactual_summary_20260907Tsol_ate_cta_fidelity.json"
ate_cta_s = json.loads(ate_cta.read_text())["tasks"]["ctibench/ate"] if ate_cta.exists() else None

print("===1 MCQ option-aware turbo n=100 (DONE)===")
if mcq:
    print(
        f"  CB={mcq['closed_book_score']:.1%}  option-aware RAG={mcq['forced_rag_score']:.1%}  "
        f"delta={mcq['score_delta']:+.1%}  rescues={mcq['rescues']} damages={mcq['damages']}"
    )

print("===2 ATA behaviour-grounded turbo n=50 (IN PROGRESS)===")
if ata:
    print(
        f"  partial n={ata['n']}/50  CB={ata['cb']:.1%}  grounded RAG={ata['rag']:.1%}  "
        f"delta={ata['delta']:+.1%}  rescues={ata['rescues']} damages={ata['damages']}"
    )
    print(f"  style={ata.get('prompt_style')} diversify/retrieval={ata.get('diversify')}")

print("===3 ATE exploitation-stage ablation===")
if ate_paths:
    print("  files:", [str(p) for p in ate_paths])
else:
    print("  NO RUN YET (implemented only; launcher not started)")
if ate_cta_s:
    print(
        f"  prior dense/CTA ATE (sol, n={ate_cta_s['n']}): "
        f"CB={ate_cta_s['closed_book_score']:.1%} RAG={ate_cta_s['forced_rag_score']:.1%} "
        f"(Macro-F1 exact-ish on that stamp — not exploitation ablation)"
    )
