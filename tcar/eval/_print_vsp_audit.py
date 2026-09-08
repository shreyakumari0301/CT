import json
from pathlib import Path

d = json.loads(Path("tcar/eval_results/vsp_per_metric_audit.json").read_text())
for r in d:
    print("===", Path(r["source"]).name, "n=", r["n"])
    print(
        "exact",
        round(r["exact_rag"], 3),
        "mad8",
        None if r["mad8_rag"] is None else round(r["mad8_rag"], 3),
        "mad_base",
        None if r["mad_base_rag"] is None else round(r["mad_base_rag"], 3),
    )
    print("per_metric", {k: round(v, 3) for k, v in r["per_metric_acc_rag"].items()})
    print("weakest", r["weakest_metrics"])
    print(
        "rulebased_exact",
        round(r["rulebased_exact"], 3),
        "rb_mad_base",
        None if r["rulebased_mad_base"] is None else round(r["rulebased_mad_base"], 3),
    )
