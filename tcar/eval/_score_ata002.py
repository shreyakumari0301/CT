from pathlib import Path
import json
from eval.cticonnect_metrics import score_id_item

r = json.loads(Path("tcar/eval_results/counterfactual_cticonnect_ata_20260907Tturbo_ata_grounded_n50.jsonl").read_text(encoding="utf-8").splitlines()[1])
for label in ["closed_book_prediction", "retrieval_prediction"]:
    item = score_id_item(r[label], r["gold"], task="ata")
    print(label, "f1=", item.f1)
    print("  ", item)
