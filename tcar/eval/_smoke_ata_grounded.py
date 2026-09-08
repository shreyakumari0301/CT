"""Smoke test for behaviour-grounded ATA (no API)."""
from tcar.ata_behavior_grounded import reciprocal_rank_fusion, segment_behaviors_rulebased
from tcar.pipeline_prompts import build_cticonnect_ata_grounded_prompt
from tcar.task_branches import ata_retrieval_mode
import os

s = segment_behaviors_rulebased(
    "The malware used PowerShell to download a payload. Later it created a scheduled task for persistence."
)
assert len(s) >= 1, s
assert reciprocal_rank_fusion([["T1059.001", "T1053"], ["T1053", "T1547"]])[0][0] == "T1053"
p = build_cticonnect_ata_grounded_prompt(question="x", grounded_block="y")
assert "GROUNDED" in p
os.environ["ATA_RETRIEVAL"] = "grounded"
assert ata_retrieval_mode() == "grounded"
print("grounded_unit_ok", s)
