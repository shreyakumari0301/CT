from tcar.ata_behavior_grounded import _clause_split, segment_behaviors_rulebased

s = "The malware downloaded a payload and created a scheduled task for persistence."
print("clause", _clause_split(s))
print("seg", segment_behaviors_rulebased(s))
