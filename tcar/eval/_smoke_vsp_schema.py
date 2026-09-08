#!/usr/bin/env python3
"""Quick smoke for VSP nested schema + no uncertain defaults."""
from __future__ import annotations

import os

os.environ["VSP_CONSISTENCY"] = "high_precision"

from tcar.vsp_structured_decoder import decode_vsp_prediction, parse_vsp_facts_json

raw = """{
  "PR": {"value": "N", "confidence": "low", "evidence": "No authentication is required."},
  "AV": {"value": "N", "confidence": "high", "evidence": "remote"},
  "AC": {"value": "L", "confidence": "high", "evidence": ""},
  "UI": {"value": "N", "confidence": "medium", "evidence": ""},
  "S":  {"value": "U", "confidence": "low", "evidence": "no boundary"},
  "C":  {"value": "H", "confidence": "medium", "evidence": "disclosure"},
  "I":  {"value": "N", "confidence": "low", "evidence": ""},
  "A":  {"value": "N", "confidence": "low", "evidence": ""}
}"""
f = parse_vsp_facts_json(raw)
assert f.required_privileges == "none", f.required_privileges
vec, meta = decode_vsp_prediction(
    raw, description="Unauthenticated remote attacker can disclose data"
)
print("nested", vec, meta.get("consistency_mode"))

raw2 = (
    '{"PR": "uncertain", "AV": "network", "AC": "no special condition", '
    '"UI": "none", "scope_change": false, "confidentiality_impact": "high", '
    '"integrity_impact": "none", "availability_impact": "none"}'
)
vec2, meta2 = decode_vsp_prediction(
    raw2,
    description="Unauthenticated remote attacker causes information disclosure",
)
print("uncertain-PR", vec2, "filled", meta2.get("filled_from_rulebased"))
assert "required_privileges" in (meta2.get("filled_from_rulebased") or [])
print("ok")
