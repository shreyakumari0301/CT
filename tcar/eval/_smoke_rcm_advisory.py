#!/usr/bin/env python3
import os
from tcar.rcm_mechanism_hybrid import rcm_pipeline_mode, rcm_advisory_mode

os.environ["RCM_PIPELINE"] = "vanilla_advisory"
os.environ["RCM_ADVISORY"] = "contrast"
print(rcm_pipeline_mode(), rcm_advisory_mode())
