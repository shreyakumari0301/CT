#!/usr/bin/env bash
# Offline Relation-Aware Option Retrieval metrics (no LLM).
# Design/holdout split; reports STIX bundle version.
set -euo pipefail
cd "$(dirname "$0")/../.."
source .venv/bin/activate
export PYTHONPATH=.
python tcar/eval/run_mcq_relation_offline.py
