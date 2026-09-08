#!/usr/bin/env bash
# =============================================================================
# CTI-Chatbot — one-shot GPU/friend bootstrap + next-task runners
#
# After cloning:
#   cp .env.example .env   # put OPENAI_API_KEY inside (never commit .env)
#   bash run_on_gpu.sh                  # setup + dependency check
#   bash run_on_gpu.sh all              # setup + RCM pilots + VSP pilots
#   bash run_on_gpu.sh rcm              # RCM diagnostic + advisory pilots
#   bash run_on_gpu.sh vsp              # VSP no-uncertain pilots (n=75)
#   bash run_on_gpu.sh mcq-merge        # merge MCQ v3 when regen jsonl is complete
#   bash run_on_gpu.sh setup-only       # venv + pip only
#
# Optional env:
#   WORKERS=2                 # LLM parallel workers (default 1)
#   GENERATION_MODEL=gpt-4-turbo
#   SKIP_PIP=1                # skip pip install
#   USE_FAISS_GPU=1           # try faiss-gpu (else faiss-cpu)
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

MODE="${1:-setup}"
WORKERS="${WORKERS:-1}"
GENERATION_MODEL="${GENERATION_MODEL:-gpt-4-turbo}"
VENV_DIR="${VENV_DIR:-.venv}"
LOG_DIR="$ROOT/tcar/eval_results/logs"
mkdir -p "$LOG_DIR"

ts() { date -u +%Y-%m-%dT%H:%M:%SZ; }
log() { echo "[$(ts)] $*"; }
die() { echo "[$(ts)] ERROR: $*" >&2; exit 1; }

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing command: $1"
}

activate_venv() {
  # shellcheck disable=SC1091
  source "$VENV_DIR/bin/activate"
  export PYTHONPATH="$ROOT${PYTHONPATH:+:$PYTHONPATH}"
}

load_dotenv() {
  if [[ -f "$ROOT/.env" ]]; then
    set -a
    # shellcheck disable=SC1091
    source "$ROOT/.env"
    set +a
  fi
  export GENERATION_MODEL="${GENERATION_MODEL:-gpt-4-turbo}"
  export MODEL="$GENERATION_MODEL"
  export USE_OPENROUTER="${USE_OPENROUTER:-0}"
  unset OPENAI_BASE_URL OPENROUTER_API_KEY 2>/dev/null || true
}

check_api_key() {
  load_dotenv
  [[ -n "${OPENAI_API_KEY:-}" ]] || die "OPENAI_API_KEY not set. Copy .env.example → .env and add your key."
  case "$OPENAI_API_KEY" in
    sk-*) ;;
    *) die "OPENAI_API_KEY does not look like an OpenAI/OpenRouter key (expected sk-...)" ;;
  esac
  log "API key present (suffix …${OPENAI_API_KEY: -6})"
}

setup_venv() {
  need_cmd python3
  need_cmd pip3 || true
  if [[ ! -d "$VENV_DIR" ]]; then
    log "Creating venv at $VENV_DIR"
    python3 -m venv "$VENV_DIR"
  fi
  activate_venv
  python -m pip install -U pip wheel setuptools

  if [[ "${SKIP_PIP:-0}" == "1" ]]; then
    log "SKIP_PIP=1 — not installing packages"
    return
  fi

  log "Installing requirements.txt"
  pip install -r requirements.txt

  # Prefer GPU FAISS when requested and CUDA is visible; else keep faiss-cpu from requirements.
  if [[ "${USE_FAISS_GPU:-0}" == "1" ]] && command -v nvidia-smi >/dev/null 2>&1; then
    log "USE_FAISS_GPU=1 + nvidia-smi — attempting faiss-gpu"
    pip uninstall -y faiss-cpu 2>/dev/null || true
    pip install faiss-gpu || {
      log "faiss-gpu install failed; restoring faiss-cpu"
      pip install faiss-cpu
    }
  fi

  # Embedding models use torch; GPU speeds retrieval encoding (generation is still OpenAI API).
  if command -v nvidia-smi >/dev/null 2>&1; then
    log "GPU detected:"
    nvidia-smi -L || true
    python - <<'PY' || true
import torch
print("torch", torch.__version__, "cuda_available", torch.cuda.is_available())
if torch.cuda.is_available():
    print("device", torch.cuda.get_device_name(0))
PY
  else
    log "No nvidia-smi — CPU embeddings (OK; LLM calls still use API)"
  fi
}

check_tree() {
  local missing=0
  req() {
    if [[ ! -e "$1" ]]; then
      echo "  MISSING: $1"
      missing=1
    else
      echo "  ok: $1"
    fi
  }
  log "Checking required paths…"
  req "requirements.txt"
  req "tcar/eval/run_counterfactual.py"
  req "tcar/vsp_structured_decoder.py"
  req "tcar/rcm_mechanism_hybrid.py"
  req "data/cti-mcq.tsv"
  req "data/cti-rcm.tsv"
  req "data/cti-vsp.tsv"
  req "vector_dbs/understanding_vdbs/faiss_cwe/chunks_cwe.json"
  req "vector_dbs/understanding_vdbs/faiss_kb/index.faiss"
  req "vector_dbs/problem_solving_vdb/vsp_faiss_index.faiss"
  req "CTICONNECT data/CTIConnect-main/construction/seeds/correlations/cwe_xrefs.jsonl"

  # Pilot / merge inputs (needed for RCM/VSP/MCQ next steps)
  req "tcar/eval_results/counterfactual_ctibench_rcm_20260908Tturbo_rcm_hybrid_n200.jsonl"
  req "tcar/eval_results/counterfactual_ctibench_rcm_20260902Ttask_prompts_cb.jsonl"
  req "tcar/eval_results/counterfactual_ctibench_vsp_20260908Tturbo_vsp_structured_n75.jsonl"
  req "tcar/eval_results/counterfactual_ctibench_mcq_20260907Tturbo_mcq_option_aware_v2.jsonl"

  if [[ "$missing" -ne 0 ]]; then
    die "Repo incomplete for GPU friend run. Push/sync missing paths (see FRIEND checklist in script header comments), then re-run."
  fi
  log "Tree check passed"
}

ensure_stix() {
  mkdir -p data/ctibench_taa
  local ent="data/ctibench_taa/enterprise-attack.json"
  local ics="data/ctibench_taa/ics-attack.json"
  local mob="data/ctibench_taa/mobile-attack.json"
  if [[ -f "$ent" && -f "$ics" && -f "$mob" ]]; then
    log "STIX bundles already present"
    return
  fi
  need_cmd curl
  log "Downloading MITRE ATT&CK STIX (enterprise + ICS + mobile)…"
  local BASE="https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master"
  [[ -f "$ent" ]] || curl -fsSL -o "$ent" "$BASE/enterprise-attack/enterprise-attack.json"
  [[ -f "$ics" ]] || curl -fsSL -o "$ics" "$BASE/ics-attack/ics-attack.json"
  [[ -f "$mob" ]] || curl -fsSL -o "$mob" "$BASE/mobile-attack/mobile-attack.json"
  ls -lh data/ctibench_taa/*attack*.json
}

smoke_imports() {
  activate_venv
  load_dotenv
  log "Smoke-importing TCAR modules…"
  PYTHONPATH=. python - <<'PY'
from tcar.rcm_mechanism_hybrid import rcm_pipeline_mode, rcm_advisory_mode
from tcar.vsp_structured_decoder import decode_vsp_prediction, vsp_consistency_mode
import os
os.environ["RCM_PIPELINE"] = "vanilla_advisory"
assert rcm_pipeline_mode() == "vanilla_advisory"
print("rcm_ok", rcm_advisory_mode(), "vsp_consistency_default_check", vsp_consistency_mode())
vec, meta = decode_vsp_prediction(
    '{"PR":{"value":"N","confidence":"low","evidence":"x"},'
    '"AV":{"value":"N","confidence":"high","evidence":""},'
    '"AC":{"value":"L","confidence":"high","evidence":""},'
    '"UI":{"value":"N","confidence":"medium","evidence":""},'
    '"S":{"value":"U","confidence":"low","evidence":""},'
    '"C":{"value":"H","confidence":"medium","evidence":""},'
    '"I":{"value":"N","confidence":"low","evidence":""},'
    '"A":{"value":"N","confidence":"low","evidence":""}}',
    description="Unauthenticated remote attacker discloses data",
)
print("vsp_ok", vec)
PY
}

run_rcm() {
  activate_venv
  check_api_key
  log "RCM: gold@prompt diagnostic (offline)"
  PYTHONPATH=. python tcar/eval/run_rcm_gold_prompt_diagnostic.py \
    | tee "$LOG_DIR/rcm_prompt_diagnostic_$(date +%Y%m%dT%H%M%S).log"

  local IDS="tcar/eval_results/rcm_prompt_diagnostic/pilot_ids.txt"
  [[ -f "$IDS" ]] || die "missing $IDS after diagnostic"

  run_rcm_variant() {
    local stamp="$1"
    shift
    log "RCM pilot: $stamp"
    env "$@" \
      GAD_MODE=off RCM_GAD=off \
      GENERATION_MODEL="$GENERATION_MODEL" MODEL="$GENERATION_MODEL" USE_OPENROUTER=0 \
      PYTHONPATH=. python -m tcar.eval.run_counterfactual \
        --benchmark ctibench --tasks rcm --workers "$WORKERS" \
        --model "$GENERATION_MODEL" --variant no_confusion \
        --stamp "$stamp" --ids-file "$IDS" --limit 0 \
        2>&1 | tee "$LOG_DIR/${stamp}.log"
  }

  run_rcm_variant "20260908Tturbo_rcm_vanilla_pilot" \
    RCM_PIPELINE=default RCM_PROMPT=strict
  run_rcm_variant "20260908Tturbo_rcm_advisory_top1_pilot" \
    RCM_PIPELINE=vanilla_advisory RCM_ADVISORY=top1 RCM_PROMPT=advisory
  run_rcm_variant "20260908Tturbo_rcm_advisory_contrast_pilot" \
    RCM_PIPELINE=vanilla_advisory RCM_ADVISORY=contrast RCM_PROMPT=advisory

  log "RCM pilots finished — compare Acc on identical pilot IDs"
}

run_vsp() {
  activate_venv
  check_api_key
  log "VSP: offline consistency ablation on stored n=75 raw facts"
  PYTHONPATH=. python tcar/eval/run_vsp_consistency_ablation.py \
    | tee "$LOG_DIR/vsp_consistency_ablation.log" || true

  # Rebuild pilot ID list
  PYTHONPATH=. python - <<'PY'
import json
from pathlib import Path
root = Path("tcar/eval_results")
src = root / "counterfactual_ctibench_vsp_20260908Tturbo_vsp_structured_n75.jsonl"
alt = root / "counterfactual_ctibench_vsp_20260907Tsol_vsp_metric_wise.jsonl"
ids = []
for p in (src, alt):
    if not p.exists():
        continue
    for line in p.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        r = json.loads(line)
        if r.get("error"):
            continue
        ids.append(r["id"])
    if ids:
        break
out = root / "_vsp_structured_pilot_ids.txt"
out.write_text("\n".join(dict.fromkeys(ids)) + ("\n" if ids else ""), encoding="utf-8")
print(f"ids={len(ids)} -> {out}")
PY

  local IDS="tcar/eval_results/_vsp_structured_pilot_ids.txt"
  [[ -f "$IDS" ]] || die "missing VSP pilot ids"

  run_vsp_variant() {
    local stamp="$1"
    local cons="$2"
    log "VSP pilot: $stamp (VSP_CONSISTENCY=$cons)"
    VSP_RETRIEVAL=structured VSP_CONSISTENCY="$cons" GAD_MODE=off \
      GENERATION_MODEL="$GENERATION_MODEL" MODEL="$GENERATION_MODEL" USE_OPENROUTER=0 \
      PYTHONPATH=. python -m tcar.eval.run_counterfactual \
        --benchmark ctibench --tasks vsp --workers "$WORKERS" \
        --model "$GENERATION_MODEL" --variant no_confusion \
        --stamp "$stamp" --ids-file "$IDS" --limit 0 \
        2>&1 | tee "$LOG_DIR/${stamp}.log"
  }

  run_vsp_variant "20260908Tturbo_vsp_struct_no_unc_hp_n75" "high_precision"
  run_vsp_variant "20260908Tturbo_vsp_struct_no_unc_off_n75" "off"
  log "VSP pilots finished — compare Exact / MAD_base vs Vanilla 25.3% / 0.93"
}

run_mcq_merge() {
  activate_venv
  local V3="tcar/eval_results/counterfactual_ctibench_mcq_20260908Tturbo_mcq_relation_aware_changed.jsonl"
  [[ -f "$V3" ]] || die "missing $V3 — finish MCQ v3 regen first"
  log "MCQ final merge (refuses Acc if regen incomplete)"
  PYTHONPATH=. python tcar/eval/merge_mcq_v3_final.py --v3-jsonl "$V3" \
    | tee "$LOG_DIR/mcq_v3_final_merge.log"
}

do_setup() {
  setup_venv
  activate_venv
  check_api_key
  ensure_stix
  check_tree
  smoke_imports
  log "Setup complete."
  cat <<EOF

Next:
  bash run_on_gpu.sh rcm          # ~85 IDs × 3 variants (API cost)
  bash run_on_gpu.sh vsp          # same 75 IDs × 2 variants
  bash run_on_gpu.sh all          # rcm then vsp
  bash run_on_gpu.sh mcq-merge    # after MCQ v3 jsonl is complete

Note: GPU speeds local embeddings; generation still needs OPENAI_API_KEY.
EOF
}

case "$MODE" in
  setup|setup-only|"")
    do_setup
    ;;
  check)
    activate_venv 2>/dev/null || true
    check_tree
    ensure_stix
    ;;
  rcm)
    do_setup
    run_rcm
    ;;
  vsp)
    do_setup
    run_vsp
    ;;
  mcq-merge)
    activate_venv
    run_mcq_merge
    ;;
  all)
    do_setup
    run_rcm
    run_vsp
    log "Optional: bash run_on_gpu.sh mcq-merge when v3 regen is done"
    ;;
  *)
    cat <<EOF
Usage: bash run_on_gpu.sh [setup|check|rcm|vsp|mcq-merge|all]
EOF
    exit 2
    ;;
esac
