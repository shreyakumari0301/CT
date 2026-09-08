#!/usr/bin/env bash
# Build a standalone TCAR repo (sibling of CTI-Chatbot) for GitHub push.
# Does NOT modify/push Hammad2910/CTI-Chatbot.
set -euo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DEST="${TCAR_DEST:-$(dirname "$SRC")/TCAR}"

echo "SRC=$SRC"
echo "DEST=$DEST"
rm -rf "$DEST"
mkdir -p "$DEST"

rsync -a --delete \
  --exclude '__pycache__/' \
  --exclude '*.pyc' \
  --exclude '.venv/' \
  --exclude 'logs/*.nohup.out' \
  --exclude '_gpu_friend_bundle/' \
  "$SRC/tcar/" "$DEST/tcar/"

# Minimal host deps TCAR imports
mkdir -p "$DEST/eval" "$DEST/utils"
for f in \
  scoring.py \
  cticonnect_kb.py \
  cticonnect_loader.py \
  cticonnect_metrics.py \
  cta_rag_port.py \
  run_ctibench.py \
  run_cticonnect.py \
  run_unified_rag.py
do
  [[ -f "$SRC/eval/$f" ]] && cp -a "$SRC/eval/$f" "$DEST/eval/$f"
done
# eval package marker
touch "$DEST/eval/__init__.py"
[[ -f "$SRC/utils/llm_client.py" ]] && cp -a "$SRC/utils/llm_client.py" "$DEST/utils/"
[[ -f "$SRC/utils/cve_sanitize.py" ]] && cp -a "$SRC/utils/cve_sanitize.py" "$DEST/utils/"
touch "$DEST/utils/__init__.py"

# Data + indexes needed to run
mkdir -p "$DEST/data" "$DEST/vector_dbs"
rsync -a "$SRC/data/" "$DEST/data/" \
  --exclude 'ctibench_taa/*.json' || true
# STIX can be re-downloaded; copy if present (optional large)
if [[ -d "$SRC/data/ctibench_taa" ]]; then
  mkdir -p "$DEST/data/ctibench_taa"
  # copy only small meta; STIX json downloaded by run script
  find "$SRC/data/ctibench_taa" -maxdepth 1 -type f ! -name '*.json' -exec cp -a {} "$DEST/data/ctibench_taa/" \; || true
fi

rsync -a "$SRC/vector_dbs/" "$DEST/vector_dbs/" \
  --exclude 'reasoning_taa_vdb_leaky_backup/' \
  --exclude '*.DS_Store'

# CTICONNECT: keep corpus + xrefs (needed), skip huge unused trees if any
mkdir -p "$DEST/CTICONNECT data"
if [[ -d "$SRC/CTICONNECT data/CTIConnect-main" ]]; then
  rsync -a \
    --exclude '.git/' \
    --exclude '**/__pycache__/' \
    --exclude 'baselines/**/outputs/' \
    "$SRC/CTICONNECT data/CTIConnect-main/" \
    "$DEST/CTICONNECT data/CTIConnect-main/"
fi

# Essential prior-run artifacts for pilots / merge
mkdir -p "$DEST/tcar/eval_results"
ESS=(
  "counterfactual_ctibench_rcm_20260908Tturbo_rcm_hybrid_n200.jsonl"
  "counterfactual_ctibench_rcm_20260902Ttask_prompts_cb.jsonl"
  "counterfactual_ctibench_vsp_20260908Tturbo_vsp_structured_n75.jsonl"
  "counterfactual_ctibench_vsp_20260907Tsol_vsp_metric_wise.jsonl"
  "counterfactual_ctibench_mcq_20260907Tturbo_mcq_option_aware_v2.jsonl"
  "counterfactual_ctibench_mcq_20260908Tturbo_mcq_relation_aware_changed.jsonl"
)
for f in "${ESS[@]}"; do
  [[ -f "$SRC/tcar/eval_results/$f" ]] && cp -a "$SRC/tcar/eval_results/$f" "$DEST/tcar/eval_results/$f"
done
if [[ -d "$SRC/tcar/eval_results/mcq_v3_changed" ]]; then
  mkdir -p "$DEST/tcar/eval_results/mcq_v3_changed"
  cp -a "$SRC/tcar/eval_results/mcq_v3_changed/manifest.csv" "$DEST/tcar/eval_results/mcq_v3_changed/" 2>/dev/null || true
  cp -a "$SRC/tcar/eval_results/mcq_v3_changed/regen_ids.txt" "$DEST/tcar/eval_results/mcq_v3_changed/" 2>/dev/null || true
  cp -a "$SRC/tcar/eval_results/mcq_v3_changed/"*.json "$DEST/tcar/eval_results/mcq_v3_changed/" 2>/dev/null || true
fi
# keep rcm diagnostic if present
if [[ -d "$SRC/tcar/eval_results/rcm_prompt_diagnostic" ]]; then
  rsync -a "$SRC/tcar/eval_results/rcm_prompt_diagnostic/" "$DEST/tcar/eval_results/rcm_prompt_diagnostic/"
fi

cp -a "$SRC/requirements.txt" "$DEST/"
cp -a "$SRC/.env.example" "$DEST/"
cp -a "$SRC/run_on_gpu.sh" "$DEST/"
chmod +x "$DEST/run_on_gpu.sh"

cat > "$DEST/.gitignore" <<'EOF'
.venv/
.env
__pycache__/
*.pyc
.vscode/
tcar/eval_results/logs/*.nohup.out
tcar/eval_results/_gpu_friend_bundle/
*.bak_*
EOF

cat > "$DEST/README.md" <<'EOF'
# TCAR — Taxonomy-Contrastive Adaptive RAG

Standalone research code for CTIBench / CTIConnect specialist RAG experiments
(MCQ / RCM / VSP / ATA / ATE). **Not** the CTA-RAG CTI-Chatbot demo repo.

## Quick start (GPU machine)

```bash
git clone https://github.com/Hammad2910/TCAR.git
cd TCAR
cp .env.example .env   # add OPENAI_API_KEY
bash run_on_gpu.sh     # setup + checks
bash run_on_gpu.sh all # RCM + VSP pilots
```

Generation uses the OpenAI API; a GPU only speeds local embeddings.

Never commit `.env`.
EOF

# Fresh git history — do not reuse CTI-Chatbot remotes
cd "$DEST"
git init -b main
git add -A
# Safety: never stage .env
git status --porcelain | grep -E '\.env$' && { echo "REFUSING: .env staged"; exit 1; }
git -c user.email="${GIT_AUTHOR_EMAIL:-tcar@local}" -c user.name="${GIT_AUTHOR_NAME:-TCAR}" \
  commit -m "$(cat <<'EOF'
Initial TCAR standalone export for GPU friend runs.

Includes specialist code, indexes, CTIConnect corpus seeds, and pilot artifacts.
EOF
)"

echo "Standalone repo ready at $DEST"
du -sh "$DEST"
git -C "$DEST" log -1 --oneline
git -C "$DEST" remote -v || true
