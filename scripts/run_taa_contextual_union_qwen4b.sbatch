#!/bin/bash
#SBATCH --job-name=taa-context-q4b
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=1
#SBATCH --gres=gpu:1
#SBATCH --partition=cscc-gpu-p
#SBATCH --qos=cscc-gpu-qos
#SBATCH --exclude=gpu-05
#SBATCH --time=24:00:00
#SBATCH --output=/home/ashish.mehta/ss/CT/logs/%x_%j.out
#SBATCH --error=/home/ashish.mehta/ss/CT/logs/%x_%j.err

set -euo pipefail

PROJECT=/home/ashish.mehta/ss/CT
cd "$PROJECT"
mkdir -p logs

export HF_HOME=/l/users/ashish.mehta/ct_hf_cache
export HF_DATASETS_CACHE="$HF_HOME/datasets"
export TRANSFORMERS_CACHE="$HF_HOME/transformers"
export PIP_CACHE_DIR=/l/users/ashish.mehta/ct_pip_cache
export CONTEXTUAL_EMBEDDING_CACHE=/l/users/ashish.mehta/ct_hf_cache/contextual_taa_embeddings
export CONTEXTUAL_QWEN_MODEL=Qwen/Qwen3-Reranker-4B
export CONTEXTUAL_QWEN_OUTPUT=eval_results/controlled_benchmark/full/taa_contextual_union_qwen4b_audit
export CONTEXTUAL_QWEN_BATCH_SIZE=8
export TOKENIZERS_PARALLELISM=false
mkdir -p "$HF_HOME" "$HF_DATASETS_CACHE" "$TRANSFORMERS_CACHE" "$PIP_CACHE_DIR" "$CONTEXTUAL_EMBEDDING_CACHE"

if [ ! -x .venv/bin/python ]; then
  python3 -m venv .venv
fi
source .venv/bin/activate

python -m pip install --upgrade pip
python -m pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu124
python -m pip install sentence-transformers flashrank pandas numpy

echo "host=$(hostname) job=${SLURM_JOB_ID} model=${CONTEXTUAL_QWEN_MODEL} CUDA_VISIBLE_DEVICES=${CUDA_VISIBLE_DEVICES:-unset}"
nvidia-smi
python - <<'PY'
import torch
print("CUDA available:", torch.cuda.is_available())
print("GPU:", torch.cuda.get_device_name(0) if torch.cuda.is_available() else "none")
if not torch.cuda.is_available():
    raise SystemExit("CUDA is not available in this Slurm allocation")
PY

python eval/controlled_benchmark/audit_taa_contextual_union_qwen4b.py
