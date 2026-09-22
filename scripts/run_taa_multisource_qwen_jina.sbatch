#!/bin/bash
#SBATCH --job-name=taa-ms-qwen-jina
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=1
#SBATCH --gres=gpu:1
#SBATCH --partition=cscc-gpu-p
#SBATCH --qos=cscc-gpu-qos
#SBATCH --exclude=gpu-05,gpu-54
#SBATCH --time=24:00:00
#SBATCH --output=/home/ashish.mehta/ss/CT/logs/%x_%j.out
#SBATCH --error=/home/ashish.mehta/ss/CT/logs/%x_%j.err
set -euo pipefail

cd /home/ashish.mehta/ss/CT
mkdir -p logs
export HF_HOME=/l/users/ashish.mehta/ct_hf_cache
export HF_DATASETS_CACHE="$HF_HOME/datasets"
export TRANSFORMERS_CACHE="$HF_HOME/transformers"
export PIP_CACHE_DIR=/l/users/ashish.mehta/ct_pip_cache
export TOKENIZERS_PARALLELISM=false
export MULTISOURCE_RERANKERS=qwen,jina
export MULTISOURCE_DENSE_TOP_K=20
export MULTISOURCE_BM25_TOP_K=20
export MULTISOURCE_CTA_TOP_K=10
export MULTISOURCE_SHARED_TOP_K=20
mkdir -p "$HF_HOME" "$HF_DATASETS_CACHE" "$TRANSFORMERS_CACHE" "$PIP_CACHE_DIR"
source .venv/bin/activate
echo "host=$(hostname) job=${SLURM_JOB_ID} CUDA_VISIBLE_DEVICES=${CUDA_VISIBLE_DEVICES:-unset} rerankers=${MULTISOURCE_RERANKERS}"
nvidia-smi
python - <<'PY'
import torch
if not torch.cuda.is_available():
    raise SystemExit("CUDA is not available in this Slurm allocation")
print("GPU:", torch.cuda.get_device_name(0))
PY
python eval/controlled_benchmark/audit_taa_multisource_qwen_jina.py
