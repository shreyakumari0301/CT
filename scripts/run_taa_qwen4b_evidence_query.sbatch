#!/bin/bash
#SBATCH --job-name=taa-q4b-evidence
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
export EVIDENCE_QWEN_MODEL=Qwen/Qwen3-Reranker-4B
export EVIDENCE_QWEN_OUTPUT=eval_results/controlled_benchmark/full/taa_qwen4b_evidence_query_audit
export EVIDENCE_QWEN_BATCH_SIZE=8
export EVIDENCE_QWEN_QUERY_TOKENS=1100
export TOKENIZERS_PARALLELISM=false
mkdir -p "$HF_HOME" "$HF_DATASETS_CACHE" "$TRANSFORMERS_CACHE" "$PIP_CACHE_DIR"
source .venv/bin/activate
python -m pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu124
python -m pip install sentence-transformers flashrank pandas numpy
echo "host=$(hostname) job=${SLURM_JOB_ID} model=${EVIDENCE_QWEN_MODEL} CUDA_VISIBLE_DEVICES=${CUDA_VISIBLE_DEVICES:-unset}"
nvidia-smi
python - <<'PY'
import torch
if not torch.cuda.is_available(): raise SystemExit('CUDA is not available in this Slurm allocation')
print('GPU:', torch.cuda.get_device_name(0))
PY
python eval/controlled_benchmark/audit_taa_qwen4b_evidence_query.py
