#!/bin/bash
#SBATCH --job-name=taa-e2e-openai
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=4
#SBATCH --gres=gpu:1
#SBATCH --partition=cscc-gpu-p
#SBATCH --qos=cscc-gpu-qos
#SBATCH --exclude=gpu-05,gpu-54
#SBATCH --time=24:00:00
#SBATCH --output=/home/ashish.mehta/ss/CT/logs/%x_%j.out
#SBATCH --error=/home/ashish.mehta/ss/CT/logs/%x_%j.err

set -euo pipefail

PROJECT=/home/ashish.mehta/ss/CT
cd "$PROJECT"
mkdir -p logs
export HF_HOME=/l/users/ashish.mehta/ct_hf_cache
export TRANSFORMERS_CACHE="$HF_HOME/transformers"
export TOKENIZERS_PARALLELISM=false
mkdir -p "$HF_HOME" "$TRANSFORMERS_CACHE"

source .venv/bin/activate
echo "host=$(hostname) job=${SLURM_JOB_ID} model=$(sed -n 's/^GENERATION_MODEL=//p' .env | sed 's/^\"\|\"$//g') CUDA_VISIBLE_DEVICES=${CUDA_VISIBLE_DEVICES:-unset}"
nvidia-smi --query-gpu=name,memory.total --format=csv,noheader

python -u -m eval.run_taa_e2e_openai --n 50