#!/bin/bash
#SBATCH --job-name=taa-norm-e2e
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
cd /home/ashish.mehta/ss/CT
mkdir -p logs
source .venv/bin/activate
echo "host=$(hostname) job=${SLURM_JOB_ID} model=$(sed -n 's/^GENERATION_MODEL=//p' .env | sed 's/^\"\|\"$//g') CUDA_VISIBLE_DEVICES=${CUDA_VISIBLE_DEVICES:-unset}"
nvidia-smi --query-gpu=name,memory.total --format=csv,noheader
python -u -m eval.run_taa_normalized_e2e_openai --n 50