#!/bin/bash
#SBATCH --job-name=taa-ensemble
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=1
#SBATCH --gres=gpu:1
#SBATCH --partition=cscc-gpu-p
#SBATCH --qos=cscc-gpu-qos
# gpu-05 has no visible CUDA device; gpu-54 lacks the required /l mount.
#SBATCH --exclude=gpu-05,gpu-54
#SBATCH --time=00:30:00
#SBATCH --output=/home/ashish.mehta/ss/CT/logs/%x_%j.out
#SBATCH --error=/home/ashish.mehta/ss/CT/logs/%x_%j.err

set -euo pipefail
cd /home/ashish.mehta/ss/CT
mkdir -p logs
source .venv/bin/activate
python eval/controlled_benchmark/analyze_taa_reranker_ensemble.py
