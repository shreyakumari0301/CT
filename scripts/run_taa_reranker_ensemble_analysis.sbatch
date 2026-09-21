#!/bin/bash
#SBATCH --job-name=taa-ensemble
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=1
#SBATCH --partition=cscc-cpu-p
#SBATCH --account=cscc-users
#SBATCH --qos=normal
#SBATCH --time=00:30:00
#SBATCH --output=/home/ashish.mehta/ss/CT/logs/%x_%j.out
#SBATCH --error=/home/ashish.mehta/ss/CT/logs/%x_%j.err

set -euo pipefail
cd /home/ashish.mehta/ss/CT
mkdir -p logs
source .venv/bin/activate
python eval/controlled_benchmark/analyze_taa_reranker_ensemble.py
