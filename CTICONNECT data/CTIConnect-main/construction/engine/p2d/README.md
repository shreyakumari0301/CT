# Prompt to Data (p2d) Module

## Overview

The p2d module processes prompts through LLM APIs to generate data. It reads prompts from the generated files and calls LLM services to produce structured JSON responses for RAG benchmarking. Supports multiple correlation types including CAPEC, MITRE ATT&CK, CVE, and CWE relationships.

## Module Structure

```
dataset_generation/engine/p2d_1/
├── __init__.py              # Module initialization
├── llm_client.py           # LLM API clients (OpenAI, Anthropic)
├── data_generator.py       # Main DataGenerator class
├── run_generator.py        # Command-line script
├── requirements.txt        # Python dependencies
└── README.md              # This file
```

### API Keys

Set up your API keys in the `.env` file at the project root:
```bash
OPENAI_API_KEY=your_openai_api_key_here
```
The module will automatically load these from the `.env` file or use the `OPENAI_API_KEY` environment variable.

## Usage

### Command Line

```bash
# Basic usage with OpenAI (default) - creates timestamped output directory
python dataset_generation/engine/p2d/run_generator.py \
    --task vca \
    --aspect mitigation \
    --template-version v1 \
    --max-jobs 10 \
    --batch-id batch_0 

# Use new path structure without timestamp
python dataset_generation/engine/p2d/run_generator.py \
    --task ata \
    --template-version v5 \
    --batch-id batch_2 \
    --no-timestamp

python dataset_generation/engine/p2d/run_generator.py \
    --task mla \
    --template-version v2 \
    --batch-id batch_0 \
        --no-timestamp

python dataset_generation/engine/p2d/run_generator.py \
    --task tap \
    --template-version v1 \
    --batch-id batch_0 \
    --no-timestamp

# With aspect subfolder
python dataset_generation/engine/p2d/run_generator.py \
    --task rcm \
    --template-version v3 \
    --batch-id batch_1 \
    --aspect security \
    --no-timestamp

python dataset_generation/engine/p2d/run_generator.py \
    --task esd \
    --template-version v2 \
    --batch-id batch_1 \
    --no-timestamp

# Limit processing to 10 jobs (for testing)
python dataset_generation/engine/p2d/run_generator.py \
    --task atd \
    --template-version v4 \
    --batch-id batch_1 \
    --no-timestamp

python dataset_generation/engine/p2d/run_generator.py \
    --task rcm \
    --template-version v3 \
    --batch-id batch_1 \
    --no-timestamp

python dataset_generation/engine/p2d/run_generator.py \
    --task wim \
    --template-version v2 \
    --batch-id batch_0 \
    --no-timestamp
```

## Input/Output

### Input
- **Prompt Files**: `dataset_generation/prompts/{task}/{aspect}/{template-version}/{batch-id}/{SRC}-{TGT}.txt` or `dataset_generation/prompts/{task}/{template-version}/{batch-id}/{SRC}-{TGT}.txt`

### Output
- **Data Files**: `dataset_generation/data/{task}/{aspect}/{template-version}/{batch-id}/{SRC}-{TGT}.json` or `dataset_generation/data/{task}/{template-version}/{batch-id}/{SRC}-{TGT}.json`
- **Format**: JSON files containing LLM-generated responses
- **Report**: `generation_report.json` with statistics and configuration

## Supported LLM Providers

### OpenAI (only)
- **Models**: o3-mini, gpt-5, gpt-5-mini, etc.
- **API Key**: `OPENAI_API_KEY` environment variable
- **Default Model**: o4-mini

## Path Structure

The module uses a structured path hierarchy for organizing prompts and data:

```
dataset_generation/
├── prompts/
│   └── {task}/
│       └── {aspect}/
│           └── {template-version}/
│               └── {batch-id}/
│                   └── {src}-{tgt}.txt
│       └── {template-version}/
│           └── {batch-id}/
│               └── {src}-{tgt}.txt
└── data/
    └── {task}/
        └── {aspect}/
            └── {template-version}/
                └── {batch-id}/
                    └── {src}-{tgt}.json
        └── {template-version}/
            └── {batch-id}/
                └── {src}-{tgt}.json
```

Where:
- `task`: rcm, cca, csc, eea, etc.
- `aspect`: subfolder name under task folder (optional)
- `template-version`: v1, v2, v3, etc.
- `batch-id`: batch_1, batch_2, etc.

## Example Output

Generated data files contain:
```json
{
  "question": "CVE-2019-5418 maps via the stated relationship to its underlying weakness. What root-cause details does that CWE provide?",
  "intents": [
    {
      "framework": "cve",
      "keyword": "CVE-2019-5418"
    },
    {
      "framework": "cwe", 
      "keyword": "CWE-22"
    }
  ],
  "answer": "- From CVE-2019-5418, the relationship resolves to CWE-22 (root cause)...",
  "soc_task": "Root Cause Mapping (RCM)"
}
```

### Task-Specific Intent Fields

The module automatically adds intent fields for specific tasks:

#### ATA (Attack Technique Attribution)
```json
{
  "question": "What MITRE ATT&CK technique does this attack behavior represent?",
  "intents": [
    {
      "framework": "mitre_attack",
      "keyword": "The attack behavior text extracted from SOURCE_NODE"
    }
  ],
  "answer": "This represents T1204.002...",
  "soc_task": "Attack Technique Attribution (ATA)"
}
```

#### VCA (Vulnerability Classification and Attribution)
```json
{
  "question": "What CWE category represents this vulnerability?",
  "intents": [
    {
      "framework": "cwe",
      "keyword": "The vulnerability text extracted from SOURCE_NODE"
    }
  ],
  "answer": "This represents CWE-284...",
  "soc_task": "Vulnerability Classification and Attribution (VCA)"
}
```