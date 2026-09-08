# Template to Prompt (t2p_new) Module

This module generates prompts by combining entries with correlation data using predefined Jinja2 templates. It supports various tasks including VCA (Vulnerability Classification and Attribution) and ATA (Attack Technique Attribution).

## VCA Task Implementation

### Overview
The VCA task generates prompts for vulnerability classification and attribution by mapping blog vulnerability descriptions to CWE (Common Weakness Enumeration) entries.

### Data Requirements
- **Input**: `seeds/correlations/b2f_cwe.jsonl` - B2F annotations linking blog vulnerability passages to CWE entries
- **Target**: `corpus_kb/cwe.jsonl` - CWE framework reference data
- **Templates**: `templates/vca/` - Jinja2 templates for prompt generation

### Field Mapping
- **SOURCE_NODE**: Uses only the `vulnerability_text` field value from blog entries
- **TARGET_NODE**: Uses the corresponding CWE entry retrieved by `cwe_id` field

### File Format
The `b2f_cwe.jsonl` file should contain entries with:
```json
{
  "cwe_id": "CWE-400",
  "blog_id": 1,
  "blog_title": "Example Blog Title",
  "vulnerability_text": "Description of the vulnerability..."
}
```

**Note**: Only the `vulnerability_text` field value is passed to the template as `{{ SOURCE_NODE }}`.

## Usage

### Command Line Interface

The canonical template version per task (matches `construction/templates/README.md`):

| Task | Canonical version |
|---|---|
| RCM | `v4` |
| WIM | `v3` |
| ATD | `v5` |
| ESD | `v3` |
| ATA | `v5` |
| VCA | `v4` |
| CSC | `v6` |
| TAP | `v2` |
| MLA | `v2` |

```bash
# Entity Linking tasks
python engine/t2p/run_generator.py --task rcm --template-version v4 --enable-batching --correlation-dir correlation
python engine/t2p/run_generator.py --task wim --template-version v3 --enable-batching --correlation-dir correlation
python engine/t2p/run_generator.py --task atd --template-version v5 --enable-batching --correlation-dir correlation
python engine/t2p/run_generator.py --task esd --template-version v3 --enable-batching --correlation-dir correlation

# Entity Attribution tasks
python engine/t2p/run_generator.py --task ata --template-version v5 --enable-batching
python engine/t2p/run_generator.py --task vca --template-version v4 --enable-batching

# Multi-Document Synthesis tasks
python engine/t2p/run_generator.py --task csc --template-version v6 --enable-batching --restart --corpus-dir corpus_reports/preprocessed_reports.jsonl --blog-cluster-file seeds/clusters/
python engine/t2p/run_generator.py --task tap --template-version v2 --enable-batching --restart --corpus-dir corpus_reports/preprocessed_reports.jsonl --blog-cluster-file seeds/clusters/
python engine/t2p/run_generator.py --task mla --template-version v2 --enable-batching --restart --corpus-dir corpus_reports/preprocessed_reports.jsonl --blog-cluster-file seeds/clusters/
```

### Parameters
- `--task`: Task identifier (rcm, wim, atd, esd, ata, vca, csc, tap, mla)
- `--template-version`: Canonical template version (see table above)
- `--enable-batching`: Enable random batching of generated prompts
- `--batch-size`: Number of prompts per batch (default: 100)
- `--restart`: Remove existing files in output directory before generation
- `--corpus-dir`: Path to corpus directory (default: corpus_kb)
- `--correlation-dir`: Path to correlation data directory (default: correlation)
- `--template-dir`: Path to Jinja2 template directory (default: templates)
- `--output-dir`: Directory to save generated prompts (default: prompts)
- `--blog-cluster-file`: Path to BlogCluster.csv file for CSC/TAP/MLA tasks (default: seeds/clusters/)

### Output Structure
Generated prompts are saved in:
```
prompts/vca/{template_version}/
├── batch_0/
│   ├── blog-1-CWE-400.txt
│   ├── blog-2-CWE-307.txt
│   └── ...
└── batch_1/
    ├── blog-10-CWE-494.txt
    └── ...
```

## Implementation Details

### Key Methods
- `load_blog_cwe_llm_filtered_enriched_data()`: Loads blog-CWE correlation data
- `generate_prompts_for_vca()`: Generates VCA prompts using vulnerability_text and CWE entries
- `load_corpus_data("cwe")`: Loads CWE framework reference data

### Template Variables
- `{{ SOURCE_NODE }}`: The vulnerability_text field value (plain text)
- `{{ TARGET_NODE }}`: JSON representation of corresponding CWE entry

### Error Handling
- Validates file existence before processing
- Handles missing CWE entries gracefully
- Provides detailed progress reporting
- Continues processing on individual entry errors

## Supported Tasks

### VCA (Vulnerability Classification and Attribution)
- Maps blog vulnerability descriptions to CWE categories
- Uses `vulnerability_text` field for source data
- Retrieves CWE entries by `cwe_id` for target data

### ATA (Attack Technique Attribution)
- Maps blog attack descriptions to MITRE ATT&CK techniques
- Uses `attack_behavior_text` field for source data
- Retrieves MITRE entries by `technique_id` for target data

### CSC (Campaign Storyline Construction)
- Maps blog entries about events/campaigns to reconstruct campaign storylines
- Uses BlogCluster.csv to group related blog entries by object_id
- Generates prompts for event/campaign types to identify key intrusion vectors, phases, and incidents
- Template: `templates/csc/v6.jinja`

### TAP (Threat Actor Profiling)
- Maps blog entries about threat actors to compile comprehensive actor profiles
- Uses BlogCluster.csv to group related blog entries by object_id
- Generates prompts for threat actor types to identify infrastructure, tactics, and targets
- Template: `templates/tap/v2.jinja`

### MLA (Malware Lineage Analysis)
- Maps blog entries about malware families to trace malware evolution
- Uses BlogCluster.csv to group related blog entries by object_id
- Generates prompts for malware types to analyze code reuse, variants, distribution, and targeting
- Template: `templates/mla/v2.jinja`

### Other Tasks
- RCM (Root Cause Mapping)
  - Maps CVE entries to CWE categories
  - Filters both source and target nodes to only include id, name, description fields
  - Uses CVE-CWE correlation data from correlation/cve.jsonl
  - **Filtering**: Only includes CVE entries that have exactly one `correlated_cwe` entry (one-to-one mapping)
- WIM (Weakness Instantiation Mapping)
  - Maps CWE entries to CVE vulnerabilities
  - Filters both source and target nodes to only include id, name, description fields
  - Uses CWE-CVE correlation data from correlation/cwe.jsonl
  - **Filtering**: Only includes CWE entries that have exactly one `correlated_cve` entry (one-to-one mapping)
- ATD (Attack Technique Derivation)
  - Maps CAPEC attack patterns to MITRE ATT&CK techniques
  - Filters both source and target nodes to only include id, name, description fields
  - Uses CAPEC-MITRE correlation data from correlation/capec.jsonl
  - **Filtering**: Only includes CAPEC entries that have exactly one `correlated_mitre` entry (one-to-one mapping)
- ESD (Exploitation Surface Discovery)
  - Maps CWE entries to CAPEC attack patterns
  - Filters both source and target nodes to only include id, name, description fields
  - Uses CWE-CAPEC correlation data from correlation/cwe.jsonl
  - **Filtering**: Only includes CWE entries that have exactly one `correlated_capec` entry (one-to-one mapping)

## Data Filtering

The generator automatically filters correlation data based on the task type to ensure only relevant entries are processed:

- **RCM Task**: Only processes CVE entries that have exactly one `correlated_cwe` entry (one-to-one mapping)
- **WIM Task**: Only processes CWE entries that have exactly one `correlated_cve` entry (one-to-one mapping)
- **ATD Task**: Only processes CAPEC entries that have exactly one `correlated_mitre` entry (one-to-one mapping)
- **ESD Task**: Only processes CWE entries that have exactly one `correlated_capec` entry (one-to-one mapping)

This filtering ensures that prompts are only generated for entries with single, unambiguous relationships, improving data quality and reducing complexity in the generated prompts.

## Dependencies
- Python 3.6+
- Jinja2
- Standard library modules: json, sys, random, shutil, pathlib


## ATA Task Implementation

### Overview
The ATA task generates prompts for attack technique attribution by mapping blog attack descriptions to MITRE ATT&CK techniques.

### Data Requirements
- **Input**: `seeds/correlations/b2f_mitre.jsonl` - B2F annotations linking blog attack-behavior passages to MITRE ATT&CK techniques
- **Target**: `corpus_kb/mitre.jsonl` - MITRE ATT&CK framework reference data
- **Templates**: `templates/ata/` - Jinja2 templates for prompt generation

## CSC/TAP/MLA Task Implementation

### Examples

#### CSC
* question: The latest report (Aug 2025) attributes a spear-phishing campaign in the energy sector to the group Storm-1234. Based on historical reports, reconstruct the campaign storyline: What were the key intrusion vectors, phases, and notable incidents?

* answer:
-June 2024: Initial credential-harvesting via fake Microsoft login pages targeting oil & gas employees.
-Nov 2024: Shift to weaponized Excel attachments exploiting CVE-2024-45789.
-Mar 2025: Expanded targeting of European utilities; infrastructure overlap with prior campaigns confirmed.
-Aug 2025: Latest report shows convergence of spear-phishing + lateral movement via PsExec, indicating campaign maturation.

#### TAP
* question: The threat actor “Crimson Jackal” was reported in July 2025 for targeting the financial sector. Using historical reports, compile a profile of its infrastructure, tactics, and targets.
* answer:
-Infrastructure: Known C2 domains hosted on bulletproof services; heavy reliance on fast-flux DNS.
-Tactics: Consistent use of phishing lures, privilege escalation via token impersonation, and data exfiltration through cloud storage.
-Targets: Transitioned from APAC banks (late 2024) to North American fintech firms (2025).

#### MLA
* question: The July 2025 report describes a new variant of the malware family “ShadowRAT.” Trace its lineage based on reports since June 2024: How has the malware evolved in terms of code reuse, variants, distribution, and targeting?
* answer:
-Infrastructure: Known C2 domains hosted on bulletproof services; heavy reliance on fast-flux DNS.
-Tactics: Consistent use of phishing lures, privilege escalation via token impersonation, and data exfiltration through cloud storage.
-Targets: Transitioned from APAC banks (late 2024) to North American fintech firms (2025).

### Cluster-based workflow (CSC / TAP / MLA)

For the three multi-document synthesis tasks, prompts are rendered from
cluster manifests in `seeds/clusters/cluster_*.json`. Each cluster groups
related blog posts under one `object_id`; the corresponding executive
summaries are pulled from `../corpus_reports/preprocessed_reports.jsonl` by `blog_id`.
The template selected per cluster depends on its `type`:

| Cluster type | Template |
|---|---|
| `event` / `campaign` | `templates/csc/v6.jinja` |
| `threat actor` | `templates/tap/v2.jinja` |
| `malware` | `templates/mla/v2.jinja` |

