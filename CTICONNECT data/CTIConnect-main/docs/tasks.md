# CTIConnect Task Definitions

CTIConnect organizes CTI analysis into **9 tasks** across **3 categories**,
covering all cross-source directions over heterogeneous CTI data.

Each task category is graded differently (`eval_type` field in the data):

| Category | eval_type | Grading |
|---|---|---|
| Entity Linking | `single_id_match` | exact ID match → Precision/Recall/F1 after identifier normalization |
| Entity Attribution | `id_set_match` | set match over taxonomy IDs → P/R/F1 |
| Multi-Doc Synthesis | `judge` | LLM-as-a-judge over free-form synthesis (claim-level P/R/F1) |

---

## 🔗 Entity Linking (structured → structured)

Map an entry in one structured CTI knowledge base to its counterpart in
another. The retrieval space is large (200K+ CVEs, 900+ CWEs, 500+ CAPECs),
and the bottleneck is vocabulary canonicalization between near-identical
entries. Input is a behavioral description with **no source ID revealed**; the
model must infer the target from behavior alone.

### RCM — Root Cause Mapping (CVE → CWE)
Identify the underlying weakness category of a disclosed vulnerability from its
description.
- **Input**: vulnerability behavior description
- **Output**: `CWE-XXX` + reasoning
- **Example**: *"A vulnerability ... allows remote attackers to enumerate valid usernames by observing differences in server response timing ..."* → `CWE-203` (Observable Discrepancy)

### WIM — Weakness Instantiation Mapping (CWE → CVE)
Given an abstract weakness, identify a concrete CVE that instantiates it.
- **Input**: weakness behavior description
- **Output**: `CVE-XXXX-XXXXX` + reasoning

### ATD — Attack Technique Derivation (CAPEC → ATT&CK)
Map a CAPEC attack pattern to its corresponding MITRE ATT&CK technique.
- **Input**: attack-pattern behavior description
- **Output**: `TXXXX[.XXX]` + reasoning

### ESD — Exploitation Surface Discovery (CWE → CAPEC)
Reason from a weakness (defensive view) to the attack pattern that exploits it
(offensive view).
- **Input**: weakness behavior description
- **Output**: `CAPEC-XXX` + reasoning

---

## 📰 Entity Attribution (unstructured → structured)

Ground narrative attack/vulnerability descriptions from threat reports to formal
taxonomy entries. The challenge: analyst prose uses action-oriented language
("harvested credentials from memory") that differs from technique-oriented
taxonomy terminology ("T1003.001 — LSASS Memory"). A single passage may
describe multiple interleaved behaviors (one-to-many).

### ATA — Attack Technique Attribution (Report → ATT&CK)
Identify all MITRE ATT&CK techniques described in a report passage.
- **Input**: *"I recently read in a security blog: '<excerpt>' ..."* + 2–3 sub-questions (technique, mapping explanation, affected platforms / data sources)
- **Output**: one or more `TXXXX` entries with explanations
- **Ground truth**: set of technique IDs

### VCA — Vulnerability Catalog Attribution (Report → CWE)
Identify all CWE weakness categories referenced in an exploitation narrative.
Reports describe *effects* rather than naming weaknesses, so the model must
infer root causes from consequences.
- **Input**: blog excerpt + sub-questions
- **Output**: one or more `CWE-XXX` entries with explanations
- **Ground truth**: set of CWE IDs

---

## 🔀 Multi-Document Synthesis (unstructured → unstructured)

Aggregate intelligence about the same entity scattered across multiple vendor
reports. The defining challenge is **entity aliasing**: vendors name the same
actor/malware/campaign differently (APT29 / Cozy Bear / Midnight Blizzard),
creating near-miss distractors that defeat embedding similarity.

**Input form** (important): the model is given **one anchor report** plus a
synthesis question. It must **retrieve related reports** about the same entity
from the corpus, then synthesize. Closed-book is not evaluated for this
category because the task inherently requires multi-document retrieval. The
gold answer set lists which corpus reports the retriever should surface.

### TAP — Threat Actor Profiling
Synthesize a comprehensive actor profile (TTPs, targets, toolset) from reports
referencing the same group under different aliases, requiring implicit entity
resolution before aggregation.

### MLA — Malware Lineage Analysis
Trace the evolutionary lineage of a malware family across reports on related
variants — capability progression, code reuse, distribution and targeting
shifts over time. Genuinely requires multiple reports across years; a single
recent report cannot answer how the family evolved.

### CSC — Campaign Storyline Construction
Reconstruct a coherent campaign timeline from reports documenting different
phases of the same operation, reconciling fragmented, partially overlapping
accounts into a unified chronology.

MDS questions are templated per analytical aspect (e.g., CSC has
`dates` / `entities` / `targeting` / `tool`; TAP has `actor` / `target` /
`tool`; MLA has `variant` / `capability` / `lineage`).

---

## Data sources behind each category

| Category | Ground-truth source | Tasks |
|---|---|---|
| Entity Linking | Official cross-source mappings (MITRE, NVD) | RCM, WIM, ATD, ESD |
| Entity Attribution | Blog-to-Framework dual expert annotation | ATA, VCA |
| Multi-Doc Synthesis | Adversary-centric report clusters (≥2 vendors) | CSC, TAP, MLA |
