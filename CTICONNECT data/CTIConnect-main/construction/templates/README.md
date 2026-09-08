# Construction Templates

Each subdirectory holds the Jinja2 prompt template for one CTIConnect task. The repository ships **one canonical template per task** — the version used to produce the published `v0.9` release (paper Appendix C, "Prompt in Benchmark Construction").

## Canonical versions (v0.9 release)

| Task | Template | Why this version |
|---|---|---|
| RCM | `rcm/v4.jinja` | Forbids the question from leaking the source CVE ID or target CWE ID/name; requires the answer description field to be non-empty. |
| WIM | `wim/v3.jinja` | Same identifier-leakage rule as RCM, adapted to CWE→CVE direction. |
| ATD | `atd/v5.jinja` | Same identifier-leakage rule, adapted to CAPEC→ATT&CK. |
| ESD | `esd/v3.jinja` | Same identifier-leakage rule, adapted to CWE→CAPEC. |
| ATA | `ata/v5.jinja` | Stable B2F-aware template producing report-passage → ATT&CK QA. |
| VCA | `vca/v4.jinja` | Stable B2F-aware template producing report-passage → CWE QA. |
| CSC | `csc/v6.jinja` | First CSC version to consistently emit the `question` field in every output. |
| TAP | `tap/v2.jinja` | Stable cluster-aware template producing actor / target / tool aspect QA. |
| MLA | `mla/v2.jinja` | Stable cluster-aware template producing variant / capability aspect QA. |

## Pinning policy

The release pipeline consumes only the canonical version per task — the version numbers above match `engine/t2p/run_generator.py --template-version` defaults and the `data/manifest.json` provenance stamps for the shipped `v0.9` benchmark. To change the canonical version, add a new `vN.jinja` (do not overwrite older versions in place — they may have generated already-published data) and update this table.

## Designing a new template

A CTIConnect template renders into a single LLM prompt. It receives two Jinja variables:

- `SOURCE_NODE` — JSON string of the seed entity (CVE / CWE / CAPEC / MITRE / blog).
- `TARGET_NODE` — JSON string of the answer entity (or, for MDS, the related entities in the same cluster).

Conventions enforced across all current templates:

1. **No identifier leakage in the question.** For Entity Linking, the question must describe the behavior in natural language without naming the source or target identifier. Vendor product names with specific versions, internal function names, and exact endpoint paths are also forbidden — they uniquely fingerprint the CVE and trivialise retrieval.
2. **Structured answer format.** The answer always starts with the target identifier as a bullet, followed by a single short description bullet that paraphrases the target's name or definition (≤ 22 words). This makes regex-based scoring tractable for the leaderboard evaluator.
3. **Use only the provided inputs.** Templates instruct the LLM not to invent facts. The construction-time triage (`evaluation/judge/run_judge.py`) re-checks grounding by scoring against the original CTI document.
