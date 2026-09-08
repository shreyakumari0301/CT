"""Task-specific CTA-RAG prompt templates (mirrors pipelines/, not TCAR contrast cards)."""

from __future__ import annotations

import os

_NO_CANDIDATES = "(No retrieved catalogue candidates.)"
_NO_CONTEXT = "(No retrieved context.)"
_NO_KB = "No knowledge base context available."
_NO_CWE = "No CWE context available."

# Shared with eval/cta_rag_port.py — keep wording identical.
RCM_SINGLE_ID_REQUIREMENTS = (
    '1. Line 1 must contain exactly one CWE-ID (e.g., "CWE-ID: CWE-284").\n'
    "2. Provide the corresponding CWE name on the next line\n"
    "3. Give a concise justification explaining how the vulnerability aligns with the CWE description\n"
    "4. Reference retrieved catalogue entries only when they match the root cause, "
    "and never by writing any other CWE-### identifier"
)

RCM_PARENT_OVER_SIBLING = (
    "- Retrieved CWE entries / similar cases are hints, not an allow-list. "
    "If none fits, use any valid CWE ID from the vulnerability description.\n"
    "- Presence in the retrieved list is not a reason to pick that ID. "
    "Pick the NVD-style ROOT CAUSE, even if a sibling/child ranks higher.\n"
    "- If the retrieved set is a near-miss cluster (siblings/variants of the right family) "
    "and none matches the root cause in the description, do NOT adopt a retrieved ID—"
    "keep the standard NVD mapping from the description alone.\n"
    "- Do NOT copy a CWE label from a similar KB case when the case's weakness differs "
    "from this description (e.g. do not switch CWE-120↔CWE-119 or CWE-787↔CWE-122 "
    "just because a neighbour used the other ID).\n"
    "- Prefer the most specific correct weakness when the description supports it:\n"
    "  * path traversal → CWE-22, not CWE-23 / CWE-36 / CWE-41\n"
    "  * OS command injection (shell/OS command built from user input, system()/exec) → "
    "CWE-78; if the text only says generic \"command injection\" without an OS/shell cue → "
    "CWE-77, not CWE-78\n"
    "  * non-OS command / argument injection without an OS shell → CWE-77, not CWE-74\n"
    "  * XSS → CWE-79, not CWE-80 / CWE-81 / CWE-83\n"
    "  * SQL injection → CWE-89, not CWE-943 (or other data-query injection neighbours)\n"
    "  * CORS / cross-origin checks that fail to validate the request Origin → CWE-346 "
    "(origin validation error), not CWE-942 (permissive cross-domain policy) unless the "
    "flaw is literally a permissive policy document\n"
    "  * out-of-bounds read / reading past a buffer into adjacent memory → CWE-125, "
    "not CWE-126 / CWE-127 unless the text specifically names buffer over-read/under-read "
    "as the catalogued variant\n"
    "  * classic buffer copy / buffer overflow without size checking (gets, strcpy-style, "
    "\"buffer overflow\" in parsers) → prefer CWE-120 over generic CWE-119\n"
    "  * heap/stack buffer overflow that is a memory write past bounds, or "
    "\"out-of-bounds write\" / \"invalid memory write\" → prefer CWE-787 over CWE-122 / "
    "CWE-121 / CWE-119 unless the text clearly names only stack/heap overflow as the "
    "catalogued class and not a write-past-bounds root cause\n"
    "  * uncontrolled resource consumption / DoS from exhaustion → CWE-400, not "
    "CWE-770 / CWE-674 / CWE-730 / CWE-410 / CWE-407 / CWE-409 unless that more-specific "
    "mechanism is clearly the only root cause (e.g. only unbounded recursion with no "
    "broader resource exhaustion)\n"
    "  * missing authentication / API that allows requests with no auth by default → "
    "CWE-306, not CWE-1392 (default credentials). Missing auth ≠ default credentials; "
    "do not switch to CWE-1392 just because the query says \"default\".\n"
    "  * improper privilege management / local privilege escalation via bad privilege "
    "handling → CWE-269, not CWE-732 / CWE-272 unless permissions/assignment is the "
    "only stated root cause\n"
    "- Do not switch to a retrieved near-miss when a well-known base CWE is a better fit.\n"
    '- Always commit to the most likely CWE; do not answer "UNKNOWN" and do not abstain.\n'
    "- Output exactly one CWE-ID in the whole response (on line 1). "
    "Do not mention any other CWE-### identifier anywhere in the answer."
)

# How many CWE catalogue hits to put in the RCM prompt (retrieve at least this many).
RCM_PROMPT_K = 12
# CTIConnect ATA / CTIBench ATE: MITRE GAD prompt size (same pipeline as RCM: diversify → K).
ATA_PROMPT_K = 12
# ATE / MCQ / VSP graph-aware catalogue size (same K as RCM/ATA GAD).
OTHER_GAD_K = 12

# CTIBench understanding path: keep GAD CWE in prompt, but do not let it override KB.
RCM_KB_FIRST_OVER_CWE = (
    "- PRIMARY evidence is the vulnerability DESCRIPTION, then RCM knowledge-base context "
    "(similar cases / mem chunks) as supporting analogies only.\n"
    "- Infer the NVD-style ROOT CAUSE from the description first. "
    "Do not adopt a neighbour case's CWE if that case describes a different weakness.\n"
    "- The CWE catalogue block (when present) is SECONDARY / advisory only "
    "(graph-diversified hints). It is not an allow-list and must not override a clear "
    "description mapping.\n"
    "- Adopt a retrieved CWE ID only when it clearly matches that root cause. "
    "If the catalogue / KB neighbours are a near-miss cluster, keep the description "
    "mapping instead of switching to a listed neighbour.\n"
    "- Never rewrite a description-correct CWE-120 into CWE-119 (or CWE-269 into "
    "CWE-732 / CWE-284) just because the neighbour ID appears in retrieved context.\n"
)

# Vanilla KB primary + taxonomy candidates as verification only (RCM v2).
RCM_VANILLA_ADVISORY = (
    "1. Determine the weakness from the vulnerability description and KB evidence.\n"
    "2. Use CWE candidates only to verify the identified mechanism.\n"
    "3. Do not change a KB-supported answer solely because a related candidate "
    "appears in the catalogue.\n"
    "4. Return exactly one CWE.\n"
)

# CTIConnect RCM: no mem KB — description-first, GAD catalogue advisory (same soft idea).
RCM_DESC_FIRST_OVER_CWE = (
    "- PRIMARY evidence is the vulnerability description. "
    "Infer the NVD-style ROOT CAUSE from the description first.\n"
    "- Retrieved CWE catalogue entries are SECONDARY / advisory only "
    "(graph-diversified hints). They are not an allow-list and must not override a "
    "clear description-based mapping.\n"
    "- Adopt a retrieved CWE ID only when it clearly matches that root cause. "
    "If the catalogue is a near-miss cluster (siblings/variants), keep the "
    "description mapping instead of switching to a listed neighbour.\n"
    "- Never rewrite CWE-400→CWE-674, CWE-476→CWE-822, or CWE-269→CWE-284 just because "
    "the neighbour appears in the catalogue.\n"
)


def cticonnect_rcm_requirements_guidance() -> tuple[str, str]:
    """Soft understanding guidance (matches eval/cta_rag_port.py)."""
    return RCM_SINGLE_ID_REQUIREMENTS, RCM_DESC_FIRST_OVER_CWE + RCM_PARENT_OVER_SIBLING


def build_cticonnect_rcm_prompt(*, question: str, candidates: str) -> str:
    requirements, guidance = cticonnect_rcm_requirements_guidance()
    return f"""You are the CTA-RAG understanding module (task: root-cause mapping).

PRIMARY — VULNERABILITY DESCRIPTION:
{question}

ADVISORY CWE CATALOGUE (graph-diversified hints — secondary; not an allow-list):
{candidates}

TASK:
Map the vulnerability to the most relevant CWE. Decide from the description first; use the
advisory catalogue only to confirm or refine when it clearly matches that root cause.

RESPONSE REQUIREMENTS:
{requirements}

IMPORTANT:
{guidance}"""


def build_cticonnect_ata_behavior_prompt(*, question: str, behavior_blocks: str) -> str:
    """ATA Forced RAG: per-behavior candidates; every ID must map to an explicit behavior."""
    from tcar.specialist_retrieval import ata_abstain_enabled  # noqa: WPS433

    if ata_abstain_enabled():
        return f"""You are the CTA-RAG reasoning module (task: attack technique attribution).

PRIMARY — FULL TEXT:
{question}

PER-BEHAVIOR EVIDENCE (retrieve independently for each atomic behavior):
{behavior_blocks}

TASK:
Map each atomic behavior to at most one MITRE ATT&CK technique ID that is clearly
supported by that behavior's text. Then emit the consolidated unique ID set.

HARD CONSTRAINTS:
- Every emitted technique MUST map to an explicit atomic behavior above.
- Do NOT add actor-associated or "commonly related" techniques without textual evidence
  in that behavior.
- Do NOT emit both a parent (T####) and its sub-technique (T####.###) for the same behavior;
  keep the most specific supported ID only.
- Presence in a candidate list is NOT a reason to include that ID.
- Prefer PRECISION over recall: omit unsupported IDs rather than over-predicting.
- If no technique has explicit behavioural support in the evidence blocks, leave the
  answer line empty (the system will keep the closed-book prediction).
- Otherwise emit only supported technique IDs.

Provide your response in the following format:
reasoning: [map each behavior → chosen ID or none]
answer: [comma-separated technique IDs]"""
    return f"""You are the CTA-RAG reasoning module (task: attack technique attribution).

PRIMARY — FULL TEXT:
{question}

PER-BEHAVIOR EVIDENCE (retrieve independently for each atomic behavior):
{behavior_blocks}

TASK:
Map each atomic behavior to at most one MITRE ATT&CK technique ID that is clearly
supported by that behavior's text. Then emit the consolidated unique ID set.

HARD CONSTRAINTS:
- Every emitted technique MUST map to an explicit atomic behavior above.
- Do NOT add actor-associated or "commonly related" techniques without textual evidence
  in that behavior.
- Do NOT emit both a parent (T####) and its sub-technique (T####.###) for the same behavior;
  keep the most specific supported ID only.
- Presence in a candidate list is NOT a reason to include that ID.
- Prefer PRECISION over recall: omit unsupported IDs rather than over-predicting.
- NEVER leave the answer empty if at least one behavior has a clear technique.

Provide your response in the following format:
reasoning: [map each behavior → chosen ID or none]
answer: [comma-separated technique IDs]"""


def build_cticonnect_ata_grounded_prompt(*, question: str, grounded_block: str) -> str:
    """Behaviour-grounded ATA v4: exactly one taxonomy-aware ID + abstain when inconsistent."""
    return f"""ROLE:
You are a CTI analyst mapping explicit adversary behaviours to MITRE ATT&CK techniques.

REPORT:
{question}

CANDIDATES (strong = lexical/action support; provisional = high-RRF / weak link):
{grounded_block}

DECISION RULES:
- Return EXACTLY ONE technique ID — the single best match for the report — or abstain.
- Compare each candidate against the explicit observed behaviour, not actor/malware names.
- PARENT/SUB: if distinguishing sub-technique behaviour is explicit (e.g. PowerShell → T1059.001),
  choose the sub; otherwise the parent.
- NEAR-MISS CONTRAST: when two neighbour families appear (e.g. T1606 vs T1558, T1203 vs T1204,
  T1190 vs T1588), choose only the ID whose distinguishing behaviour is explicit.
- Presence in the candidate list is NOT alone a reason to choose that ID.
- If evidence is mixed, only loosely related, or supports conflicting neighbours, abstain.

OUTPUT (STRICT):
Return ONLY one JSON object. No reasoning. No markdown. No other keys.
{{"predicted_id": "Txxxx"}}
or
{{"predicted_id": ""}}"""


def build_cticonnect_ata_prompt(*, question: str, candidates: str) -> str:
    """CTIConnect ATA only (not CTIBench ATE). Soft = text-first, catalogue advisory."""
    # Default soft for Forced RAG: dense catalogue often harms exact-ID scoring.
    soft = (os.getenv("ATA_PROMPT", "soft") or "soft").strip().lower() != "strict"
    if soft:
        return f"""You are the CTA-RAG reasoning module (task: attack technique attribution).

PRIMARY — TEXT TO ANALYZE:
{question}

ADVISORY MITRE ATT&CK CATALOGUE (retrieved hints — secondary; not an allow-list):
{candidates}

TASK:
Extract all MITRE ATT&CK techniques evidenced in the text. Decide from the text first; use
the advisory catalogue only to confirm or refine IDs when they clearly match the evidence.

Rules:
- Include sub-technique IDs (T####.###) when the text supports that granularity.
- Use parent technique IDs (T####) when sub-technique level is not justified.
- Do not invent techniques not supported by the text.
- Presence in the retrieved list is not a reason to include that ID.
- If a retrieved neighbour is a near-miss, prefer the ID justified by the text alone.
- NEVER leave the answer empty: always emit at least the best-supported technique ID(s)
  from the TEXT (parametric knowledge is allowed when the catalogue is off-topic).

Provide your response in the following format:
reasoning: [your reasoning here]
answer: [comma-separated technique IDs]"""

    return f"""You are the CTA-RAG reasoning module (task: attack technique attribution).

Extract all MITRE ATT&CK techniques evidenced in the text. Map each to technique IDs.
Use retrieved catalogue entries as supporting evidence when they match.

RETRIEVED MITRE ATT&CK CANDIDATES:
{candidates}

TEXT TO ANALYZE:
{question}

Rules:
- Include sub-technique IDs (T####.###) when the text supports that granularity.
- Use parent technique IDs (T####) when sub-technique level is not justified.
- Do not invent techniques not supported by the text.
- NEVER leave the answer empty.

Provide your response in the following format:
reasoning: [your reasoning here]
answer: [comma-separated technique IDs]"""


def understanding_rcm_prompt_blocks() -> tuple[str, str]:
    """Match pipelines/understanding_pipeline._prompt_blocks (env RCM_PROMPT / RCM_GAD)."""
    soft = (os.getenv("RCM_PROMPT", "strict") or "strict").strip().lower() != "strict"
    force_gad = (os.getenv("RCM_GAD") or "").strip().lower() == "force"
    # Soft prompt or Force GAD: KB-first + parent-over-sibling (catalogue is advisory).
    if soft or force_gad:
        return RCM_SINGLE_ID_REQUIREMENTS, RCM_KB_FIRST_OVER_CWE + RCM_PARENT_OVER_SIBLING

    requirements = (
        '1. Line 1 must contain exactly one CWE-ID from the CWE context (e.g., "CWE-ID: CWE-284").\n'
        "2. Provide the exact CWE name from the CWE context on the next line\n"
        "3. Give a concise justification explaining how the vulnerability aligns with the CWE description\n"
        "4. Reference details from RCM knowledge base / CWE contexts without writing any other CWE-### ID\n"
        '5. If no clear match exists in the provided CWE contexts, respond with "CWE-UNKNOWN" as the only CWE-ID'
    )
    guidance = (
        "- Only use CWE IDs that appear in the provided CWE context\n"
        "- Be precise in matching vulnerability characteristics to CWE descriptions\n"
        "- If several context IDs could match, prefer the base/parent CWE over a "
        "child, sibling, or symptom variant (CWE-22 not 23/36/41; CWE-77 not 74; "
        "CWE-79 not 80/81; missing auth / no-auth-by-default → CWE-306 not CWE-1392 "
        "default credentials. Missing auth ≠ default credentials.)\n"
        "- Do not pick a retrieved ID just because it appears in the list; pick the "
        "NVD-style root cause.\n"
        "- Output exactly one CWE-ID in the whole response (on line 1). "
        "Do not mention any other CWE-### identifier anywhere in the answer."
    )
    return requirements, guidance

def build_understanding_rcm_prompt(
    *,
    query: str,
    kb_context: str,
    cwe_context: str,
) -> str:
    """Same structure as pipelines/understanding_pipeline._generate_response.

    Soft / Force GAD: description-first; KB + CWE catalogue are advisory.
    K / retrieval unchanged — only primacy wording.

    RCM_PIPELINE=vanilla_advisory (or RCM_PROMPT=advisory): Vanilla KB primary;
    taxonomy candidates verify only — never replace KB-supported answers.
    """
    advisory = (os.getenv("RCM_PROMPT") or "").strip().lower() in {
        "advisory",
        "vanilla_advisory",
        "kb_advisory",
    } or (os.getenv("RCM_PIPELINE") or "").strip().lower() in {
        "vanilla_advisory",
        "advisory",
        "kb_advisory",
        "kb_primary",
        "verify",
    }
    if advisory:
        return f"""
You are a cybersecurity analyst specializing in vulnerability classification and CWE mapping.

PRIMARY — VULNERABILITY DESCRIPTION:
{query}

PRIMARY EVIDENCE — RCM KNOWLEDGE BASE (similar cases / analogies):
{kb_context}

ADVISORY CWE CANDIDATES (verification only — not primary evidence):
{cwe_context}

TASK:
{RCM_VANILLA_ADVISORY}

RESPONSE FORMAT (JSON):
{{
    "predicted_cwe": "CWE-XXX",
    "cwe_name": "CWE name",
    "justification": "Brief technical explanation referencing description + KB; candidates only if verifying"
}}

IMPORTANT:
{RCM_SINGLE_ID_REQUIREMENTS}
{RCM_KB_FIRST_OVER_CWE}{RCM_PARENT_OVER_SIBLING}
"""
    requirements, guidance = understanding_rcm_prompt_blocks()
    soft = (os.getenv("RCM_PROMPT", "strict") or "strict").strip().lower() != "strict"
    force_gad = (os.getenv("RCM_GAD") or "").strip().lower() == "force"
    if soft or force_gad:
        return f"""
You are a cybersecurity analyst specializing in vulnerability classification and CWE mapping.

PRIMARY — VULNERABILITY DESCRIPTION:
{query}

SUPPORTING RCM KNOWLEDGE BASE (similar cases — analogies only; do not copy a neighbour's CWE):
{kb_context}

ADVISORY CWE CATALOGUE (secondary; not an allow-list):
{cwe_context}

TASK:
Map the vulnerability to the most relevant CWE. Decide from the DESCRIPTION first.
Use KB/catalogue only to confirm when they clearly match that root cause — never switch
away from a clear description mapping because a neighbour used a different CWE.

RESPONSE REQUIREMENTS:
{requirements}

RESPONSE FORMAT (JSON):
{{
    "predicted_cwe": "CWE-XXX",
    "cwe_name": "CWE name (from description or matching catalogue entry)",
    "justification": "Brief technical explanation referencing specific context details..."
}}

IMPORTANT:
{guidance}
"""
    return f"""
You are a cybersecurity analyst specializing in vulnerability classification and CWE mapping.

CONTEXT FROM RCM KNOWLEDGE BASE:
{kb_context}

CONTEXT FROM CWE DATABASE:
{cwe_context}

VULNERABILITY DESCRIPTION:
{query}

TASK:
Analyze the vulnerability description and map it to the most relevant CWE \
category based on the provided contexts.

RESPONSE REQUIREMENTS:
{requirements}

RESPONSE FORMAT (JSON):
{{
    "predicted_cwe": "CWE-XXX",
    "cwe_name": "Exact Name from CWE Context",
    "justification": "Brief technical explanation referencing specific context details..."
}}

IMPORTANT:
{guidance}
"""


def build_ate_prompt(*, description: str, similar_context: str, catalogue: str = "") -> str:
    """ATE: default = mem-chunk context; GAD force/soft add MITRE catalogue.

    Set ATE_PROMPT=cta for original CTA-RAG reasoning_ate_pipeline wording/order
    (context → description) to measure pipeline fidelity vs Forced-RAG prompt edits.
    """
    from tcar.specialist_retrieval import ate_prompt_mode  # noqa: WPS433

    if ate_prompt_mode() == "cta" and not catalogue:
        # Verbatim CTA paper pipeline prompt (pipelines/reasoning_ate_pipeline._build_prompt).
        return f"""Extract all MITRE attack patterns from the following text and map them to their corresponding MITRE technique IDs. Provide reasoning for each identification. Ensure the final line contains only the IDs for the main techniques, separated by commas, excluding any subtechnique IDs.

Relevant context:
{similar_context}

Text to analyze:
{description}

Provide your response in the following format:
reasoning: [your reasoning here]
answer: [comma-separated technique IDs]"""

    instruction = (
        "Extract all MITRE attack patterns from the following text and map them to their "
        "corresponding MITRE technique IDs. Provide reasoning for each identification. "
        "Ensure the final line contains only the IDs for the main techniques, separated "
        "by commas, excluding any subtechnique IDs."
    )
    mode = (os.getenv("GAD_MODE") or "off").strip().lower()
    if mode == "soft" and catalogue:
        return f"""You are the CTA-RAG reasoning module (task: ATT&CK technique extraction).

PRIMARY — TEXT TO ANALYZE:
{description}

ADVISORY MITRE ATT&CK CATALOGUE (graph-diversified hints — secondary; not an allow-list):
{catalogue}

SUPPORTING PASSAGES:
{similar_context}

TASK:
Extract all MITRE ATT&CK techniques evidenced in the text. Decide from the text first;
use the advisory catalogue only to confirm IDs when they clearly match the evidence.
Presence in the retrieved list is not a reason to include that ID.
Exclude subtechnique IDs from the final answer line (main techniques only).

Provide your response in the following format:
reasoning: [your reasoning here]
answer: [comma-separated technique IDs]"""
    if mode == "force" and catalogue:
        return f"""{instruction}

PRIMARY — TEXT TO ANALYZE:
{description}

ADVISORY MITRE ATT&CK CATALOGUE (graph-diversified hints — supporting only, NOT an allow-list):
{catalogue}

SUPPORTING PASSAGES:
{similar_context}

CRITICAL RULES:
- Decide techniques from the TEXT first. Include a catalogue ID only when the text clearly supports it.
- Presence in the retrieved list is NOT a reason to emit that ID.
- Prefer PRECISION over recall: do not add catalogue neighbours (e.g. remote-access software,
  non-standard port) that are not evidenced in the text — extra wrong IDs fail the score.
- Do NOT invent techniques that are only nearby in the ATT&CK hierarchy.
- Prefer MAIN technique IDs (Txxxx). Never put subtechnique IDs (Txxxx.xxx) on the final answer line —
  if you reason about a subtechnique, map it to its parent main ID for the answer.
- The final answer line must be comma-separated MAIN technique IDs only.

Provide your response in the following format:
reasoning: [your reasoning here]
answer: [comma-separated main technique IDs]"""
    return f"""{instruction}

PRIMARY — TEXT TO ANALYZE:
{description}

SUPPORTING PASSAGES (similar mem chunks — advisory only; not an allow-list):
{similar_context}

CRITICAL RULES:
- Extract EVERY ATT&CK technique clearly evidenced in the TEXT (be comprehensive on recall).
- Prefer PRECISION as well: do not add techniques that only appear in supporting passages
  unless the text itself supports them.
- Prefer MAIN technique IDs (Txxxx). Never put subtechnique IDs (Txxxx.xxx) on the final
  answer line — map subs to their parent main ID.
- The final answer line must list comma-separated MAIN technique IDs covering all
  evidenced behaviours. Do not leave the answer empty.

Provide your response in the following format:
reasoning: [your reasoning here]
answer: [comma-separated main technique IDs]"""


def build_ate_exploitation_prompt(*, description: str, stage_context: str) -> str:
    """ATE ablation: exploitation-stage evidence; recall-balanced chain coverage.

    Distinct from ATA behaviour-grounded prompts (precision / minimal set).
    """
    return f"""You are a CTI analyst mapping a vulnerability's exploitation chain to
MITRE ATT&CK techniques.

VULNERABILITY DESCRIPTION:
{description}

EXPLOITATION-STAGE EVIDENCE (advisory; retrieve per stage — not an allow-list):
{stage_context}

DECISION RULES:
- Cover the exploitation chain: initial access condition, exploitation mechanism,
  privilege/execution effect, post-exploitation capability, and impact when evidenced.
- Prefer RECALL of techniques that participate in exploiting this vulnerability;
  do not omit a clearly supported chain step.
- Do not invent techniques from similar vulnerabilities that are not supported by
  THIS description.
- Prefer MAIN technique IDs (Txxxx). Never put subtechnique IDs (Txxxx.xxx) on the
  final answer line — map subs to their parent main ID.
- Presence in retrieved passages alone is not a reason to emit an ID.

OUTPUT FORMAT:
reasoning: [brief chain coverage reasoning]
answer: [comma-separated main technique IDs]"""


def build_mcq_prompt(*, question: str, context: str, catalogue: str = "") -> str:
    """MCQ: default mem context; GAD force/soft add CWE/MITRE catalogue hints."""
    mode = (os.getenv("GAD_MODE") or "off").strip().lower()
    if mode == "soft" and catalogue:
        return f"""You are a Cyber Threat Intelligence (CTI) assistant answering a multiple-choice question.

PRIMARY — QUESTION:
{question}

ADVISORY CATALOGUE (graph-diversified CWE/ATT&CK hints — secondary; not an allow-list):
{catalogue}

SUPPORTING PASSAGES:
{context}

Decide from the question first. Use catalogue/passages only when they clearly match.
Presence in the retrieved list is not a reason to pick an option.

REQUIREMENTS:
- Choose exactly one option: A, B, C, or D.
- Give brief reasoning (a few sentences).
- The last line must be exactly: Final Answer: <A|B|C|D>
- Do not abstain. Do not say "cannot be determined".
"""
    if mode == "force" and catalogue:
        return f"""You are a Cyber Threat Intelligence (CTI) assistant answering a multiple-choice question.

PRIMARY — QUESTION (keep the named malware / tool / group / CVE exactly as written):
{question}

ADVISORY CATALOGUE (graph-diversified CWE/ATT&CK — supporting only, NOT an allow-list):
{catalogue}

SUPPORTING PASSAGES:
{context}

CRITICAL RULES:
- Keep the malware, tool, group, or CVE named in the QUESTION. Do NOT swap it for a different
  entity just because that entity appears in the retrieved catalogue or passages
  (e.g. do not replace Pupy with InvisiMole, or Brute Ratel with BendyBear).
- Use catalogue/passages only to confirm facts about the entity named in the question.
- Presence in the retrieved list is not a reason to pick an option.

REQUIREMENTS:
- Choose exactly one option: A, B, C, or D.
- Give brief reasoning (a few sentences).
- The last line must be exactly: Final Answer: <A|B|C|D>
- Do not abstain. Do not say "cannot be determined".
"""
    return f"""You are a Cyber Threat Intelligence (CTI) assistant answering a multiple-choice question.

PRIMARY — QUESTION (keep the named malware / tool / group / CVE exactly as written):
{question}

SUPPORTING PASSAGES (advisory only — not an allow-list):
{context}

CRITICAL RULES:
- Decide from the QUESTION first. Keep the malware, tool, group, or CVE named in the question.
  Do NOT swap it for a different entity that appears only in supporting passages
  (e.g. do not replace APT39 with Fox Kitten, iKitten with Green Lambert, Akira with LockerGoga,
  Black Basta with StoneDrill, or Pupy with InvisiMole).
- If passages discuss a DIFFERENT named actor/malware/tool than the question, IGNORE the
  passages completely and answer from the question + reliable CTI knowledge alone.
- Use passages only to confirm facts about the entity named in the question.
- If passages are incomplete, off-topic, or conflict with the named entity, prefer parametric
  knowledge over the passages.

REQUIREMENTS:
- Choose exactly one option: A, B, C, or D.
- Give brief reasoning (a few sentences).
- The last line must be exactly: Final Answer: <A|B|C|D>
- Do not abstain. Do not say "cannot be determined".
"""


VSP_BASE_PROMPT = """
Analyze the following CVE description and calculate the CVSS v3.1 Base Score. Determine the values for each base metric: AV, AC, PR, UI, S, C, I, and A. Summarize each metric's value and provide the final CVSS v3.1 vector string. Valid options for each metric are as follows: - **Attack Vector (AV)**: Network (N), Adjacent (A), Local (L), Physical (P) - **Attack Complexity (AC)**: Low (L), High (H) - **Privileges Required (PR)**: None (N), Low (L), High (H) - **User Interaction (UI)**: None (N), Required (R) - **Scope (S)**: Unchanged (U), Changed (C) - **Confidentiality (C)**: None (N), Low (L), High (H) - **Integrity (I)**: None (N), Low (L), High (H) - **Availability (A)**: None (N), Low (L), High (H) Summarize each metric's value and provide the final CVSS v3.1 vector string. Ensure the final line of your response contains only the CVSS v3 Vector String in the following format: Example format: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H CVE
""".strip()


def build_vsp_prompt(*, query_description: str, case_block: str, catalogue: str = "") -> str:
    """VSP: default historical cases; GAD force/soft add CWE catalogue hints."""
    mode = (os.getenv("GAD_MODE") or "off").strip().lower()
    if mode == "soft" and catalogue:
        return (
            f"PRIMARY — CVE Description:\n{query_description}\n\n"
            f"ADVISORY CWE CATALOGUE (graph-diversified hints — secondary; not an allow-list):\n"
            f"{catalogue}\n\n"
            f"{case_block}\n"
            "Score from the CVE description first. Use catalogue/cases only when they "
            "match the described impact; do not copy a neighbour's vector.\n\n"
            f"{VSP_BASE_PROMPT}\n\n"
            "Provide the summary for each metric and ensure the final line ONLY contains "
            "the CVSS v3.1 vector string."
        )
    if mode == "force" and catalogue:
        return (
            f"CVE Description (PRIMARY evidence for scoring):\n{query_description}\n\n"
            f"{case_block}\n"
            f"RETRIEVED CWE CATALOGUE (optional hints only — do NOT copy CVSS from neighbours):\n"
            f"{catalogue}\n\n"
            f"{VSP_BASE_PROMPT}\n\n"
            "CRITICAL RULES:\n"
            "- Score AV/AC/PR/UI/S/C/I/A from the CVE description itself.\n"
            "- CWE IDs do not determine Attack Vector or Attack Complexity; do not flip AV:L↔AV:N "
            "or AC:L↔AC:H just because a CWE appears in the catalogue.\n"
            "- Historical cases are analogies only; do not copy another CVE's vector.\n"
            "Provide the summary for each metric and ensure the final line ONLY contains "
            "the CVSS v3.1 vector string."
        )
    return (
        f"PRIMARY — CVE Description:\n{query_description}\n\n"
        f"{case_block}\n"
        "CRITICAL RULES:\n"
        "- Score AV/AC/PR/UI/S/C/I/A from the CVE description itself, metric by metric.\n"
        "- Historical cases are analogies only; do NOT copy another case's privileges, "
        "impact, scope, or full vector (especially PR / UI / S / C / I / A).\n"
        "- If a historical case disagrees with the description on any metric, trust the "
        "description and ignore that case's value for that metric.\n"
        "- Prefer a description-derived vector over a copied neighbour vector.\n"
        f"{VSP_BASE_PROMPT}\n\n"
        "Provide the summary for each metric and ensure the final line ONLY contains "
        "the CVSS v3.1 vector string."
    )


def empty_candidates() -> str:
    return _NO_CANDIDATES


def empty_mem_context() -> str:
    return _NO_CONTEXT


def empty_rcm_kb_context() -> str:
    return _NO_KB


def empty_rcm_cwe_context() -> str:
    return _NO_CWE
