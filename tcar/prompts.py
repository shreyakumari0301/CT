"""TCAR prompts (single LLM call for final answer)."""

RCM_CLOSED_BOOK = """You are a Cyber Threat Intelligence expert. Answer directly.
When asked for a CWE weakness category, state the exact CWE-### identifier and brief justification.

QUESTION:
{question}

Answer with the CWE-ID explicitly in the form CWE-###."""

RCM_CONTRAST = """You are a Cyber Threat Intelligence expert performing root-cause mapping (CVE description -> CWE).

Use the contrast card below. Prefer the candidate with the strongest support and weakest contradictions.
Do NOT list multiple CWE IDs unless the question clearly requires several; for RCM output exactly ONE CWE-ID.

{contrast_card}

QUESTION:
{question}

End your answer with a line: CWE-ID: CWE-###"""

ATA_CLOSED_BOOK = """You are a Cyber Threat Intelligence expert. Map the described behavior to MITRE ATT&CK.
Output format:
reasoning: [brief]
answer: [comma-separated technique IDs only, e.g. T1190 or T1053.005]

TEXT:
{question}"""

ATA_CONTRAST = """You are a Cyber Threat Intelligence expert. Map behaviors to MITRE ATT&CK technique IDs.

Rules:
- Include ONLY techniques supported by explicit behaviors in the text.
- Prefer sub-technique IDs when the text supports that granularity.
- Do NOT add techniques merely because they appear in the contrast card.

{contrast_card}

TEXT:
{question}

Output format:
reasoning: [brief]
answer: [comma-separated technique IDs]"""
