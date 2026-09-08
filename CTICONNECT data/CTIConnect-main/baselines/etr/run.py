#!/usr/bin/env python3
"""Extract-then-Retrieve (EtR) — domain-specific strategy for Entity Linking.

Two stages:
  1. *Extract + canonicalize* — the LLM rewrites the query into a 3-5
     keyphrase list expressed in the **target framework's own idiom**
     (CWE-style "Improper X" / MITRE-style "Parent: Sub-technique" / etc.),
     so the rewritten string lexically aligns with KB entries before
     embedding. The per-task style guides are in ``CANONICALIZATION_HINTS``.
  2. *Retrieve + answer* — the canonicalized keyphrase string drives dense
     retrieval against the target KB; the answering model then picks the
     best match from the retrieved candidates.

    python -m baselines.etr.run --out preds_etr.jsonl --tasks rcm wim atd esd --limit 5
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from baselines._shared import baseline_cli  # noqa: E402
from baselines._shared.llm import ChatLLM  # noqa: E402
from baselines._shared.retriever import KBRetriever, format_candidates  # noqa: E402


# Per-task framework style guide. Each task's target KB has a stable
# linguistic register; aligning the LLM-rewritten query to that register
# tightens the cosine match against KB entries.
CANONICALIZATION_HINTS = {
    "rcm": {  # target KB: CWE
        "framework": "CWE (Common Weakness Enumeration)",
        "style": (
            "CWE entries name defect classes using templates like "
            "'Improper X', 'Use of X', 'Missing X', 'Incorrect X', "
            "'Unchecked X', 'Exposure of X', 'Insufficient X'. Examples: "
            "'Improper Neutralization of Special Elements used in an SQL "
            "Command (\"SQL Injection\")', 'Use of Hard-coded Credentials', "
            "'Missing Authentication for Critical Function', "
            "'Buffer Copy without Checking Size of Input', "
            "'Out-of-bounds Read', "
            "'Cleartext Transmission of Sensitive Information'."
        ),
    },
    "wim": {  # target KB: CVE
        "framework": "CVE (Common Vulnerabilities and Exposures)",
        "style": (
            "CVE descriptions are concrete: they name a specific vulnerable "
            "component or product, the underlying defect mechanism, the "
            "attack vector, and the impact. Examples: 'malformed "
            "Transfer-Encoding header enabling HTTP request smuggling', "
            "'out-of-bounds write in IPv6 fragmentation reassembly causing "
            "remote kernel memory corruption', 'integer overflow during "
            "image decoding leading to heap buffer overflow and remote code "
            "execution', 'improper privilege check in admin RPC interface "
            "allowing authentication bypass'."
        ),
    },
    "atd": {  # target KB: MITRE ATT&CK
        "framework": "MITRE ATT&CK techniques",
        "style": (
            "ATT&CK technique titles are noun/verb phrases naming adversary "
            "actions, often in sub-technique form 'Parent: Specific'. "
            "Examples: 'Command and Scripting Interpreter: PowerShell', "
            "'OS Credential Dumping: LSASS Memory', "
            "'Obfuscated Files or Information', "
            "'Process Injection: DLL Side-Loading', "
            "'Brute Force: Password Spraying', "
            "'Hijack Execution Flow: DLL Search Order Hijacking', "
            "'Valid Accounts: Domain Accounts'."
        ),
    },
    "esd": {  # target KB: CAPEC
        "framework": "CAPEC (Common Attack Pattern Enumeration and Classification)",
        "style": (
            "CAPEC titles name attack techniques as verb phrases or named "
            "methods describing how an attacker exploits a weakness. "
            "Examples: 'SQL Injection', "
            "'Buffer Overflow via Environment Variables', "
            "'Cross-Site Scripting (XSS) - Reflected', "
            "'Reflection Attack in an Authentication Protocol', "
            "'Spoofing of UDDI/ebXML Messages', "
            "'Symlink Attack', "
            "'Forced Deadlock'."
        ),
    },
}


EXTRACT_PROMPT_CANONICAL = """You are a CTI analyst preparing a retrieval query against {framework}.

Style guide — keyphrases must match how {framework} entries are written:
{style}

Rewrite the following query as a comma-separated list of 3-5 keyphrases that
(a) capture the underlying weakness / attack pattern in the query, and
(b) use vocabulary aligned with the {framework} style above. Each keyphrase
should look like a fragment of a real {framework} entry title or description.
Do NOT answer the question; output only the keyphrases.

Query:
{question}

Canonicalized {framework} keyphrases:"""


# Legacy generic prompt kept for ablation/comparison only.
EXTRACT_PROMPT_GENERIC = """You are a CTI analyst. From the following query, extract the
security-relevant search attributes that best characterize the underlying
weakness/attack pattern, as a concise comma-separated keyphrase list
(vulnerability type, mechanism, impact). Do NOT answer the question; output
only the keyphrases.

Query:
{question}

Keyphrases:"""


def build_extract_prompt(question: str, task: str) -> str:
    """Build the task-aware canonicalization prompt for stage 1.

    Falls back to the generic prompt if the task has no canonicalization
    hint registered (e.g., a task other than the four EL tasks).
    """
    hint = CANONICALIZATION_HINTS.get(task)
    if hint is None:
        return EXTRACT_PROMPT_GENERIC.format(question=question)
    return EXTRACT_PROMPT_CANONICAL.format(
        framework=hint["framework"],
        style=hint["style"],
        question=question,
    )


ANSWER_SYSTEM = ("You are a Cyber Threat Intelligence expert. Use the retrieved "
                 "candidates to answer. State the exact identifier "
                 "(CWE-/CVE-/CAPEC-/T-) explicitly.")

ANSWER_PROMPT = """Question:
{question}

Extracted search attributes: {keys}

Retrieved knowledge-base candidates (via the extracted attributes):
{candidates}

Select the single best-matching identifier and answer the question, citing it
explicitly."""


def predict(qa, ctx) -> str:
    llm = ctx["llm"]
    # Stage 1: extract + canonicalize to target-framework idiom.
    keys = llm.chat(
        build_extract_prompt(qa.question, qa.task), max_tokens=128,
    ).strip()
    # Stage 2: retrieve using the canonicalized keyphrases (fall back to raw query).
    query = keys if keys else qa.question
    hits = ctx["retriever"].retrieve_for_task(query, qa.task, k=ctx["k"])
    prompt = ANSWER_PROMPT.format(question=qa.question, keys=keys,
                                  candidates=format_candidates(hits))
    return llm.chat(prompt, system=ANSWER_SYSTEM, max_tokens=512)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Extract-then-Retrieve (Entity Linking)")
    baseline_cli.add_common_args(ap)
    args = ap.parse_args(argv)
    ctx = {
        "llm": ChatLLM(model=args.model) if args.model else ChatLLM(),
        "retriever": KBRetriever(),
        "k": args.top_k,
    }
    baseline_cli.run(predict, args, ctx)


if __name__ == "__main__":
    main()
