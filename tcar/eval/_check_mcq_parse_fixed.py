"""Verify inline MCQ option parsing is fixed."""
from tcar.specialist_retrieval import mcq_option_queries, parse_mcq_options

q = (
    "You are given a multiple-choice question (MCQ) from a Cyber Threat Intelligence "
    "(CTI) knowledge benchmark dataset. Your task is to choose the best option among "
    "the four provided. Return your answer as a single uppercase letter: A, B, C, or D.  "
    "**Question:** Which of the following mitigations involves preventing applications "
    "from running that haven't been downloaded from legitimate repositories?  "
    "**Options:** A) Audit B) Execution Prevention C) Operating System Configuration "
    "D) User Account Control  **Important:** The last line of your answer should contain "
    "only the single letter corresponding"
)
opts = parse_mcq_options(q)
assert opts.get("A") == "Audit", opts
assert "Execution" in opts.get("B", ""), opts
assert len(opts) == 4, opts
qs = mcq_option_queries(q)
assert qs[0][0] != "ALL", qs
assert all(lab in "ABCD" for lab, _ in qs), qs
print("parse_fixed_ok", opts)
print("queries", [(a, b[:70]) for a, b in qs])
