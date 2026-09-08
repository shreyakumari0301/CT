# ATE metrics (locked) — Turbo task_prompts_cb stamp `20260902Ttask_prompts_cb`, n=60

Do **not** redesign ATE (no ATA grounding port). Report both:

| Metric | Closed book | Forced RAG |
|--------|-------------|------------|
| Exact-set Acc (F1≥1) | 6.7% | **30.0%** |
| Mean instance F1 | 0.488 | **0.858** |

Note: CF fields labeled “Macro-F1” in older logs are exact-set Acc. CTA-RAG reference mean F1 ≈ 0.945 — remaining gap is prompt/evidence alignment only.
