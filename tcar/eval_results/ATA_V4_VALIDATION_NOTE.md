# ATA v4 — method frozen; validate externally (do not tune further on the 160-gate set)

Stamp: `20260908Tturbo_ata_grounded_v4_full` (CTIConnect, F1≥1, n=160)

| | Acc |
|--|--|
| Closed book | 17.5% (28/160) |
| Forced RAG v4 | **43.8%** (70/160) |
| Rescues / damages | 43 / 1 → **+26.3 pp** |
| Branch oracle | ~71/160 (~1 item headroom) |

**Paper note:** If the damage gate used these 160 golds, **43.8% is a development result**, not an independent test. Next: held-out ATA split / alternate dataset, or report CV gate performance; record cost/latency vs dense Forced-RAG. No further architectural work.
