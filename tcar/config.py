"""TCAR hyperparameters and ablation flags."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class TCARConfig:
    """Taxonomy-Contrastive Adaptive RAG configuration."""

    k_retrieve: int = 5
    max_confusion: int = 6
    reliability_threshold: float = 0.35

    # Scoring weights (contrastive)
    alpha_support: float = 0.45
    beta_contradiction: float = 0.35
    gamma_abstraction: float = 0.20

    # Gate weights
    w_margin: float = 0.35
    w_agreement: float = 0.25
    w_evidence: float = 0.30
    w_ambiguity: float = 0.25

    # Ablations / oracle modes (for experiments)
    use_confusion_set: bool = True
    use_contrast_cards: bool = True
    use_reliability_gate: bool = True
    use_ata_matcher: bool = True
    oracle_confusion: bool = False
    oracle_gate: bool = False

    # Paths (defaults relative to repo root)
    cwe_xrefs: str = "CTICONNECT data/CTIConnect-main/construction/seeds/correlations/cwe_xrefs.jsonl"
    corpus_kb: str = "CTICONNECT data/CTIConnect-main/corpus_kb"

    variant: str = "full"  # full | no_gate | no_confusion | closed_book

    def apply_variant(self) -> "TCARConfig":
        """Return a copy with ablation flags set from ``variant``."""
        import copy

        c = copy.copy(self)
        if self.variant == "no_gate":
            c.use_reliability_gate = False
        elif self.variant == "no_confusion":
            c.use_confusion_set = False
            c.max_confusion = self.k_retrieve
        elif self.variant == "closed_book":
            c.use_reliability_gate = True
            c.reliability_threshold = 999.0  # never admit retrieval
        elif self.variant == "no_contrast":
            c.use_contrast_cards = False
        return c


DEFAULT_CONFIG = TCARConfig()
