"""TCAR: Taxonomy-Contrastive Adaptive RAG for CWE / ATT&CK mapping."""

__all__ = ["TCARConfig", "TCARPipeline"]


def __getattr__(name: str):
    if name == "TCARConfig":
        from tcar.config import TCARConfig

        return TCARConfig
    if name == "TCARPipeline":
        from tcar.pipeline import TCARPipeline

        return TCARPipeline
    raise AttributeError(name)
