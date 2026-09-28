# pipelines/reasoning_ate_pipeline.py
import json
import os

from langchain_community.vectorstores import FAISS
from langchain_huggingface import HuggingFaceEmbeddings

from dotenv import load_dotenv

load_dotenv()  # loads variables from .env

from utils.llm_client import get_openai_client, chat_completion_kwargs  # noqa: E402
from pipelines.errors import PipelineAPIError, status_from_exc  # noqa: E402


class ReasoningATEPipeline:
    def __init__(self):
        base_dir = os.path.dirname(os.path.abspath(__file__))
        self.vector_db_path = os.path.join(base_dir, "../vector_dbs/memorization_vdb")
        self.chunks_path = os.path.join(self.vector_db_path, "chunks.json")

        self.vector_db = self._load_vector_db()
        self.chunks_data = self._load_chunks()
        self._unified_retriever = None
        self.client = get_openai_client()

    def _load_vector_db(self):
        embeddings = HuggingFaceEmbeddings(model_name="sentence-transformers/all-MiniLM-L6-v2")
        return FAISS.load_local(
            self.vector_db_path,
            embeddings,
            allow_dangerous_deserialization=True,
        )

    def _load_chunks(self):
        with open(self.chunks_path, "r", encoding="utf-8") as f:
            return json.load(f)

    def _retrieve_ata_entity_guided_context(self, description: str, k: int = 5) -> str:
        if self._unified_retriever is None:
            from eval.run_unified_rag import UnifiedRetriever

            self._unified_retriever = UnifiedRetriever()
        from eval.controlled_benchmark.run_controlled_smoke import (
            _truncate_evidence,
            retrieve_graphrag_local,
        )

        evidence, _ = retrieve_graphrag_local(self._unified_retriever, description, k=k)
        attack = self._unified_retriever.search_attack_patterns(
            description,
            k=max(8, int(k)),
            previous_text=evidence,
        )
        return _truncate_evidence("\n\n".join(part for part in (attack, evidence) if part))

    def _retrieve_context(self, description: str, k: int = 5) -> str:
        results = self.vector_db.similarity_search(description, k=max(k, 12))
        context = "\n\n".join([
            f"Source: {res.metadata.get('url', 'Unknown')}\nContent: {res.page_content}"
            for res in results
        ])
        if not getattr(self, "_ata_mode", False):
            return context

        mode = (os.environ.get("CTA_ATA_RETRIEVAL") or "entity_guided").strip().lower()
        if mode != "legacy":
            return self._retrieve_ata_entity_guided_context(description, k=k)

        from pathlib import Path
        from eval.controlled_benchmark.attack_retrieval import format_attack_entries, load_enterprise_attack
        from eval.controlled_benchmark.cta_ata_retrieval import cta_candidate_pool

        catalog = load_enterprise_attack(
            Path(__file__).resolve().parents[1] / "data" / "ctibench_taa" / "enterprise-attack.json"
        )
        pool_variant = (os.environ.get("CTA_ATA_POOL") or "hybrid_tuned").strip()
        pool_k = int(os.environ.get("CTA_ATA_CANDIDATE_K") or "5")
        retrieved = cta_candidate_pool(catalog, description, variant=pool_variant, limit=pool_k)
        catalog_context = format_attack_entries(retrieved)
        return "\n\n".join(part for part in (catalog_context, context) if part)

    def _build_prompt(self, similar_context: str, description: str) -> str:
        return f"""Extract all MITRE attack patterns from the following text and map them to their corresponding MITRE technique IDs. Provide reasoning for each identification. Ensure the final line contains only the IDs for the main techniques, separated by commas, excluding any subtechnique IDs.

Relevant context:
{similar_context}

Text to analyze:
{description}

Provide your response in the following format:
reasoning: [your reasoning here]
answer: [comma-separated technique IDs]"""

    def _call_openai(self, prompt: str, *, max_tokens: int = 70) -> str:
        try:
            response = self.client.chat.completions.create(
                messages=[{"role": "user", "content": prompt}],
                **chat_completion_kwargs(
                    "gpt-4-turbo",
                    max_tokens=int(os.getenv("CONTROLLED_MAX_TOKENS") or max_tokens),
                    temperature=0.0,
                ),
            )
            return response.choices[0].message.content.strip()
        except Exception as e:  # noqa: BLE001
            raise PipelineAPIError(
                f"ATE generation API failed: {e}",
                stage="ate_generation",
                original_error=e,
                status=status_from_exc(e),
                provider="openrouter"
                if (os.getenv("USE_OPENROUTER") or "").strip().lower()
                in {"1", "true", "yes", "on"}
                else "openai",
            ) from e

    def run(self, description: str, *, preserve_subtechniques: bool = False) -> str:
        previous_mode = getattr(self, "_ata_mode", False)
        self._ata_mode = bool(preserve_subtechniques)
        try:
            similar_context = self._retrieve_context(description, k=5)
        finally:
            self._ata_mode = previous_mode
        prompt = self._build_prompt(similar_context=similar_context, description=description)
        if preserve_subtechniques:
            from eval.controlled_benchmark.canonical_prompts import build_cticonnect_ata_prompt

            prompt = build_cticonnect_ata_prompt(description, similar_context)
        return self._call_openai(prompt, max_tokens=256 if preserve_subtechniques else 70)


_pipeline_instance = ReasoningATEPipeline()


def run(description: str, *, preserve_subtechniques: bool = False) -> str:
    return _pipeline_instance.run(description, preserve_subtechniques=preserve_subtechniques)
