import os
import json
import pickle
import faiss
from pathlib import Path
from openai import OpenAI

from sentence_transformers import SentenceTransformer


class ReasoningTAAPipeline:
    def __init__(self):
        base_dir = Path(__file__).resolve().parent

        # -------------------------------
        # Paths
        # -------------------------------
        self.vector_db_path = base_dir.parent / "vector_dbs" / "reasoning_taa_vdb"
        self.index_path = self.vector_db_path / "taa_index.faiss"
        self.chunks_path = self.vector_db_path / "taa_chunks.pkl"

        # -------------------------------
        # Load FAISS + Chunks
        # -------------------------------
        self.index = faiss.read_index(str(self.index_path))

        with open(self.chunks_path, "rb") as f:
            self.chunks = pickle.load(f)

        # Embedding model
        self.embedder = SentenceTransformer("all-MiniLM-L6-v2")

        # OpenAI client
        api_key = os.getenv("OPENAI_API_KEY")
        self.client = OpenAI(api_key=api_key)

    # -------------------------------------------------------
    # Helper: retrieve context using faiss
    # -------------------------------------------------------
    def _retrieve_context(self, query: str, k: int = 3) -> str:
        emb = self.embedder.encode([query], convert_to_numpy=True)
        scores, indices = self.index.search(emb, k)
        retrieved = [self.chunks[i] for i in indices[0]]
        return "\n\n".join(retrieved)

    # -------------------------------------------------------
    # Helper: call OpenAI
    # -------------------------------------------------------
    def _call_openai(self, prompt: str, model=None) -> str:
        model = model or os.getenv("GENERATION_MODEL", "gpt-4-turbo")
        response = self.client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.1,
            max_tokens=1500
        )
        return response.choices[0].message.content.strip()

    # -------------------------------------------------------
    # Main: Multi-Hop Reasoning Pipeline
    # -------------------------------------------------------
    def run(self, report_text: str) -> str:

        # 🔹 Hop 1 — Infer clues
        hop1_prompt = f"""
You are a CTI analyst. The following threat report has [PLACEHOLDER] replacing names.

Infer:
- Possible malware/tools involved
- Possible campaigns
- ATT&CK techniques
- Any identifying behavior

Give 5–10 short clues (keywords only).

Threat Report:
{report_text}
"""

        hop1_output = self._call_openai(hop1_prompt)

        # 🔹 Hop 2 — Retrieve context using enriched query
        enriched_query = report_text + "\n\nInferred clues:\n" + hop1_output
        hop2_context = self._retrieve_context(enriched_query, k=3)

        # 🔹 Hop 3 — Final attribution reasoning
        final_prompt = f"""
You are a CTI attribution expert.

Threat Report:
{report_text}

=== Step 1: Inferred Clues ===
{hop1_output}

=== Step 2: Retrieved Intelligence Context ===
{hop2_context}

TASK:
Identify which known threat actor is most likely responsible.

Follow this format exactly:

<Reasoning>
Explain how the clues, behaviors, and retrieved context match a known group.
</Reasoning>

<ThreatActor>
Final predicted threat actor name
</ThreatActor>
"""

        final_answer = self._call_openai(final_prompt)

        return final_answer


# -- Create global instance for easy usage like the MCQ pipeline --
_pipeline_instance = ReasoningTAAPipeline()

def run(text: str) -> str:
    return _pipeline_instance.run(text)
