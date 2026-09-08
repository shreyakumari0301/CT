"""Auth shape check — never prints secret values."""
from pathlib import Path
from dotenv import load_dotenv
import os

load_dotenv(Path(__file__).resolve().parents[2] / ".env", override=True)
oa = (os.getenv("OPENAI_API_KEY") or "").strip()
ork = (os.getenv("OPENROUTER_API_KEY") or "").strip()
base = (os.getenv("OPENAI_BASE_URL") or "").strip()
print("openai_key_len", len(oa))
print("openai_key_is_openrouter", oa.startswith("sk-or-"))
print("openai_key_is_openai_proj", oa.startswith("sk-proj-"))
print("openrouter_key_len", len(ork))
print("openrouter_key_is_openrouter", ork.startswith("sk-or-"))
print("base_url_set", bool(base))
print("base_is_openrouter", "openrouter.ai" in base)
print("generation_model", (os.getenv("GENERATION_MODEL") or "").strip() or "(unset)")
print("reasoning_effort", (os.getenv("OPENROUTER_REASONING_EFFORT") or "").strip() or "(unset)")
