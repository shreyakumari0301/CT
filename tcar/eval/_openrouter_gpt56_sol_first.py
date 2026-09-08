"""First OpenRouter request with openai/gpt-5.6-sol + reasoning.

Requires OPENROUTER_API_KEY (or OPENAI_API_KEY starting with sk-or-).
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[2]
load_dotenv(ROOT / ".env")

or_key = (os.getenv("OPENROUTER_API_KEY") or "").strip()
oa_key = (os.getenv("OPENAI_API_KEY") or "").strip()
if or_key:
    os.environ["OPENAI_API_KEY"] = or_key  # OpenAI SDK reads this by default too
elif not oa_key.startswith("sk-or-"):
    print(
        "ERROR: OpenRouter auth missing. Set OPENROUTER_API_KEY in .env "
        "(or set OPENAI_API_KEY to an sk-or-... key)."
    )
    sys.exit(2)

os.environ["OPENAI_BASE_URL"] = "https://openrouter.ai/api/v1"
os.environ["USE_OPENROUTER"] = "1"
os.environ["GENERATION_MODEL"] = "openai/gpt-5.6-sol"

from utils.llm_client import (  # noqa: E402
    assistant_message_with_reasoning,
    chat_completion_kwargs,
    clear_client_cache,
    get_openai_client,
    reasoning_body,
    resolve_model,
)

clear_client_cache()
MODEL = "openai/gpt-5.6-sol"
client = get_openai_client()
print("model", resolve_model(MODEL))
print("base", str(getattr(client, "base_url", "")))
print("auth_ready", True)

messages = [
    {
        "role": "user",
        "content": "How many r's are in the word 'strawberry'? Reply with just the number and a one-line reason.",
    }
]

kw = chat_completion_kwargs(
    MODEL,
    max_tokens=256,
    temperature=None,
    reasoning=reasoning_body(effort="medium", exclude=False),
)
print("reasoning", (kw.get("extra_body") or {}).get("reasoning"))

resp = client.chat.completions.create(messages=messages, **kw)
msg = resp.choices[0].message
print("content:", (msg.content or "").strip())
print("has_reasoning:", bool(getattr(msg, "reasoning", None)))
details = getattr(msg, "reasoning_details", None)
print("has_reasoning_details:", details is not None)
if getattr(msg, "reasoning", None):
    print("reasoning_preview:", str(msg.reasoning)[:400])
if details:
    try:
        dumped = [d.model_dump() if hasattr(d, "model_dump") else d for d in details]
        print("reasoning_details_n:", len(dumped))
        print("reasoning_details_preview:", json.dumps(dumped[:1], default=str)[:400])
    except Exception as e:
        print("reasoning_details_err", e)

follow = messages + [
    assistant_message_with_reasoning(msg),
    {"role": "user", "content": "Now count the vowels in strawberry. One number only."},
]
resp2 = client.chat.completions.create(
    messages=follow,
    **chat_completion_kwargs(
        MODEL,
        max_tokens=128,
        temperature=None,
        reasoning=reasoning_body(effort="low", exclude=False),
    ),
)
print("followup_content:", (resp2.choices[0].message.content or "").strip())
print("OK")
