"""Synchronous OpenAI-compatible chat wrapper for the baselines.

Reads OPENAI_API_KEY (and honors OPENAI_BASE_URL) from the environment. The
default answering model can be set via CTICONNECT_MODEL, else `gpt-4o`.

For other providers (Anthropic, Google), set up LiteLLM and point ChatLLM at
it — the call surface is intentionally a single `chat(prompt) -> str`.
"""

from __future__ import annotations

import os
import re
import time

DEFAULT_MODEL = os.environ.get("CTICONNECT_MODEL", "gpt-4o")
_GPT5_LIKE = re.compile(r"gpt-5", re.IGNORECASE)


class ChatLLM:
    def __init__(self, model: str = DEFAULT_MODEL, *, api_key: str | None = None,
                 max_retries: int = 4, temperature: float = 0.0):
        from openai import OpenAI
        self.model = model
        self.max_retries = max_retries
        self.temperature = temperature
        self._client = OpenAI(api_key=api_key or os.environ.get("OPENAI_API_KEY"))

    def chat(self, prompt: str, *, system: str | None = None,
             max_tokens: int = 2000) -> str:
        is_gpt5 = bool(_GPT5_LIKE.search(self.model))
        token_kw = "max_completion_tokens" if is_gpt5 else "max_tokens"
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        params = {"model": self.model, "messages": messages, token_kw: max_tokens}
        if not is_gpt5:
            params["temperature"] = self.temperature

        last = None
        for attempt in range(self.max_retries):
            try:
                resp = self._client.chat.completions.create(**params)
                return resp.choices[0].message.content or ""
            except Exception as e:  # noqa: BLE001
                last = e
                time.sleep(2 ** attempt)
        raise RuntimeError(f"chat failed after {self.max_retries} retries: {last}")
