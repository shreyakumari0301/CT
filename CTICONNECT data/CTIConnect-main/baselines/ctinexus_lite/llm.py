"""Thin async OpenAI client with retry and JSON parsing.

Only one client object is needed. The caller provides the model name; we
default to the env var ``CTINEXUS_MODEL`` if set, else ``gpt-4o``. The
API key is read from ``OPENAI_API_KEY``.

JSON parsing is permissive — we strip common LLM "noise" (code fences,
preamble) before ``json.loads``. If parsing still fails we raise so the
caller can decide whether to retry or skip the chunk.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import time
from dataclasses import dataclass
from typing import Any

from openai import AsyncOpenAI, APIError, RateLimitError, APIConnectionError


DEFAULT_MODEL = os.environ.get("CTINEXUS_MODEL", "gpt-4o")

# Models in the gpt-5 family use ``max_completion_tokens`` rather than
# ``max_tokens``, and do not support a custom temperature.
_GPT5_LIKE = re.compile(r"gpt-5", re.IGNORECASE)


@dataclass(frozen=True)
class LLMResult:
    content: str
    model: str
    usage: dict[str, int]


class LLMClient:
    """Async OpenAI wrapper with retry + JSON parsing."""

    def __init__(
        self,
        model: str = DEFAULT_MODEL,
        api_key: str | None = None,
        max_retries: int = 4,
        timeout: float = 90.0,
    ):
        api_key = api_key or os.environ.get("OPENAI_API_KEY")
        if not api_key:
            raise RuntimeError(
                "OPENAI_API_KEY env var is required for ctinexus_lite.llm"
            )
        self.model = model
        self.max_retries = max_retries
        self._client = AsyncOpenAI(api_key=api_key, timeout=timeout)

    # ------------------- public API -------------------

    async def aask(self, prompt: str, *, max_tokens: int = 4000,
                   system: str | None = None) -> LLMResult:
        """Send ``prompt`` to the model with exponential-backoff retries."""
        is_gpt5 = bool(_GPT5_LIKE.search(self.model))
        token_kw = "max_completion_tokens" if is_gpt5 else "max_tokens"
        params: dict[str, Any] = {
            "model": self.model,
            "messages": _build_messages(prompt, system),
            token_kw: max_tokens,
        }
        if not is_gpt5:
            params["temperature"] = 0.0  # determinism for KG extraction

        last_exc: Exception | None = None
        for attempt in range(self.max_retries):
            try:
                resp = await self._client.chat.completions.create(**params)
                content = resp.choices[0].message.content or ""
                usage = {
                    "prompt_tokens": getattr(resp.usage, "prompt_tokens", 0) or 0,
                    "completion_tokens": getattr(resp.usage, "completion_tokens", 0) or 0,
                    "total_tokens": getattr(resp.usage, "total_tokens", 0) or 0,
                }
                return LLMResult(content=content, model=self.model, usage=usage)
            except (RateLimitError, APIConnectionError, APIError) as e:
                last_exc = e
                # Exponential backoff: 1s, 2s, 4s, 8s
                wait = 2 ** attempt
                await asyncio.sleep(wait)
        # Out of retries.
        raise RuntimeError(
            f"LLM call failed after {self.max_retries} attempts: {last_exc}"
        ) from last_exc

    async def aask_json(self, prompt: str, *, max_tokens: int = 4000,
                        system: str | None = None) -> tuple[dict, LLMResult]:
        """Like ``aask`` but parses the response as JSON.

        Strips common code-fence wrappers; raises ``ValueError`` if the
        cleaned text is not valid JSON.
        """
        result = await self.aask(prompt, max_tokens=max_tokens, system=system)
        try:
            obj = parse_json_lenient(result.content)
        except ValueError:
            # One more chance: ask the model to fix its own output.
            fix_prompt = (
                "Your previous response was not valid JSON. Please re-emit "
                "the same content as a single valid JSON object with no extra "
                "text, no code fences, and no comments.\n\n"
                f"Previous response:\n{result.content}"
            )
            retry = await self.aask(fix_prompt, max_tokens=max_tokens, system=system)
            obj = parse_json_lenient(retry.content)  # let this raise if it fails
            # Account for both calls in usage.
            result = LLMResult(
                content=retry.content,
                model=retry.model,
                usage={k: result.usage.get(k, 0) + retry.usage.get(k, 0)
                       for k in {"prompt_tokens", "completion_tokens", "total_tokens"}},
            )
        return obj, result


# ------------------- helpers -------------------

def _build_messages(prompt: str, system: str | None) -> list[dict]:
    msgs: list[dict] = []
    if system:
        msgs.append({"role": "system", "content": system})
    msgs.append({"role": "user", "content": prompt})
    return msgs


_CODE_FENCE_RE = re.compile(r"^```(?:json)?\s*|\s*```$", re.IGNORECASE | re.MULTILINE)


def parse_json_lenient(text: str) -> dict:
    """Try hard to extract a JSON object from a free-form LLM response."""
    if not text:
        raise ValueError("empty LLM response")
    cleaned = text.strip()
    # Strip code fences
    cleaned = _CODE_FENCE_RE.sub("", cleaned).strip()
    # If there is preamble before the first '{', drop it
    first_brace = cleaned.find("{")
    last_brace = cleaned.rfind("}")
    if first_brace == -1 or last_brace == -1 or last_brace < first_brace:
        raise ValueError(f"no JSON object found in response: {text[:200]!r}")
    candidate = cleaned[first_brace:last_brace + 1]
    try:
        return json.loads(candidate)
    except json.JSONDecodeError as e:
        raise ValueError(f"invalid JSON: {e} | text={candidate[:200]!r}") from e


# ------------------- bounded-concurrency map -------------------

async def gather_bounded(
    coros: list,
    *,
    concurrency: int = 8,
) -> list:
    """Run an async iterable of coroutines with a semaphore-bounded fan-out."""
    sem = asyncio.Semaphore(concurrency)

    async def _runner(coro):
        async with sem:
            return await coro

    return await asyncio.gather(*(_runner(c) for c in coros), return_exceptions=False)
