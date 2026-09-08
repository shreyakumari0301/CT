"""Shared in-memory ``LLMClient`` for offline ctinexus-lite tests.

Returns canned responses in call order so extractor / alias / pipeline tests
can run without an API key or network access.
"""

from __future__ import annotations

from baselines.ctinexus_lite.llm import LLMClient, LLMResult, parse_json_lenient


class FakeLLM(LLMClient):
    """In-memory client that returns canned responses per call sequence."""

    def __init__(self, responses: list):
        # Bypass the parent ctor (which insists on API key + network setup).
        self.model = "fake-model"
        self.max_retries = 1
        self._responses = list(responses)
        self._idx = 0

    async def aask(self, prompt, *, max_tokens=4000, system=None):
        if self._idx >= len(self._responses):
            raise AssertionError("ran out of fake responses")
        text = self._responses[self._idx]
        self._idx += 1
        return LLMResult(
            content=text,
            model=self.model,
            usage={"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
        )

    async def aask_json(self, prompt, *, max_tokens=4000, system=None):
        result = await self.aask(prompt, max_tokens=max_tokens, system=system)
        return parse_json_lenient(result.content), result
