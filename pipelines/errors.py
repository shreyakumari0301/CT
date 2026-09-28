"""Operational failures from specialist pipelines (provider/API), not model errors."""

from __future__ import annotations


class PipelineAPIError(RuntimeError):
    """Raised when a specialist LLM call fails at the provider layer."""

    def __init__(
        self,
        message: str,
        *,
        stage: str = "generation",
        original_error: BaseException | None = None,
        status: int | None = None,
        provider: str | None = None,
    ) -> None:
        super().__init__(message)
        self.stage = stage
        self.original_error = original_error
        self.status = status
        self.provider = provider

    def to_dict(self) -> dict:
        return {
            "status": self.status,
            "provider": self.provider,
            "stage": self.stage,
            "message": str(self.original_error or self),
            "type": type(self.original_error).__name__
            if self.original_error is not None
            else type(self).__name__,
        }


def status_from_exc(exc: BaseException) -> int | None:
    """Best-effort HTTP status from OpenAI/OpenRouter SDK errors."""
    status = getattr(exc, "status_code", None)
    if status is not None:
        try:
            return int(status)
        except (TypeError, ValueError):
            pass
    body = getattr(exc, "body", None)
    if isinstance(body, dict):
        err = body.get("error") or {}
        code = err.get("code")
        if code in {"credit_balance_exhausted", "insufficient_quota"}:
            return 402
    msg = str(exc)
    for code in (402, 429, 500, 502, 503):
        if str(code) in msg:
            return code
    return None
