"""Shared OpenAI-compatible client (OpenAI API or OpenRouter).

OpenRouter reasoning models (e.g. openai/gpt-5.6-sol):
  pass reasoning via extra_body={"reasoning": {"effort": "medium", "exclude": False}}
  read message.reasoning / message.reasoning_details
  when continuing a chat, preserve reasoning_details on assistant messages.
"""

from __future__ import annotations

import os
from functools import lru_cache
from typing import Any, Dict, List, Optional

from openai import OpenAI


OPENROUTER_BASE = "https://openrouter.ai/api/v1"
DEFAULT_OPENROUTER_MODEL = "openai/gpt-5.6-sol"

# When using OpenRouter, bare OpenAI model ids must be prefixed.
_OPENROUTER_MODEL_MAP = {
    "gpt-4-turbo": "openai/gpt-4-turbo",
    "gpt-4o-mini": "openai/gpt-4o-mini",
    "gpt-4o": "openai/gpt-4o",
    "gpt-4": "openai/gpt-4",
    "gpt-3.5-turbo": "openai/gpt-3.5-turbo",
    "gpt-5.4": "openai/gpt-5.4",
    "gpt-5.4-mini": "openai/gpt-5.4-mini",
    "gpt-5.4-nano": "openai/gpt-5.4-nano",
    "gpt-5.6-sol": "openai/gpt-5.6-sol",
    "gpt-5.6-sol-pro": "openai/gpt-5.6-sol-pro",
}


def _detect_base_url() -> str | None:
    use_or = (os.getenv("USE_OPENROUTER") or "").strip().lower()
    # Explicit off forces native OpenAI even if an OpenRouter key remains in the env.
    if use_or in {"0", "false", "no", "off"}:
        explicit = (os.getenv("OPENAI_BASE_URL") or "").strip()
        if explicit and "openrouter.ai" not in explicit:
            return explicit
        return None
    explicit = (os.getenv("OPENAI_BASE_URL") or "").strip()
    if explicit:
        return explicit
    # Prefer OpenRouter when an OpenRouter key is present.
    if (os.getenv("OPENROUTER_API_KEY") or "").strip():
        return OPENROUTER_BASE
    key = (os.getenv("OPENAI_API_KEY") or "").strip()
    if key.startswith("sk-or-"):
        return OPENROUTER_BASE
    if use_or in {"1", "true", "yes", "on"}:
        return OPENROUTER_BASE
    return None


def _api_key() -> str:
    base = _detect_base_url() or ""
    if "openrouter.ai" in base:
        return (
            (os.getenv("OPENROUTER_API_KEY") or "").strip()
            or (os.getenv("OPENAI_API_KEY") or "").strip()
        )
    return (os.getenv("OPENAI_API_KEY") or "").strip()


def resolve_model(model: str) -> str:
    """Map short OpenAI model names to provider-specific ids when needed."""
    model = (model or "").strip() or (
        os.getenv("GENERATION_MODEL") or DEFAULT_OPENROUTER_MODEL
    ).strip()
    override = (os.getenv("GENERATION_MODEL") or "").strip()
    if override and model in {"gpt-4-turbo", "default"}:
        model = override
    base = _detect_base_url() or ""
    if "openrouter.ai" in base:
        if "/" in model:
            return model
        return _OPENROUTER_MODEL_MAP.get(
            model, f"openai/{model}" if model.startswith("gpt-") else model
        )
    # Native OpenAI: strip OpenRouter-style "openai/" prefix if present.
    if model.startswith("openai/"):
        model = model.split("/", 1)[1]
    return model


def _model_family(model: str) -> str:
    raw = (model or "").strip().lower()
    if "/" in raw:
        raw = raw.split("/", 1)[-1]
    return raw


def uses_max_completion_tokens(model: str) -> bool:
    """gpt-5* chat models often reject max_tokens on native OpenAI; OpenRouter accepts max_tokens."""
    base = _detect_base_url() or ""
    if "openrouter.ai" in base:
        return False
    fam = _model_family(model)
    return fam.startswith("gpt-5")


def omits_temperature(model: str) -> bool:
    """Some gpt-5.6-sol / reasoning chat models only allow default temperature on OpenAI."""
    base = _detect_base_url() or ""
    if "openrouter.ai" in base:
        return False
    fam = _model_family(model)
    return fam.startswith("gpt-5.6-sol") or fam in {"gpt-5", "gpt-5.6"}


def reasoning_body(
    *,
    effort: str = "medium",
    exclude: bool = False,
    enabled: bool = True,
    max_tokens: Optional[int] = None,
) -> Dict[str, Any]:
    """OpenRouter `reasoning` object (passed via extra_body)."""
    body: Dict[str, Any] = {"exclude": bool(exclude)}
    if max_tokens is not None:
        body["max_tokens"] = int(max_tokens)
    elif effort:
        body["effort"] = effort
    else:
        body["enabled"] = bool(enabled)
    return body


def chat_completion_kwargs(
    model: str,
    *,
    max_tokens: int = 800,
    temperature: float | None = 0.0,
    reasoning: Optional[Dict[str, Any]] = None,
    reasoning_effort: Optional[str] = None,
    **extra: object,
) -> dict:
    """Build chat.completions.create kwargs for OpenAI / OpenRouter (incl. reasoning)."""
    resolved = resolve_model(model)
    kwargs: dict = {"model": resolved, **extra}

    if uses_max_completion_tokens(resolved):
        kwargs["max_completion_tokens"] = int(max_tokens)
    else:
        kwargs["max_tokens"] = int(max_tokens)

    if temperature is not None and not omits_temperature(resolved):
        kwargs["temperature"] = float(temperature)

    # OpenRouter reasoning config (ignored / stripped by plain OpenAI if unused).
    reason = reasoning
    if reason is None and reasoning_effort:
        reason = reasoning_body(effort=reasoning_effort)
    if reason is None:
        env_effort = (os.getenv("OPENROUTER_REASONING_EFFORT") or "").strip()
        if env_effort and env_effort.lower() not in {"off", "none", "0"}:
            reason = reasoning_body(effort=env_effort)
        elif (os.getenv("OPENROUTER_REASONING") or "").strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }:
            reason = reasoning_body(effort="medium")
    if reason is not None and "openrouter.ai" in (_detect_base_url() or ""):
        kwargs["extra_body"] = {**(kwargs.get("extra_body") or {}), "reasoning": reason}

    return kwargs


def assistant_message_with_reasoning(message: Any) -> Dict[str, Any]:
    """Build an assistant message that preserves reasoning_details for multi-turn chats."""
    out: Dict[str, Any] = {
        "role": "assistant",
        "content": getattr(message, "content", None) or "",
    }
    details = getattr(message, "reasoning_details", None)
    if details is not None:
        # OpenAI SDK may return pydantic objects; coerce to plain JSON.
        try:
            out["reasoning_details"] = [
                d.model_dump() if hasattr(d, "model_dump") else dict(d) if hasattr(d, "keys") else d
                for d in details
            ]
        except Exception:
            out["reasoning_details"] = details
    reasoning = getattr(message, "reasoning", None)
    if reasoning:
        out["reasoning"] = reasoning
    return out


def resolve_classifier_model(model: str = "gpt-4o-mini") -> str:
    explicit = (os.getenv("CLASSIFIER_MODEL") or "").strip()
    if explicit:
        return explicit
    return resolve_model(model)


@lru_cache(maxsize=1)
def get_openai_client() -> OpenAI:
    api_key = _api_key()
    if not api_key:
        raise ValueError(
            "API key missing. Set OPENROUTER_API_KEY (preferred) or OPENAI_API_KEY."
        )
    kwargs: Dict[str, Any] = {"api_key": api_key, "timeout": 300.0}
    base_url = _detect_base_url()
    if base_url:
        kwargs["base_url"] = base_url
    # Optional OpenRouter leaderboard / attribution headers.
    if base_url and "openrouter.ai" in base_url:
        headers = {
            "HTTP-Referer": (os.getenv("OPENROUTER_HTTP_REFERER") or "https://github.com/CTI-Chatbot").strip(),
            "X-Title": (os.getenv("OPENROUTER_APP_TITLE") or "CTI-Chatbot").strip(),
        }
        kwargs["default_headers"] = headers
    return OpenAI(**kwargs)


def clear_client_cache() -> None:
    get_openai_client.cache_clear()
