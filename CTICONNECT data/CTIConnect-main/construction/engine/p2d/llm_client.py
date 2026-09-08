#!/usr/bin/env python3
"""
LLM Client for generating data from prompts.

Supports multiple LLM providers through a unified interface.
"""

import os
from typing import Dict, Any, Optional
from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class LLMResponse:
    """Response from LLM API."""
    content: str
    model: str
    usage: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    
    @property
    def is_success(self) -> bool:
        return self.error is None


class BaseLLMClient(ABC):
    """Base class for LLM clients."""
    
    def __init__(self, model: str, api_key: str):
        self.model = model
        self.api_key = api_key
    
    @abstractmethod
    def generate(self, prompt: str, **kwargs) -> LLMResponse:
        """Generate response from prompt."""
        pass


class OpenAIClient(BaseLLMClient):
    """OpenAI API client."""
    
    def __init__(self, model: str = "o4-mini", api_key: Optional[str] = None):
        if api_key is None:
            api_key = os.getenv("OPENAI_API_KEY")
            if not api_key:
                raise ValueError("OpenAI API key not found. Set OPENAI_API_KEY environment variable.")
        
        super().__init__(model, api_key)
        
        try:
            import openai
            self.client = openai.OpenAI(api_key=api_key)
        except ImportError:
            raise ImportError("OpenAI library not installed. Run: pip install openai")
    
    def _get_token_param_name(self) -> str:
        """Get the correct token parameter name for the model."""
        # Models that use max_completion_tokens instead of max_tokens
        completion_token_models = [
            "o3", "o3-mini", "o3-preview",
            "o4", "o4-mini", "o4-preview",
            "gpt-5", "gpt-5-mini"
        ]
        
        if any(model_name in self.model.lower() for model_name in completion_token_models):
            return "max_completion_tokens"
        else:
            return "max_tokens"
    
    def _should_skip_temperature(self) -> bool:
        """Check if temperature parameter should be skipped for this model."""
        # Models that don't support custom temperature
        no_temp_models = [
            "o3", "o3-mini", "o3-preview",
            "o4", "o4-mini", "o4-preview",
            "gpt-5", "gpt-5-mini"
        ]
        
        return any(model_name in self.model.lower() for model_name in no_temp_models)
    
    def generate(self, prompt: str, max_tokens: int = 10000, temperature: float = 0.7, **kwargs) -> LLMResponse:
        """Generate response using OpenAI API."""
        try:
            # Determine the correct token parameter name
            token_param_name = self._get_token_param_name()
            
            # Estimate prompt tokens (rough estimate: 1 token ≈ 4 characters)
            estimated_prompt_tokens = len(prompt) // 4
            
            # For GPT-5 and o3 models, dynamically adjust max_tokens based on prompt length
            # GPT-5 has 128K context window, o3 models have 32K context window
            if "gpt-5" in self.model.lower():
                max_context_tokens = 120000  # Leave 8K buffer
                available_tokens = max_context_tokens - estimated_prompt_tokens
                
                # Ensure we have at least 1000 tokens for output
                if available_tokens > 1000:
                    # Use the smaller of: available_tokens, max_tokens, or 8000
                    adjusted_max_tokens = min(available_tokens, max_tokens, 8000)
                    print(f"GPT-5: Estimated prompt tokens: {estimated_prompt_tokens}, "
                          f"Available for output: {available_tokens}, "
                          f"Using: {adjusted_max_tokens}")
                else:
                    adjusted_max_tokens = 1000
                    print(f"GPT-5: Prompt too long ({estimated_prompt_tokens} tokens), "
                          f"using minimum output tokens: {adjusted_max_tokens}")
            elif "o3" in self.model.lower():
                max_context_tokens = 30000  # Leave 2K buffer for o3 models
                available_tokens = max_context_tokens - estimated_prompt_tokens
                
                # Ensure we have at least 1000 tokens for output
                if available_tokens > 1000:
                    # Use the smaller of: available_tokens, max_tokens, or 4000
                    adjusted_max_tokens = min(available_tokens, max_tokens, 4000)
                    print(f"O3: Estimated prompt tokens: {estimated_prompt_tokens}, "
                          f"Available for output: {available_tokens}, "
                          f"Using: {adjusted_max_tokens}")
                else:
                    adjusted_max_tokens = 1000
                    print(f"O3: Prompt too long ({estimated_prompt_tokens} tokens), "
                          f"using minimum output tokens: {adjusted_max_tokens}")
            else:
                adjusted_max_tokens = max_tokens
            
            # Build the request parameters
            request_params = {
                "model": self.model,
                "messages": [
                    {"role": "system", "content": "You are an expert cyber threat intelligence analyst."},
                    {"role": "user", "content": prompt}
                ],
                **kwargs
            }
            
            # Add temperature only if the model supports it
            if not self._should_skip_temperature():
                request_params["temperature"] = temperature
            
            # Add the correct token parameter
            request_params[token_param_name] = adjusted_max_tokens
            
            response = self.client.chat.completions.create(**request_params)
            
            content = response.choices[0].message.content
            # Extract usage, including cached prompt tokens if available
            cached_tokens = 0
            try:
                # Newer SDKs expose usage.prompt_tokens_details.cached_tokens
                details = getattr(response.usage, "prompt_tokens_details", None)
                if isinstance(details, dict):
                    cached_tokens = int(details.get("cached_tokens", 0) or 0)
                elif details is not None:
                    cached_tokens = int(getattr(details, "cached_tokens", 0) or 0)
            except Exception:
                cached_tokens = 0

            usage = {
                "prompt_tokens": getattr(response.usage, "prompt_tokens", None),
                "completion_tokens": getattr(response.usage, "completion_tokens", None),
                "total_tokens": getattr(response.usage, "total_tokens", None),
                "prompt_tokens_details": {
                    "cached_tokens": cached_tokens
                }
            }
            
            return LLMResponse(
                content=content,
                model=self.model,
                usage=usage
            )
            
        except Exception as e:
            return LLMResponse(
                content="",
                model=self.model,
                error=str(e)
            )


class LLMClientFactory:
    """Factory for creating LLM clients."""

    @staticmethod
    def create_client(model: Optional[str] = None, api_key: Optional[str] = None) -> BaseLLMClient:
        """Create an OpenAI client (OpenAI-only simplified factory)."""
        model = model or "o4-mini"
        return OpenAIClient(model=model, api_key=api_key)
