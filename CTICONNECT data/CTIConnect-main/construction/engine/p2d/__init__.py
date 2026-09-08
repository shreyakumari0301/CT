#!/usr/bin/env python3
"""
Prompt to Data (p2d) Module

This module processes prompts through LLM APIs to generate structured JSON data
for RAG benchmarking. It supports multiple correlation types including CAPEC,
MITRE ATT&CK, CVE, and CWE relationships.

Main components:
- LLMClient: Interface for different LLM providers (OpenAI, Anthropic)
- DataGenerator: Main class for processing prompts and generating data
- run_generator: Command-line interface
"""

from .llm_client import LLMClientFactory, BaseLLMClient, LLMResponse, OpenAIClient
from .data_generator import DataGenerator, GenerationJob, GenerationResult

__version__ = "1.0.0"
__all__ = [
    "LLMClientFactory",
    "BaseLLMClient",
    "LLMResponse",
    "OpenAIClient",
    "DataGenerator",
    "GenerationJob",
    "GenerationResult",
]
