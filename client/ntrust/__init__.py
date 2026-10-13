"""Ntrust Confidential Inference SDK.

Hardware-attested, memory-only LLM inference for confidential computing.
"""
from .attestation import AttestationVerifier
from .chat import Chat, ChatCompletions
from .client import ConfidentialClient
from .exceptions import (
    APIConnectionError,
    APIError,
    AttestationError,
    AuthenticationError,
    InvalidRequestError,
    NtrustError,
    RateLimitError,
)
from .models import ChatCompletionChunk, ChatCompletionResponse, ModelInfo

__version__ = "0.1.0"

__all__ = [
    "ConfidentialClient",
    "AttestationVerifier",
    "Chat",
    "ChatCompletions",
    "ChatCompletionResponse",
    "ChatCompletionChunk",
    "ModelInfo",
    "NtrustError",
    "AuthenticationError",
    "AttestationError",
    "APIConnectionError",
    "APIError",
    "RateLimitError",
    "InvalidRequestError",
]
