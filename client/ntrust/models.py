"""Data models and object wrappers for OpenAI-compatible inference responses."""
from typing import Any, Dict, Iterator, List, Optional


class DotDict(dict):
    """Dictionary subclass supporting attribute-style dot access."""
    def __getattr__(self, name: str) -> Any:
        try:
            val = self[name]
            if isinstance(val, dict) and not isinstance(val, DotDict):
                val = DotDict(val)
                self[name] = val
            elif isinstance(val, list):
                val = [DotDict(item) if isinstance(item, dict) and not isinstance(item, DotDict) else item for item in val]
                self[name] = val
            return val
        except KeyError:
            raise AttributeError(f"'{type(self).__name__}' object has no attribute '{name}'")

    def __setattr__(self, name: str, value: Any) -> None:
        self[name] = value

    def __delattr__(self, name: str) -> None:
        try:
            del self[name]
        except KeyError:
            raise AttributeError(f"'{type(self).__name__}' object has no attribute '{name}'")


class ChatCompletionResponse(DotDict):
    """Represents a non-streaming chat completion result."""
    @property
    def text(self) -> str:
        """Convenience property returning the first choice text content."""
        choices = self.get("choices", [])
        if choices and isinstance(choices[0], dict):
            message = choices[0].get("message", {})
            return message.get("content", "") or ""
        return ""


class ChatCompletionChunk(DotDict):
    """Represents a single streaming SSE delta chunk."""
    @property
    def delta_text(self) -> str:
        """Convenience property returning delta content if present."""
        choices = self.get("choices", [])
        if choices and isinstance(choices[0], dict):
            delta = choices[0].get("delta", {})
            return delta.get("content", "") or ""
        return ""


class ModelInfo(DotDict):
    """Information about an available model."""
    pass
