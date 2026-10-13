"""Chat completions resource for the Ntrust SDK."""
import json
from typing import Any, Dict, Iterator, List, Optional, Union

from .exceptions import APIError, AuthenticationError, InvalidRequestError, RateLimitError
from .models import ChatCompletionChunk, ChatCompletionResponse


class ChatCompletions:
    """Provides methods for chat completion creation and streaming."""

    def __init__(self, http_client):
        self._http = http_client

    def create(self,
               model: str,
               messages: List[Dict[str, str]],
               temperature: Optional[float] = None,
               top_p: Optional[float] = None,
               max_tokens: Optional[int] = None,
               stop: Optional[Union[str, List[str]]] = None,
               stream: bool = False,
               **kwargs: Any) -> Union[ChatCompletionResponse, Iterator[ChatCompletionChunk]]:
        """Create a chat completion.

        If stream is True, returns an iterator yielding ChatCompletionChunk objects.
        Otherwise, returns a single ChatCompletionResponse.
        """
        payload: Dict[str, Any] = {
            "model": model,
            "messages": messages,
            "stream": stream,
        }
        if temperature is not None:
            payload["temperature"] = temperature
        if top_p is not None:
            payload["top_p"] = top_p
        if max_tokens is not None:
            payload["max_tokens"] = max_tokens
        if stop is not None:
            payload["stop"] = stop
        payload.update(kwargs)

        if stream:
            return self._stream_request(payload)
        return self._unary_request(payload)

    def stream(self,
               model: str,
               messages: List[Dict[str, str]],
               **kwargs: Any) -> Iterator[ChatCompletionChunk]:
        """Convenience method for creating a streaming chat completion."""
        return self.create(model=model, messages=messages, stream=True, **kwargs)

    def _unary_request(self, payload: Dict[str, Any]) -> ChatCompletionResponse:
        status, headers, body = self._http.post_json("/v1/chat/completions", payload)
        self._check_status(status, body)
        try:
            data = json.loads(body.decode("utf-8"))
        except ValueError as exc:
            raise APIError(f"Malformed JSON from server: {exc}", status_code=status, response_body=body.decode("utf-8", errors="replace")) from exc
        return ChatCompletionResponse(data)

    def _stream_request(self, payload: Dict[str, Any]) -> Iterator[ChatCompletionChunk]:
        stream_iter = self._http.post_stream("/v1/chat/completions", payload)
        buffer = ""
        for raw_bytes in stream_iter:
            buffer += raw_bytes.decode("utf-8", errors="replace")
            while "\n\n" in buffer:
                event_str, buffer = buffer.split("\n\n", 1)
                for line in event_str.split("\n"):
                    line = line.strip()
                    if not line.startswith("data:"):
                        continue
                    data_str = line[len("data:"):].strip()
                    if not data_str or data_str == "[DONE]":
                        continue
                    try:
                        chunk_data = json.loads(data_str)
                        yield ChatCompletionChunk(chunk_data)
                    except ValueError:
                        continue

    def _check_status(self, status: int, body: bytes) -> None:
        if 200 <= status < 300:
            return
        body_text = body.decode("utf-8", errors="replace")
        if status in (401, 403):
            raise AuthenticationError(f"Authentication failed (HTTP {status}): {body_text}")
        if status == 400:
            raise InvalidRequestError(f"Bad request (HTTP 400): {body_text}", status_code=status, response_body=body_text)
        if status == 429:
            raise RateLimitError(f"Rate limited (HTTP 429): {body_text}", status_code=status, response_body=body_text)
        raise APIError(f"Inference request failed with HTTP {status}: {body_text}", status_code=status, response_body=body_text)


class Chat:
    """Namespace for chat operations."""
    def __init__(self, http_client):
        self.completions = ChatCompletions(http_client)
