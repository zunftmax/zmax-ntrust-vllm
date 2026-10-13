"""Exceptions for the Ntrust Confidential Inference SDK."""

class NtrustError(Exception):
    """Base exception for all Ntrust errors."""
    pass


class AuthenticationError(NtrustError):
    """Raised when the API key or bearer credential is invalid or missing."""
    pass


class AttestationError(NtrustError):
    """Raised when hardware attestation verification fails or is rejected."""
    pass


class APIConnectionError(NtrustError):
    """Raised when communication with the confidential host fails (TLS, timeout, network)."""
    pass


class APIError(NtrustError):
    """Raised when the remote server returns a non-2xx status code."""
    def __init__(self, message: str, status_code: int | None = None, response_body: str | None = None):
        super().__init__(message)
        self.status_code = status_code
        self.response_body = response_body


class RateLimitError(APIError):
    """Raised when the endpoint returns HTTP 429 Too Many Requests."""
    pass


class InvalidRequestError(APIError):
    """Raised when the request parameters or payload are malformed (HTTP 400)."""
    pass
