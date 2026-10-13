"""Core ConfidentialClient and HTTP transport implementation."""
import http.client
import json
import os
import ssl
from typing import Any, Dict, Iterator, List, Optional, Tuple
from urllib.parse import urlparse

from .attestation import AttestationVerifier
from ._key_continuity import AttestedHTTPSConnection, verified_key_pin
from .chat import Chat
from .exceptions import APIConnectionError, APIError, AuthenticationError, AttestationError
from .models import ModelInfo


class _HTTPClient:
    """Zero-dependency HTTPS client leveraging Python standard library."""

    def __init__(self, base_url: str, api_key: Optional[str] = None, cafile: Optional[str] = None, timeout: float = 60.0):
        self.base_url = base_url.rstrip("/")
        if not (self.base_url.startswith("http://") or self.base_url.startswith("https://")):
            self.base_url = "https://" + self.base_url
        self.api_key = api_key
        self.cafile = cafile
        self.timeout = timeout
        self._attestation_check = None

        parsed = urlparse(self.base_url)
        self.scheme = parsed.scheme
        self.host = parsed.hostname or "127.0.0.1"
        self.port = parsed.port or (443 if self.scheme == "https" else 80)

        self._ssl_ctx: Optional[ssl.SSLContext] = None
        if self.scheme == "https":
            self._ssl_ctx = ssl.create_default_context(cafile=self.cafile)
            self._ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_3

    def _headers(self, custom_headers: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        headers = {
            "Accept": "application/json",
            "User-Agent": "ntrust-python-sdk/0.1.0",
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        if custom_headers:
            headers.update(custom_headers)
        return headers

    def _create_connection(self) -> http.client.HTTPConnection:
        # A fresh challenge is verified for every request, including streams.
        # Failure never selects the ordinary unverified connection path.
        if self._attestation_check is not None:
            if self.scheme != "https":
                raise AttestationError("Attested requests require HTTPS")
            verdict = self._attestation_check()
            conn = AttestedHTTPSConnection(self.host, self.port, context=self._ssl_ctx,
                timeout=self.timeout, expected_pin=verified_key_pin(verdict))
            try:
                conn.connect()
            except (http.client.HTTPException, OSError) as exc:
                conn.close()
                raise APIConnectionError(f"Attested TLS connection failed: {exc}") from exc
            return conn
        try:
            if self.scheme == "https":
                return http.client.HTTPSConnection(self.host, self.port, context=self._ssl_ctx, timeout=self.timeout)
            return http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)
        except Exception as exc:
            raise APIConnectionError(f"Failed to initialize connection to {self.host}:{self.port}: {exc}") from exc

    def require_attestation(self, check):
        """One-way transition: all subsequent requests require fresh appraisal."""
        if not callable(check):
            raise AttestationError("A required attestation verifier cannot be removed")
        self._attestation_check = check

    def get_json(self, path: str) -> Tuple[int, Dict[str, str], bytes]:
        conn = self._create_connection()
        try:
            conn.request("GET", path, headers=self._headers())
            resp = conn.getresponse()
            headers = dict(resp.getheaders())
            body = resp.read()
            return resp.status, headers, body
        except (http.client.HTTPException, OSError) as exc:
            raise APIConnectionError(f"HTTP GET {path} failed: {exc}") from exc
        finally:
            conn.close()

    def post_json(self, path: str, payload: Dict[str, Any]) -> Tuple[int, Dict[str, str], bytes]:
        conn = self._create_connection()
        try:
            body_bytes = json.dumps(payload).encode("utf-8")
            headers = self._headers({"Content-Type": "application/json"})
            conn.request("POST", path, body=body_bytes, headers=headers)
            resp = conn.getresponse()
            resp_headers = dict(resp.getheaders())
            body = resp.read()
            return resp.status, resp_headers, body
        except (http.client.HTTPException, OSError) as exc:
            raise APIConnectionError(f"HTTP POST {path} failed: {exc}") from exc
        finally:
            conn.close()

    def post_stream(self, path: str, payload: Dict[str, Any]) -> Iterator[bytes]:
        conn = self._create_connection()
        try:
            body_bytes = json.dumps(payload).encode("utf-8")
            headers = self._headers({"Content-Type": "application/json", "Accept": "text/event-stream"})
            conn.request("POST", path, body=body_bytes, headers=headers)
            resp = conn.getresponse()
            if not (200 <= resp.status < 300):
                err_body = resp.read().decode("utf-8", errors="replace")
                conn.close()
                if resp.status in (401, 403):
                    raise AuthenticationError(f"Authentication failed (HTTP {resp.status}): {err_body}")
                raise APIError(f"Streaming request failed (HTTP {resp.status}): {err_body}", status_code=resp.status, response_body=err_body)

            while True:
                chunk = resp.read(1024)
                if not chunk:
                    break
                yield chunk
        except (http.client.HTTPException, OSError) as exc:
            raise APIConnectionError(f"Streaming failed on {path}: {exc}") from exc
        finally:
            conn.close()


class Models:
    """Provides methods for querying available models."""
    def __init__(self, http_client: _HTTPClient):
        self._http = http_client

    def list(self) -> List[ModelInfo]:
        """List all models currently served by the confidential endpoint."""
        status, _, body = self._http.get_json("/v1/models")
        if status in (401, 403):
            raise AuthenticationError(f"Authentication failed (HTTP {status})")
        if status != 200:
            raise APIError(f"Failed to list models (HTTP {status}): {body.decode('utf-8', errors='replace')}", status_code=status)
        try:
            data = json.loads(body.decode("utf-8"))
        except ValueError as exc:
            raise APIError(f"Malformed JSON from /v1/models: {exc}") from exc

        raw_list = data.get("data", [])
        return [ModelInfo(item) for item in raw_list]


class ConfidentialClient:
    """High-level client for confidential AI inference with hardware attestation."""

    def __init__(self,
                 base_url: Optional[str] = None,
                 api_key: Optional[str] = None,
                 verify_attestation: bool = False,
                 expected_value_x: Optional[str] = None,
                 expected_measurement: Optional[str] = None,
                 gpu_policy: Optional[str] = None,
                 cpu_only: bool = False,
                 cafile: Optional[str] = None,
                 timeout: float = 60.0, *,
                 uq_binary: Optional[str] = None,
                 boot_policy: Optional[str] = None, uki: Optional[str] = None,
                 google_boot_verifier: Optional[str] = None,
                 prior_stage_policy: Optional[str] = None,
                 platform: Optional[str] = None,
                 cpu_collateral: Optional[str] = None,
                 cpu_tcb_policy: Optional[str] = None,
                 azure_policy: Optional[str] = None,
                 nitrotpm_policy: Optional[str] = None):
        self.base_url = base_url or os.environ.get("NTRUST_BASE_URL", "https://localhost:443")
        self.api_key = api_key or os.environ.get("NTRUST_API_KEY")
        self.cafile = cafile or os.environ.get("NTRUST_CA_FILE")
        self.timeout = timeout

        self._http = _HTTPClient(base_url=self.base_url, api_key=self.api_key, cafile=self.cafile, timeout=self.timeout)
        self.chat = Chat(self._http)
        self.models = Models(self._http)
        self.attestation = AttestationVerifier(
            expected_value_x=expected_value_x,
            expected_measurement=expected_measurement,
            gpu_policy=gpu_policy,
            cpu_only=cpu_only,
            cafile=self.cafile,
            timeout=timeout,
            uq_binary=uq_binary, boot_policy=boot_policy, uki=uki,
            google_boot_verifier=google_boot_verifier, prior_stage_policy=prior_stage_policy,
            platform=platform, cpu_collateral=cpu_collateral, cpu_tcb_policy=cpu_tcb_policy,
            azure_policy=azure_policy, nitrotpm_policy=nitrotpm_policy,
        )

        self._attestation_verdict: Optional[dict] = None
        if verify_attestation:
            self.verify_attestation()

    @property
    def attestation_verdict(self) -> Optional[dict]:
        """Latest successful verification; never reused to authorize a request."""
        return self._attestation_verdict

    def verify_attestation(self) -> dict:
        """Enable per-request appraisal, then verify now. Failure keeps it enabled."""
        self._http.require_attestation(self._verify_request_attestation)
        return self._verify_request_attestation()

    def _verify_request_attestation(self) -> dict:
        self._attestation_verdict = None
        verdict = self.attestation.verify(self.base_url)
        verified_key_pin(verdict)
        self._attestation_verdict = verdict
        return self._attestation_verdict
