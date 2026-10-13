"""Bind each SDK request handshake to its freshly verified attestation key.

This does not appraise evidence. The caller must obtain the pin from the shared
Rust-backed attestation adapter, which hashes the observed receipt TLS SPKI only
after successful verification. Pins are used for one request, never cached.
"""
import hashlib
import hmac
import http.client
import re
import time

from ._attestation_transport import extract_spki_der
from .exceptions import AttestationError

# Limit the time between a fresh verification and sending this request. An
# existing response stream may continue: all of its records use the checked TLS
# connection. This is not an evidence/collateral expiration override.
MAX_KEY_USE_DELAY = 30.0


def verified_key_pin(verdict: dict) -> bytes:
    """Read only the adapter-owned key value after a successful Rust verdict."""
    if not isinstance(verdict, dict) or verdict.get("valid") is not True:
        raise AttestationError("Attestation did not return an accepting Rust verdict")
    pin = verdict.get("tls_spki_sha256")
    if not isinstance(pin, str) or re.fullmatch(r"[0-9a-f]{64}", pin) is None:
        raise AttestationError("Attestation omitted the verified transport TLS key")
    return bytes.fromhex(pin)


class AttestedHTTPSConnection(http.client.HTTPSConnection):
    """Check every connect/reconnect before http.client can send HTTP bytes."""

    def __init__(self, host, port, *, context, timeout, expected_pin: bytes):
        super().__init__(host, port, context=context, timeout=timeout)
        self._expected_pin = expected_pin
        self._key_deadline = time.monotonic() + MAX_KEY_USE_DELAY
        self._key_rejected = False

    def _require_current_key(self):
        if self._key_rejected or time.monotonic() >= self._key_deadline:
            self._key_rejected = True
            self.close()
            raise AttestationError("Fresh attestation key authorization expired or was rejected")

    def connect(self):
        self._require_current_key()
        try:
            # CA/hostname validation and TLS minimum are still enforced by the
            # configured SSLContext before the additional attested-key check.
            super().connect()
            certificate = self.sock.getpeercert(binary_form=True) if self.sock else None
            if not certificate:
                raise AttestationError("Request TLS connection returned no certificate")
            actual_pin = hashlib.sha256(extract_spki_der(certificate)).digest()
            if not hmac.compare_digest(actual_pin, self._expected_pin):
                raise AttestationError("Request TLS key differs from the freshly attested key")
            self._require_current_key()
        except Exception:
            self._key_rejected = True
            self.close()
            raise

    def send(self, data):
        self._require_current_key()
        if self.sock is None:
            self.connect()
        self._require_current_key()
        return super().send(data)
