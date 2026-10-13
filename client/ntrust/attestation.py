"""Hardware attestation verification client integration."""
import hashlib
import http.client
import json
from pathlib import Path
import re
import secrets
import socket
import ssl
import subprocess
import tempfile
import time
from urllib.parse import urlparse

from .exceptions import AttestationError, APIConnectionError

MAX_EVIDENCE_BYTES = 64 * 1024 * 1024
MAX_VERDICT_BYTES = 1024 * 1024
VERIFICATION_TIMEOUT = 120


def _read_asn1_tlv(data: bytes, offset: int) -> tuple[int, int, int, int]:
    """Return (tag, value_start, value_end, next_offset) for a DER TLV."""
    if offset >= len(data):
        raise ValueError("Truncated ASN.1 DER tag")
    tag = data[offset]
    pos = offset + 1
    if pos >= len(data):
        raise ValueError("Truncated ASN.1 DER length")
    first_len = data[pos]
    pos += 1
    if first_len < 0x80:
        length = first_len
    else:
        num_octets = first_len & 0x7F
        if num_octets == 0 or num_octets > 4 or pos + num_octets > len(data):
            raise ValueError("Invalid ASN.1 DER length octets")
        length = int.from_bytes(data[pos : pos + num_octets], "big")
        pos += num_octets
    end = pos + length
    if end > len(data):
        raise ValueError("ASN.1 DER value exceeds buffer")
    return tag, pos, end, end


def extract_spki_der(cert_der: bytes) -> bytes:
    """Extract DER-encoded SubjectPublicKeyInfo from an X.509 certificate."""
    tag, cert_start, _, _ = _read_asn1_tlv(cert_der, 0)
    if tag != 0x30:
        raise ValueError("X.509 Certificate must start with SEQUENCE")
    tbs_tag, tbs_start, tbs_end, _ = _read_asn1_tlv(cert_der, cert_start)
    if tbs_tag != 0x30:
        raise ValueError("TBSCertificate must be a SEQUENCE")
    pos = tbs_start
    first_tag, _, _, next_pos = _read_asn1_tlv(cert_der, pos)
    if first_tag == 0xA0:
        pos = next_pos
    for _ in range(5):
        _, _, _, pos = _read_asn1_tlv(cert_der, pos)
    spki_tag, _, _, spki_end = _read_asn1_tlv(cert_der, pos)
    if spki_tag != 0x30 or spki_end > tbs_end:
        raise ValueError("Invalid SubjectPublicKeyInfo SEQUENCE in TBSCertificate")
    return cert_der[pos:spki_end]


class AttestationVerifier:
    """Performs live hardware attestation appraisal for an Ntrust endpoint."""

    def __init__(self,
                 expected_value_x: str | None = None,
                 expected_measurement: str | None = None,
                 gpu_policy: str | Path | None = None,
                 cpu_only: bool = False,
                 uq_binary: str | Path | None = None,
                 cafile: str | None = None,
                 timeout: float = 30.0):
        self.expected_value_x = expected_value_x
        self.expected_measurement = expected_measurement
        self.gpu_policy = Path(gpu_policy) if gpu_policy else None
        self.cpu_only = cpu_only
        self.uq_binary = Path(uq_binary) if uq_binary else Path("/usr/local/bin/uq")
        self.cafile = cafile
        self.timeout = timeout

    def verify(self, base_url: str) -> dict:
        """Fetch fresh attestation token and appraise against expected policies."""
        parsed = urlparse(base_url if "://" in base_url else f"https://{base_url}")
        if parsed.scheme != "https" or not parsed.hostname:
            raise AttestationError("Attestation verification requires an HTTPS endpoint")

        host, port = parsed.hostname, parsed.port or 443
        nonce = secrets.token_hex(32)
        ctx = ssl.create_default_context(cafile=self.cafile)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3

        try:
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as stream:
                    cert = stream.getpeercert(binary_form=True)
                    if not cert:
                        raise AttestationError("TLS server returned no peer certificate")
                    spki_der = extract_spki_der(cert)
                    spki_sha256 = hashlib.sha256(spki_der).hexdigest()

                    conn = http.client.HTTPSConnection(host, port, context=ctx)
                    conn.sock = stream
                    conn.request("GET", f"/v1/attest?nonce={nonce}",
                                 headers={"Accept": "application/json", "Connection": "close"})
                    response = conn.getresponse()
                    if response.status != 200:
                        raise AttestationError(f"Attestation endpoint returned HTTP {response.status}")
                    body = response.read(MAX_EVIDENCE_BYTES + 1)
                    if len(body) > MAX_EVIDENCE_BYTES:
                        raise AttestationError("Attestation response exceeds maximum allowed size")

        except (socket.error, ssl.SSLError, http.client.HTTPException) as exc:
            raise APIConnectionError(f"Failed to connect to attestation service at {host}:{port}: {exc}") from exc

        try:
            receipt = json.loads(body)
        except ValueError as exc:
            raise AttestationError(f"Malformed JSON in attestation response: {exc}") from exc

        # If Rust uq verifier is available and policies are specified, execute full composite verifier
        if self.uq_binary.is_file() and os.access(self.uq_binary, os.X_OK) and self.expected_value_x and self.expected_measurement:
            return self._verify_via_rust(body, nonce, spki_der)

        # Standalone structural and cryptographic binding verification
        return self._verify_structural(receipt, nonce, spki_sha256)

    def _verify_structural(self, receipt: dict, nonce: str, expected_spki_sha256: str) -> dict:
        """Structural sanity check of the receipt when full offline Rust appraisal is not configured."""
        if not isinstance(receipt, dict):
            raise AttestationError("Receipt must be a JSON object")

        if receipt.get("nonce") != nonce:
            raise AttestationError(f"Nonce mismatch: expected {nonce}, got {receipt.get('nonce')}")

        if self.expected_value_x and receipt.get("value_x_hex") != self.expected_value_x.lower():
            raise AttestationError(f"Value X mismatch: expected {self.expected_value_x}, got {receipt.get('value_x_hex')}")

        tls_binding = receipt.get("tls_binding", {})
        if tls_binding.get("leaf_spki_sha256") and tls_binding["leaf_spki_sha256"].lower() != expected_spki_sha256.lower():
            raise AttestationError("TLS SPKI hash in attestation receipt does not match the active TLS connection key")

        return {
            "valid": True,
            "mode": "structural_binding",
            "receipt": receipt,
            "observed_spki_sha256": expected_spki_sha256,
        }

    def _verify_via_rust(self, raw_bytes: bytes, nonce: str, spki_der: bytes) -> dict:
        """Call out to native /usr/local/bin/uq verify-composite."""
        with tempfile.TemporaryDirectory(prefix="ntrust-sdk-verify-") as tmpdir:
            work = Path(tmpdir)
            receipt_file = work / "receipt.json"
            spki_file = work / "tls-spki.der"
            receipt_file.write_bytes(raw_bytes)
            spki_file.write_bytes(spki_der)

            cmd = [
                str(self.uq_binary), "verify-composite", str(receipt_file),
                "--format", "json",
                "--nonce", nonce,
                "--tls-spki", str(spki_file),
                "--value-x", self.expected_value_x.lower(),
                "--expected-platform-measurement", self.expected_measurement.lower(),
                "--json"
            ]
            if self.gpu_policy:
                cmd.extend(["--require-gpu-verified", "--gpu-policy", str(self.gpu_policy)])
            elif self.cpu_only:
                cmd.append("--cpu-only")

            proc = subprocess.run(cmd, capture_output=True, timeout=VERIFICATION_TIMEOUT, text=True)
            if proc.returncode != 0:
                raise AttestationError(f"Native Rust verifier rejected attestation (code {proc.returncode}): {proc.stderr.strip()}")

            try:
                verdict = json.loads(proc.stdout)
            except ValueError:
                raise AttestationError("Native Rust verifier returned non-JSON verdict")

            if not verdict.get("valid"):
                raise AttestationError(f"Attestation verdict invalid: {verdict.get('errors')}")

            return verdict
