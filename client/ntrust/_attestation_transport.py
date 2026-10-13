#!/usr/bin/env python3
"""TLS transport for mandatory Rust uq composite verification.

The only appraisal implementation is the installed Rust verifier. Expected image
measurements and GPU inventory policy come from the customer, never the receipt.
CPU-only relay verification authenticates the relay and does not attest its origin.
"""
import argparse
import http.client
import hashlib
import json
import math
import os
from pathlib import Path
import re
import secrets
import socket
import ssl
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlparse

MAX_EVIDENCE_BYTES = 64 * 1024 * 1024
MAX_VERDICT_BYTES = 1024 * 1024
MAX_UKI_BYTES = 512 * 1024 * 1024
MAX_HELPER_BYTES = 512 * 1024 * 1024
VERIFICATION_TIMEOUT = 240
CPU_PLATFORMS = ("tdx", "sev-snp", "azure-snp-vtpm", "aws-snp-nitrotpm")

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
    """Extract the exact DER-encoded SubjectPublicKeyInfo TLV from an X.509 cert."""
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



def _hex(value: str, count: int, name: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-fA-F]{" + str(count) + r"}", value):
        raise ValueError(f"{name} must be {count} hexadecimal characters")
    return value.lower()


def _validate_local_uki(uki: Path | None, boot_policy: Path | None) -> None:
    if uki is None:
        return
    if boot_policy is None:
        raise ValueError("A local UKI image requires --boot-policy")
    if not uki.is_file() or not 0 < uki.stat().st_size <= MAX_UKI_BYTES:
        raise ValueError("Local UKI image is missing, empty or exceeds 512 MiB")


def _validate_local_options(google_boot_verifier: Path | None, prior_stage_policy: Path | None,
                            boot_policy: Path | None) -> None:
    if google_boot_verifier is not None:
        if boot_policy is None:
            raise ValueError("--google-boot-verifier requires --boot-policy")
        if (not google_boot_verifier.is_absolute() or not google_boot_verifier.is_file()
                or not 0 < google_boot_verifier.stat().st_size <= MAX_HELPER_BYTES
                or not os.access(google_boot_verifier, os.X_OK)):
            raise ValueError("Google boot verifier must be a nonempty regular executable at an absolute path")
    if prior_stage_policy is not None and (not prior_stage_policy.is_file()
            or not 0 < prior_stage_policy.stat().st_size <= MAX_VERDICT_BYTES):
        raise ValueError("Prior-stage policy must be a nonempty local JSON file of at most 1 MiB")


def _validate_verifier_configuration(*, expected_value_x, expected_measurement, gpu_policy,
                                    cpu_only, boot_policy, uki, google_boot_verifier,
                                    prior_stage_policy, platform, cpu_collateral,
                                    cpu_tcb_policy, azure_policy, nitrotpm_policy, uq_binary):
    _hex(expected_value_x, 96, "expected Value X")
    _hex(expected_measurement, 96, "expected CPU measurement")
    if cpu_only == (gpu_policy is not None):
        raise ValueError("Select exactly one enrolled GPU policy or explicit CPU-only relay policy")
    if platform is not None and platform not in CPU_PLATFORMS:
        raise ValueError("Expected platform must be tdx, sev-snp, azure-snp-vtpm or aws-snp-nitrotpm")
    if platform is not None and (cpu_collateral is None or cpu_tcb_policy is None):
        raise ValueError("Explicit CPU platform requires CPU collateral and an independent CPU TCB policy")
    if (azure_policy is not None) != (platform == "azure-snp-vtpm"):
        raise ValueError("Azure policy is required exactly for explicit azure-snp-vtpm platform")
    if (nitrotpm_policy is not None) != (platform == "aws-snp-nitrotpm"):
        raise ValueError("NitroTPM policy is required exactly for explicit aws-snp-nitrotpm platform")
    _validate_local_uki(uki, boot_policy)
    _validate_local_options(google_boot_verifier, prior_stage_policy, boot_policy)
    if cpu_collateral is not None and (not cpu_collateral.is_file() or not 0 < cpu_collateral.stat().st_size <= MAX_EVIDENCE_BYTES):
        raise ValueError("CPU collateral is missing, empty or oversized")
    for name, policy in (("GPU", gpu_policy), ("boot", boot_policy), ("CPU TCB", cpu_tcb_policy),
                         ("Azure", azure_policy), ("NitroTPM", nitrotpm_policy)):
        if policy is not None and (not policy.is_file() or not 0 < policy.stat().st_size <= MAX_VERDICT_BYTES):
            raise ValueError(f"{name} policy is missing, empty or oversized")
    if (not uq_binary.is_absolute() or not uq_binary.is_file()
            or uq_binary.stat().st_size == 0 or not os.access(uq_binary, os.X_OK)):
        raise RuntimeError("An installed Rust uq executable at an absolute path is required")


def verify_rats_bundle(raw: bytes, *, expected_nonce: str, tls_spki_der: bytes,
                       expected_value_x: str, expected_measurement: str,
                       gpu_policy: Path | None = None, cpu_only: bool = False,
                       boot_policy: Path | None = None, uki: Path | None = None,
                     google_boot_verifier: Path | None = None, prior_stage_policy: Path | None = None,
                       platform: str | None = None,
                       cpu_collateral: Path | None = None, cpu_tcb_policy: Path | None = None,
                       azure_policy: Path | None = None, nitrotpm_policy: Path | None = None,
                       uq_binary: Path = Path("/usr/local/bin/uq")) -> dict:
    """Invoke the real Rust verifier on the exact transport bytes and observed key."""
    nonce = _hex(expected_nonce, 64, "nonce")
    value_x = _hex(expected_value_x, 96, "expected Value X")
    measurement = _hex(expected_measurement, 96, "expected CPU measurement")
    if not isinstance(raw, bytes) or not raw or len(raw) > MAX_EVIDENCE_BYTES:
        raise ValueError("Receipt body is empty or oversized")
    if not tls_spki_der or len(tls_spki_der) > 16 * 1024:
        raise ValueError("Observed TLS SPKI DER is empty or oversized")
    _validate_verifier_configuration(expected_value_x=expected_value_x,
        expected_measurement=expected_measurement, gpu_policy=gpu_policy, cpu_only=cpu_only,
        boot_policy=boot_policy, uki=uki, google_boot_verifier=google_boot_verifier,
        prior_stage_policy=prior_stage_policy, platform=platform, cpu_collateral=cpu_collateral,
        cpu_tcb_policy=cpu_tcb_policy, azure_policy=azure_policy,
        nitrotpm_policy=nitrotpm_policy, uq_binary=uq_binary)
    with tempfile.TemporaryDirectory(prefix="ntrust-verifier-") as directory:
        work = Path(directory)
        receipt, spki = work / "receipt.json", work / "tls-spki.der"
        receipt.write_bytes(raw)
        spki.write_bytes(tls_spki_der)
        command = [str(uq_binary), "verify-composite", str(receipt), "--format", "json",
                   "--nonce", nonce, "--tls-spki", str(spki), "--value-x", value_x,
                   "--expected-platform-measurement", measurement, "--json"]
        if gpu_policy is not None:
            command.extend(["--require-gpu-verified", "--gpu-policy", str(gpu_policy.resolve())])
        if boot_policy is not None:
            command.extend(["--boot-policy", str(boot_policy.resolve())])
        if uki is not None:
            command.extend(["--uki", str(uki.resolve())])
        if google_boot_verifier is not None:
            command.extend(["--google-boot-verifier", str(google_boot_verifier.resolve())])
        if prior_stage_policy is not None:
            command.extend(["--prior-stage-policy", str(prior_stage_policy.resolve())])
        if platform is not None:
            command.extend(["--platform", platform])
        if cpu_collateral is not None:
            command.extend(["--cpu-collateral", str(cpu_collateral.resolve())])
        if cpu_tcb_policy is not None:
            command.extend(["--cpu-tcb-policy", str(cpu_tcb_policy.resolve())])
        if azure_policy is not None:
            command.extend(["--azure-policy", str(azure_policy.resolve())])
        if nitrotpm_policy is not None:
            command.extend(["--nitrotpm-policy", str(nitrotpm_policy.resolve())])
        with (work / "verdict.json").open("w+b") as stdout:
            try:
                result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=stdout,
                                        stderr=subprocess.DEVNULL, timeout=VERIFICATION_TIMEOUT,
                                        check=False)
            except subprocess.TimeoutExpired as error:
                raise RuntimeError("Rust attestation verification timed out") from error
            except OSError as error:
                raise RuntimeError("Rust attestation verifier could not start") from error
            if result.returncode != 0:
                raise RuntimeError(f"Rust attestation verification failed (exit {result.returncode})")
            stdout.seek(0)
            verdict_raw = stdout.read(MAX_VERDICT_BYTES + 1)
        if not verdict_raw or len(verdict_raw) > MAX_VERDICT_BYTES:
            raise RuntimeError("Rust verifier returned no bounded verdict")
        verdict = json.loads(verdict_raw)
        if not isinstance(verdict, dict) or verdict.get("valid") is not True:
            raise RuntimeError("Rust verifier did not return a valid verdict")
        checks = verdict.get("checks")
        if not isinstance(checks, list) or not any(isinstance(c, dict) and c.get("check") == "cpu" and c.get("passed") is True for c in checks):
            raise RuntimeError("Rust verifier omitted authenticated CPU appraisal")
        if gpu_policy is not None and (verdict.get("gpu") is None or not any(isinstance(c, dict) and c.get("check") == "gpu" and c.get("passed") is True for c in checks)):
            raise RuntimeError("Rust verifier omitted required GPU appraisal")
        profile_check = {"azure-snp-vtpm": "azure_vtpm", "aws-snp-nitrotpm": "nitrotpm"}.get(platform)
        if profile_check is not None and not any(isinstance(c, dict) and c.get("check") == profile_check and c.get("passed") is True for c in checks):
            raise RuntimeError("Rust verifier omitted required CPU/TPM profile appraisal")
        # Adapter-owned channel pin, assigned only after complete Rust appraisal.
        # Never trust an identically named key supplied by a server or subprocess.
        verdict["tls_spki_sha256"] = hashlib.sha256(tls_spki_der).hexdigest()
        return verdict


def fetch_and_verify(base_url: str, *, expected_value_x: str, expected_measurement: str,
                     gpu_policy: Path | None = None, cpu_only: bool = False,
                     boot_policy: Path | None = None, uki: Path | None = None,
                     google_boot_verifier: Path | None = None, prior_stage_policy: Path | None = None,
                     cafile: str | None = None, connection_timeout: float = 15.0,
                     platform: str | None = None, cpu_collateral: Path | None = None,
                     cpu_tcb_policy: Path | None = None,
                     azure_policy: Path | None = None, nitrotpm_policy: Path | None = None,
                     uq_binary: Path = Path("/usr/local/bin/uq")) -> dict:
    _validate_verifier_configuration(expected_value_x=expected_value_x,
        expected_measurement=expected_measurement, gpu_policy=gpu_policy, cpu_only=cpu_only,
        boot_policy=boot_policy, uki=uki, google_boot_verifier=google_boot_verifier,
        prior_stage_policy=prior_stage_policy, platform=platform, cpu_collateral=cpu_collateral,
        cpu_tcb_policy=cpu_tcb_policy, azure_policy=azure_policy,
        nitrotpm_policy=nitrotpm_policy, uq_binary=uq_binary)
    if not isinstance(connection_timeout, (int, float)) or not math.isfinite(connection_timeout) or connection_timeout <= 0:
        raise ValueError("Connection timeout must be positive and finite")
    parsed = urlparse(base_url if "://" in base_url else "https://" + base_url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in ("", "/"):
        raise ValueError("A bare HTTPS origin is required")
    host, port = parsed.hostname, parsed.port or 443
    nonce = secrets.token_hex(32)
    ctx = ssl.create_default_context(cafile=cafile)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    with socket.create_connection((host, port), timeout=connection_timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as stream:
            stream.settimeout(VERIFICATION_TIMEOUT + 10)
            cert = stream.getpeercert(binary_form=True)
            if not cert:
                raise RuntimeError("TLS server returned no peer certificate")
            spki = extract_spki_der(cert)
            # Attach the already authenticated socket; do not create a second
            # connection whose key might differ from the key used for evidence.
            connection = http.client.HTTPSConnection(host, port, context=ctx)
            connection.sock = stream
            connection.request("GET", f"/v1/attest?nonce={nonce}", headers={"Accept": "application/json", "Connection": "close"})
            response = connection.getresponse()
            if response.status != 200:
                raise RuntimeError(f"Attestation endpoint returned HTTP {response.status}")
            if response.getheader("Content-Encoding", "identity") != "identity":
                raise RuntimeError("Compressed attestation responses are unsupported")
            length = response.getheader("Content-Length")
            if length is not None and (not length.isdecimal() or int(length) > MAX_EVIDENCE_BYTES):
                raise RuntimeError("Attestation response exceeds byte limit")
            deadline = time.monotonic() + VERIFICATION_TIMEOUT
            body = bytearray()
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise RuntimeError("Attestation response deadline exceeded")
                stream.settimeout(remaining)
                chunk = response.read1(min(64 * 1024, MAX_EVIDENCE_BYTES + 1 - len(body)))
                if not chunk:
                    break
                body.extend(chunk)
                if len(body) > MAX_EVIDENCE_BYTES:
                    raise RuntimeError("Attestation response exceeds byte limit")
            body = bytes(body)
    return verify_rats_bundle(body, expected_nonce=nonce, tls_spki_der=spki,
                             expected_value_x=expected_value_x, expected_measurement=expected_measurement,
                             gpu_policy=gpu_policy, cpu_only=cpu_only, boot_policy=boot_policy, uki=uki,
                             uq_binary=uq_binary, platform=platform, cpu_collateral=cpu_collateral,
                             cpu_tcb_policy=cpu_tcb_policy, google_boot_verifier=google_boot_verifier,
                             prior_stage_policy=prior_stage_policy, azure_policy=azure_policy,
                             nitrotpm_policy=nitrotpm_policy)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("endpoint", help="HTTPS origin serving /v1/attest")
    parser.add_argument("--expected-value-x", required=True, help="Approved image Value X (96 hex)")
    parser.add_argument("--expected-measurement", required=True, help="Approved CPU launch measurement (96 hex)")
    policy = parser.add_mutually_exclusive_group(required=True)
    policy.add_argument("--gpu-policy", type=Path, help="Locally enrolled Rust GPU inventory policy JSON")
    policy.add_argument("--cpu-only", action="store_true", help="Authenticate a CPU relay only; no claim about remote inference hardware")
    parser.add_argument("--boot-policy", type=Path, help="Optional enrolled Rust measured-boot policy JSON")
    parser.add_argument("--google-boot-verifier", type=Path, help="Local independently trusted helper executable; requires --boot-policy")
    parser.add_argument("--prior-stage-policy", type=Path, help="Local independent prior-stage verification policy JSON")
    parser.add_argument("--uki", type=Path, help="Local verifier UKI image (at most 512 MiB); requires --boot-policy")
    parser.add_argument("--platform", choices=CPU_PLATFORMS, help="Expected CPU platform")
    parser.add_argument("--cpu-collateral", type=Path, help="Authenticated TDX/SNP collateral JSON; required for an explicit CPU platform")
    parser.add_argument("--cpu-tcb-policy", type=Path, help="Independent CPU rollback floors; required for an explicit CPU platform")
    parser.add_argument("--azure-policy", type=Path, help="Independent enrolled AK, VM, paravisor and PCR policy; requires azure-snp-vtpm")
    parser.add_argument("--nitrotpm-policy", type=Path, help="Independent AWS NitroTPM PCR and freshness policy; requires aws-snp-nitrotpm")
    parser.add_argument("--uq-bin", type=Path, default=Path("/usr/local/bin/uq"))
    parser.add_argument("--cafile", help="Explicit trusted TLS CA bundle")
    args = parser.parse_args()
    try:
        verdict = fetch_and_verify(args.endpoint, expected_value_x=args.expected_value_x,
                                   expected_measurement=args.expected_measurement,
                                   gpu_policy=args.gpu_policy, cpu_only=args.cpu_only,
                                   boot_policy=args.boot_policy, uki=args.uki, cafile=args.cafile, uq_binary=args.uq_bin,
                                   platform=args.platform, cpu_collateral=args.cpu_collateral,
                                   cpu_tcb_policy=args.cpu_tcb_policy,
                                   azure_policy=args.azure_policy, nitrotpm_policy=args.nitrotpm_policy,
                                   google_boot_verifier=args.google_boot_verifier,
                                   prior_stage_policy=args.prior_stage_policy)
    except Exception as error:
        print(f"ATTESTATION FAILED: {error}", file=sys.stderr)
        return 1
    print(json.dumps(verdict, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
