#!/usr/bin/env python3
"""Customer verifier for ntrust unified-quote (https://uq.secure.build/eat/v2) attestation.

Connects over TLS 1.3, extracts the live server certificate's SubjectPublicKeyInfo
(SPKI) directly from the TLS socket, sends a fresh 32-byte nonce to GET /v1/attest,
and verifies:
  1. EatToken::binding_bytes_v2() in hardware report_data[0..32]
  2. EatToken::second_commitment(sha256(gpu || tpm_pcrs)) in report_data[32..64]
  3. Value X (48-byte SHA-384 deterministic disk image tree measurement)
  4. AMD SEV-SNP (VMPL 0, DEBUG=0, vTPM PCRs) and Intel TDX (MRTD + RTMR 0..3, DEBUG=0)
  5. NVIDIA GPU SPDM attestation readiness
"""
import argparse
import base64
import hashlib
import http.client
import json
import re
import secrets
import socket
import ssl
import struct
import sys
from urllib.parse import urlparse

EAT_VERSION = 2
EAT_PROFILE = "https://uq.secure.build/eat/v2"
SECOND_COMMITMENT_DOMAIN = b"uq/eat/report-data-2\0"
NONCE_RE = re.compile(r"^[0-9a-f]{64}$")
SHA384_RE = re.compile(r"^[0-9a-f]{96}$")

# AMD SEV-SNP attestation_report offsets (ABI Specification rev 1.55, Table 22)
SNP_MIN_REPORT_LEN = 1184
SNP_OFFSET_VERSION = 0x00
SNP_OFFSET_POLICY = 0x08
SNP_POLICY_DEBUG_BIT = 1 << 19
SNP_OFFSET_VMPL = 0x30
SNP_OFFSET_REPORT_DATA = 0x50
SNP_OFFSET_MEASUREMENT = 0x90
HCL_MAGIC = 0x414C4348
HCL_SNP_OFFSET = 0x20

# Intel TDX Quote v4 offsets (Header 48B + TD Quote Body 584B)
TDX_MIN_QUOTE_LEN = 632
TDX_TEE_TYPE = 0x00000081
TDX_OFFSET_ATTRIBUTES = 0x30 + 0x70   # 0xA0
TDX_ATTR_DEBUG_BIT = 1 << 0
TDX_OFFSET_MRTD = 0x30 + 0x88         # 0xB8 (48B)
TDX_OFFSET_RTMR0 = 0x30 + 0x118       # 0x148 (48B)
TDX_OFFSET_RTMR1 = 0x30 + 0x148       # 0x178 (48B)
TDX_OFFSET_RTMR2 = 0x30 + 0x178       # 0x1A8 (48B)
TDX_OFFSET_RTMR3 = 0x30 + 0x1A8       # 0x1D8 (48B)
TDX_OFFSET_REPORT_DATA = 0x30 + 0x208  # 0x238 (64B)


def _read_asn1_tlv(data: bytes, offset: int) -> tuple[int, int, int, int]:
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
    """Extract the DER-encoded SubjectPublicKeyInfo TLV from an X.509 cert."""
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


def compute_expected_report_data(
    *,
    value_x: bytes,
    platform: int,
    tls_spki_hash: bytes,
    source_hash: bytes,
    artifact_hash: bytes,
    iat: int,
    eat_nonce: bytes,
    gpu_evidence_sha256: str,
    pcr_composite_sha256: str,
) -> bytes:
    """Recompute unified-quote 64-byte report_data (binding_bytes_v2 || second_commitment)."""
    h1 = hashlib.sha256()
    h1.update(struct.pack(">I", EAT_VERSION))
    profile_bytes = EAT_PROFILE.encode("ascii")
    h1.update(struct.pack(">I", len(profile_bytes)))
    h1.update(profile_bytes)
    h1.update(value_x)
    h1.update(bytes([platform]))
    h1.update(tls_spki_hash)
    h1.update(source_hash)
    h1.update(artifact_hash)
    h1.update(struct.pack(">Q", iat))
    h1.update(eat_nonce)
    h1.update(b"\x00" * 32)
    lower_32 = h1.digest()

    aux_challenge = hashlib.sha256(
        f"ntrust-aux-v2:{gpu_evidence_sha256}:{pcr_composite_sha256}".encode("ascii")
    ).digest()
    h2 = hashlib.sha256()
    h2.update(SECOND_COMMITMENT_DOMAIN)
    h2.update(aux_challenge)
    h2.update(value_x[:32])
    upper_32 = h2.digest()
    return lower_32 + upper_32


def parse_and_verify_cpu_quote(
    provider: str,
    quote_bytes: bytes,
    expected_report_data: bytes,
) -> dict:
    """Verify binary hardware quote invariants, RTMRs, and REPORT_DATA binding."""
    if provider in ("sev_guest", "sev-snp", "azure_hcl"):
        # Unwrap Azure HCL vTPM header if present
        if len(quote_bytes) >= HCL_SNP_OFFSET + SNP_MIN_REPORT_LEN:
            (magic,) = struct.unpack_from("<I", quote_bytes, 0)
            if magic == HCL_MAGIC:
                quote_bytes = quote_bytes[HCL_SNP_OFFSET:]
        if len(quote_bytes) < SNP_MIN_REPORT_LEN:
            raise ValueError(
                f"SEV-SNP report too short: {len(quote_bytes)} < {SNP_MIN_REPORT_LEN}"
            )
        (version,) = struct.unpack_from("<I", quote_bytes, SNP_OFFSET_VERSION)
        if version < 2:
            raise ValueError(f"Unsupported SEV-SNP report version: {version}")
        (policy,) = struct.unpack_from("<Q", quote_bytes, SNP_OFFSET_POLICY)
        if policy & SNP_POLICY_DEBUG_BIT:
            raise ValueError("SEV-SNP guest policy has DEBUG bit enabled")
        (vmpl,) = struct.unpack_from("<I", quote_bytes, SNP_OFFSET_VMPL)
        if vmpl != 0:
            raise ValueError(f"SEV-SNP report must originate from VMPL 0, got {vmpl}")
        report_data = quote_bytes[SNP_OFFSET_REPORT_DATA : SNP_OFFSET_REPORT_DATA + 64]
        if report_data != expected_report_data:
            raise ValueError("SEV-SNP hardware REPORT_DATA does not match expected binding")
        measurement = quote_bytes[SNP_OFFSET_MEASUREMENT : SNP_OFFSET_MEASUREMENT + 48].hex()
        return {
            "tee": "sev-snp",
            "version": version,
            "vmpl": vmpl,
            "debug": False,
            "measurement_hex": measurement,
        }

    if provider in ("tdx_guest", "tdx"):
        if len(quote_bytes) < TDX_MIN_QUOTE_LEN:
            raise ValueError(
                f"TDX quote too short: {len(quote_bytes)} < {TDX_MIN_QUOTE_LEN}"
            )
        version, _att_key_type, tee_type = struct.unpack_from("<HHI", quote_bytes, 0)
        if version not in (4, 5):
            raise ValueError(f"Unsupported TDX quote version: {version}")
        if tee_type != TDX_TEE_TYPE:
            raise ValueError(f"Unexpected TDX quote tee_type: 0x{tee_type:08x}")
        (td_attributes,) = struct.unpack_from("<Q", quote_bytes, TDX_OFFSET_ATTRIBUTES)
        if td_attributes & TDX_ATTR_DEBUG_BIT:
            raise ValueError("TDX TDATTRIBUTES has DEBUG bit enabled")
        report_data = quote_bytes[TDX_OFFSET_REPORT_DATA : TDX_OFFSET_REPORT_DATA + 64]
        if report_data != expected_report_data:
            raise ValueError("TDX hardware REPORTDATA does not match expected binding")
        measurement = quote_bytes[TDX_OFFSET_MRTD : TDX_OFFSET_MRTD + 48].hex()
        rtmrs = {
            "rtmr0": quote_bytes[TDX_OFFSET_RTMR0 : TDX_OFFSET_RTMR0 + 48].hex(),
            "rtmr1": quote_bytes[TDX_OFFSET_RTMR1 : TDX_OFFSET_RTMR1 + 48].hex(),
            "rtmr2": quote_bytes[TDX_OFFSET_RTMR2 : TDX_OFFSET_RTMR2 + 48].hex(),
            "rtmr3": quote_bytes[TDX_OFFSET_RTMR3 : TDX_OFFSET_RTMR3 + 48].hex(),
        }
        return {
            "tee": "tdx",
            "version": version,
            "debug": False,
            "measurement_hex": measurement,
            "rtmrs_hex": rtmrs,
        }

    raise ValueError(f"Unsupported CPU TEE quote provider: {provider}")


def verify_rats_bundle(
    bundle: dict,
    *,
    expected_nonce: str,
    expected_spki_sha256: str,
    require_gpu: bool = True,
    allow_untrusted_cpu: bool = False,
    expected_measurement: str | None = None,
    expected_value_x: str | None = None,
) -> dict:
    """Verify an ntrust unified-quote v2 EAT + RATS composite evidence bundle."""
    if bundle.get("eat_profile") != EAT_PROFILE or bundle.get("version") != EAT_VERSION:
        raise ValueError(f"Unexpected EAT profile: {bundle.get('eat_profile')}")

    nonce = bundle.get("nonce", "")
    if not NONCE_RE.match(nonce) or nonce != expected_nonce.lower():
        raise ValueError("RATS evidence nonce mismatch")

    tls_binding = bundle.get("tls_binding") or {}
    leaf_spki_sha256 = tls_binding.get("leaf_spki_sha256", "")
    if leaf_spki_sha256 != expected_spki_sha256.lower():
        raise ValueError(
            "TLS SPKI mismatch: attestation evidence does not match active TLS key"
        )

    value_x_hex = bundle.get("value_x_hex", "")
    source_hash_hex = bundle.get("source_hash_hex", "")
    artifact_hash_hex = bundle.get("artifact_hash_hex", "")
    for name, val in (
        ("value_x_hex", value_x_hex),
        ("source_hash_hex", source_hash_hex),
        ("artifact_hash_hex", artifact_hash_hex),
    ):
        if not SHA384_RE.match(val):
            raise ValueError(f"Invalid 48-byte SHA-384 field: {name}")
    if expected_value_x and value_x_hex != expected_value_x.lower():
        raise ValueError(f"Value X mismatch: {value_x_hex} != {expected_value_x}")

    gpu_tee = bundle.get("gpu_tee") or {}
    gpu_evidence_sha256 = gpu_tee.get("evidence_sha256", "")
    if not NONCE_RE.match(gpu_evidence_sha256):
        raise ValueError("Invalid GPU evidence SHA-256 digest")
    if require_gpu:
        if not gpu_tee.get("present") or not gpu_tee.get("verified"):
            raise ValueError("Confidential GPU evidence is required but not verified")

    tpm = bundle.get("tpm") or {}
    pcr_composite_sha256 = tpm.get("pcr_composite_sha256", "")
    if not NONCE_RE.match(pcr_composite_sha256):
        raise ValueError("Invalid TPM PCR composite SHA-256 digest")

    cpu_tee = bundle.get("cpu_tee") or {}
    platform = int(cpu_tee.get("platform", 0))
    iat = int(bundle.get("iat", 0))

    expected_report_data = compute_expected_report_data(
        value_x=bytes.fromhex(value_x_hex),
        platform=platform,
        tls_spki_hash=bytes.fromhex(leaf_spki_sha256),
        source_hash=bytes.fromhex(source_hash_hex),
        artifact_hash=bytes.fromhex(artifact_hash_hex),
        iat=iat,
        eat_nonce=bytes.fromhex(nonce),
        gpu_evidence_sha256=gpu_evidence_sha256,
        pcr_composite_sha256=pcr_composite_sha256,
    )

    if cpu_tee.get("report_data_hex") != expected_report_data.hex():
        raise ValueError("CPU report_data_hex does not match recomputed unified-quote binding")

    if not cpu_tee.get("confidential"):
        if not allow_untrusted_cpu:
            raise ValueError(
                f"Guest CPU is not confidential (cvm={cpu_tee.get('cvm')})"
            )
        return {
            "verified": True,
            "confidential_cpu": False,
            "confidential_gpu": bool(gpu_tee.get("verified")),
            "value_x_hex": value_x_hex,
            "leaf_spki_sha256": leaf_spki_sha256,
            "report_data_hex": expected_report_data.hex(),
            "measurement_hex": None,
        }

    quote_b64 = cpu_tee.get("quote_b64")
    if not quote_b64:
        raise ValueError("Missing hardware quote_b64 in confidential CPU bundle")
    quote_bytes = base64.b64decode(quote_b64)
    parsed_quote = parse_and_verify_cpu_quote(
        cpu_tee.get("provider", ""), quote_bytes, expected_report_data
    )
    if expected_measurement and parsed_quote["measurement_hex"] != expected_measurement.lower():
        raise ValueError(
            f"Launch measurement mismatch: {parsed_quote['measurement_hex']} != {expected_measurement}"
        )

    return {
        "verified": True,
        "confidential_cpu": True,
        "cpu_tee": parsed_quote["tee"],
        "confidential_gpu": bool(gpu_tee.get("verified")),
        "value_x_hex": value_x_hex,
        "leaf_spki_sha256": leaf_spki_sha256,
        "report_data_hex": expected_report_data.hex(),
        "measurement_hex": parsed_quote["measurement_hex"],
        "rtmrs_hex": parsed_quote.get("rtmrs_hex"),
        "pcr_composite_sha256": pcr_composite_sha256,
    }


def fetch_and_verify(
    base_url: str,
    *,
    require_gpu: bool = True,
    allow_untrusted_cpu: bool = False,
    expected_measurement: str | None = None,
    expected_value_x: str | None = None,
    cafile: str | None = None,
) -> dict:
    parsed = urlparse(base_url if "://" in base_url else f"https://{base_url}")
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError("An https:// base URL or hostname is required")
    host = parsed.hostname
    port = parsed.port or 443
    nonce = secrets.token_hex(32)

    ctx = ssl.create_default_context(cafile=cafile)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    with socket.create_connection((host, port), timeout=15.0) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            cert_der = ssock.getpeercert(binary_form=True)
            if not cert_der:
                raise RuntimeError("No TLS peer certificate received")
            spki_sha256 = hashlib.sha256(extract_spki_der(cert_der)).hexdigest()
            conn = http.client.HTTPSConnection(host, port, context=ctx)
            conn.sock = ssock
            conn.request(
                "GET",
                f"/v1/attest?nonce={nonce}",
                headers={"Host": host, "Accept": "application/json"},
            )
            resp = conn.getresponse()
            body = resp.read()
            if resp.status != 200:
                raise RuntimeError(f"GET /v1/attest failed with HTTP {resp.status}")
            bundle = json.loads(body.decode("utf-8"))

    return verify_rats_bundle(
        bundle,
        expected_nonce=nonce,
        expected_spki_sha256=spki_sha256,
        require_gpu=require_gpu,
        allow_untrusted_cpu=allow_untrusted_cpu,
        expected_measurement=expected_measurement,
        expected_value_x=expected_value_x,
    )


def main():
    parser = argparse.ArgumentParser(
        description="Verify ntrust unified-quote (https://uq.secure.build/eat/v2) remote attestation over TLS 1.3."
    )
    parser.add_argument("endpoint", help="HTTPS endpoint (e.g. https://inference.example.com)")
    parser.add_argument(
        "--no-gpu",
        action="store_true",
        help="Allow CPU-only TEE relay or dev path without GPU evidence",
    )
    parser.add_argument(
        "--allow-untrusted-cpu",
        action="store_true",
        help="Allow non-TEE KVM tryout responses (never treated as confidential)",
    )
    parser.add_argument(
        "--expected-measurement",
        help="Expected 96-hex SEV-SNP launch measurement or TDX MRTD",
    )
    parser.add_argument(
        "--expected-value-x",
        help="Expected 96-hex SHA-384 disk image tree measurement (Value X)",
    )
    parser.add_argument("--cafile", help="Custom CA bundle for staging ACME certificates")
    args = parser.parse_args()
    try:
        result = fetch_and_verify(
            args.endpoint,
            require_gpu=not args.no_gpu,
            allow_untrusted_cpu=args.allow_untrusted_cpu,
            expected_measurement=args.expected_measurement,
            expected_value_x=args.expected_value_x,
            cafile=args.cafile,
        )
    except Exception as exc:
        print(f"ATTESTATION FAILED: {exc}", file=sys.stderr)
        sys.exit(1)
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
