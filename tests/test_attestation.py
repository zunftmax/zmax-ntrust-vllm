"""Test IETF RATS composite remote attestation responder and client verifier."""
import base64
import copy
import hashlib
import importlib.machinery
import importlib.util
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


def _load_module(name: str, path: Path):
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


attest_server = _load_module("attest_server", ROOT / "guest" / "attest-server")
verify_client = _load_module("verify_client", ROOT / "client" / "verify-attestation.py")


def _make_snp_report(
    report_data: bytes,
    *,
    version: int = 2,
    policy: int = 0x30000,
    vmpl: int = 0,
    measurement: bytes = b"\xaa" * 48,
) -> bytes:
    buf = bytearray(1184)
    struct.pack_into("<I", buf, 0x00, version)
    struct.pack_into("<Q", buf, 0x08, policy)
    struct.pack_into("<I", buf, 0x30, vmpl)
    buf[0x50:0x90] = report_data
    buf[0x90:0xC0] = measurement
    return bytes(buf)


def _make_tdx_quote(
    report_data: bytes,
    *,
    version: int = 4,
    tee_type: int = 0x00000081,
    td_attributes: int = 0,
    mrtd: bytes = b"\xbb" * 48,
) -> bytes:
    buf = bytearray(632)
    struct.pack_into("<HHI", buf, 0x00, version, 2, tee_type)
    struct.pack_into("<Q", buf, 0xA0, td_attributes)
    buf[0xB8:0xE8] = mrtd
    buf[0x238:0x278] = report_data
    return bytes(buf)


class _StubTsmDir:
    """Populate ConfigFS-TSM slot files when mkdtemp creates a slot."""

    def __init__(self, root: Path, provider: str, quote_builder):
        self.root = root
        self.provider = provider
        self.quote_builder = quote_builder

    def patch_collect(self, report_data: bytes, _tsm_root: Path) -> dict:
        quote_bytes = self.quote_builder(report_data)
        return {
            "provider": self.provider,
            "generation": 1,
            "quote_b64": base64.b64encode(quote_bytes).decode("ascii"),
        }


class AttestationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ntrust-attest-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.cert_der = self.base / "leaf.der"
        self.key_pem = self.base / "leaf.key"
        subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:prime256v1",
                "-nodes",
                "-keyout",
                str(self.key_pem),
                "-out",
                str(self.cert_der),
                "-outform",
                "DER",
                "-days",
                "1",
                "-subj",
                "/CN=inference.example.com",
            ],
            check=True,
            capture_output=True,
        )
        spki_proc = subprocess.run(
            [
                "sh",
                "-c",
                f'openssl x509 -inform DER -in "{self.cert_der}" -pubkey -noout '
                "| openssl pkey -pubin -outform DER",
            ],
            check=True,
            capture_output=True,
        )
        self.openssl_spki_der = spki_proc.stdout
        self.expected_spki_sha256 = hashlib.sha256(self.openssl_spki_der).hexdigest()
        self.gpu_evidence = self.base / "attestation.json"
        self.gpu_evidence.write_text('{"overall-result": true, "gpu": "CC-ON"}\n')
        self.model_manifest = self.base / "model.json"
        self.model_manifest.write_text('{"model": "test"}\n')
        self.tsm_dir = self.base / "tsm"
        self.tsm_dir.mkdir()
        self.nonce = "0123456789abcdef" * 4

    def test_spki_der_extraction_matches_openssl(self):
        cert_bytes = self.cert_der.read_bytes()
        self.assertEqual(
            attest_server.extract_spki_der(cert_bytes), self.openssl_spki_der
        )
        self.assertEqual(
            verify_client.extract_spki_der(cert_bytes), self.openssl_spki_der
        )

    def test_sev_snp_and_tdx_rats_bundles_verify_and_bind_tls_key(self):
        for cvm, provider, builder, expected_meas in (
            ("sev-snp", "sev_guest", _make_snp_report, "aa" * 48),
            ("tdx", "tdx_guest", _make_tdx_quote, "bb" * 48),
        ):
            with self.subTest(cvm=cvm):
                stub = _StubTsmDir(self.tsm_dir, provider, builder)
                orig_collect = attest_server.collect_tsm_quote
                attest_server.collect_tsm_quote = stub.patch_collect
                try:
                    bundle = attest_server.build_rats_evidence(
                        self.nonce,
                        domain="inference.example.com",
                        cert_file=str(self.cert_der),
                        gpu_evidence_path=self.gpu_evidence,
                        model_manifest_path=self.model_manifest,
                        tsm_root=self.tsm_dir,
                        cvm=cvm,
                    )
                finally:
                    attest_server.collect_tsm_quote = orig_collect

                res = verify_client.verify_rats_bundle(
                    bundle,
                    expected_nonce=self.nonce,
                    expected_spki_sha256=self.expected_spki_sha256,
                    require_gpu=True,
                    expected_measurement=expected_meas,
                )
                self.assertTrue(res["verified"])
                self.assertTrue(res["confidential_cpu"])
                self.assertTrue(res["confidential_gpu"])
                self.assertEqual(res["measurement_hex"], expected_meas)

                # Relay/MITM attack: different TLS leaf SPKI must be rejected
                with self.assertRaisesRegex(ValueError, "TLS SPKI mismatch"):
                    verify_client.verify_rats_bundle(
                        bundle,
                        expected_nonce=self.nonce,
                        expected_spki_sha256="ff" * 32,
                    )

                # Replay attack: different client nonce must be rejected
                with self.assertRaisesRegex(ValueError, "nonce mismatch"):
                    verify_client.verify_rats_bundle(
                        bundle,
                        expected_nonce="fedcba9876543210" * 4,
                        expected_spki_sha256=self.expected_spki_sha256,
                    )

                # Tampered binary quote REPORT_DATA must be rejected
                tampered = copy.deepcopy(bundle)
                raw_quote = bytearray(base64.b64decode(tampered["cpu_tee"]["quote_b64"]))
                offset = 0x50 if cvm == "sev-snp" else 0x238
                raw_quote[offset] ^= 0xFF
                tampered["cpu_tee"]["quote_b64"] = base64.b64encode(raw_quote).decode("ascii")
                with self.assertRaisesRegex(ValueError, "REPORT.*DATA does not match"):
                    verify_client.verify_rats_bundle(
                        tampered,
                        expected_nonce=self.nonce,
                        expected_spki_sha256=self.expected_spki_sha256,
                    )

    def test_debug_policy_and_nonzero_vmpl_are_rejected(self):
        rd = b"\x11" * 64
        with self.assertRaisesRegex(ValueError, "DEBUG bit enabled"):
            verify_client.parse_and_verify_cpu_quote(
                "sev_guest",
                _make_snp_report(rd, policy=1 << 19),
                rd,
            )
        with self.assertRaisesRegex(ValueError, "VMPL 0"):
            verify_client.parse_and_verify_cpu_quote(
                "sev_guest",
                _make_snp_report(rd, vmpl=1),
                rd,
            )
        with self.assertRaisesRegex(ValueError, "DEBUG bit enabled"):
            verify_client.parse_and_verify_cpu_quote(
                "tdx_guest",
                _make_tdx_quote(rd, td_attributes=1),
                rd,
            )

    def test_untrusted_kvm_boot_is_never_labeled_confidential(self):
        bundle = attest_server.build_rats_evidence(
            self.nonce,
            domain="inference.example.com",
            cert_file=str(self.cert_der),
            gpu_evidence_path=None,
            model_manifest_path=self.model_manifest,
            tsm_root=self.tsm_dir,
            cvm="none",
        )
        self.assertFalse(bundle["cpu_tee"]["confidential"])
        self.assertIsNone(bundle["cpu_tee"]["quote_b64"])
        with self.assertRaisesRegex(ValueError, "not confidential"):
            verify_client.verify_rats_bundle(
                bundle,
                expected_nonce=self.nonce,
                expected_spki_sha256=self.expected_spki_sha256,
                require_gpu=False,
            )


if __name__ == "__main__":
    unittest.main()
