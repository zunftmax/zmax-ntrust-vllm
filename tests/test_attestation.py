"""Adapter contract tests only; mocked subprocesses prove no hardware attestation.

Cryptographic verification lives in Rust. These tests make sure transport/config
errors cannot select a Python fallback or manufacture an accepted GPU verdict.
"""
import hashlib
from email.message import Message
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch, Mock

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


server = load("attest_server", ROOT / "guest/attest-server")
client = load("verify_client", ROOT / "client/verify-attestation.py")
release = load("uq_release", ROOT / "image/uq-release.py")
NONCE = "ab" * 32
VALUE_X = "cd" * 48
MEASUREMENT = "ef" * 48
# Deliberately not a hardware receipt; only the trusted subprocess contract is mocked.
COLLECTOR_OUTPUT = {"version": 2, "eat_profile": server.EAT_PROFILE, "binding_suite": 2}
CPU_VERDICT = {"valid": True, "checks": [{"check": "cpu", "passed": True}], "gpu": None}
GPU_VERDICT = {"valid": True, "checks": [{"check": "cpu", "passed": True}, {"check": "gpu", "passed": True}], "gpu": {"adapter_contract_only": True}}


class AdapterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.certs = tempfile.TemporaryDirectory(prefix="ntrust-test-tls-")
        path = Path(cls.certs.name)
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
                        "-nodes", "-keyout", str(path / "key.pem"), "-outform", "DER", "-out", str(path / "cert.der"),
                        "-subj", "/CN=localhost", "-days", "1"], check=True, capture_output=True)
        cls.cert = (path / "cert.der").read_bytes()
        cls.spki = subprocess.check_output(["openssl", "pkey", "-in", str(path / "key.pem"), "-pubout", "-outform", "DER"])

    @classmethod
    def tearDownClass(cls):
        cls.certs.cleanup()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="ntrust-contract-")
        self.addCleanup(self.tmp.cleanup)
        self.work = Path(self.tmp.name).resolve()
        self.binary = self.work / "uq"
        self.binary.write_bytes(b"test-only subprocess marker")
        self.binary.chmod(0o755)
        self.policy = self.work / "policy.json"
        self.policy.write_text("{}")

    def collection_context(self):
        from contextlib import ExitStack
        stack = ExitStack()
        stack.enter_context(patch.dict(os.environ, {"NTRUST_ATTEST_MODE": "gpu", "NTRUST_DOMAIN": "localhost"}, clear=True))
        stack.enter_context(patch.object(server, "RUNTIME_DIR", self.work))
        stack.enter_context(patch.object(server, "UQ_BINARY", self.binary))
        stack.enter_context(patch.object(server, "require_pinned_uq"))
        stack.enter_context(patch.object(server, "fetch_live_tls_cert_der", return_value=self.cert))
        stack.enter_context(patch.object(server, "compute_value_x", return_value=bytes.fromhex(VALUE_X)))
        return stack

    def verifier_args(self, **updates):
        values = dict(expected_nonce=NONCE, tls_spki_der=self.spki, expected_value_x=VALUE_X,
                      expected_measurement=MEASUREMENT, gpu_policy=self.policy, uq_binary=self.binary)
        values.update(updates)
        return values

    def test_exact_tls_spki_matches_openssl(self):
        self.assertEqual(server.extract_spki_der(self.cert), self.spki)
        self.assertEqual(client.extract_spki_der(self.cert), self.spki)
        for malformed in (b"", b"\x30\x82\xff\xff", self.cert[:12]):
            with self.assertRaises(ValueError):
                client.extract_spki_der(malformed)

    def test_measured_tree_detects_file_changes(self):
        tree = self.work / "tree"
        tree.mkdir()
        (tree / "app").write_bytes(b"one")
        old = server.compute_value_x(paths=(str(tree / "app"),))
        (tree / "app").write_bytes(b"two")
        self.assertNotEqual(old, server.compute_value_x(paths=(str(tree / "app"),)))
        self.assertIn("/usr/local/bin/uq", server.DEFAULT_MEASURED_PATHS)
        self.assertIn("/usr/share/doc/ntrust/uq-release.json", server.DEFAULT_MEASURED_PATHS)

    def test_required_measured_files_cannot_be_missing_or_linked(self):
        file = self.work / "measured"
        file.write_bytes(b"required file")
        with self.assertRaises(OSError):
            server.compute_value_x(paths=(str(file), str(self.work / "missing")))
        link = self.work / "linked"
        link.symlink_to(file)
        with self.assertRaises(OSError):
            server.compute_value_x(paths=(str(link),))
        with self.assertRaises(RuntimeError):
            server.compute_value_x(paths=(str(self.work),))

    def test_installed_binary_must_match_pinned_bytes(self):
        record = self.work / "release.json"
        record.write_text(json.dumps({"binary_sha256": hashlib.sha256(self.binary.read_bytes()).hexdigest()}))
        server.require_pinned_uq(self.binary, record)
        self.binary.write_bytes(b"changed")
        with self.assertRaisesRegex(RuntimeError, "differs"):
            server.require_pinned_uq(self.binary, record)
        with self.assertRaises(RuntimeError):
            server.require_pinned_uq(self.work / "missing", record)

    def test_collector_receives_observed_spki_nonce_and_gpu_mode(self):
        seen = []
        def run(command, **kwargs):
            seen.append(command)
            self.assertEqual(Path(command[command.index("--tls-spki") + 1]).read_bytes(), self.spki)
            self.assertEqual(command[command.index("--nonce") + 1], NONCE)
            self.assertEqual(command[command.index("--value-x") + 1], VALUE_X)
            self.assertIn("--gpu", command)
            self.assertEqual(kwargs["timeout"], 240)
            Path(command[command.index("--out") + 1]).write_text(json.dumps(COLLECTOR_OUTPUT))
            return subprocess.CompletedProcess(command, 0)
        with self.collection_context(), patch.object(server.subprocess, "run", side_effect=run):
            self.assertEqual(server.build_rats_evidence(NONCE), COLLECTOR_OUTPUT)
        self.assertEqual(len(seen), 1)
        self.assertEqual(list(self.work.glob("request-*")), [])

    def test_cpu_only_collection_is_explicit_and_never_claims_origin_gpu(self):
        def run(command, **_kwargs):
            self.assertNotIn("--gpu", command)
            Path(command[command.index("--out") + 1]).write_text(json.dumps(COLLECTOR_OUTPUT))
            return subprocess.CompletedProcess(command, 0)
        with self.collection_context(), patch.dict(os.environ, {"NTRUST_ATTEST_MODE": "cpu-only"}), patch.object(server.subprocess, "run", side_effect=run):
            self.assertEqual(server.build_rats_evidence(NONCE), COLLECTOR_OUTPUT)
        with self.collection_context(), patch.dict(os.environ, {"NTRUST_ATTEST_MODE": ""}), patch.object(server.subprocess, "run") as command:
            with self.assertRaises(RuntimeError):
                server.build_rats_evidence(NONCE)
            command.assert_not_called()

    def test_bad_nonce_never_starts_collection(self):
        for nonce in ("", "00", "AB" * 32, NONCE + "\n", NONCE + "00"):
            with self.subTest(nonce=nonce), patch.object(server.subprocess, "run") as command:
                with self.assertRaises(ValueError):
                    server.build_rats_evidence(nonce)
                command.assert_not_called()

    def test_ambiguous_http_framing_never_starts_collection(self):
        for headers, suffix in (([("Host", "a"), ("Host", "b")], ""),
                                ([("Host", "a"), ("Content-Length", "0"), ("Content-Length", "0")], ""),
                                ([("Host", "a"), ("Transfer-Encoding", "chunked")], ""),
                                ([("Host", "a")], "#fragment")):
            handler = object.__new__(server.AttestHandler)
            handler.path = "/v1/attest?nonce=" + NONCE + suffix
            handler.headers = Message()
            for key, value in headers:
                handler.headers.add_header(key, value)
            handler._send_json = Mock()
            with patch.object(server, "build_rats_evidence") as collector:
                handler.do_GET()
                collector.assert_not_called()
            self.assertEqual(handler._send_json.call_args.args[0], 400)

    def test_collection_process_failures_cannot_fall_back_to_python(self):
        for error in (OSError("missing"), subprocess.TimeoutExpired("uq", 240)):
            with self.subTest(error=error), self.collection_context(), patch.object(server.subprocess, "run", side_effect=error):
                with self.assertRaises(RuntimeError):
                    server.build_rats_evidence(NONCE)
        def rejected(command, **_kwargs):
            Path(command[command.index("--out") + 1]).write_text('{"gpu_tee":{"present":true,"verified":true}}')
            return subprocess.CompletedProcess(command, 1)
        with self.collection_context(), patch.object(server.subprocess, "run", side_effect=rejected):
            with self.assertRaisesRegex(RuntimeError, "exit 1"):
                server.build_rats_evidence(NONCE)

    def test_collection_rejects_empty_oversized_malformed_or_legacy_output(self):
        for raw in (b"", b"x" * 101, b"{", b'{"gpu_tee":{"verified":true}}', b'[]'):
            def run(command, **_kwargs):
                Path(command[command.index("--out") + 1]).write_bytes(raw)
                return subprocess.CompletedProcess(command, 0)
            with self.subTest(raw=raw[:20]), self.collection_context(), patch.object(server, "MAX_EVIDENCE_BYTES", 100), patch.object(server.subprocess, "run", side_effect=run):
                with self.assertRaises((RuntimeError, ValueError)):
                    server.build_rats_evidence(NONCE)

    def test_verifier_receives_raw_receipt_spki_and_independent_policy(self):
        raw = b'{"untrusted_transport_input":true}'
        def run(command, **kwargs):
            self.assertEqual(command[1], "verify-composite")
            self.assertEqual(Path(command[2]).read_bytes(), raw)
            for flag, expected in (("--nonce", NONCE), ("--value-x", VALUE_X), ("--expected-platform-measurement", MEASUREMENT), ("--gpu-policy", str(self.policy.resolve()))):
                self.assertEqual(command[command.index(flag) + 1], expected)
            self.assertEqual(Path(command[command.index("--tls-spki") + 1]).read_bytes(), self.spki)
            self.assertIn("--require-gpu-verified", command)
            kwargs["stdout"].write(json.dumps(GPU_VERDICT).encode())
            return subprocess.CompletedProcess(command, 0)
        with patch.object(client.subprocess, "run", side_effect=run):
            self.assertEqual(client.verify_rats_bundle(raw, **self.verifier_args()), GPU_VERDICT)

    def test_verifier_requires_independent_image_and_inventory_policy(self):
        for update in ({"expected_value_x": ""}, {"expected_measurement": ""}, {"gpu_policy": None},
                       {"cpu_only": True}, {"gpu_policy": self.work / "missing"}, {"uq_binary": self.work / "missing"}):
            with self.subTest(update=update), patch.object(client.subprocess, "run") as command:
                with self.assertRaises((RuntimeError, ValueError)):
                    client.verify_rats_bundle(b"{}", **self.verifier_args(**update))
                command.assert_not_called()

    def test_explicit_cpu_platform_requires_and_forwards_collateral(self):
        for platform in ("tdx", "sev-snp"):
            with self.subTest(platform=platform), patch.object(client.subprocess, "run") as command:
                with self.assertRaisesRegex(ValueError, "CPU collateral"):
                    client.verify_rats_bundle(b"{}", **self.verifier_args(platform=platform))
                command.assert_not_called()
        collateral = self.work / "cpu.json"
        collateral.write_text("{}")
        def run(command, **kwargs):
            self.assertEqual(command[command.index("--platform") + 1], "tdx")
            self.assertEqual(command[command.index("--cpu-collateral") + 1], str(collateral))
            self.assertEqual(command[command.index("--cpu-tcb-policy") + 1], str(self.policy))
            kwargs["stdout"].write(json.dumps(GPU_VERDICT).encode())
            return subprocess.CompletedProcess(command, 0)
        with patch.object(client.subprocess, "run", side_effect=run):
            client.verify_rats_bundle(b"{}", **self.verifier_args(platform="tdx", cpu_collateral=collateral, cpu_tcb_policy=self.policy))

    def test_invalid_or_incomplete_rust_verdict_is_never_success(self):
        for verdict, code in ((GPU_VERDICT, 1), ({"verified": True}, 0), ({"valid": False}, 0),
                              ({"valid": True, "checks": [], "gpu": {}}, 0), (CPU_VERDICT, 0)):
            def run(command, **kwargs):
                kwargs["stdout"].write(json.dumps(verdict).encode())
                return subprocess.CompletedProcess(command, code)
            with self.subTest(verdict=verdict, code=code), patch.object(client.subprocess, "run", side_effect=run):
                with self.assertRaises(RuntimeError):
                    client.verify_rats_bundle(b"{}", **self.verifier_args())
        for error in (OSError("missing"), subprocess.TimeoutExpired("uq", 240)):
            with patch.object(client.subprocess, "run", side_effect=error):
                with self.assertRaises(RuntimeError):
                    client.verify_rats_bundle(b"{}", **self.verifier_args())

    def test_local_uki_requires_policy_and_is_forwarded_only_to_local_rust(self):
        uki = self.work / "approved-image.efi"
        uki.write_bytes(b"adapter argument fixture, not a UKI")
        with patch.object(client.subprocess, "run") as command:
            with self.assertRaisesRegex(ValueError, "requires --boot-policy"):
                client.verify_rats_bundle(b"{}", **self.verifier_args(uki=uki))
            command.assert_not_called()
        with patch.object(client.socket, "create_connection") as connection:
            with self.assertRaisesRegex(ValueError, "requires --boot-policy"):
                client.fetch_and_verify("https://example.com", expected_value_x=VALUE_X,
                                        expected_measurement=MEASUREMENT, gpu_policy=self.policy, uki=uki)
            connection.assert_not_called()
        empty = self.work / "empty.efi"
        empty.touch()
        for invalid in (self.work / "missing.efi", self.work, empty, uki):
            with self.subTest(uki=invalid), patch.object(client, "MAX_UKI_BYTES", 1), patch.object(client.subprocess, "run") as command:
                with self.assertRaisesRegex(ValueError, "Local UKI image"):
                    client.verify_rats_bundle(b"{}", **self.verifier_args(uki=invalid, boot_policy=self.policy))
                command.assert_not_called()

        def run(command, **kwargs):
            self.assertEqual(command[command.index("--uki") + 1], str(uki.resolve()))
            self.assertEqual(command[command.index("--boot-policy") + 1], str(self.policy.resolve()))
            self.assertEqual(Path(command[2]).read_bytes(), b"{}")
            kwargs["stdout"].write(json.dumps(GPU_VERDICT).encode())
            return subprocess.CompletedProcess(command, 0)

        stack, _tls, connection, _factory = self.tls_context()
        with stack, patch.object(client.subprocess, "run", side_effect=run) as command:
            self.assertEqual(client.fetch_and_verify("https://example.com", expected_value_x=VALUE_X,
                                                    expected_measurement=MEASUREMENT, gpu_policy=self.policy,
                                                    uki=uki, boot_policy=self.policy, uq_binary=self.binary), GPU_VERDICT)
            command.assert_called_once()
            self.assertRegex(connection.request.call_args.args[1], r"^/v1/attest\?nonce=[0-9a-f]{64}$")
            self.assertNotIn("body", connection.request.call_args.kwargs)

        argv = ["verify-attestation.py", "https://example.com", "--expected-value-x", VALUE_X,
                "--expected-measurement", MEASUREMENT, "--gpu-policy", str(self.policy),
                "--boot-policy", str(self.policy), "--uki", str(uki)]
        with patch.object(client.sys, "argv", argv), patch.object(client, "fetch_and_verify", return_value=GPU_VERDICT) as fetch, patch("builtins.print"):
            self.assertEqual(client.main(), 0)
            self.assertEqual(fetch.call_args.kwargs["uki"], uki)
            self.assertEqual(fetch.call_args.kwargs["boot_policy"], self.policy)

    def test_cpu_only_client_never_requests_gpu_success(self):
        def run(command, **kwargs):
            self.assertNotIn("--require-gpu-verified", command)
            self.assertNotIn("--gpu-policy", command)
            kwargs["stdout"].write(json.dumps(CPU_VERDICT).encode())
            return subprocess.CompletedProcess(command, 0)
        with patch.object(client.subprocess, "run", side_effect=run):
            self.assertEqual(client.verify_rats_bundle(b"{}", **self.verifier_args(cpu_only=True, gpu_policy=None)), CPU_VERDICT)

    def tls_context(self, body=b"{}", length="2"):
        from contextlib import ExitStack
        stack = ExitStack()
        tcp = Mock()
        socket_context = Mock()
        socket_context.__enter__ = Mock(return_value=tcp)
        socket_context.__exit__ = Mock(return_value=False)
        stack.enter_context(patch.object(client.socket, "create_connection", return_value=socket_context))
        tls = Mock()
        tls.getpeercert.return_value = self.cert
        tls_context = Mock()
        tls_context.__enter__ = Mock(return_value=tls)
        tls_context.__exit__ = Mock(return_value=False)
        context = Mock()
        context.wrap_socket.return_value = tls_context
        stack.enter_context(patch.object(client.ssl, "create_default_context", return_value=context))
        connection = Mock()
        response = connection.getresponse.return_value
        response.status = 200
        response.getheader.side_effect = lambda name, default=None: {"Content-Length": length}.get(name, default)
        response.read.return_value = body
        response.read1.side_effect = [body, b""]
        connection_class = stack.enter_context(patch.object(client.http.client, "HTTPSConnection", return_value=connection))
        return stack, tls, connection, connection_class

    def test_fetch_binds_exact_same_tls_socket_and_passes_transport_bytes(self):
        stack, tls, connection, factory = self.tls_context()
        with stack, patch.object(client, "verify_rats_bundle", return_value={"adapter_transport_only": True}) as verifier:
            result = client.fetch_and_verify("https://example.com", expected_value_x=VALUE_X,
                                             expected_measurement=MEASUREMENT, gpu_policy=self.policy, uq_binary=self.binary)
            self.assertEqual(result, {"adapter_transport_only": True})
            self.assertIs(connection.sock, tls)
            factory.assert_called_once()
            self.assertEqual(verifier.call_args.args[0], b"{}")
            self.assertEqual(verifier.call_args.kwargs["tls_spki_der"], self.spki)
            nonce = verifier.call_args.kwargs["expected_nonce"]
            self.assertEqual(connection.request.call_args.args[:2], ("GET", "/v1/attest?nonce=" + nonce))

    def test_oversized_http_body_never_reaches_verifier(self):
        stack, _tls, _connection, _factory = self.tls_context(length=str(client.MAX_EVIDENCE_BYTES + 1))
        with stack, patch.object(client, "verify_rats_bundle") as verifier:
            with self.assertRaisesRegex(RuntimeError, "byte limit"):
                client.fetch_and_verify("https://example.com", expected_value_x=VALUE_X,
                                       expected_measurement=MEASUREMENT, gpu_policy=self.policy)
            verifier.assert_not_called()


class PackagingTests(unittest.TestCase):
    def test_release_record_requires_real_exact_pins(self):
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / "release.json"
            valid = {"release_tag": "v1.2.3", "source_sha": "a1" * 20, "binary_sha256": "b2" * 32,
                     "target": "x86_64-unknown-linux-gnu"}
            path.write_text(json.dumps(valid))
            self.assertEqual(release.load_release(path), valid)
            for changes in ({"source_sha": "main"}, {"binary_sha256": "0" * 64}, {"release_tag": "latest"},
                            {"target": "aarch64-apple-darwin"}, {"unexpected": "value"}):
                path.write_text(json.dumps({**valid, **changes}))
                with self.assertRaises(ValueError):
                    release.load_release(path)
            path.write_text('{"release_tag":"v1","release_tag":"v2"}')
            with self.assertRaises(ValueError):
                release.load_release(path)

    def test_fetch_stops_when_approval_configuration_is_missing(self):
        env = dict(os.environ)
        env.pop("NTRUST_UQ_RELEASE_CONFIG", None)
        result = subprocess.run(["bash", str(ROOT / "image/fetch-uq.sh")], env=env, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("independently approved", result.stderr)

    def test_source_keeps_activation_disabled_and_pins_in_image_inventory(self):
        install = (ROOT / "image/install.sh").read_text()
        self.assertIn("systemctl disable ntrust-attest.service", install)
        self.assertNotIn("systemctl enable ntrust-attest.service", install)
        self.assertIn('build/uq', (ROOT / 'image/ntrust.pkr.hcl').read_text())
        self.assertIn("usr/local/bin/uq", (ROOT / 'image/inventory.py').read_text())
        self.assertIn("NTRUST_ATTEST_MODE=cpu-only" if ROOT.name.endswith("-relay") else "NTRUST_ATTEST_MODE=gpu",
                      (ROOT / 'guest/systemd/ntrust-attest.service').read_text())


if __name__ == "__main__":
    unittest.main()
