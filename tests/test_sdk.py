"""Unit tests for the Ntrust Python Client SDK."""
import http.server
import json
import socket
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

# Add client directory to sys.path
CLIENT_DIR = Path(__file__).resolve().parents[1] / "client"
if str(CLIENT_DIR) not in sys.path:
    sys.path.insert(0, str(CLIENT_DIR))

from ntrust import (
    AttestationError,
    AttestationVerifier,
    AuthenticationError,
    ChatCompletionChunk,
    ChatCompletionResponse,
    ConfidentialClient,
    NtrustError,
    RateLimitError,
)
from ntrust.models import DotDict
from ntrust.attestation import transport
import ntrust.__main__ as sdk_cli


class MockInferenceHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # Quiet logs during test execution

    def do_GET(self):
        auth = self.headers.get("Authorization", "")
        if auth != "Bearer test-secret-key":
            self.send_response(401)
            self.end_headers()
            self.wfile.write(b'{"error": "Unauthorized"}')
            return

        if self.path == "/v1/models":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "object": "list",
                "data": [{"id": "meta-llama/Llama-3.1-8B-Instruct", "object": "model"}]
            }).encode())
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        raw_body = self.rfile.read(length) if length > 0 else b""
        auth = self.headers.get("Authorization", "")
        if auth != "Bearer test-secret-key":
            msg = b'{"error": "Unauthorized"}'
            self.send_response(401)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(msg)))
            self.end_headers()
            self.wfile.write(msg)
            return

        body = json.loads(raw_body.decode())

        if self.path == "/v1/chat/completions":
            if body.get("model") == "rate-limited":
                self.send_response(429)
                self.end_headers()
                self.wfile.write(b'{"error": "Rate limit exceeded"}')
                return

            if body.get("stream"):
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Cache-Control", "no-cache")
                self.end_headers()
                chunks = [
                    {"choices": [{"delta": {"content": "Hello"}}]},
                    {"choices": [{"delta": {"content": " world!"}}]},
                ]
                for c in chunks:
                    self.wfile.write(f"data: {json.dumps(c)}\n\n".encode())
                self.wfile.write(b"data: [DONE]\n\n")
            else:
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                resp = {
                    "id": "chatcmpl-test",
                    "object": "chat.completion",
                    "choices": [{
                        "index": 0,
                        "message": {"role": "assistant", "content": "Hello from confidential VM!"},
                        "finish_reason": "stop"
                    }],
                    "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}
                }
                self.wfile.write(json.dumps(resp).encode())
        else:
            self.send_response(404)
            self.end_headers()


class SDKTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = http.server.HTTPServer(("127.0.0.1", 0), MockInferenceHandler)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_dot_dict_access(self):
        d = DotDict({"a": 1, "b": {"c": 2}, "list": [{"val": 3}]})
        self.assertEqual(d.a, 1)
        self.assertEqual(d.b.c, 2)
        self.assertEqual(d.list[0].val, 3)

    def test_chat_completion_unary(self):
        client = ConfidentialClient(base_url=self.base_url, api_key="test-secret-key")
        resp = client.chat.completions.create(
            model="test-model",
            messages=[{"role": "user", "content": "Hi"}],
        )
        self.assertIsInstance(resp, ChatCompletionResponse)
        self.assertEqual(resp.text, "Hello from confidential VM!")
        self.assertEqual(resp.choices[0].message.content, "Hello from confidential VM!")
        self.assertEqual(resp.usage.total_tokens, 15)

    def test_chat_completion_stream(self):
        client = ConfidentialClient(base_url=self.base_url, api_key="test-secret-key")
        stream = client.chat.completions.stream(
            model="test-model",
            messages=[{"role": "user", "content": "Hi"}],
        )
        tokens = []
        for chunk in stream:
            self.assertIsInstance(chunk, ChatCompletionChunk)
            tokens.append(chunk.delta_text)
        self.assertEqual("".join(tokens), "Hello world!")

    def test_authentication_failure(self):
        client = ConfidentialClient(base_url=self.base_url, api_key="wrong-key")
        with self.assertRaises(AuthenticationError):
            client.chat.completions.create(
                model="test-model",
                messages=[{"role": "user", "content": "Hi"}],
            )

    def test_rate_limit_error(self):
        client = ConfidentialClient(base_url=self.base_url, api_key="test-secret-key")
        with self.assertRaises(RateLimitError):
            client.chat.completions.create(
                model="rate-limited",
                messages=[{"role": "user", "content": "Hi"}],
            )

    def test_list_models(self):
        client = ConfidentialClient(base_url=self.base_url, api_key="test-secret-key")
        models = client.models.list()
        self.assertEqual(len(models), 1)
        self.assertEqual(models[0].id, "meta-llama/Llama-3.1-8B-Instruct")

    def test_attestation_requires_binary_and_independent_policy_before_connecting(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            binary = work / "uq"
            binary.write_bytes(b"test-only executable marker")
            binary.chmod(0o755)
            policy = work / "policy.json"
            policy.write_text("{}")
            base = dict(expected_value_x="ab" * 48, expected_measurement="cd" * 48,
                        gpu_policy=policy, uq_binary=binary)
            for changes in ({"expected_value_x": None}, {"expected_measurement": None},
                            {"gpu_policy": None}, {"uq_binary": work / "missing"}):
                with self.subTest(changes=changes), patch.object(transport.socket, "create_connection") as network:
                    with self.assertRaises(AttestationError):
                        AttestationVerifier(**{**base, **changes}).verify("https://example.com")
                    network.assert_not_called()
            with patch.object(transport.socket, "create_connection") as network:
                with self.assertRaises(AttestationError):
                    ConfidentialClient(base_url="https://example.com", verify_attestation=True)
                network.assert_not_called()
        self.assertFalse(hasattr(AttestationVerifier, "_verify_structural"))

    def test_sdk_forwards_all_independent_policy_to_shared_rust_transport(self):
        config = dict(expected_value_x="ab" * 48, expected_measurement="cd" * 48,
            gpu_policy="/policy/gpu.json", uq_binary="/trusted/uq", boot_policy="/policy/boot.json",
            uki="/policy/image.efi", google_boot_verifier="/trusted/uq-google-attestation",
            prior_stage_policy="/policy/prior.json", platform="tdx",
            cpu_collateral="/policy/cpu.json", cpu_tcb_policy="/policy/tcb.json")
        verdict = {"valid": True, "test_only_subprocess_contract": True, "tls_spki_sha256": "ab" * 32}
        with patch.object(transport, "fetch_and_verify", return_value=verdict) as verify:
            client = ConfidentialClient(base_url="https://example.com", verify_attestation=True, **config)
            self.assertIs(client._attestation_verdict, verdict)
            for name in ("gpu_policy", "uq_binary", "boot_policy", "uki", "google_boot_verifier",
                         "prior_stage_policy", "cpu_collateral", "cpu_tcb_policy"):
                self.assertEqual(verify.call_args.kwargs[name], Path(config[name]))
            self.assertEqual(verify.call_args.kwargs["platform"], "tdx")
        with patch.object(transport, "fetch_and_verify", side_effect=RuntimeError("Rust rejected evidence")):
            with self.assertRaisesRegex(AttestationError, "Rust rejected"):
                AttestationVerifier(**config).verify("https://example.com")

    def test_sdk_forwards_explicit_cpu_tpm_profile_policy(self):
        for platform, key, flag in [("azure-snp-vtpm", "azure_policy", "--azure-policy"),
                                    ("aws-snp-nitrotpm", "nitrotpm_policy", "--nitrotpm-policy")]:
            options = dict(expected_value_x="ab" * 48, expected_measurement="cd" * 48,
                cpu_only=True, platform=platform, cpu_collateral="/policy/cpu.json",
                cpu_tcb_policy="/policy/tcb.json", **{key: "/policy/profile.json"})
            with self.subTest(platform=platform), patch.object(transport, "fetch_and_verify", return_value={"valid": True, "tls_spki_sha256": "ab" * 32, "adapter_contract_only": True}) as verify:
                ConfidentialClient(base_url="https://example.com", **options).verify_attestation()
                self.assertEqual(verify.call_args.kwargs[key], Path("/policy/profile.json"))
                self.assertEqual(verify.call_args.kwargs["platform"], platform)
            argv = ["ntrust", "attest", "--endpoint", "https://example.com", "--value-x", "ab" * 48,
                    "--measurement", "cd" * 48, "--cpu-only", "--platform", platform,
                    flag, "/policy/profile.json", "--cpu-collateral", "/policy/cpu.json",
                    "--cpu-tcb-policy", "/policy/tcb.json"]
            with patch.object(sdk_cli.sys, "argv", argv), patch.object(sdk_cli, "ConfidentialClient") as client, patch("builtins.print"):
                client.return_value.verify_attestation.return_value = {"adapter_contract_only": True}
                sdk_cli.main()
                self.assertEqual(client.call_args.kwargs[key], "/policy/profile.json")
                self.assertEqual(client.call_args.kwargs["platform"], platform)

    def test_installed_cli_requires_and_forwards_attestation_policy(self):
        argv = ["ntrust", "attest", "--endpoint", "https://example.com", "--value-x", "ab" * 48,
                "--measurement", "cd" * 48, "--cpu-only", "--boot-policy", "/policy/boot.json",
                "--google-boot-verifier", "/trusted/helper", "--prior-stage-policy", "/policy/prior.json"]
        with patch.object(sys, "argv", argv), patch.object(sdk_cli, "ConfidentialClient") as client, patch("builtins.print"):
            client.return_value.verify_attestation.return_value = {"adapter_contract_only": True}
            sdk_cli.main()
            self.assertEqual(client.call_args.kwargs["google_boot_verifier"], "/trusted/helper")
            self.assertEqual(client.call_args.kwargs["prior_stage_policy"], "/policy/prior.json")
            client.return_value.verify_attestation.assert_called_once()


if __name__ == "__main__":
    unittest.main()
