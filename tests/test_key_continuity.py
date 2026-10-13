"""Request TLS tests; mocked appraisal is not hardware verification.

Real local TLS handshakes exercise the application's send boundary. Constructed
certificate fixtures and adapter verdicts are confined to these contract tests.
"""
import hashlib
import http.client
import http.server
import io
import json
from pathlib import Path
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch

CLIENT_DIR = Path(__file__).resolve().parents[1] / "client"
if str(CLIENT_DIR) not in sys.path:
    sys.path.insert(0, str(CLIENT_DIR))

from ntrust import AttestationError, ConfidentialClient
from ntrust import _key_continuity as continuity
from ntrust._attestation_transport import extract_spki_der
from ntrust.client import _HTTPClient


class CaptureHandler(http.server.BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.rfile.close()
        self.rfile = io.BufferedReader(CaptureReader(self.connection, self.server.received))

    def handle(self):
        try:
            super().handle()
        except ConnectionResetError:
            pass # Expected when the client rejects immediately after handshake.
        finally:
            with self.server.finished_condition:
                self.server.finished += 1
                self.server.finished_condition.notify_all()

    def log_message(self, *_):
        pass

    def do_GET(self):
        self._answer()

    def do_POST(self):
        self._answer()

    def _answer(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self.server.requests.append((self.command, dict(self.headers), body))
        output = b'{"data":[]}' if self.command == "GET" else b'data: stream-one\n\ndata: stream-two\n\n'
        self.send_response(200)
        self.send_header("Content-Length", str(len(output)))
        self.end_headers()
        self.wfile.write(output)


class CaptureReader(io.RawIOBase):
    def __init__(self, connection, received):
        self.connection, self.received = connection, received

    def readable(self):
        return True

    def readinto(self, buffer):
        count = self.connection.recv_into(buffer)
        self.received.extend(buffer[:count])
        return count


class KeyContinuityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix="ntrust-channel-test-")
        work = Path(cls.directory.name)
        config = work / "openssl.cnf"
        config.write_text("[req]\ndistinguished_name=dn\nx509_extensions=ext\nprompt=no\n"
            "[dn]\nCN=localhost\n[ext]\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n"
            "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,digitalSignature,keyCertSign\n")
        cls.certificates = []
        cls.keys = []
        for name in ("a", "b"):
            certificate, key = work / (name + ".pem"), work / (name + ".key")
            subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
                "-nodes", "-keyout", str(key), "-out", str(certificate), "-config", str(config), "-days", "1"],
                check=True, capture_output=True)
            cls.certificates.append(certificate)
            cls.keys.append(key)
        cls.ca = work / "ca.pem"
        cls.ca.write_bytes(b"".join(path.read_bytes() for path in cls.certificates))
        cls.der = [ssl.PEM_cert_to_DER_cert(path.read_text()) for path in cls.certificates]
        cls.pins = [hashlib.sha256(extract_spki_der(der)).hexdigest() for der in cls.der]

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def setUp(self):
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), CaptureHandler)
        self.server.requests = []
        self.server.received = bytearray()
        self.server.finished = 0
        self.server.finished_condition = threading.Condition()
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.load_cert_chain(self.certificates[0], self.keys[0])
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        self.thread.start()
        self.addCleanup(self._stop)
        self.origin = "https://localhost:" + str(self.server.server_port)

    def _stop(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def verdict(self, index=0):
        return {"valid": True, "tls_spki_sha256": self.pins[index], "test_only_adapter_result": True}

    def client(self):
        return ConfidentialClient(base_url=self.origin, api_key="must-not-leak-api-key", cafile=str(self.ca), timeout=2)

    def assert_no_http_bytes(self, connections):
        with self.server.finished_condition:
            finished = self.server.finished_condition.wait_for(lambda: self.server.finished >= connections, timeout=2)
        self.assertTrue(finished, "TLS test handler did not finish")
        self.assertEqual(self.server.received, b"")
        self.assertEqual(self.server.requests, [])

    def test_changed_handshake_key_sends_no_headers_or_body_for_any_request(self):
        for operation in (lambda c: c._http.get_json("/v1/models"),
                          lambda c: c._http.post_json("/v1/chat/completions", {"secret": "must-not-leak-prompt"}),
                          lambda c: list(c._http.post_stream("/v1/chat/completions", {"secret": "must-not-leak-stream"}))):
            client = self.client()
            with patch.object(client.attestation, "verify", return_value=self.verdict(1)) as verify:
                client.verify_attestation()
                with self.assertRaisesRegex(AttestationError, "differs"):
                    operation(client)
                self.assertEqual(verify.call_count, 2) # Explicit check plus fresh request appraisal.
        self.assert_no_http_bytes(3)

    def test_requests_and_streams_each_refresh_and_preserve_checked_tls_channel(self):
        client = self.client()
        with patch.object(client.attestation, "verify", return_value=self.verdict()) as verify:
            client.verify_attestation()
            self.assertEqual(client._http.get_json("/v1/models")[0], 200)
            self.assertEqual(client._http.post_json("/v1/chat/completions", {"message": "one"})[0], 200)
            output = b"".join(client._http.post_stream("/v1/chat/completions", {"message": "two"}))
            self.assertIn(b"stream-two", output)
            self.assertEqual(verify.call_count, 4)
        self.assertEqual(len(self.server.requests), 3)
        self.assertTrue(all(headers["Authorization"] == "Bearer must-not-leak-api-key"
            for _, headers, _ in self.server.requests))

    def test_failed_refresh_drops_cached_verdict_and_never_sends_a_request(self):
        client = self.client()
        with patch.object(client.attestation, "verify", side_effect=[self.verdict(), AttestationError("new quote rejected"), AttestationError("still rejected")]):
            client.verify_attestation()
            for _ in range(2):
                with self.assertRaises(AttestationError):
                    client._http.post_json("/v1/chat/completions", {"secret": "do-not-send"})
                self.assertIsNone(client.attestation_verdict)
        self.assert_no_http_bytes(0)

    def test_explicit_failed_verification_does_not_downgrade_or_allow_plain_http(self):
        client = self.client()
        with patch.object(client.attestation, "verify", side_effect=AttestationError("rejected")) as verify:
            with self.assertRaises(AttestationError):
                client.verify_attestation()
            with self.assertRaises(AttestationError):
                client._http.get_json("/v1/models")
            self.assertEqual(verify.call_count, 2)
            with self.assertRaisesRegex(AttestationError, "cannot be removed"):
                client._http.require_attestation(None)
            with self.assertRaises(AttestationError):
                client._http.get_json("/v1/models")
        self.assert_no_http_bytes(0)
        unencrypted = ConfidentialClient(base_url="http://localhost:1", api_key="secret")
        with patch.object(unencrypted.attestation, "verify", return_value=self.verdict()):
            unencrypted.verify_attestation()
        with patch.object(http.client.HTTPConnection, "connect") as connect:
            with self.assertRaisesRegex(AttestationError, "HTTPS"):
                unencrypted._http.get_json("/v1/models")
            connect.assert_not_called()

    def test_expired_key_authorization_sends_nothing_even_after_handshake(self):
        http = _HTTPClient(self.origin, api_key="secret", cafile=str(self.ca), timeout=2)
        http.require_attestation(lambda: self.verdict())
        connection = http._create_connection()
        with patch.object(continuity.time, "monotonic", return_value=connection._key_deadline):
            with self.assertRaisesRegex(AttestationError, "expired"):
                connection.request("POST", "/v1/chat/completions", body=b"private-prompt", headers={"Authorization": "Bearer secret"})
        self.assert_no_http_bytes(1)

    def test_automatic_reconnection_checks_new_peer_before_sending(self):
        context = ssl.create_default_context(cafile=str(self.ca))
        connection = continuity.AttestedHTTPSConnection("localhost", 443, context=context, timeout=2,
            expected_pin=bytes.fromhex(self.pins[0]))
        first, changed = Mock(), Mock()
        first.getpeercert.return_value = self.der[0]
        changed.getpeercert.return_value = self.der[1]
        sockets = iter([first, changed])
        def connect(current):
            current.sock = next(sockets)
        with patch.object(http.client.HTTPSConnection, "connect", autospec=True, side_effect=connect):
            connection.connect()
            connection.close()
            with self.assertRaisesRegex(AttestationError, "differs"):
                connection.request("POST", "/v1/chat/completions", body=b"secret", headers={"Authorization": "Bearer secret"})
        changed.sendall.assert_not_called()
        first.sendall.assert_not_called()

    def test_receipt_fields_or_success_without_transport_key_cannot_authorize(self):
        for verdict in ({"valid": True, "tls_spki_hash": self.pins[0]},
                        {"valid": False, "tls_spki_sha256": self.pins[0]},
                        {"valid": True, "tls_spki_sha256": "garbage"}):
            client = self.client()
            with self.subTest(verdict=verdict), patch.object(client.attestation, "verify", return_value=verdict):
                with self.assertRaises(AttestationError):
                    client.verify_attestation()
                with self.assertRaises(AttestationError):
                    client._http.get_json("/v1/models")
        self.assert_no_http_bytes(0)


if __name__ == "__main__":
    unittest.main()
