"""Unit tests for the Ntrust Python Client SDK."""
import http.server
import json
import socket
import sys
import threading
import unittest
from pathlib import Path

# Add client directory to sys.path
CLIENT_DIR = Path(__file__).resolve().parents[1] / "client"
if str(CLIENT_DIR) not in sys.path:
    sys.path.insert(0, str(CLIENT_DIR))

from ntrust import (
    AuthenticationError,
    ChatCompletionChunk,
    ChatCompletionResponse,
    ConfidentialClient,
    NtrustError,
    RateLimitError,
)
from ntrust.models import DotDict


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


if __name__ == "__main__":
    unittest.main()
