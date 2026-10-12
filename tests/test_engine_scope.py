"""Single-engine scope: the vLLM unit and parser probe must not carry SGLang settings."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
UNIT = ROOT / "guest" / "systemd" / "ntrust-inference.service"
PROBE = ROOT / "image" / "check-engine.py"


class EngineScope(unittest.TestCase):
    def test_vllm_unit_and_probe_have_no_sglang_references(self):
        text = UNIT.read_text()
        probe = PROBE.read_text()
        self.assertIn("VLLM_API_KEY", (ROOT / "guest" / "inference-start").read_text())
        self.assertNotIn("SGLANG", text)
        self.assertIn("VLLM_", text)
        self.assertNotIn("sglang", probe.lower())
        self.assertIn("vllm", probe.lower())


if __name__ == "__main__":
    unittest.main()
