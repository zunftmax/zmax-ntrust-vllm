"""Single-engine scope: the vLLM unit must not carry SGLang settings."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
UNIT = ROOT / "guest" / "systemd" / "ntrust-inference.service"


class EngineScope(unittest.TestCase):
    def test_vllm_unit_has_no_sglang_variables(self):
        text = UNIT.read_text()
        self.assertIn("VLLM_API_KEY", (ROOT / "guest" / "inference-start").read_text())
        self.assertNotIn("SGLANG", text)
        self.assertIn("VLLM_", text)


if __name__ == "__main__":
    unittest.main()
