"""Exercise shell admission gates with stub devices; never a CVM/GPU proof.

Only filesystem paths are redirected into a temporary tree. No Linux VM,
NGINX binary or NVIDIA binary is run by these source-level tests.
"""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class GuestGates(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ntrust-test-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.bin = self.base / "bin"
        self.bin.mkdir()
        self.run = self.base / "run"
        self.run.mkdir()
        self.swaps = self.base / "swaps"
        self.swaps.write_text("Filename Type Size Used Priority\n")
        self.env = dict(os.environ, PATH=f"{self.bin}:{os.environ['PATH']}",
                        CALLS=str(self.base / "calls"), CVM="tdx", GPU_COUNT="1",
                        CC_MODE="ON", VERIFY_RC="0", READY_RC="0", QUERY_RC="0",
                        READY_STATE="ready", NTRUST_DOMAIN="inference.example.com",
                        NTRUST_EMAIL="admin@example.com")
        self.env.pop("NTRUST_ACME_DIRECTORY", None)
        self.stub("systemd-detect-virt", 'printf "%s\\n" "$CVM"')
        self.stub("nvidia-smi", '''
echo "smi $*" >> "$CALLS"
case "$1" in
  --query-gpu=uuid)
    i=0; while [ "$i" -lt "$GPU_COUNT" ]; do echo "GPU-$i"; i=$((i+1)); done
    exit "$QUERY_RC" ;;
  conf-compute)
    case "$2" in
      -f) echo " CC status: $CC_MODE" ;;
      -srs) exit "$READY_RC" ;;
      -grs) echo " Confidential Compute GPUs Ready state: $READY_STATE" ;;
      *) exit 90 ;;
    esac ;;
  *) exit 91 ;;
esac''')
        self.stub("nvattest", 'echo "verify $*" >> "$CALLS"; echo "{}"; exit "$VERIFY_RC"')
        self.stub("sleep", ':')
        self.stub("timeout", 'shift 2; exec "$@"')
        self.stub("openssl", 'echo key-generated >> "$CALLS"; echo test-only-key')
        self.stub("nginx", 'echo nginx-start >> "$CALLS"')

    def stub(self, name, body):
        p = self.bin / name
        p.write_text("#!/bin/sh\nset -eu\n" + body + "\n")
        p.chmod(0o755)

    def run_guest(self, name, **overrides):
        text = (ROOT / "guest" / name).read_text()
        text = text.replace("/run/ntrust-gpu", str(self.run))
        text = text.replace("/proc/swaps", str(self.swaps))
        text = text.replace("/run/ntrust-web", str(self.run))
        text = text.replace("/etc/ntrust/nginx.conf.template", str(ROOT / "guest/nginx.conf.template"))
        text = text.replace("/usr/sbin/nginx", str(self.bin / "nginx"))
        script = self.base / name
        script.write_text(text)
        return subprocess.run(["bash" if name == "gpu-ready" else "sh", str(script)],
                              env=dict(self.env, **overrides), capture_output=True, text=True)

    def calls(self):
        p = self.base / "calls"
        return p.read_text() if p.exists() else ""

    def test_untrusted_boot_never_enables_gpu(self):
        for overrides in ({"CVM": "none"}, {"CVM": "sev"}, {"GPU_COUNT": "0"},
                          {"GPU_COUNT": "2"}, {"CC_MODE": "OFF"},
                          {"CC_MODE": "DEVTOOLS"}, {"QUERY_RC": "1"},
                          {"VERIFY_RC": "1"}, {"VERIFY_RC": "139"}):
            with self.subTest(overrides=overrides):
                (self.base / "calls").write_text("")
                result = self.run_guest("gpu-ready", **overrides)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("-srs", self.calls())
                self.assertFalse((self.run / "api-key").exists())

    def test_verification_retry_is_bounded_and_discards_failed_evidence(self):
        self.assertNotEqual(self.run_guest("gpu-ready", VERIFY_RC="1").returncode, 0)
        self.assertEqual(self.calls().count("verify "), 3)
        self.assertFalse((self.run / "attestation.json").exists())
        self.assertNotIn("-srs", self.calls())

    def test_swap_prevents_startup(self):
        self.swaps.write_text(self.swaps.read_text() + "/swapfile file 1024 0 -2\n")
        self.assertNotEqual(self.run_guest("gpu-ready").returncode, 0)
        self.assertNotIn("verify", self.calls())

    def test_verification_precedes_ready_and_key_for_both_cpu_tees(self):
        for cvm in ("tdx", "sev-snp"):
            with self.subTest(cvm=cvm):
                (self.base / "calls").write_text("")
                key = self.run / "api-key"
                key.unlink(missing_ok=True)
                result = self.run_guest("gpu-ready", CVM=cvm)
                self.assertEqual(result.returncode, 0, result.stderr)
                calls = self.calls()
                self.assertLess(calls.index("verify"), calls.index("-srs 1"))
                self.assertLess(calls.index("-grs"), calls.index("key-generated"))
                self.assertIn("--gpu-evidence-source nvml --verifier local", calls)
                self.assertEqual(key.stat().st_mode & 0o777, 0o600)
                key.write_text("existing-key")
                self.assertEqual(self.run_guest("gpu-ready").returncode, 0)
                self.assertEqual(key.read_text(), "existing-key")

    def test_ready_failure_does_not_create_key(self):
        for overrides in ({"READY_RC": "1"}, {"READY_STATE": "not ready"}):
            with self.subTest(overrides=overrides):
                self.assertNotEqual(self.run_guest("gpu-ready", **overrides).returncode, 0)
                self.assertFalse((self.run / "api-key").exists())

    def test_nginx_config_injection_is_rejected_before_start(self):
        for overrides in ({"NTRUST_DOMAIN": "inference.example.com; include /etc/passwd;"},
                          {"NTRUST_DOMAIN": "inference.example.com\ninclude /etc/passwd"},
                          {"NTRUST_DOMAIN": "*.example.com"}, {"NTRUST_DOMAIN": ""},
                          {"NTRUST_EMAIL": "a@example.com; state_path /tmp;"},
                          {"NTRUST_EMAIL": "a@example.com\n"},
                          {"NTRUST_ACME_DIRECTORY": "http://evil.example/directory"}):
            with self.subTest(overrides=overrides):
                self.assertNotEqual(self.run_guest("https-start", **overrides).returncode, 0)
                self.assertNotIn("nginx-start", self.calls())

    @unittest.skipUnless(shutil.which("envsubst"), "gettext envsubst is required")
    def test_render_preserves_nginx_variables_and_memory_only_acme(self):
        result = self.run_guest("https-start")
        self.assertEqual(result.returncode, 0, result.stderr)
        conf = (self.run / "nginx.conf").read_text()
        self.assertIn("server_name inference.example.com;", conf)
        self.assertIn("$acme_certificate_key", conf)
        self.assertIn("$request_method", conf)
        self.assertNotIn("${NTRUST_", conf)
        self.assertIn("state_path off;", conf)
        self.assertIn("https://acme-v02.api.letsencrypt.org/directory;", conf)
        result = self.run_guest("https-start", NTRUST_ACME_DIRECTORY=
                                "https://acme-staging-v02.api.letsencrypt.org/directory")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("acme-staging-v02", (self.run / "nginx.conf").read_text())


if __name__ == "__main__":
    unittest.main()
