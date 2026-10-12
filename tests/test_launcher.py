"""Test credential handling at the actual exec boundary; no GPU simulation claim."""
import os
from pathlib import Path
import runpy
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


class Launcher(unittest.TestCase):
    def run_launcher(self, key):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        base = Path(temp.name)
        (base / 'api-key').write_text(key)
        source = (ROOT / 'guest/inference-start').read_text()
        source = source.replace('/run/ntrust-inference/server.yaml', str(base / 'server.yaml'))
        script = base / 'launcher.py'
        script.write_text(source)
        old_umask = os.umask(0o077)
        self.addCleanup(os.umask, old_umask)
        with patch.dict(os.environ, CREDENTIALS_DIRECTORY=str(base)), patch('os.execv') as launch:
            runpy.run_path(str(script), run_name='__main__')
            args = launch.call_args.args[1]
            self.assertNotIn(key, ' '.join(args))
            self.assertIn('127.0.0.1', args)
            self.assertNotIn('--trust-remote-code', args)
            if (base / 'server.yaml').exists():
                self.assertEqual((base / 'server.yaml').stat().st_mode & 0o777, 0o600)
                self.assertIn(key, (base / 'server.yaml').read_text())
            else:
                self.assertEqual(os.environ['VLLM_API_KEY'], key)

    def test_key_is_private_and_absent_from_argv(self):
        self.run_launcher('a' * 64)

    def test_malformed_key_cannot_start_server(self):
        for value in ('', 'a' * 63, 'g' * 64, 'a' * 64 + '\nattack'):
            with self.subTest(value=value), self.assertRaises(SystemExit):
                self.run_launcher(value)
