"""Catch stale archive hashes before an expensive image build starts."""
from pathlib import Path
import re
import unittest
from urllib.parse import parse_qs, urlsplit


class DependencyLock(unittest.TestCase):
    def test_every_pin_has_hashes_and_direct_url_hash_agrees(self):
        path = Path(__file__).resolve().parents[1] / 'image/requirements.lock'
        for entry in path.read_text().replace('\\\n', '').splitlines():
            if not entry.strip() or entry.startswith('#'):
                continue
            hashes = re.findall(r'--hash=sha256:([0-9a-f]{64})', entry)
            self.assertTrue(hashes, entry.split()[0])
            if ' @ ' in entry:
                url = entry.split(' @ ', 1)[1].split()[0]
                parsed = urlsplit(url)
                self.assertEqual(parsed.scheme, 'https')
                self.assertIn(parse_qs(parsed.fragment)['sha256'][0], hashes)
            else:
                self.assertIn('==', entry.split()[0])
