"""Verify OS sysctl, sshd, and systemd service sandboxing hardening."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class OsHardeningTests(unittest.TestCase):
    def test_install_sets_hardened_sysctls(self):
        install = (ROOT / "image" / "install.sh").read_text()
        for expected in (
            "kernel.dmesg_restrict=1",
            "kernel.kptr_restrict=2",
            "kernel.unprivileged_bpf_disabled=1",
            "kernel.perf_event_paranoid=3",
            "kernel.yama.ptrace_scope=3",
            "kernel.sysrq=0",
            "dev.tty.ldisc_autoload=0",
            "fs.suid_dumpable=0",
            "fs.protected_hardlinks=1",
            "fs.protected_symlinks=1",
            "fs.protected_fifos=2",
            "fs.protected_regular=2",
            "net.ipv4.tcp_syncookies=1",
            "net.ipv4.conf.all.accept_redirects=0",
            "net.ipv4.conf.all.send_redirects=0",
            "net.ipv4.conf.all.accept_source_route=0",
            "net.ipv4.conf.all.rp_filter=1",
        ):
            self.assertIn(expected, install)

    def test_finalize_hardens_sshd(self):
        finalize = (ROOT / "image" / "finalize.sh").read_text()
        for directive in (
            "PermitRootLogin no",
            "PasswordAuthentication no",
            "KbdInteractiveAuthentication no",
            "PermitEmptyPasswords no",
            "X11Forwarding no",
            "AllowTcpForwarding no",
            "AllowAgentForwarding no",
            "PermitTunnel no",
            "GatewayPorts no",
            "MaxAuthTries 3",
        ):
            self.assertIn(directive, finalize)

    def test_systemd_units_enforce_sandboxing(self):
        for w_x_unit in ("ntrust-https.service", "ntrust-attest.service"):
            unit_text = (ROOT / "guest" / "systemd" / w_x_unit).read_text()
            self.assertIn("MemoryDenyWriteExecute=yes", unit_text)
        for name in (
            "ntrust-gpu.service",
            "ntrust-attest.service",
            "ntrust-inference.service",
            "ntrust-https.service",
        ):
            unit = (ROOT / "guest" / "systemd" / name).read_text()
            for directive in (
                "NoNewPrivileges=yes",
                "ProtectSystem=strict",
                "ProtectHome=yes",
                "ProtectControlGroups=yes",
                "ProtectKernelTunables=yes",
                "ProtectClock=yes",
                "ProtectHostname=yes",
                "RestrictSUIDSGID=yes",
                "RestrictNamespaces=yes",
                "LockPersonality=yes",
                "MemorySwapMax=0",
            ):
                self.assertIn(directive, unit, f"{name} missing {directive}")


if __name__ == "__main__":
    unittest.main()
