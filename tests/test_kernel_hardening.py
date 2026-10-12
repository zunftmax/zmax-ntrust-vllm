"""Verify compiler and kernel hardening requirements and check-config.py enforcement."""
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
REQUIRED = ROOT / "kernel" / "required.config"
CHECK_CONFIG = ROOT / "kernel" / "check-config.py"


class KernelHardeningTests(unittest.TestCase):
    def test_required_config_contains_compiler_and_kernel_hardening(self):
        cfg = dict(re.findall(r"^(CONFIG_\w+)=(.*)$", REQUIRED.read_text(), re.M))
        expected = {
            "CONFIG_STACKPROTECTOR": "y",
            "CONFIG_STACKPROTECTOR_STRONG": "y",
            "CONFIG_VMAP_STACK": "y",
            "CONFIG_STRICT_KERNEL_RWX": "y",
            "CONFIG_STRICT_MODULE_RWX": "y",
            "CONFIG_HARDENED_USERCOPY": "y",
            "CONFIG_HARDENED_USERCOPY_DEFAULT_ON": "y",
            "CONFIG_FORTIFY_SOURCE": "y",
            "CONFIG_INIT_STACK_ALL_ZERO": "y",
            "CONFIG_INIT_ON_ALLOC_DEFAULT_ON": "y",
            "CONFIG_INIT_ON_FREE_DEFAULT_ON": "y",
            "CONFIG_ZERO_CALL_USED_REGS": "y",
            "CONFIG_SLAB_MERGE_DEFAULT": "n",
            "CONFIG_SLAB_FREELIST_RANDOM": "y",
            "CONFIG_SLAB_FREELIST_HARDENED": "y",
            "CONFIG_SLAB_BUCKETS": "y",
            "CONFIG_SHUFFLE_PAGE_ALLOCATOR": "y",
            "CONFIG_LIST_HARDENED": "y",
            "CONFIG_SCHED_STACK_END_CHECK": "y",
            "CONFIG_STRICT_SIGALTSTACK_SIZE": "y",
            "CONFIG_X86_USER_SHADOW_STACK": "y",
            "CONFIG_X86_INTEL_TSX_MODE_OFF": "y",
            "CONFIG_RANDOMIZE_BASE": "y",
            "CONFIG_RANDOMIZE_MEMORY": "y",
            "CONFIG_RANDOMIZE_KSTACK_OFFSET_DEFAULT": "y",
            "CONFIG_MODULE_SIG_FORCE": "y",
            "CONFIG_LOCK_DOWN_KERNEL_FORCE_INTEGRITY": "y",
            "CONFIG_BPF_UNPRIV_DEFAULT_OFF": "y",
            "CONFIG_SYN_COOKIES": "y",
            "CONFIG_RESET_ATTACK_MITIGATION": "y",
            "CONFIG_MITIGATION_PAGE_TABLE_ISOLATION": "y",
            "CONFIG_MITIGATION_RETPOLINE": "y",
            "CONFIG_MITIGATION_TSA": "y",
            "CONFIG_KPROBES": "n",
            "CONFIG_UPROBES": "n",
            "CONFIG_KALLSYMS_ALL": "n",
            "CONFIG_PROC_KCORE": "n",
            "CONFIG_LEGACY_TIOCSTI": "n",
            "CONFIG_LEGACY_PTYS": "n",
            "CONFIG_LDISC_AUTOLOAD": "n",
            "CONFIG_USERFAULTFD": "n",
            "CONFIG_COMPAT_BRK": "n",
            "CONFIG_MODIFY_LDT_SYSCALL": "n",
        }
        for key, val in expected.items():
            self.assertEqual(cfg.get(key), val, f"{key} should be {val}")

    def test_check_config_accepts_valid_and_rejects_weakened_config(self):
        req_lines = [
            line for line in REQUIRED.read_text().splitlines()
            if line.startswith("CONFIG_") and not line.endswith("=n")
        ]
        req_lines.append("CONFIG_MMU_NOTIFIER=y")
        with tempfile.TemporaryDirectory() as tmp:
            resolved = Path(tmp) / ".config"
            resolved.write_text("\n".join(req_lines) + "\n")
            ok = subprocess.run(
                [sys.executable, str(CHECK_CONFIG), str(resolved)],
                capture_output=True,
                text=True,
            )
            self.assertEqual(ok.returncode, 0, ok.stderr)

            weakened = Path(tmp) / "weak.config"
            weakened.write_text(
                "\n".join(
                    line for line in req_lines
                    if not line.startswith("CONFIG_ZERO_CALL_USED_REGS=")
                )
                + "\nCONFIG_USERFAULTFD=y\n"
            )
            bad = subprocess.run(
                [sys.executable, str(CHECK_CONFIG), str(weakened)],
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(bad.returncode, 0)
            self.assertIn("CONFIG_ZERO_CALL_USED_REGS", bad.stderr)
            self.assertIn("CONFIG_USERFAULTFD", bad.stderr)


if __name__ == "__main__":
    unittest.main()
