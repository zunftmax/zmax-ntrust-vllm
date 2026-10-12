#!/usr/bin/env python3
"""Reject silently dropped requirements or re-enabled forbidden subsystems."""
import re
import sys
from pathlib import Path


def config(path):
    return dict(re.findall(r'^(CONFIG_\w+)=(.*)$', Path(path).read_text(), re.M))


required = config(Path(__file__).with_name('required.config'))
actual = config(sys.argv[1])
if len(sys.argv) > 2:
    definitions = set()
    sources = list(Path(sys.argv[2]).rglob('Kconfig*')) + [Path(__file__).with_name('Kconfig')]
    for source in sources:
        if source.is_file():
            definitions.update('CONFIG_' + name for name in re.findall(
                r'^\s*(?:menuconfig|config)\s+(\w+)', source.read_text(errors='replace'), re.M))
    unknown = required.keys() - definitions
    if unknown:
        raise SystemExit('Unknown Kconfig symbols: ' + ', '.join(sorted(unknown)))
errors = [f'{key}: required {value}, resolved {actual.get(key, "n")}'
          for key, value in required.items() if actual.get(key, 'n') != value]
if actual.get('CONFIG_MMU_NOTIFIER') != 'y':
    errors.append('NVIDIA UVM requires CONFIG_MMU_NOTIFIER=y')
for hardened, expected in (
    ('CONFIG_STACKPROTECTOR_STRONG', 'y'),
    ('CONFIG_FORTIFY_SOURCE', 'y'),
    ('CONFIG_HARDENED_USERCOPY_DEFAULT_ON', 'y'),
    ('CONFIG_INIT_STACK_ALL_ZERO', 'y'),
    ('CONFIG_INIT_ON_ALLOC_DEFAULT_ON', 'y'),
    ('CONFIG_INIT_ON_FREE_DEFAULT_ON', 'y'),
    ('CONFIG_ZERO_CALL_USED_REGS', 'y'),
    ('CONFIG_SLAB_FREELIST_HARDENED', 'y'),
    ('CONFIG_SLAB_MERGE_DEFAULT', 'n'),
    ('CONFIG_STRICT_KERNEL_RWX', 'y'),
    ('CONFIG_STRICT_MODULE_RWX', 'y'),
    ('CONFIG_MODULE_SIG_FORCE', 'y'),
    ('CONFIG_LOCK_DOWN_KERNEL_FORCE_INTEGRITY', 'y'),
    ('CONFIG_BPF_UNPRIV_DEFAULT_OFF', 'y'),
):
    if actual.get(hardened, 'n') != expected:
        errors.append(f'Hardening invariant failed: {hardened}={expected}')
if errors:
    raise SystemExit('\n'.join(errors))
print(f'PASS: {len(required)} explicit settings; '
      f'{sum(v == "y" for v in actual.values())} built-in symbols; '
      f'{sum(v == "m" for v in actual.values())} module symbols')
