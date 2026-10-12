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
                r'^(?:menuconfig|config)\s+(\w+)', source.read_text(errors='replace'), re.M))
    unknown = required.keys() - definitions
    if unknown:
        raise SystemExit('Unknown Kconfig symbols: ' + ', '.join(sorted(unknown)))
errors = [f'{key}: required {value}, resolved {actual.get(key, "n")}'
          for key, value in required.items() if actual.get(key, 'n') != value]
if actual.get('CONFIG_MMU_NOTIFIER') != 'y':
    errors.append('NVIDIA UVM requires CONFIG_MMU_NOTIFIER=y')
if errors:
    raise SystemExit('\n'.join(errors))
print(f'PASS: {len(required)} explicit settings; '
      f'{sum(v == "y" for v in actual.values())} built-in symbols; '
      f'{sum(v == "m" for v in actual.values())} module symbols')
