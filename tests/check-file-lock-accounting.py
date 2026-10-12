#!/usr/bin/python3
"""Bounded synthetic check: POSIX lock objects must be charged to this cgroup."""
import fcntl
from pathlib import Path
import tempfile
import time

group = next(line.removeprefix('0::') for line in Path('/proc/self/cgroup').read_text().splitlines()
             if line.startswith('0::'))
stat = Path('/sys/fs/cgroup' + group) / 'memory.stat'


def slab_bytes():
    return int(dict(line.split() for line in stat.read_text().splitlines())['slab_unreclaimable'])


locks = 65536
with tempfile.TemporaryFile(dir='/run/ntrust-lock-check') as file:
    before = slab_bytes()
    # Descending disjoint ranges avoid quadratic insertion and lock merging.
    # Locks past EOF allocate no file data; the 96 MiB cgroup bounds this test.
    for position in range(locks, 0, -1):
        fcntl.lockf(file, fcntl.LOCK_EX | fcntl.LOCK_NB, 1, position * 2)
    for _ in range(30):
        delta = slab_bytes() - before
        if delta >= locks * 32:
            break
        time.sleep(0.1)
    assert delta >= locks * 32, f'File locks escaped cgroup accounting: {delta} bytes'
    print(f'PASS: {locks} POSIX locks charged {delta} slab bytes to the bounded test cgroup')
