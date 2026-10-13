#!/usr/bin/env python3
"""Validate an independently approved exact Rust uq release record and binary."""
import hashlib
import json
from pathlib import Path
import re
import sys

FIELDS = {"release_tag", "source_sha", "binary_sha256", "target"}


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate release field: " + key)
        result[key] = value
    return result


def load_release(path: Path) -> dict:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 4096:
        raise ValueError("approved uq release JSON is missing, linked or oversized")
    record = json.loads(path.read_text(), object_pairs_hook=unique_object)
    if not isinstance(record, dict) or set(record) != FIELDS or any(not isinstance(v, str) for v in record.values()):
        raise ValueError("release record requires exactly release_tag, source_sha, binary_sha256 and target")
    if not re.fullmatch(r"v[0-9][0-9A-Za-z.-]*", record["release_tag"]):
        raise ValueError("release_tag must identify one exact version")
    for name, count in (("source_sha", 40), ("binary_sha256", 64)):
        if not re.fullmatch(r"[0-9a-f]{" + str(count) + r"}", record[name]) or record[name] == "0" * count:
            raise ValueError(name + " must contain an independently approved nonzero lowercase hex pin")
    if record["target"] != "x86_64-unknown-linux-gnu":
        raise ValueError("this image requires the x86_64-unknown-linux-gnu release")
    return record


def check_binary(record: dict, binary: Path) -> None:
    if binary.is_symlink() or not binary.is_file() or not 0 < binary.stat().st_size <= 512 * 1024 * 1024:
        raise ValueError("uq binary is missing, linked or oversized")
    with binary.open("rb") as stream:
        header = stream.read(20)
        # ELF64, little endian, x86-64. This is a packaging check, not execution.
        if len(header) != 20 or header[:7] != b"\x7fELF\x02\x01\x01" or header[18:20] != b"\x3e\x00":
            raise ValueError("uq binary is not an x86-64 Linux ELF")
        stream.seek(0)
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    if digest != record["binary_sha256"]:
        raise ValueError("uq binary differs from the independently approved SHA-256")


def main():
    if len(sys.argv) not in (2, 3):
        raise ValueError("usage: uq-release.py <approved-release.json> [uq-binary]")
    record = load_release(Path(sys.argv[1]))
    if len(sys.argv) == 3:
        check_binary(record, Path(sys.argv[2]))
    print(json.dumps(record, sort_keys=True, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError) as error:
        print("uq release configuration: " + str(error), file=sys.stderr)
        raise SystemExit(1)
