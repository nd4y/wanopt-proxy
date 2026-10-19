#!/usr/bin/env python3
"""Verify every packaged release asset against its exact source manifest."""
import argparse
import hashlib
import json
from pathlib import Path
import tarfile
import zipfile


def verify(root, source):
    manifest = json.loads((root / "manifest.json").read_text())
    if manifest["source_commit"] != source:
        raise ValueError("release source does not match expected source")
    for line in (root / "SHA256SUMS").read_text().splitlines():
        digest, name = line.split("  ", 1)
        if Path(name).name != name:
            raise ValueError("unsafe asset path")
        if hashlib.sha256((root / name).read_bytes()).hexdigest() != digest:
            raise ValueError(f"checksum mismatch: {name}")
    for package in manifest["packages"]:
        name = package["asset"]
        if Path(name).name != name or hashlib.sha256((root / name).read_bytes()).hexdigest() != package["sha256"]:
            raise ValueError("manifest package mismatch")
        archive_path = root / name
        if name.endswith(".zip"):
            with zipfile.ZipFile(archive_path) as archive:
                files = {item.filename: archive.read(item) for item in archive.infolist()}
        else:
            with tarfile.open(archive_path, "r:gz") as archive:
                if not all(item.isfile() for item in archive.getmembers()):
                    raise ValueError("non-regular archive member")
                files = {item.name: archive.extractfile(item).read() for item in archive.getmembers()}
        if any(Path(key).name != key for key in files):
            raise ValueError("unsafe archive member")
        actual = {key: hashlib.sha256(data).hexdigest() for key, data in files.items()}
        if actual != package["binaries"]:
            raise ValueError("packaged binary hashes do not match manifest")
    return manifest


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dir", type=Path, required=True)
    parser.add_argument("--source", required=True)
    args = parser.parse_args()
    result = verify(args.dir, args.source)
    print(f"Verified {result['version']}, source {result['source_commit']}, {len(result['packages'])} packages")
