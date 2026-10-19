import hashlib
import json
from pathlib import Path
import tempfile
import unittest
import zipfile
from verify_assets import verify


class ReleaseAssets(unittest.TestCase):
    def fixture(self, root, member="wanopt-client.exe"):
        target = root / "release.zip"
        with zipfile.ZipFile(target, "w") as archive:
            archive.writestr(member, b"test executable content")
        digest = hashlib.sha256(target.read_bytes()).hexdigest()
        manifest = {"version": "v0.0.0", "source_commit": "expected", "packages": [
            {"asset": target.name, "sha256": digest,
             "binaries": {member: hashlib.sha256(b"test executable content").hexdigest()}}]}
        (root / "manifest.json").write_text(json.dumps(manifest))
        (root / "SHA256SUMS").write_text(f"{digest}  release.zip\n")

    def test_exact_asset_and_binary_hashes(self):
        with tempfile.TemporaryDirectory() as directory:
            self.fixture(Path(directory))
            self.assertEqual(verify(Path(directory), "expected")["source_commit"], "expected")

    def test_wrong_source_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            self.fixture(Path(directory))
            with self.assertRaises(ValueError):
                verify(Path(directory), "different")

    def test_corrupt_asset_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root)
            with (root / "release.zip").open("ab") as f:
                f.write(b"unexpected content")
            with self.assertRaises(ValueError):
                verify(root, "expected")

    def test_unsafe_archive_member_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root, "../outside.exe")
            with self.assertRaises(ValueError):
                verify(root, "expected")
