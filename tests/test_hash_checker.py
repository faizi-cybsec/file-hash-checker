"""Unit tests for hash_checker (stdlib unittest, no external deps)."""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import hash_checker as hc

# Known test vectors for the content b"abc".
ABC_MD5 = "900150983cd24fb0d6963f7d28e17f72"
ABC_SHA1 = "a9993e364706816aba3e25717850c26c9cd0d89d"
ABC_SHA256 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


class HashFileTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def _write(self, name, data: bytes) -> Path:
        path = self.dir / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def test_known_vectors(self):
        f = self._write("a.txt", b"abc")
        hashes = hc.hash_file(f, ("md5", "sha1", "sha256"))
        self.assertEqual(hashes["md5"], ABC_MD5)
        self.assertEqual(hashes["sha1"], ABC_SHA1)
        self.assertEqual(hashes["sha256"], ABC_SHA256)

    def test_empty_file(self):
        f = self._write("empty.bin", b"")
        self.assertEqual(hc.hash_file(f, ("sha256",))["sha256"], EMPTY_SHA256)

    def test_large_file_chunked(self):
        data = b"A" * (hc.CHUNK_SIZE * 2 + 123)
        f = self._write("big.bin", data)
        import hashlib
        self.assertEqual(hc.hash_file(f, ("sha256",))["sha256"],
                         hashlib.sha256(data).hexdigest())

    def test_detect_algorithm(self):
        self.assertEqual(hc.detect_algorithm(ABC_MD5), "md5")
        self.assertEqual(hc.detect_algorithm(ABC_SHA1), "sha1")
        self.assertEqual(hc.detect_algorithm(ABC_SHA256), "sha256")
        self.assertIsNone(hc.detect_algorithm("xyz"))


class ManifestTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "watch"
        self.root.mkdir()
        (self.root / "one.txt").write_bytes(b"one")
        (self.root / "sub").mkdir()
        (self.root / "sub" / "two.txt").write_bytes(b"two")

    def tearDown(self):
        self.tmp.cleanup()

    def test_baseline_then_clean_check(self):
        manifest = hc.build_manifest(self.root)
        self.assertEqual(len(manifest["files"]), 2)
        result = hc.check_manifest(manifest)
        self.assertEqual(len(result["ok"]), 2)
        self.assertFalse(result["modified"] or result["missing"] or result["new"])

    def test_check_detects_modified_missing_new(self):
        manifest = hc.build_manifest(self.root)
        (self.root / "one.txt").write_bytes(b"tampered")
        (self.root / "sub" / "two.txt").unlink()
        (self.root / "three.txt").write_bytes(b"three")
        result = hc.check_manifest(manifest)
        self.assertEqual(result["modified"], ["one.txt"])
        self.assertEqual(result["missing"], [str(Path("sub") / "two.txt")])
        self.assertEqual(result["new"], ["three.txt"])


class BlocklistTests(unittest.TestCase):
    def test_load_and_hit(self):
        with tempfile.TemporaryDirectory() as tmp:
            bl = Path(tmp) / "bad.txt"
            bl.write_text(f"# known bad\n{ABC_SHA256}\n\n", encoding="utf-8")
            blocklist = hc.load_blocklist(bl)
            self.assertIn(ABC_SHA256, blocklist)
            self.assertEqual(hc.blocklist_hit({"sha256": ABC_SHA256}, blocklist), "sha256")
            self.assertIsNone(hc.blocklist_hit({"sha256": EMPTY_SHA256}, blocklist))


class CliTests(unittest.TestCase):
    def test_verify_match_and_mismatch_exit_codes(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "a.txt"
            f.write_bytes(b"abc")
            self.assertEqual(hc.main([str(f), "--verify", ABC_SHA256]), 0)
            self.assertEqual(hc.main([str(f), "--verify", EMPTY_SHA256]), 1)

    def test_baseline_and_check_via_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "data"
            root.mkdir()
            (root / "x.txt").write_bytes(b"x")
            manifest = Path(tmp) / "baseline.json"
            self.assertEqual(hc.main([str(root), "--baseline", str(manifest)]), 0)
            saved = json.loads(manifest.read_text(encoding="utf-8"))
            self.assertEqual(len(saved["files"]), 1)
            self.assertEqual(hc.main(["--check", str(manifest)]), 0)
            (root / "x.txt").write_bytes(b"changed")
            self.assertEqual(hc.main(["--check", str(manifest)]), 1)


if __name__ == "__main__":
    unittest.main()
