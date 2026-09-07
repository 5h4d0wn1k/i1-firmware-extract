#!/usr/bin/env python3
"""Deterministic offline tests for I1 — firmware extractor."""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import firmware_extractor as i1
from firmware_extractor import (
    EntropyAnalyzer, FirmwareExtractor, HeaderDetector, build_fixture, run_demo)


FIXTURE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "fixtures")


class TestEntropyAnalyzer(unittest.TestCase):
    def test_empty_data_zero(self):
        self.assertEqual(EntropyAnalyzer.calculate(b""), 0.0)

    def test_constant_byte_zero(self):
        self.assertEqual(EntropyAnalyzer.calculate(b"\x41" * 1024), 0.0)

    def test_uniform_bytes_max(self):
        data = bytes(range(256)) * 16
        ent = EntropyAnalyzer.calculate(data)
        self.assertAlmostEqual(ent, 8.0, places=2)

    def test_block_entropy(self):
        blocks = EntropyAnalyzer.block_entropy(b"\x00" * 2000, block_size=1024)
        self.assertEqual(len(blocks), 2)
        self.assertEqual(blocks[0].offset, 0)
        self.assertEqual(blocks[1].length, 976)

    def test_high_entropy_regions(self):
        data = b"\x00" * 1024 + bytes(range(256)) * 4
        regions = EntropyAnalyzer.find_high_entropy_regions(data, block_size=1024, threshold=7.5)
        self.assertTrue(any(r.offset == 1024 for r in regions))


class TestFixtureBuild(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = os.path.join(FIXTURE_DIR, "lab-router.bin")
        build_fixture(cls.fixture)
        cls.extractor = FirmwareExtractor(cls.fixture)

    def test_fixture_is_regular_file(self):
        self.assertTrue(os.path.isfile(self.fixture))

    def test_uimage_detected(self):
        headers = self.extractor.detect_headers()
        self.assertIsNotNone(headers["uimage"])
        self.assertEqual(headers["uimage"]["magic"], "0x27051956")

    def test_gzip_signature_present(self):
        sigs = [d for _, d in self.extractor.detect_headers()["signatures"]]
        self.assertTrue(any("Gzip" in d for d in sigs))

    def test_basic_info(self):
        info = self.extractor.get_basic_info()
        self.assertEqual(len(info["md5"]), 32)
        self.assertEqual(len(info["sha256"]), 64)
        self.assertLess(info["entropy"], 8.1)

    def test_strings_contain_markers(self):
        strings = self.extractor.scan_strings()
        joined = "\n".join(strings)
        self.assertIn("admin", joined)
        self.assertIn("openwrt", joined)
        self.assertIn("192.0.2.1", joined)

    def test_extract_filesystem_skips_null(self):
        with tempfile.TemporaryDirectory() as tmp:
            entries = self.extractor.extract_filesystem(tmp)
            self.assertGreaterEqual(len(entries), 2)
            for e in entries:
                self.assertNotEqual(e.file_type, "null")
                self.assertTrue(os.path.exists(e.path))

    def test_extract_compressed_gzip(self):
        with tempfile.TemporaryDirectory() as tmp:
            entries = self.extractor.extract_compressed(tmp)
            gzips = [e for e in entries if e.file_type == "gzip"]
            self.assertGreaterEqual(len(gzips), 1)


class TestDemo(unittest.TestCase):
    def test_demo_exits_zero_with_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            rc = run_demo(os.path.join(tmp, "reports"))
            self.assertEqual(rc, 0)
            report = os.path.join(tmp, "reports", "i1_demo_report.json")
            self.assertTrue(os.path.exists(report))
            with open(report) as f:
                data = json.load(f)
            self.assertEqual(data["info"]["filename"], "lab-router.bin")
            self.assertGreaterEqual(data["extracted"], 2)
            self.assertGreaterEqual(data["strings_count"], 1)


if __name__ == "__main__":
    unittest.main()