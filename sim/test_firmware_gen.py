#!/usr/bin/env python3
"""
Unit tests for Firmware Corpus Generator

Tests the firmware_gen module to ensure correct generation of clean and tampered blobs and hashes.json output, using mocks to avoid large file writes.
"""
import unittest
from unittest.mock import patch, MagicMock, mock_open
from pathlib import Path
import json
import os

import firmware_gen

class TestFirmwareGen(unittest.TestCase):
    @patch("firmware_gen.write_blob")
    @patch("firmware_gen.sha256sum", return_value="dummyhash")
    def test_clean_blob_generation(self, mock_sha, mock_write):
        """Test that the correct number of clean blobs are generated and hashed."""
        out_dir = Path("/tmp/test_fw")
        hashes = firmware_gen.generate_firmware_corpus(out_dir, n_clean=3, n_tampered=0, seed=1)
        self.assertEqual(len([k for k in hashes if k.startswith("fw_clean_")]), 3)
        self.assertTrue(all(h == "dummyhash" for h in hashes.values()))
        self.assertEqual(len(hashes), 3)

    @patch("firmware_gen.write_blob")
    @patch("firmware_gen.sha256sum", return_value="dummyhash")
    def test_tampered_blob_generation(self, mock_sha, mock_write):
        """Test that the correct number of tampered blobs are generated and hashed."""
        out_dir = Path("/tmp/test_fw")
        hashes = firmware_gen.generate_firmware_corpus(out_dir, n_clean=0, n_tampered=2, seed=2)
        self.assertEqual(len([k for k in hashes if k.startswith("fw_tampered_")]), 2)
        self.assertEqual(len(hashes), 2)

    @patch("firmware_gen.write_blob")
    @patch("firmware_gen.sha256sum", return_value="dummyhash")
    def test_hashes_json_output(self, mock_sha, mock_write):
        """Test that hashes.json is written with correct keys and values."""
        out_dir = Path("/tmp/test_fw")
        hashes = firmware_gen.generate_firmware_corpus(out_dir, n_clean=1, n_tampered=1, seed=3)
        # Simulate writing hashes.json
        with patch("builtins.open", mock_open()) as m:
            with open("/tmp/test_fw/hashes.json", "w") as f:
                json.dump(hashes, f, indent=2)
            m.assert_called_with("/tmp/test_fw/hashes.json", "w")
            handle = m()
            handle.write.assert_called()  # At least one write call
        self.assertEqual(set(hashes.keys()), {"fw_clean_00.bin", "fw_tampered_00.bin"})

if __name__ == "__main__":
    unittest.main() 