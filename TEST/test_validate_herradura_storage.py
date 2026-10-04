#!/usr/bin/env python3
"""Regressions for Herradura at-rest artifact inspection."""

import base64
import contextlib
import io
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from validate_herradura_storage import frame_profile, inspect_storage, main


class StorageTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.engine = Path(self.tmp.name) / "engine"
        self.storage = Path(self.tmp.name) / "storage"
        self.engine.mkdir()
        self.storage.mkdir()
        self.frame = base64.encodebytes(b"CDSEHKX1\x01\0" + bytes(64) + b"ciphertext").decode()

    def create_db(self, path, value):
        with contextlib.closing(sqlite3.connect(path)) as db:
            db.execute('CREATE TABLE "stored" (value TEXT)')
            db.execute('INSERT INTO stored VALUES (?)', (value,))
            db.commit()

    def test_wrapped_base64_and_mac_prefix(self):
        self.assertEqual(frame_profile(self.frame), 1)
        self.assertEqual(frame_profile("a" * 64 + self.frame), 1)

    def test_installed_inputs_are_excluded(self):
        fixtures = self.engine / "testfiles"
        fixtures.mkdir()
        (fixtures / "input.csv").write_text("Jacob,Nieves,82400,")
        binaries = self.engine / "bin"
        binaries.mkdir()
        (binaries / "CaumeDSE").write_text("Jacob,Nieves,82400,")
        self.create_db(self.engine / "ResourcesDB", "a" * 64 + self.frame)
        self.create_db(self.storage / "random-name", self.frame)
        count, profiles, failures = inspect_storage(self.engine, self.storage)
        self.assertEqual((count, profiles, failures), (2, {1: 2}, []))

    def test_plaintext_sqlite_canary_fails(self):
        self.create_db(self.storage / "column", "82400")
        self.assertTrue(any("plaintext canary" in f for f in inspect_storage(self.engine, self.storage)[2]))

    def test_plaintext_raw_csv_canary_fails(self):
        (self.storage / "part").write_text("Jacob,Nieves,82400,")
        self.assertTrue(any("plaintext CSV canary" in f for f in inspect_storage(self.engine, self.storage)[2]))

    def test_salt_and_mac_do_not_hide_plaintext(self):
        for prefix in (32, 64, 96):
            with self.subTest(prefix=prefix):
                self.create_db(self.storage / f"salted-{prefix}", "a" * prefix + "Jacob")
        self.assertEqual(sum("plaintext canary" in f for f in inspect_storage(self.engine, self.storage)[2]), 3)

    def test_engine_frames_cannot_mask_unprotected_target(self):
        self.create_db(self.engine / "ResourcesDB", self.frame)
        self.assertTrue(any("target storage" in f for f in inspect_storage(self.engine, self.storage)[2]))

    def test_raw_protected_part_is_counted(self):
        (self.storage / "part").write_text(self.frame)
        self.assertEqual(inspect_storage(self.engine, self.storage)[1], {1: 1})

    def test_missing_frames_fail(self):
        with patch.object(sys, "argv", ["validator", "--engine-dir", str(self.engine),
                                       "--storage-dir", str(self.storage)]):
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(), 1)


if __name__ == "__main__":
    unittest.main()
