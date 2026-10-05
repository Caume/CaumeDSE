#!/usr/bin/env python3
"""Whole-export migration contract; all keys and payloads are synthetic."""
import argparse
import base64
import hashlib
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import time
import unittest

parser = argparse.ArgumentParser()
parser.add_argument('--admin', required=True)
parser.add_argument('--fixture', required=True)
args, remaining = parser.parse_known_args() if __name__ == '__main__' else (argparse.Namespace(admin='./caumedse-admin', fixture='./reprotect-fixture'), [])
ADMIN = str(Path(args.admin).resolve())
FIXTURE = str(Path(args.fixture).resolve())
ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(Path(ADMIN).is_file() and Path(FIXTURE).is_file(), 'run through make check in a configured build')
class StorageTests(unittest.TestCase):
    def setUp(self):
        help_result = subprocess.run([ADMIN, 'reprotect-storage', '--help'], capture_output=True, text=True)
        if 'SQLite serialization support is required' in help_result.stderr:
            self.skipTest('SQLite serialization is unavailable in this build')
        self.temp = tempfile.TemporaryDirectory(prefix='cdse storage ')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / 'export'
        self.source.mkdir(mode=0o700)
        self.old = self.root / 'old.key'
        self.new = self.root / 'new.key'
        self.old.write_text('fixture-source-key\n')
        self.new.write_text('fixture-target-key\n')
        self.old.chmod(0o600)
        self.new.chmod(0o600)
        self.build()

    def build(self, profile='aes-256-gcm', shuffle=False, legacy=False, empty=False):
        for path in self.source.iterdir():
            path.unlink()
        for name in ('ResourcesDB', 'RolesDB', 'LogsDB'):
            with sqlite3.connect(ROOT / 'TEST/testDB_opt_cdse' / name) as original, sqlite3.connect(self.source / name) as target:
                if name == 'LogsDB':
                    target.execute('CREATE TABLE transactions (id INTEGER PRIMARY KEY,userId TEXT,orgId TEXT,salt TEXT,requestMethod TEXT,requestUrl TEXT,requestHeaders TEXT,startTimestamp TEXT,endTimestamp TEXT,requestDataSize TEXT,responseDataSize TEXT,orgResourceId TEXT,requestIPAddress TEXT,responseCode TEXT,responseHeaders TEXT,authenticated TEXT)')
                    target.execute('CREATE TABLE meta (id INTEGER PRIMARY KEY,userId TEXT,orgId TEXT,salt TEXT,initTimestamp TEXT,memorySizeBytes TEXT,operatingSystem TEXT,serverIpAddress TEXT,serverNetworkInfo TEXT,serverCPUInfo TEXT)')
                else:
                    for sql, in original.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name!='schema_meta'"):
                        target.execute(sql)
                if name == 'ResourcesDB':
                    for column in ('documentIdLookup', 'storageIdLookup', 'orgResourceIdLookup'):
                        target.execute(f'ALTER TABLE documents ADD COLUMN {column} TEXT')
                table = 'storage' if name == 'ResourcesDB' else 'documents' if name == 'RolesDB' else 'transactions'
                cols = [row[1] for row in target.execute(f'PRAGMA table_info({table})')]
                values = {column: '' for column in cols}
                values.update(id=1, userId='fixtureUser', orgId='fixtureOrg', orgResourceId='fixtureOrg')
                if name == 'ResourcesDB':
                    values.update(storageId='fixtureStorage', accessPath=str(self.source) + '/', type='local', accessPassword=None)
                elif name == 'LogsDB':
                    values['responseHeaders'] = None
                target.execute(f"INSERT INTO {table} ({','.join(cols)}) VALUES ({','.join('?' for _ in cols)})", [values[c] for c in cols])
                if name == 'ResourcesDB':
                    cols = [row[1] for row in target.execute('PRAGMA table_info(documents)')]
                    for index, (filename, kind) in enumerate((('column', 'file.csv'), ('rawpart', 'file.raw')), 1):
                        values = {column: '' for column in cols}
                        values.update(id=index, userId='fixtureUser', orgId='fixtureOrg', columnFile=filename,
                            type=kind, documentId=filename, storageId='fixtureStorage', orgResourceId='fixtureOrg',
                            totalParts='1', partId='1', columnId='1')
                        for column in cols:
                            if column.endswith('Lookup'):
                                values[column] = None
                        target.execute(f"INSERT INTO documents ({','.join(cols)}) VALUES ({','.join('?' for _ in cols)})", [values[c] for c in cols])
        env = dict(os.environ, CDSE_DEFAULT_ENC_ALG=profile)
        if legacy:
            env['CDSE_FIXTURE_LEGACY_RAW'] = '1'
            self.old.write_text('Password\n')
        subprocess.run([FIXTURE, str(self.source / 'column'), 'shuffle' if shuffle else 'empty' if empty else 'integrity'], env=env, capture_output=True, check=True)
        with sqlite3.connect(self.source / 'column') as column:
            column.execute('PRAGMA secure_delete=OFF')
            column.execute('CREATE TABLE retired_pages (payload TEXT)')
            column.execute('INSERT INTO retired_pages VALUES (?)', ('fixture-retired-ciphertext' * 4096,))
            column.execute('DROP TABLE retired_pages')
        self.assertIn(b'fixture-retired-ciphertext', (self.source / 'column').read_bytes())
        if legacy:
            frame = bytes.fromhex(
                '43445345484b583102000000000000000000000000000000000000000000000000000000000000000000'
                'd8c1ae718a13d602a293ee54a8b27e9fe441573f6215d4c317c74f8ecb0310cd'
                '22452ee29adc287bd70e9272a54807346dcfcbb330e4cc3779f849baed9f990b1fc54210f6e1e8f3bccfb99dc12ca35faeee40')
            (self.source / 'rawpart').write_bytes(base64.encodebytes(frame))
        else:
            (self.source / 'rawpart').write_bytes(b'raw\x00binary\xfffixture\n')
        subprocess.run([FIXTURE, str(self.source), 'bundle'], env=env, capture_output=True, check=True)
        self.fingerprint = self.hashes()

    def hashes(self):
        return {path.name: hashlib.sha256(path.read_bytes()).digest() for path in self.source.iterdir()}

    def command(self, *flags, root=None, old=None, new=None, source_profile='aes-256-gcm', target_profile='aes-256-gcm'):
        source = root or self.source
        result = subprocess.run([ADMIN, 'reprotect-storage', '--storage-root', str(source), '--confirmed-scope', str(source.resolve()),
            '--source-key-file', str(old or self.old), '--target-key-file', str(new or self.new),
            '--source-profile', source_profile, '--target-profile', target_profile, *flags], capture_output=True, text=True)
        for secret in ('fixture-source-key', 'fixture-target-key', 'fixtureUser', 'fixtureOrg', 'fixture-alpha', 'rawbinary'):
            self.assertNotIn(secret, result.stdout + result.stderr)
        self.assertEqual(self.hashes(), self.fingerprint)
        return result

    def test_dry_run_and_commit(self):
        self.assertEqual(self.command('--dry-run').returncode, 0)
        output = self.root / 'checkpoint'
        result = self.command('--commit', '--output-dir', str(output))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('payloadParts=2', result.stdout)
        self.assertEqual((output / 'status').read_text(), 'verified\nsource-unchanged\nwhole-export-verified\n')
        for name in ('ResourcesDB', 'RolesDB', 'LogsDB', 'column'):
            with sqlite3.connect(output / 'after' / name) as db:
                self.assertEqual(db.execute('PRAGMA freelist_count').fetchone()[0], 0)
            self.assertNotIn(b'fixture-retired-ciphertext', (output / 'after' / name).read_bytes())
        for directory in (output, output / 'before', output / 'after'):
            self.assertEqual(directory.stat().st_mode & 0o777, 0o700)
            for path in directory.iterdir():
                if path.is_file():
                    self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.command('--dry-run', root=output / 'after', old=self.new).returncode, 0)
        subprocess.run([FIXTURE, str(output / 'after'), 'verify-bundle'], check=True, capture_output=True)
        self.assertNotEqual(self.command('--dry-run', root=output / 'after').returncode, 0)
        self.assertNotEqual(self.command('--commit', '--output-dir', str(output)).returncode, 0)

    def test_resume_and_binding(self):
        output = self.root / 'checkpoint'
        self.assertEqual(self.command('--commit', '--output-dir', str(output)).returncode, 0)
        (output / 'status').unlink()
        for path in (output / 'after').iterdir():
            path.unlink()
        self.assertEqual(self.command('--resume', '--output-dir', str(output)).returncode, 0)
        self.assertNotEqual(self.command('--resume', '--output-dir', str(output), new=self.old).returncode, 0)
        self.assertNotEqual(self.command('--resume', '--output-dir', str(output), target_profile='aes-256-cbc').returncode, 0)
        (output / 'before' / 'rawpart').write_bytes(b'tampered')
        self.assertNotEqual(self.command('--resume', '--output-dir', str(output)).returncode, 0)
        self.assertFalse((output / 'status').exists())

    def test_interrupted_stage_resumes(self):
        output = self.root / 'interrupted'
        process = subprocess.Popen([ADMIN, 'reprotect-storage', '--storage-root', str(self.source),
            '--confirmed-scope', str(self.source.resolve()), '--source-key-file', str(self.old),
            '--target-key-file', str(self.new), '--source-profile', 'aes-256-gcm', '--target-profile', 'aes-256-gcm',
            '--commit', '--output-dir', str(output)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            deadline = time.monotonic() + 60
            while time.monotonic() < deadline and process.poll() is None:
                if (output / 'after' / 'column').exists():
                    process.kill()
                    break
                time.sleep(0.01)
            process.communicate(timeout=10)
            self.assertLess(process.returncode, 0)
            self.assertFalse((output / 'status').exists())
            self.assertEqual(self.hashes(), self.fingerprint)
            result = self.command('--resume', '--output-dir', str(output))
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            subprocess.run([FIXTURE, str(output / 'after'), 'verify-bundle'], check=True, capture_output=True)
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate()

    def test_scope_and_tamper_refusals(self):
        self.assertNotEqual(self.command('--commit', '--output-dir', str(self.source / 'nested')).returncode, 0)
        self.assertFalse((self.source / 'nested').exists())
        self.assertNotEqual(self.command('--dry-run', old=self.new).returncode, 0)
        for filename in ('rawpart', 'column', 'RolesDB', 'LogsDB'):
            original = (self.source / filename).read_bytes()
            (self.source / filename).write_bytes(b'corrupt')
            self.fingerprint = self.hashes()
            output = self.root / ('bad-' + filename)
            self.assertNotEqual(self.command('--commit', '--output-dir', str(output)).returncode, 0)
            self.assertFalse((output / 'status').exists())
            (self.source / filename).write_bytes(original)
            self.fingerprint = self.hashes()
        extra = self.source / 'unaccounted'
        extra.write_bytes(b'legacy-artifact')
        self.fingerprint = self.hashes()
        self.assertNotEqual(self.command('--dry-run').returncode, 0)
        extra.unlink()
        original = (self.source / 'rawpart').read_bytes()
        (self.source / 'rawpart').unlink()
        self.fingerprint = self.hashes()
        self.assertNotEqual(self.command('--dry-run').returncode, 0)
        (self.source / 'rawpart').write_bytes(original)
        self.fingerprint = self.hashes()
        with sqlite3.connect(self.source / 'ResourcesDB') as db:
            db.execute("UPDATE documents SET documentIdLookup='bad' WHERE id=1")
        self.fingerprint = self.hashes()
        self.assertNotEqual(self.command('--dry-run').returncode, 0)

    def test_cbc_shuffle_and_optional_nla1(self):
        self.build(shuffle=True)
        output = self.root / 'cbc'
        result = self.command('--commit', '--output-dir', str(output), target_profile='aes-256-cbc')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        subprocess.run([FIXTURE, str(output / 'after'), 'verify-bundle'],
            env=dict(os.environ, CDSE_DEFAULT_ENC_ALG='aes-256-cbc'), check=True, capture_output=True)
        result = self.command('--dry-run', root=output / 'after', old=self.new, source_profile='aes-256-cbc')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        output = self.root / 'nla1'
        enabled = subprocess.check_output([FIXTURE, str(self.source), 'nla1-provider'], text=True).strip() == '1'
        result = self.command('--commit', '--output-dir', str(output), target_profile='herradura-hske-nla1-aead-256')
        if not enabled:
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('unsafe scope, key files or profile', result.stderr + result.stdout)
            self.assertFalse(output.exists())
        else:
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(self.command('--dry-run', source_profile='herradura-hske-nla1-aead-256').returncode, 0)
            self.assertEqual(self.command('--dry-run', root=output / 'after', old=self.new, source_profile='herradura-hske-nla1-aead-256').returncode, 0)
            subprocess.run([FIXTURE, str(output / 'after'), 'verify-bundle'],
                env=dict(os.environ, CDSE_DEFAULT_ENC_ALG='herradura-hske-nla1-aead-256'), check=True, capture_output=True)

    def test_historical_duplex_gate(self):
        self.build(legacy=True)
        enabled = subprocess.check_output([FIXTURE, str(self.source), 'legacy-provider'], text=True).strip() == '1'
        output = self.root / 'legacy'
        result = self.command('--commit', '--output-dir', str(output))
        if enabled:
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn('herradura-hske-duplex-256=1', result.stdout)
            result = self.command('--dry-run', root=output / 'after', old=self.new)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn('herradura-hske-duplex-256=0', result.stdout)
        else:
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((output / 'status').exists())

    def test_empty_protected_cell(self):
        self.build(empty=True)
        output = self.root / 'empty'
        result = self.command('--commit', '--output-dir', str(output))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        result = self.command('--dry-run', root=output / 'after', old=self.new)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main(argv=[__file__, *remaining])
