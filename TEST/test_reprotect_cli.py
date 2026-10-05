#!/usr/bin/env python3
"""Installed command contract with synthetic encrypted ColumnFiles."""
import argparse
import hashlib
import importlib.util
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import unittest

parser = argparse.ArgumentParser()
parser.add_argument('--admin', required=True)
parser.add_argument('--fixture', required=True)
args, remaining = parser.parse_known_args() if __name__ == '__main__' else (argparse.Namespace(admin='./caumedse-admin', fixture='./reprotect-fixture'), [])
ADMIN = str(Path(args.admin).resolve())
FIXTURE = str(Path(args.fixture).resolve())
if __name__ == '__main__' and (not Path(ADMIN).is_file() or not Path(FIXTURE).is_file()):
    parser.error('admin and fixture binaries must exist')


@unittest.skipUnless(Path(ADMIN).is_file() and Path(FIXTURE).is_file(), 'run through make check in a configured build')
class CommandTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='cdse reprotect ')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.db = self.root / 'column.sqlite'
        self.source = self.root / 'source.key'
        self.target = self.root / 'target.key'
        self.source.write_text('fixture-source-key\n')
        self.target.write_text('fixture-target-key\n')
        self.source.chmod(0o600)
        self.target.chmod(0o600)
        self.make_fixture()
        self.original = hashlib.sha256(self.db.read_bytes()).digest()

    def make_fixture(self, kind='normal'):
        self.db.unlink(missing_ok=True)
        subprocess.run([FIXTURE, str(self.db), kind], check=True, capture_output=True)

    def command(self, *extra, source=None, target=None, db=None, profile='aes-256-gcm', scope=None):
        database = db or self.db
        return subprocess.run([ADMIN, 'reprotect-columnfile', '--database', str(database),
            '--confirmed-scope', scope or str(database.resolve()),
            '--source-key-file', str(source or self.source), '--target-key-file', str(target or self.target),
            '--target-profile', profile, *extra], capture_output=True, text=True)

    def assert_clean(self, result):
        combined = result.stdout + result.stderr
        for secret in ('fixture-source-key', 'fixture-target-key', 'fixture-alpha', 'fixture-beta', 'fixtureUser'):
            self.assertNotIn(secret, combined)
        self.assertEqual(hashlib.sha256(self.db.read_bytes()).digest(), self.original)

    def test_dry_run(self):
        result = self.command('--dry-run')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('dataRows=2 metaRows=2 protectedValueRows=2', result.stdout)
        self.assertEqual(len(list(self.root.iterdir())), 3)
        self.assert_clean(result)

    def test_commit_and_persisted_readback(self):
        output = self.root / 'checkpoint'
        result = self.command('--commit', '--output-dir', str(output))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(output.stat().st_mode & 0o777, 0o700)
        for name in ('before.sqlite', 'after.sqlite', 'status'):
            self.assertEqual((output / name).stat().st_mode & 0o777, 0o600)
        self.assertTrue((output / 'status').read_text().startswith('verified\n'))
        self.assert_clean(result)
        result = self.command('--dry-run', db=output / 'after.sqlite', source=self.target)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        result = self.command('--dry-run', db=output / 'after.sqlite')
        self.assertNotEqual(result.returncode, 0)
        result = self.command('--commit', '--output-dir', str(output))
        self.assertNotEqual(result.returncode, 0)

    def test_wrong_key_and_corrupt_data(self):
        result = self.command('--commit', '--output-dir', str(self.root / 'checkpoint'), source=self.target)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / 'checkpoint').exists())
        self.assert_clean(result)
        with sqlite3.connect(self.db) as db:
            db.execute("UPDATE data SET value='not-ciphertext' WHERE id=2")
        original = self.db.read_bytes()
        result = self.command('--dry-run')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.db.read_bytes(), original)

    def test_key_file_protection(self):
        self.source.chmod(0o644)
        self.assertNotEqual(self.command('--dry-run').returncode, 0)
        self.source.chmod(0o600)
        link = self.root / 'link.key'
        link.symlink_to(self.source)
        self.assertNotEqual(self.command('--dry-run', source=link).returncode, 0)
        fifo = self.root / 'fifo.key'
        os.mkfifo(fifo)
        self.assertNotEqual(self.command('--dry-run', source=fifo).returncode, 0)
        self.source.write_bytes(b'')
        self.assertNotEqual(self.command('--dry-run').returncode, 0)

    def test_scope_modes_and_profiles(self):
        for flags in ((), ('--commit',), ('--dry-run', '--commit'), ('--dry-run', '--unknown')):
            self.assertNotEqual(self.command(*flags).returncode, 0)
        self.assertNotEqual(self.command('--dry-run', scope='storage:anything').returncode, 0)
        for profile in ('unknown', 'herradura-hske-duplex-256', 'herradura-hske-nla2-aead-256'):
            self.assertNotEqual(self.command('--dry-run', profile=profile).returncode, 0)
        self.assertEqual(self.command('--dry-run', profile='aes-256-cbc').returncode, 0)

    def test_shuffle_refused(self):
        for kind in ('shuffle',):
            self.make_fixture(kind)
            before = self.db.read_bytes()
            result = self.command('--commit', '--output-dir', str(self.root / kind))
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((self.root / kind).exists())
            self.assertEqual(self.db.read_bytes(), before)

    def test_integrity_rotation_and_tampering(self):
        for kind in ('mac', 'integrity'):
            self.make_fixture(kind)
            before = self.db.read_bytes()
            self.assertEqual(self.command('--dry-run').returncode, 0)
            for profile in ('aes-256-gcm', 'aes-256-cbc', 'herradura-hske-nla1-aead-256'):
                output = self.root / (kind + profile)
                result = self.command('--commit', '--output-dir', str(output), profile=profile)
                if profile.startswith('herradura') and result.returncode:
                    self.assertIn('unavailable target profile', result.stdout)
                    continue
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(self.db.read_bytes(), before)
                staged = output / 'after.sqlite'
                self.assertEqual(self.command('--dry-run', db=staged, source=self.target).returncode, 0)
                self.assertNotEqual(self.command('--dry-run', db=staged).returncode, 0)
                with sqlite3.connect(self.db) as old, sqlite3.connect(staged) as new:
                    self.assertNotEqual(old.execute('SELECT MAC FROM data').fetchall(), new.execute('SELECT MAC FROM data').fetchall())
            self.assertNotEqual(self.command('--dry-run', source=self.target).returncode, 0)
        for field in ('MAC', 'sign', 'MACProtected', 'signProtected', 'value', 'salt'):
            self.make_fixture('integrity')
            with sqlite3.connect(self.db) as db:
                db.execute(f"UPDATE data SET {field}='tampered' WHERE id=2")
            before = self.db.read_bytes()
            output = self.root / ('tampered-' + field)
            self.assertNotEqual(self.command('--commit', '--output-dir', str(output)).returncode, 0)
            self.assertFalse(output.exists())
            self.assertEqual(self.db.read_bytes(), before)

    def test_undeclared_integrity_refused(self):
        with sqlite3.connect(self.db) as db:
            db.execute("UPDATE data SET MAC='undeclared' WHERE id=1")
        self.assertNotEqual(self.command('--dry-run').returncode, 0)

    def test_duplicate_and_missing_integrity_refused(self):
        for sql in (
            "INSERT INTO meta SELECT 7,userId,orgId,salt,attribute,attributeData FROM meta WHERE id=3",
            "UPDATE data SET MAC='' WHERE id=2",
            "UPDATE data SET signProtected=NULL WHERE id=2",
            "UPDATE data SET MAC=MAC||char(0)||'extra' WHERE id=2",
            "DELETE FROM meta WHERE id=3",
        ):
            self.make_fixture('integrity')
            with sqlite3.connect(self.db) as db:
                db.execute(sql)
            before = self.db.read_bytes()
            self.assertNotEqual(self.command('--dry-run').returncode, 0)
            self.assertEqual(self.db.read_bytes(), before)

    def test_transaction_rollback_and_interruption(self):
        for mode in ('rollback-data', 'rollback-meta', 'rollback-tags', 'interrupt'):
            self.make_fixture(mode)
            # The native fixture asserts byte-for-byte table equality after failure.
            with sqlite3.connect(self.db) as db:
                db.execute('DROP TRIGGER fail')
            self.assertEqual(self.command('--dry-run').returncode, 0)

    def test_extra_objects_and_invalid_ids(self):
        for sql in ('CREATE TABLE unrelated (id INTEGER)', 'UPDATE data SET id=2147483648 WHERE id=1'):
            self.make_fixture()
            with sqlite3.connect(self.db) as db:
                db.execute(sql)
            self.assertNotEqual(self.command('--dry-run').returncode, 0)

    def test_cbc_profile_and_optional_herradura(self):
        for profile in ('aes-256-cbc', 'herradura-hske-nla1-aead-256'):
            output = self.root / profile
            result = self.command('--commit', '--output-dir', str(output), profile=profile)
            if profile.startswith('herradura') and result.returncode:
                self.assertIn('unavailable target profile', result.stdout)
                self.assertFalse(output.exists())
                continue
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            result = self.command('--dry-run', db=output / 'after.sqlite', source=self.target)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_planner_commands_execute(self):
        module_path = Path(__file__).resolve().parents[1] / 'samples/reprotect-workflow/reprotect_workflow.py'
        spec = importlib.util.spec_from_file_location('reprotect_planner', module_path)
        planner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(planner)
        scope = planner.load_json(planner.DEFAULT_SCOPE)
        scope['targetProfile'] = 'aes-256-gcm'
        scope['databases'] = [scope['databases'][0]]
        scope['databases'][0]['name'] = self.db.name
        commands = planner.build_operator_commands(planner.build_plan(scope))['commands'][0]
        checkpoints = self.root / 'checkpoints'
        checkpoints.mkdir(mode=0o700)
        env = dict(os.environ, PATH=str(Path(ADMIN).parent) + os.pathsep + os.environ['PATH'],
            CDSE_COLUMNFILE_ROOT=str(self.root), CDSE_CHECKPOINT_ROOT=str(checkpoints),
            CDSE_SOURCE_ORG_KEY_FILE=str(self.source), CDSE_TARGET_ORG_KEY_FILE=str(self.target))
        for mode in ('dryRun', 'commit'):
            result = subprocess.run(commands[mode], shell=True, env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assert_clean(result)


if __name__ == '__main__':
    unittest.main(argv=[__file__, *remaining])
