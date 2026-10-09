#!/usr/bin/env python3
"""Synthetic owner-side publication, fresh C reader and process-crash checks."""
import copy
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import struct
import subprocess
import tempfile
import unittest

import herradura_registry_contract as contract

FIXTURE = str(Path(os.environ.get('CDSE_CONTEXT_MANAGER_FIXTURE', './context-manager-fixture')).resolve())


def token(anchor):
    return struct.pack('>16s16sQB32s', bytes.fromhex(anchor.deployment), bytes.fromhex(anchor.organization),
                       anchor.generation, anchor.minimum_format, anchor.digest).hex()


class ManagerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='cdse manager ')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.authority = self.root / 'authority'
        self.authority.mkdir(mode=0o700)
        self.context = dict(zip(contract.UUID_FIELDS, (bytes([i]).hex() * 16 for i in range(1, 6))))
        self.context.update(role='ColumnFile', table='data', field='value')
        self.snapshot = dict(schema=1, deployment=self.context['deployment'],
                             organization=self.context['organization'], generation=1, minimumFormat=1,
                             entries=[dict(lookup='column/record/value', state='active', context=self.context)])
        self.body, self.tag, self.anchor = contract.issue(self.snapshot, b'k' * 32)
        self.assertEqual(self.command('init').returncode, 0)

    def args(self, action, *args, directory=None, organization=None):
        return [FIXTURE, str(directory or self.authority), action, self.anchor.deployment,
                organization or self.anchor.organization, *map(str, args)]

    def command(self, action, *args, env=None, **options):
        return subprocess.run(self.args(action, *args, **options), capture_output=True,
                              env=dict(os.environ, **(env or {})), timeout=30)

    def publish_args(self, snapshot=None, expected=None, body=None, tag=None, anchor=None):
        if body is None:
            body, tag, anchor = contract.issue(snapshot or self.snapshot, b'k' * 32)
        path = self.root / (hashlib.sha256(body).hexdigest() + '.json')
        path.write_bytes(body)
        return path, tag.hex(), anchor.digest.hex(), anchor.generation, anchor.minimum_format, (
            '-' if expected is None else token(expected))

    def publish(self, snapshot=None, expected=None, env=None, **options):
        return self.command('publish', *self.publish_args(snapshot, expected, **options), env=env)

    def current(self):
        result = self.command('anchor')
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.decode().strip()

    def bootstrap(self):
        self.assertEqual(self.publish().returncode, 0)
        self.assertEqual(self.current(), token(self.anchor))

    def test_bootstrap_reopen_and_current_reader(self):
        self.assertNotEqual(self.command('anchor').returncode, 0)
        self.bootstrap()
        result = self.command('read', 'column/record/value')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), dict(floor=1, record=self.context['record']))
        self.assertEqual(self.command('init').returncode, 1)
        self.assertEqual((self.authority / 'registry.sqlite').stat().st_mode & 0o777, 0o600)
        with sqlite3.connect(self.authority / 'registry.sqlite') as db:
            self.assertEqual(db.execute('pragma journal_mode').fetchone()[0], 'delete')
            self.assertEqual(db.execute('select initialized from registry_meta').fetchone()[0], 1)

    def test_initial_policy_and_exact_cas(self):
        for snapshot in (dict(self.snapshot, generation=2), dict(self.snapshot, minimumFormat=2)):
            self.assertEqual(self.publish(snapshot).returncode, 1)
        self.bootstrap()
        self.assertEqual(self.publish().returncode, 2)
        current = dict(self.snapshot, generation=2)
        self.assertEqual(self.publish(current, replace(self.anchor, digest=bytes(32))).returncode, 2)
        self.assertEqual(self.publish(current, self.anchor).returncode, 0)
        self.assertEqual(self.publish(current, self.anchor).returncode, 2)

    def test_generation_floor_and_identity_transitions(self):
        self.bootstrap()
        for generation in (1, 3):
            self.assertEqual(self.publish(dict(self.snapshot, generation=generation), self.anchor).returncode, 1)
        for change in ('remove', 'context'):
            snapshot = copy.deepcopy(self.snapshot)
            snapshot['generation'] = 2
            if change == 'remove':
                snapshot['entries'] = []
            else:
                snapshot['entries'][0]['context']['record'] = 'aa' * 16
            self.assertEqual(self.publish(snapshot, self.anchor).returncode, 1)
        snapshot = dict(self.snapshot, generation=2, minimumFormat=2)
        self.assertEqual(self.publish(snapshot, self.anchor).returncode, 0)
        _, _, raised = contract.issue(snapshot, b'k' * 32)
        self.assertEqual(self.publish(dict(snapshot, generation=3, minimumFormat=1), raised).returncode, 1)

    def test_revocation_is_fresh_and_irreversible(self):
        self.bootstrap()
        snapshot = copy.deepcopy(self.snapshot)
        snapshot['generation'] = 2
        snapshot['entries'][0]['state'] = 'revoked'
        self.assertEqual(self.publish(snapshot, self.anchor).returncode, 0)
        _, _, revoked = contract.issue(snapshot, b'k' * 32)
        self.assertEqual(self.command('read', 'column/record/value').returncode, 1)
        self.assertEqual(self.publish(dict(self.snapshot, generation=3), revoked).returncode, 1)
        self.assertEqual(self.publish(dict(snapshot, generation=3, entries=[]), revoked).returncode, 1)
        self.assertEqual(self.current(), token(revoked))

    def test_stale_candidate_and_foreign_scope_rejected(self):
        self.bootstrap()
        old_path = self.publish_args()[0]
        snapshot = dict(self.snapshot, generation=2)
        self.assertEqual(self.publish(snapshot, self.anchor).returncode, 0)
        self.assertEqual(self.command('verify', old_path, self.tag.hex(), 'column/record/value').returncode, 1)
        self.assertEqual(self.command('anchor', organization='aa' * 16).returncode, 1)
        self.assertEqual(self.command('anchor', env={'CDSE_REGISTRY_WRONG_KEY': '1'}).returncode, 1)

    def test_authentication_and_schema_before_publication(self):
        for body, tag, anchor in ((self.body, bytes(32), self.anchor),
                                  (self.body.replace(b'value', b'other'), self.tag, self.anchor),
                                  (self.body, self.tag, replace(self.anchor, digest=bytes(32)))):
            self.assertEqual(self.publish(body=body, tag=tag, anchor=anchor).returncode, 1)
        body = json.dumps(self.snapshot).encode()
        self.assertEqual(self.publish(body=body, tag=contract.authenticate(body, b'k' * 32),
                                     anchor=replace(self.anchor, digest=hashlib.sha256(body).digest())).returncode, 1)
        self.assertEqual(self.command('anchor').returncode, 1)
        self.bootstrap()

    def test_process_crashes_before_and_after_commit(self):
        for point in ('after-begin', 'after-write', 'after-commit'):
            with self.subTest(point=point):
                authority = self.root / point
                authority.mkdir(mode=0o700)
                self.assertEqual(self.command('init', directory=authority).returncode, 0)
                self.assertEqual(self.command('publish', *self.publish_args(), directory=authority).returncode, 0)
                snapshot = dict(self.snapshot, generation=2)
                _, _, new = contract.issue(snapshot, b'k' * 32)
                result = self.command('publish', *self.publish_args(snapshot, self.anchor), directory=authority,
                                      env={'CDSE_CONTEXT_MANAGER_CRASH': point})
                self.assertEqual(result.returncode, 86, result.stderr)
                expected = new if point == 'after-commit' else self.anchor
                self.assertEqual(self.command('anchor', directory=authority).stdout.decode().strip(), token(expected))
                retry = self.command('publish', *self.publish_args(snapshot, self.anchor), directory=authority)
                self.assertEqual(retry.returncode, 2 if point == 'after-commit' else 0)

    def test_crashed_bootstrap_does_not_expose_partial_anchor(self):
        result = self.publish(env={'CDSE_CONTEXT_MANAGER_CRASH': 'after-write'})
        self.assertEqual(result.returncode, 86)
        self.assertEqual(self.command('anchor').returncode, 1)
        self.bootstrap()

    def test_two_writers_exactly_one_wins(self):
        self.bootstrap()
        args = self.args('publish', *self.publish_args(dict(self.snapshot, generation=2), self.anchor))
        first = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        second = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            first.communicate(timeout=30)
            second.communicate(timeout=30)
            self.assertEqual(sorted((first.returncode, second.returncode)), [0, 2])
        finally:
            for process in (first, second):
                if process.poll() is None:
                    process.kill()
                process.communicate()

    def test_existing_manager_handle_fetches_other_connection_commit(self):
        self.bootstrap()
        snapshot = dict(self.snapshot, generation=2)
        result = self.command('handoff', *self.publish_args(snapshot, self.anchor))
        self.assertEqual(result.returncode, 0, result.stderr)
        _, _, current = contract.issue(snapshot, b'k' * 32)
        self.assertEqual(self.current(), token(current))

    def test_missing_corrupt_state_never_resets_authority(self):
        self.bootstrap()
        with sqlite3.connect(self.authority / 'registry.sqlite') as db:
            db.execute('delete from registry_current')
        self.assertEqual(self.command('anchor').returncode, 1)
        self.assertEqual(self.publish().returncode, 1)
        self.assertEqual(self.command('init').returncode, 1)

    def test_corrupt_snapshot_or_anchor_fails_closed(self):
        self.bootstrap()
        for field in ('body', 'tag', 'anchor'):
            with self.subTest(field=field), sqlite3.connect(self.authority / 'registry.sqlite') as db:
                original = db.execute(f'select {field} from registry_current').fetchone()[0]
                broken = bytearray(original)
                broken[-1] ^= 1
                db.execute(f'update registry_current set {field}=?', (bytes(broken),))
                db.commit()
                self.assertEqual(self.command('anchor').returncode, 1)
                self.assertEqual(self.publish(dict(self.snapshot, generation=2), self.anchor).returncode, 1)
                db.execute(f'update registry_current set {field}=?', (original,))

    def test_private_paths_symlinks_hardlinks_and_missing_db(self):
        self.bootstrap()
        link = self.root / 'alias'
        link.symlink_to(self.authority, target_is_directory=True)
        self.assertEqual(self.command('anchor', directory=link).returncode, 1)
        self.authority.chmod(0o755)
        self.assertEqual(self.command('anchor').returncode, 1)
        self.authority.chmod(0o700)
        database = self.authority / 'registry.sqlite'
        database.chmod(0o644)
        self.assertEqual(self.command('anchor').returncode, 1)
        database.chmod(0o600)
        backup = self.authority / 'backup'
        os.link(database, backup)
        self.assertEqual(self.command('anchor').returncode, 1)
        backup.unlink()
        database.rename(backup)
        database.symlink_to(backup)
        self.assertEqual(self.command('anchor').returncode, 1)
        database.unlink()
        self.assertEqual(self.command('anchor').returncode, 1)
        self.assertFalse(database.exists())


if __name__ == '__main__':
    unittest.main()
