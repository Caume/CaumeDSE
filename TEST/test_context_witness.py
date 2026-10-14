#!/usr/bin/env python3
"""Independent retained checkpoints, not hardware monotonic-storage claims."""
from contextlib import closing
import hashlib
import hmac
import json
import os
from pathlib import Path
import shutil
import sqlite3
import struct
import subprocess
import unittest

import test_context_manager as manager_tests
import test_context_owner as owner_tests


def witness_body(deployment, organization, revision, registry, catalog, previous):
    return (b'CDSE-HKX-WITNESS-v1\0' + bytes.fromhex(deployment) + bytes.fromhex(organization)
            + revision + registry + catalog + previous)


class WitnessTests(manager_tests.ManagerTests):
    def setUp(self):
        super().setUp()
        self.bootstrap()
        self.map_init()
        self.witness = self.root / 'witness'
        self.witness.mkdir(mode=0o700)

    def wcommand(self, action, *args, env=None, directory=None):
        return self.command(action, *args, env=env, directory=directory or self.witness)

    def initialized(self):
        result = self.wcommand('witness-init', self.current(), self.map_current())
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.decode().strip()

    def witnessed(self):
        result = self.wcommand('witness-anchor')
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.decode().strip()

    def advance(self, expected, registry=None, catalog=None, env=None):
        return self.wcommand('witness-advance', registry or self.current(), catalog or self.map_current(), expected, env=env)

    def change_catalog(self, row=1):
        self.assertEqual(self.map_store([('column/record/value', 'data', row, 'value')],
                                       resource='column/record/value').returncode, 0)

    def inspect(self, token, registry=None, catalog=None, env=None):
        return self.wcommand('witness-reconcile', registry or self.current(), catalog or self.map_current(), token, env=env)

    def test_reconcile_snapshot_current_pending_receipt_and_alias(self):
        token = self.initialized()
        path = self.witness / 'witness.sqlite'
        original = path.read_bytes()
        self.assertEqual(self.inspect(token).stdout.decode().splitlines(), ['1', token])
        self.change_catalog()
        result = self.inspect(token, env={'CDSE_CONTEXT_MANAGER_ALIAS': '1'})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.decode().splitlines(), ['2', token])
        self.assertEqual(path.read_bytes(), original)

    def test_reconcile_null_api_inputs_clear_outputs(self):
        token = self.initialized()
        result = self.inspect(token, env={'CDSE_WITNESS_INVALID_INPUTS': '1'})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.decode().splitlines(), ['1', token])

    def test_reconcile_lost_ack_receipt_does_not_write_checkpoint(self):
        token = self.initialized()
        self.change_catalog()
        self.assertEqual(self.advance(token).returncode, 0)
        current = self.witnessed()
        path = self.witness / 'witness.sqlite'
        original = path.read_bytes()
        self.assertEqual(self.inspect(token).stdout.decode().splitlines(), ['3', current])
        self.assertEqual(self.inspect(current).stdout.decode().splitlines(), ['1', current])
        self.assertEqual(path.read_bytes(), original)

    def test_reconcile_rejects_forks_skips_floor_decrease_and_two_counters(self):
        token = self.initialized()
        registry, catalog = self.current(), self.map_current()
        reg = bytearray.fromhex(registry)
        reg[32:40] = struct.pack('>Q', 2)
        advanced = reg.hex()
        reg[40] = 0
        for r, c, code in ((registry[:-2] + 'ff', catalog, 2),
                           (registry, catalog[:-2] + 'ff', 2),
                           (registry, (struct.pack('>Q', 3) + bytes.fromhex(catalog)[8:]).hex(), 2),
                           (advanced, (struct.pack('>Q', 2) + bytes.fromhex(catalog)[8:]).hex(), 2),
                           (reg.hex(), catalog, 1)):
            with self.subTest(registry=r, catalog=c):
                result = self.inspect(token, r, c, env={'CDSE_CONTEXT_MANAGER_ALIAS': '1'})
                self.assertEqual(result.returncode, code)
                self.assertEqual(result.stdout, b'')
                self.assertEqual(self.witnessed(), token)

    def test_reconcile_independent_token_rejects_complete_witness_backup_replay(self):
        token = self.initialized()
        path = self.witness / 'witness.sqlite'
        backup = path.read_bytes()
        self.change_catalog()
        self.assertEqual(self.advance(token).returncode, 0)
        retained = self.witnessed()
        path.write_bytes(backup)
        self.assertEqual(self.inspect(retained).returncode, 2)
        # An old retained token cannot detect the same whole-witness replay.
        self.assertEqual(self.inspect(token).stdout.decode().splitlines(), ['2', token])

    def test_reconcile_registry_floor_decrease_and_witness_revision_overflow(self):
        token = self.initialized()
        self.assertEqual(self.publish(dict(self.snapshot, generation=2, minimumFormat=2), self.anchor).returncode, 0)
        self.assertEqual(self.advance(token).returncode, 0)
        current = self.witnessed()
        reg = bytearray.fromhex(self.current())
        reg[32:40] = struct.pack('>Q', 3)
        reg[40] = 1
        self.assertEqual(self.inspect(current, registry=reg.hex()).returncode, 2)
        path = self.witness / 'witness.sqlite'
        with closing(sqlite3.connect(path)) as db, db:
            registry, catalog, previous = db.execute('select registry,catalog,previous from witness_current').fetchone()
            revision = struct.pack('>Q', 2**64 - 1)
            previous = struct.pack('>Q', 2**64 - 2) + previous[8:]
            body = witness_body(self.anchor.deployment, self.anchor.organization, revision, registry, catalog, previous)
            db.execute('update witness_current set revision=?,previous=?,tag=?',
                       (revision, previous, hmac.digest(b'w' * 32, body, 'sha256')))
        current = self.witnessed()
        self.assertEqual(self.inspect(current).stdout.decode().splitlines(), ['1', current])
        self.change_catalog()
        self.assertEqual(self.inspect(current).returncode, 2)

    def test_reconcile_invalid_tokens_corruption_and_expired_receipts(self):
        token = self.initialized()
        self.assertEqual(self.inspect('00' * 40).returncode, 1)
        wrong = bytearray.fromhex(token)
        wrong[-1] ^= 1
        self.assertEqual(self.inspect(wrong.hex()).returncode, 2)
        self.change_catalog()
        self.assertEqual(self.advance(token).returncode, 0)
        current = self.witnessed()
        self.change_catalog(2)
        self.assertEqual(self.inspect(token).returncode, 2)
        self.assertEqual(self.advance(current).returncode, 0)
        self.assertEqual(self.inspect(token).returncode, 2)
        with closing(sqlite3.connect(self.witness / 'witness.sqlite')) as db, db:
            db.execute('update witness_current set tag=zeroblob(32)')
        self.assertEqual(self.inspect(current).returncode, 1)

    def assert_codec(self):
        with closing(sqlite3.connect(self.witness / 'witness.sqlite')) as db:
            version, revision, registry, catalog, previous, tag = db.execute(
                'select version,revision,registry,catalog,previous,tag from witness_current').fetchone()
        self.assertEqual(version, 1)
        body = witness_body(self.anchor.deployment, self.anchor.organization, revision, registry, catalog, previous)
        self.assertEqual(tag, hmac.digest(b'w' * 32, body, 'sha256'))
        self.assertEqual(self.witnessed(), (revision + hashlib.sha256(body).digest()).hex())
        return registry.hex(), catalog.hex()

    def test_witness_initialization_codec_scope_and_private_metadata(self):
        current = self.initialized()
        self.assertEqual(self.assert_codec(), (self.current(), self.map_current()))
        self.assertEqual(self.witnessed(), current)
        for name in ('witness.sqlite', 'witness.initialized'):
            self.assertEqual((self.witness / name).stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.wcommand('witness-init', self.current(), self.map_current()).returncode, 1)
        self.assertEqual(self.wcommand('witness-anchor', env={'CDSE_WITNESS_WRONG_KEY': '1'}).returncode, 1)
        self.assertEqual(self.command('witness-anchor', directory=self.witness, organization='aa' * 16).returncode, 1)

    def test_witness_catalog_advance_cas_alias_and_lost_ack_receipt(self):
        before = self.initialized()
        self.change_catalog()
        result = self.advance(before, env={'CDSE_CONTEXT_MANAGER_ALIAS': '1'})
        self.assertEqual(result.returncode, 0)
        current = self.witnessed()
        self.assertNotEqual(current, before)
        self.assertEqual(self.advance(before).returncode, 0)
        self.assertEqual(self.witnessed(), current)
        self.change_catalog(2)
        self.assertEqual(self.advance(before).returncode, 2)
        self.assertEqual(self.advance(current).returncode, 0)
        self.assertEqual(self.advance(before).returncode, 2)
        self.assert_codec()

    def test_witness_registry_advance_and_monotonic_format_floor(self):
        before = self.initialized()
        snapshot = dict(self.snapshot, generation=2, minimumFormat=2)
        self.assertEqual(self.publish(snapshot, self.anchor).returncode, 0)
        self.assertEqual(self.advance(before).returncode, 0)
        current = self.witnessed()
        lowered = bytearray.fromhex(self.current())
        lowered[32:40] = struct.pack('>Q', 3)
        lowered[40] = 1
        self.assertEqual(self.advance(current, registry=lowered.hex()).returncode, 1)
        self.assertEqual(self.witnessed(), current)
        self.assert_codec()

    def test_witness_rejects_skips_same_counter_forks_and_two_counter_changes(self):
        before = self.initialized()
        registry, catalog = self.current(), self.map_current()
        for reg, cat in ((registry, catalog), (registry[:-2] + 'ff', catalog),
                         (registry, catalog[:-2] + 'ff'),
                         (registry, (struct.pack('>Q', 3) + bytes.fromhex(catalog)[8:]).hex()),
                         ((bytes.fromhex(registry)[:32] + struct.pack('>Q', 2) + bytes.fromhex(registry)[40:]).hex(),
                          (struct.pack('>Q', 2) + bytes.fromhex(catalog)[8:]).hex())):
            self.assertEqual(self.advance(before, registry=reg, catalog=cat).returncode, 1)
            self.assertEqual(self.witnessed(), before)

    def test_witness_detects_replayed_manager_pair_and_old_approval(self):
        before = self.initialized()
        old_registry, old_catalog = self.current(), self.map_current()
        self.change_catalog()
        self.assertEqual(self.advance(before).returncode, 0)
        self.assertEqual(self.wcommand('witness-check', old_registry, old_catalog).returncode, 2)
        self.assertEqual(self.wcommand('witness-check', self.current(), self.map_current()).returncode, 0)

    def test_witness_corruption_types_bounds_and_orphan_rows_fail_closed(self):
        self.initialized()
        path = self.witness / 'witness.sqlite'
        original = path.read_bytes()
        for sql in ("update witness_current set version=4294967297", "update witness_current set revision=cast(revision as text)",
                    "update witness_current set registry=zeroblob(73)", "update witness_current set catalog=zeroblob(39)",
                    "update witness_current set previous=zeroblob(39)", "update witness_current set tag=zeroblob(32)",
                    "insert into witness_current select 2,version,revision,registry,catalog,previous,tag from witness_current",
                    "delete from witness_current"):
            with self.subTest(sql=sql):
                with closing(sqlite3.connect(path)) as db, db:
                    db.execute('pragma ignore_check_constraints=on')
                    db.execute(sql)
                self.assertEqual(self.wcommand('witness-anchor').returncode, 1)
                self.assertEqual(self.wcommand('witness-init', self.current(), self.map_current()).returncode, 1)
                path.write_bytes(original)

    def test_witness_missing_database_or_marker_never_resets(self):
        self.initialized()
        path = self.witness / 'witness.sqlite'
        path.unlink()
        self.assertEqual(self.wcommand('witness-anchor').returncode, 1)
        self.assertEqual(self.wcommand('witness-init', self.current(), self.map_current()).returncode, 1)
        path.touch(mode=0o600)
        self.assertEqual(self.wcommand('witness-anchor').returncode, 1)
        (self.witness / 'witness.initialized').unlink()
        self.assertEqual(self.wcommand('witness-anchor').returncode, 1)
        self.assertEqual(self.wcommand('witness-init', self.current(), self.map_current()).returncode, 1)

    def test_witness_initialization_crashes_require_reconciliation_not_reset(self):
        for point in ('after-begin', 'after-write', 'after-commit'):
            directory = self.root / point
            directory.mkdir(mode=0o700)
            result = self.wcommand('witness-init', self.current(), self.map_current(), directory=directory,
                                   env={'CDSE_CONTEXT_WITNESS_CRASH': point})
            self.assertEqual(result.returncode, 86)
            self.assertEqual(self.wcommand('witness-anchor', directory=directory).returncode,
                             0 if point == 'after-commit' else 1)
            self.assertEqual(self.wcommand('witness-init', self.current(), self.map_current(), directory=directory).returncode, 1)

    def test_witness_advance_crashes_are_old_or_new_and_retry_is_exact(self):
        old = self.initialized()
        self.change_catalog()
        for point in ('after-begin', 'after-write', 'after-commit'):
            self.assertEqual(self.advance(old, env={'CDSE_CONTEXT_WITNESS_CRASH': point}).returncode, 86)
            if point != 'after-commit':
                self.assertEqual(self.witnessed(), old)
            else:
                self.assertNotEqual(self.witnessed(), old)
        current = self.witnessed()
        self.assertEqual(self.advance(old).returncode, 0)
        self.assertEqual(self.witnessed(), current)
        self.assert_codec()

    def test_witness_competing_distinct_approvals_share_one_cas(self):
        old = self.initialized()
        catalog = self.map_current()
        candidates = [(struct.pack('>Q', 2) + bytes([i]) * 32).hex() for i in (1, 2)]
        processes = []
        try:
            for candidate in candidates:
                processes.append(subprocess.Popen(self.args('witness-advance', self.current(), candidate, old,
                                                             directory=self.witness), stdout=subprocess.PIPE, stderr=subprocess.PIPE))
            for process in processes:
                process.communicate(timeout=30)
            self.assertEqual(sorted(p.returncode for p in processes), [0, 2])
        finally:
            for process in processes:
                if process.poll() is None:
                    process.kill()
                process.communicate()
        self.assertNotEqual(self.assert_codec()[1], catalog)

    def test_witness_uint64_overflow_is_fail_closed(self):
        self.initialized()
        with closing(sqlite3.connect(self.witness / 'witness.sqlite')) as db, db:
            _, registry, catalog = db.execute('select revision,registry,catalog from witness_current').fetchone()
            revision = struct.pack('>Q', 2**64 - 1)
            previous = struct.pack('>Q', 2**64 - 2) + b'f' * 32
            body = witness_body(self.anchor.deployment, self.anchor.organization, revision, registry, catalog, previous)
            db.execute('update witness_current set revision=?,previous=?,tag=?',
                       (revision, previous, hmac.digest(b'w' * 32, body, 'sha256')))
        current = self.witnessed()
        self.change_catalog()
        self.assertEqual(self.advance(current).returncode, 1)
        self.assertEqual(self.witnessed(), current)

    def test_witness_unsafe_directory_database_and_marker_links(self):
        self.initialized()
        self.witness.chmod(0o755)
        self.assertEqual(self.wcommand('witness-anchor').returncode, 1)
        self.witness.chmod(0o700)
        for name in ('witness.sqlite', 'witness.initialized'):
            path = self.witness / name
            path.chmod(0o644)
            self.assertEqual(self.wcommand('witness-anchor').returncode, 1)
            path.chmod(0o600)
            alias = self.witness / 'alias'
            os.link(path, alias)
            self.assertEqual(self.wcommand('witness-anchor').returncode, 1)
            alias.unlink()
        alias = self.root / 'alias'
        alias.symlink_to(self.witness, target_is_directory=True)
        self.assertEqual(self.wcommand('witness-anchor', directory=alias).returncode, 1)

    def test_witness_own_complete_backup_replay_is_not_hardware_protection(self):
        old = self.initialized()
        old_pair = self.current(), self.map_current()
        path = self.witness / 'witness.sqlite'
        backup = path.read_bytes()
        self.change_catalog()
        self.assertEqual(self.advance(old).returncode, 0)
        path.write_bytes(backup)
        self.assertEqual(self.witnessed(), old)
        self.assertEqual(self.wcommand('witness-check', *old_pair).returncode, 0)
        self.assertEqual(self.wcommand('witness-check', self.current(), self.map_current()).returncode, 2)

    def test_witness_invalid_initial_pins_leave_no_bootstrap_marker(self):
        for registry, catalog in (('00' * 73, self.map_current()), (self.current(), '00' * 40)):
            self.assertEqual(self.wcommand('witness-init', registry, catalog).returncode, 1)
            self.assertFalse((self.witness / 'witness.initialized').exists())
        self.initialized()


class GuardedOwnerTests(owner_tests.OwnerTests):
    def setUp(self):
        super().setUp()
        self.witness = self.root / 'independent'
        self.witness.mkdir(mode=0o700)
        self.witness_key = self.root / 'witness.key'
        self.witness_key.write_text('77' * 32 + '\n')
        self.witness_key.chmod(0o600)
        self.approval.update(schema=2, witness=str(self.witness))
        self.write_approval()

    def guarded(self, command, *action, extra=(), env=None, witness_directory=None):
        result = subprocess.run([owner_tests.ADMIN, command, '--approval', str(self.approval_file),
                                 '--registry-key-file', str(self.key), '--witness-key-file', str(self.witness_key),
                                 '--witness-directory', str(witness_directory or self.witness),
                                 '--confirmed-offline', str(self.approval_file), *action, *extra], capture_output=True,
                                env=dict(os.environ, **(env or {})), timeout=30)
        for secret in ((b'w' * 32).hex(), (b'k' * 32).hex(), str(self.witness), str(self.active), 'fixture-alpha'):
            self.assertNotIn(secret.encode(), result.stdout + result.stderr)
        if result.returncode:
            self.assertEqual(result.stdout, b'')
        return result

    def accepted_guarded(self, command, *action):
        result = self.guarded(command, *action)
        self.assertEqual(result.returncode, 0, result.stderr)
        return dict(line.split('=', 1) for line in result.stdout.decode().splitlines())

    def reconcile(self, token):
        self.approval['registry'] = self.current()
        self.approval['catalog'] = self.map_current()
        self.write_approval()
        return self.accepted_guarded('context-witness', '--advance', token)['witness']

    def test_owner_readonly_reconciliation_requires_reapproved_manager_pair(self):
        token = self.accepted_guarded('context-witness', '--init')['witness']
        self.assertEqual(self.accepted_guarded('context-witness', '--reconcile', token),
                         dict(state='current', witness=token))
        self.accepted_guarded('context-shuffle', '--init')
        self.assertEqual(self.guarded('context-witness', '--reconcile', token).returncode, 2)
        self.approval['catalog'] = self.map_current()
        self.write_approval()
        db = self.witness / 'witness.sqlite'
        before = db.read_bytes()
        manifest = self.approval_file.read_bytes()
        artifacts = (self.authority / 'registry.sqlite', self.active, self.staged)
        saved = [path.read_bytes() for path in artifacts]
        self.assertEqual(self.accepted_guarded('context-witness', '--reconcile', token),
                         dict(state='advance-required', witness=token))
        self.assertEqual(db.read_bytes(), before)
        self.assertEqual(self.approval_file.read_bytes(), manifest)
        self.assertEqual([path.read_bytes() for path in artifacts], saved)
        self.assertEqual(self.guarded('context-shuffle', '--prepare').returncode, 2)
        current = self.reconcile(token)
        before = db.read_bytes()
        self.assertEqual(self.accepted_guarded('context-witness', '--reconcile', token),
                         dict(state='already-advanced', witness=current))
        self.assertEqual(db.read_bytes(), before)

    def test_owner_reconciliation_registry_step_and_crashed_witness_advance(self):
        token = self.accepted_guarded('context-witness', '--init')['witness']
        self.assertEqual(self.command('revoke', 'second', self.current()).returncode, 0)
        self.approval['registry'] = self.current()
        self.write_approval()
        self.assertEqual(self.accepted_guarded('context-witness', '--reconcile', token)['state'], 'advance-required')
        result = self.command('witness-advance', self.current(), self.map_current(), token, directory=self.witness,
                              env={'CDSE_CONTEXT_WITNESS_CRASH': 'after-commit'})
        self.assertEqual(result.returncode, 86)
        self.assertEqual(self.accepted_guarded('context-witness', '--reconcile', token)['state'], 'already-advanced')

    def test_owner_reconciliation_rejects_manager_restore_with_retained_witness(self):
        token = self.accepted_guarded('context-witness', '--init')['witness']
        db = self.authority / 'registry.sqlite'
        backup, manifest = db.read_bytes(), self.approval_file.read_bytes()
        self.accepted_guarded('context-shuffle', '--init')
        current = self.reconcile(token)
        db.write_bytes(backup)
        self.approval_file.write_bytes(manifest)
        self.assertEqual(self.guarded('context-witness', '--reconcile', current).returncode, 2)
        self.assertEqual(self.guarded('context-witness', '--reconcile', token).returncode, 2)

    def test_owner_reconciliation_rejects_witness_restore_with_retained_new_token(self):
        token = self.accepted_guarded('context-witness', '--init')['witness']
        db = self.witness / 'witness.sqlite'
        backup = db.read_bytes()
        self.accepted_guarded('context-shuffle', '--init')
        current = self.reconcile(token)
        db.write_bytes(backup)
        self.assertEqual(self.guarded('context-witness', '--reconcile', current).returncode, 2)

    def test_owner_reconciliation_refuses_skipped_publications_and_bad_arguments(self):
        token = self.accepted_guarded('context-witness', '--init')['witness']
        for action in (('--reconcile',), ('--reconcile', '00' * 40), ('--reconcile', token, '--status'),
                       ('--reconcile', token, '--reconcile', token)):
            self.assertEqual(self.guarded('context-witness', *action).returncode, 1)
        self.assertEqual(self.guarded('context-shuffle', '--reconcile', token).returncode, 1)
        self.assertEqual(self.map_store(self.original_slots).returncode, 0)
        self.assertEqual(self.map_store(self.original_slots).returncode, 0)
        self.approval['catalog'] = self.map_current()
        self.write_approval()
        self.assertEqual(self.guarded('context-witness', '--reconcile', token).returncode, 2)
        self.assertEqual(self.guarded('context-witness', '--advance', token).returncode, 1)

    def test_guarded_owner_explicit_witness_reconciliation_between_mutations(self):
        token = self.accepted_guarded('context-witness', '--init')['witness']
        self.accepted_guarded('context-shuffle', '--init')
        self.approval['catalog'] = self.map_current()
        self.write_approval()
        self.assertEqual(self.guarded('context-shuffle', '--prepare').returncode, 2)
        token = self.reconcile(token)
        job = self.accepted_guarded('context-shuffle', '--prepare')['job']
        token = self.reconcile(token)
        self.accepted_guarded('context-shuffle', '--complete', job)
        token = self.reconcile(token)
        self.assertEqual(self.accepted_guarded('context-shuffle', '--status')['state'], 'completed')
        self.assertEqual(self.accepted_guarded('context-witness', '--status')['witness'], token)
        self.assertEqual(self.map_bind().returncode, 0)

    def test_guarded_owner_rejects_manager_and_approval_backup_rollback(self):
        token = self.accepted_guarded('context-witness', '--init')['witness']
        database = self.authority / 'registry.sqlite'
        old_db, old_approval = database.read_bytes(), self.approval_file.read_bytes()
        redirected = self.root / 'old-witness'
        shutil.copytree(self.witness, redirected)
        self.accepted_guarded('context-shuffle', '--init')
        self.reconcile(token)
        database.write_bytes(old_db)
        self.approval_file.write_bytes(old_approval)
        self.assertEqual(self.guarded('context-shuffle', '--init').returncode, 2)
        self.assertEqual(self.guarded('context-witness', '--status').returncode, 2)
        # A replayed approval cannot redirect the independently selected witness.
        self.approval = json.loads(old_approval)
        self.approval['witness'] = str(redirected)
        self.write_approval()
        self.assertEqual(self.guarded('context-witness', '--status').returncode, 1)

    def test_guarded_owner_missing_witness_never_bootstraps_during_shuffle(self):
        self.assertEqual(self.guarded('context-shuffle', '--init').returncode, 1)
        self.assertEqual(self.guarded('context-witness', '--reconcile', '01' * 40).returncode, 1)
        self.assertFalse((self.witness / 'witness.sqlite').exists())
        self.accepted_guarded('context-witness', '--init')
        (self.witness / 'witness.sqlite').unlink()
        self.assertEqual(self.guarded('context-witness', '--reconcile', '01' * 40).returncode, 1)
        self.assertEqual(self.guarded('context-shuffle', '--init').returncode, 1)
        self.assertEqual(self.guarded('context-witness', '--init').returncode, 1)

    def test_guarded_owner_requires_distinct_private_witness_key(self):
        self.witness_key.write_text('6b' * 32)
        self.assertEqual(self.guarded('context-witness', '--init').returncode, 1)
        self.witness_key.write_text('77' * 32)
        self.witness_key.chmod(0o644)
        self.assertEqual(self.guarded('context-witness', '--init').returncode, 1)
        self.witness_key.chmod(0o600)
        self.accepted_guarded('context-witness', '--init')
        self.witness_key.write_text('78' * 32)
        self.assertEqual(self.guarded('context-shuffle', '--init').returncode, 1)

    def test_guarded_owner_witness_location_and_schema_opt_in(self):
        original = str(self.witness)
        for directory in (self.authority, self.active.parent, self.authority / 'nested', self.staged.parent, self.root):
            self.approval['witness'] = str(directory)
            self.write_approval()
            self.assertEqual(self.guarded('context-witness', '--init', witness_directory=directory).returncode, 1)
        self.approval['witness'] = original
        nested = self.witness / 'export'
        self.active.parent.rename(nested)
        self.approval['active'] = str(nested / self.active.name)
        self.write_approval()
        self.assertEqual(self.guarded('context-witness', '--init').returncode, 1)
        nested.rename(self.active.parent)
        self.approval['active'] = str(self.active)
        self.approval['schema'] = 1
        self.write_approval()
        self.assertEqual(self.guarded('context-witness', '--init').returncode, 1)
        del self.approval['witness']
        self.write_approval()
        self.assertEqual(self.guarded('context-witness', '--init').returncode, 1)
        self.assertEqual(self.guarded('context-shuffle', '--init').returncode, 1)
        self.assertEqual(self.owner('--init').returncode, 0)

    def test_guarded_owner_exact_advance_receipt_and_wrong_token(self):
        token = self.accepted_guarded('context-witness', '--init')['witness']
        self.accepted_guarded('context-shuffle', '--init')
        current = self.reconcile(token)
        self.assertEqual(self.accepted_guarded('context-witness', '--advance', token)['witness'], current)
        self.assertEqual(self.guarded('context-witness', '--advance', '00' * 40).returncode, 1)
        wrong = bytearray.fromhex(token)
        wrong[-1] ^= 1
        self.assertEqual(self.guarded('context-witness', '--advance', wrong.hex()).returncode, 2)

    def test_guarded_owner_manager_pin_checks_precede_witness_creation(self):
        self.approval['catalog'] = (struct.pack('>Q', 99) + b'f' * 32).hex()
        self.write_approval()
        self.assertEqual(self.guarded('context-witness', '--init').returncode, 2)
        self.assertFalse((self.witness / 'witness.initialized').exists())
        self.approval['catalog'] = self.map_current()
        self.write_approval()
        with closing(sqlite3.connect(self.authority / 'registry.sqlite')) as db, db:
            db.execute('update context_map_head set tag=zeroblob(32)')
        self.assertEqual(self.guarded('context-witness', '--init').returncode, 1)
        self.assertFalse((self.witness / 'witness.initialized').exists())

    def test_guarded_owner_unwitnessed_registry_publication_blocks_until_approved(self):
        token = self.accepted_guarded('context-witness', '--init')['witness']
        self.assertEqual(self.command('revoke', 'second', self.current()).returncode, 0)
        self.approval['registry'] = self.current()
        self.write_approval()
        self.assertEqual(self.guarded('context-shuffle', '--init').returncode, 2)
        self.reconcile(token)
        self.accepted_guarded('context-shuffle', '--init')

    def test_guarded_owner_interrupted_target_install_uses_current_prepared_witness(self):
        token = self.accepted_guarded('context-witness', '--init')['witness']
        self.accepted_guarded('context-shuffle', '--init')
        token = self.reconcile(token)
        job = self.accepted_guarded('context-shuffle', '--prepare')['job']
        token = self.reconcile(token)
        result = self.command('shuffle-recover', 'view', job, 1, self.current(), self.map_current(),
                              env={'CDSE_CONTEXT_OFFLINE_CRASH': 'after-rename'})
        self.assertEqual(result.returncode, 86)
        self.accepted_guarded('context-shuffle', '--complete', job)
        self.reconcile(token)
        self.assertEqual(self.accepted_guarded('context-shuffle', '--status')['state'], 'completed')

    def test_guarded_owner_never_adopts_skipped_unguarded_publications(self):
        token = self.accepted_guarded('context-witness', '--init')['witness']
        self.assertEqual(self.map_store(self.original_slots).returncode, 0)
        self.assertEqual(self.map_store(self.original_slots).returncode, 0)
        self.approval['catalog'] = self.map_current()
        self.write_approval()
        self.assertEqual(self.guarded('context-witness', '--advance', token).returncode, 1)
        self.assertEqual(self.guarded('context-shuffle', '--init').returncode, 2)


for _name in vars(manager_tests.ManagerTests):
    if _name.startswith('test_'):
        setattr(WitnessTests, _name, None)
for _name in vars(owner_tests.OwnerTests):
    if _name.startswith('test_'):
        setattr(GuardedOwnerTests, _name, None)


if __name__ == '__main__':
    unittest.main()
