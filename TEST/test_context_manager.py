#!/usr/bin/env python3
"""Synthetic owner-side publication, fresh C reader and process-crash checks."""
import copy
from contextlib import closing
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
import uuid

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
        with closing(sqlite3.connect(self.authority / 'registry.sqlite')) as db, db:
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
        with closing(sqlite3.connect(self.authority / 'registry.sqlite')) as db, db:
            db.execute('delete from registry_current')
        self.assertEqual(self.command('anchor').returncode, 1)
        self.assertEqual(self.publish().returncode, 1)
        self.assertEqual(self.command('init').returncode, 1)

    def test_corrupt_snapshot_or_anchor_fails_closed(self):
        self.bootstrap()
        for field in ('body', 'tag', 'anchor'):
            with self.subTest(field=field), closing(sqlite3.connect(self.authority / 'registry.sqlite')) as db, db:
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

    def allocate(self, lookup='storage/resource/record/value', level=1, role=4,
                 table='data', field='value', parent='-', expected='-', env=None):
        return self.command('provision', lookup, level, role, table, field, parent, expected, env=env)

    def allocated(self, **options):
        result = self.allocate(**options)
        self.assertEqual(result.returncode, 0, result.stderr)
        snapshot = json.loads(result.stdout)
        body, tag, anchor = contract.issue(snapshot, b'k' * 32)
        self.assertEqual(result.stdout.rstrip(b'\n'), body)
        with closing(sqlite3.connect(self.authority / 'registry.sqlite')) as db, db:
            stored = db.execute('select body,tag,anchor from registry_current').fetchone()
        self.assertEqual(stored, (body, tag, bytes.fromhex(token(anchor))))
        lookup = options.get('lookup', 'storage/resource/record/value')
        context = contract.verify(body, tag, b'k' * 32, anchor).expected_context(lookup)
        return context, snapshot

    def test_allocated_uuid_persistence_and_reader_interoperability(self):
        context, snapshot = self.allocated()
        self.assertEqual(snapshot['generation'], 1)
        self.assertEqual(snapshot['minimumFormat'], 1)
        ids = [context[name] for name in ('storage', 'resource', 'record')]
        self.assertEqual(len(set(ids)), 3)
        for identifier in ids:
            value = uuid.UUID(bytes=identifier)
            self.assertEqual(value.version, 4)
            self.assertEqual(value.variant, uuid.RFC_4122)
        self.assertEqual(context['deployment'].hex(), self.anchor.deployment)
        result = self.command('read', 'storage/resource/record/value')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)['record'], context['record'].hex())
        self.assertEqual(self.command('read', 'storage/resource/record/value').stdout, result.stdout)

    def test_allocation_hierarchy_and_field_identity_reuse(self):
        first, _ = self.allocated(lookup='first')
        field, _ = self.allocated(lookup='field', level=4, parent='first', field='other', expected=self.current())
        self.assertEqual([first[x] for x in contract.UUID_FIELDS], [field[x] for x in contract.UUID_FIELDS])
        record, _ = self.allocated(lookup='record', level=3, parent='first', expected=self.current())
        self.assertEqual(record['resource'], first['resource'])
        self.assertNotEqual(record['record'], first['record'])
        resource, _ = self.allocated(lookup='resource', level=2, parent='first', expected=self.current())
        self.assertEqual(resource['storage'], first['storage'])
        self.assertNotEqual(resource['resource'], first['resource'])
        second, _ = self.allocated(lookup='second', expected=self.current())
        self.assertNotEqual(second['storage'], first['storage'])
        self.assertEqual(self.command('read', 'first').returncode, 0)

    def test_all_roles_and_shared_storage_across_external_roles(self):
        for role in (1, 2, 3):
            context, _ = self.allocated(lookup=f'internal/{role}', level=2, role=role,
                                       expected='-' if role == 1 else self.current())
            self.assertEqual(context['storage'], bytes(16))
        external, _ = self.allocated(lookup='column', expected=self.current())
        raw, _ = self.allocated(lookup='raw', level=2, role=5, table='payload', field='bytes',
                               parent='column', expected=self.current())
        self.assertEqual(raw['storage'], external['storage'])
        self.assertEqual(raw['role'], 'RawPart')
        self.assertNotEqual(raw['resource'], external['resource'])

    def test_allocation_rejects_duplicate_lookup_and_context(self):
        self.allocated(lookup='first')
        before = self.current()
        self.assertEqual(self.allocate(lookup='first', expected=before).returncode, 1)
        self.assertEqual(self.allocate(lookup='alias', level=4, parent='first', expected=before).returncode, 1)
        self.assertEqual(self.current(), before)

    def test_owner_revocation_is_irreversible_and_not_cascading(self):
        self.allocated(lookup='first')
        self.allocated(lookup='field', level=4, parent='first', field='other', expected=self.current())
        result = self.command('revoke', 'first', self.current())
        self.assertEqual(result.returncode, 0, result.stderr)
        snapshot = json.loads(result.stdout)
        self.assertEqual(snapshot['entries'][1]['state'], 'revoked')
        before = self.current()
        self.assertEqual(self.command('read', 'first').returncode, 1)
        self.assertEqual(self.command('read', 'field').returncode, 0)
        self.assertEqual(self.allocate(lookup='first', expected=before).returncode, 1)
        self.assertEqual(self.allocate(lookup='child', level=3, parent='first', expected=before).returncode, 1)
        self.assertEqual(self.command('revoke', 'first', before).returncode, 1)
        self.assertEqual(self.command('revoke', 'missing', before).returncode, 1)
        self.assertEqual(self.current(), before)

    def test_allocation_cas_and_expected_output_alias(self):
        self.allocated(lookup='first')
        before = self.current()
        self.assertEqual(self.allocate(lookup='second').returncode, 2)
        self.assertEqual(self.allocate(lookup='second', expected=token(self.anchor)).returncode, 2)
        self.allocated(lookup='second', expected=before, env={'CDSE_CONTEXT_MANAGER_ALIAS': '1'})
        self.assertEqual(self.command('revoke', 'first', before).returncode, 2)
        self.assertEqual(self.command('revoke', 'first', self.current(),
                                     env={'CDSE_CONTEXT_MANAGER_ALIAS': '1'}).returncode, 0)

    def test_allocation_random_failures_leave_no_publication(self):
        for mode in ('fail', 'collision'):
            self.assertEqual(self.allocate(env={'CDSE_CONTEXT_MANAGER_RANDOM': mode}).returncode, 1)
            self.assertEqual(self.command('anchor').returncode, 1)
        self.allocated(lookup='first')
        before = self.current()
        for mode in ('fail', 'collision'):
            self.assertEqual(self.allocate(lookup='second', expected=before,
                                          env={'CDSE_CONTEXT_MANAGER_RANDOM': mode}).returncode, 1)
            self.assertEqual(self.current(), before)
        self.allocated(lookup='field', level=4, parent='first', field='other', expected=before,
                       env={'CDSE_CONTEXT_MANAGER_RANDOM': 'fail'})

    def test_allocation_crash_publication_and_lost_acknowledgement(self):
        self.assertEqual(self.allocate(env={'CDSE_CONTEXT_MANAGER_CRASH': 'after-write'}).returncode, 86)
        self.assertEqual(self.command('anchor').returncode, 1)
        self.allocated(lookup='first')
        before = self.current()
        self.assertEqual(self.allocate(lookup='second', expected=before,
                                      env={'CDSE_CONTEXT_MANAGER_CRASH': 'after-commit'}).returncode, 86)
        self.assertEqual(self.command('read', 'second').returncode, 0)
        self.assertEqual(self.allocate(lookup='second', expected=before).returncode, 2)
        self.assertEqual(self.allocate(lookup='second', expected=self.current()).returncode, 1)

    def test_two_allocators_exactly_one_publishes(self):
        args = [self.args('provision', name, 1, 4, 'data', 'value', '-', '-') for name in ('first', 'second')]
        processes = []
        try:
            for command in args:
                processes.append(subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE))
            for process in processes:
                process.communicate(timeout=30)
            self.assertEqual(sorted(process.returncode for process in processes), [0, 2])
        finally:
            for process in processes:
                if process.poll() is None:
                    process.kill()
                process.communicate()
        with closing(sqlite3.connect(self.authority / 'registry.sqlite')) as db, db:
            snapshot = json.loads(db.execute('select body from registry_current').fetchone()[0])
        self.assertEqual(snapshot['generation'], 1)
        self.assertEqual(len(snapshot['entries']), 1)

    def test_allocation_inherits_format_floor_and_old_issuer_ids(self):
        self.bootstrap()
        self.assertEqual(self.publish(dict(self.snapshot, generation=2, minimumFormat=2), self.anchor).returncode, 0)
        context, snapshot = self.allocated(lookup='field', level=4, parent='column/record/value',
                                          field='other', expected=self.current())
        self.assertEqual(context['record'].hex(), self.context['record'])
        self.assertEqual(snapshot['minimumFormat'], 2)
        result = self.command('revoke', 'field', self.current())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)['minimumFormat'], 2)

    def test_allocation_input_and_parent_bounds(self):
        invalid = [dict(lookup=''), dict(lookup='x' * 129), dict(lookup='a.b'), dict(role=0), dict(role=6),
                   dict(level=0), dict(level=5), dict(table='x' * 65), dict(table='1table'),
                   dict(field='x' * 65), dict(field='a"b'), dict(role=5), dict(role=1),
                   dict(level=2), dict(level=3), dict(level=4), dict(parent='absent')]
        for options in invalid:
            with self.subTest(options=options):
                self.assertEqual(self.allocate(**options).returncode, 1)
        self.allocated(lookup='first')
        before = self.current()
        for options in (dict(level=3, role=1), dict(level=4, table='meta'),
                        dict(level=2, role=1), dict(level=1)):
            with self.subTest(options=options):
                self.assertEqual(self.allocate(lookup='child', parent='first', expected=before,
                                              **options).returncode, 1)
        self.assertEqual(self.current(), before)

    def test_allocation_generation_overflow_fails_closed(self):
        self.bootstrap()
        body, tag, anchor = contract.issue(dict(self.snapshot, generation=0xfffffffffffffffe), b'k' * 32)
        with closing(sqlite3.connect(self.authority / 'registry.sqlite')) as db, db:
            db.execute('update registry_current set body=?,tag=?,anchor=?', (body, tag, bytes.fromhex(token(anchor))))
        _, snapshot = self.allocated(lookup='last', level=4, parent='column/record/value',
                                     field='other', expected=self.current())
        self.assertEqual(snapshot['generation'], 0xffffffffffffffff)
        _, _, anchor = contract.issue(snapshot, b'k' * 32)
        self.assertEqual(self.allocate(expected=self.current()).returncode, 1)
        self.assertEqual(self.command('revoke', 'column/record/value', self.current()).returncode, 1)
        self.assertEqual(self.current(), token(anchor))

    def test_allocated_ids_never_reuse_retained_or_revoked_ids(self):
        context, _ = self.allocated(lookup='first')
        for revoked in (False, True):
            if revoked:
                self.assertEqual(self.command('revoke', 'first', self.current()).returncode, 0)
            before = self.current()
            result = self.allocate(lookup='second', expected=before,
                                   env={'CDSE_CONTEXT_MANAGER_RANDOM': context['record'].hex()})
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertEqual(self.current(), before)

    def test_provisioning_snapshot_capacity_fails_without_partial_ids(self):
        entries = []
        for i in range(1, contract.MAX_ENTRIES + 1):
            context = dict(self.context, record=i.to_bytes(16, 'big').hex())
            entries.append(dict(lookup=f'record/{i:04}', state='active', context=context))
        low, high = 1, len(entries)
        while low < high:
            middle = (low + high + 1) // 2
            try:
                contract.canonical(dict(self.snapshot, entries=entries[:middle]))
                low = middle
            except ValueError:
                high = middle - 1
        snapshot = dict(self.snapshot, entries=entries[:low])
        self.assertEqual(self.publish(snapshot).returncode, 0)
        before = self.current()
        result = self.allocate(lookup='x' * 128, table='t' * 64, field='f' * 64, expected=before)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(self.current(), before)

    def test_revocation_crash_recovery_before_and_after_commit(self):
        self.allocated(lookup='first')
        before = self.current()
        result = self.command('revoke', 'first', before, env={'CDSE_CONTEXT_MANAGER_CRASH': 'after-write'})
        self.assertEqual(result.returncode, 86)
        self.assertEqual(self.current(), before)
        self.assertEqual(self.command('read', 'first').returncode, 0)
        result = self.command('revoke', 'first', before, env={'CDSE_CONTEXT_MANAGER_CRASH': 'after-commit'})
        self.assertEqual(result.returncode, 86)
        self.assertNotEqual(self.current(), before)
        self.assertEqual(self.command('read', 'first').returncode, 1)
        self.assertEqual(self.command('revoke', 'first', before).returncode, 2)
        self.assertEqual(self.command('revoke', 'first', self.current()).returncode, 1)

    def scope_family(self):
        self.allocated(lookup='first')
        self.allocated(lookup='field', level=4, parent='first', field='other', expected=self.current())
        self.allocated(lookup='record', level=3, parent='first', table='meta', expected=self.current())
        self.allocated(lookup='raw', level=2, role=5, table='payload', field='bytes',
                       parent='first', expected=self.current())
        self.allocated(lookup='other-storage', expected=self.current())

    def revoke_scope(self, lookup='first', scope=1, expected=None, **options):
        return self.command('revoke-scope', lookup, scope,
                            self.current() if expected is None else expected, **options)

    def assert_scope_snapshot(self, result, revoked, generation):
        self.assertEqual(result.returncode, 0, result.stderr)
        snapshot = json.loads(result.stdout)
        self.assertEqual(snapshot['generation'], generation)
        body, tag, anchor = contract.issue(snapshot, b'k' * 32)
        self.assertEqual(result.stdout.rstrip(b'\n'), body)
        with closing(sqlite3.connect(self.authority / 'registry.sqlite')) as db, db:
            self.assertEqual(db.execute('select body,tag,anchor from registry_current').fetchone(),
                             (body, tag, bytes.fromhex(token(anchor))))
        for entry in snapshot['entries']:
            rejected = entry['lookup'] in revoked
            self.assertEqual(entry['state'], 'revoked' if rejected else 'active')
            self.assertEqual(self.command('read', entry['lookup']).returncode, 1 if rejected else 0)
        return snapshot

    def test_resource_revocation_covers_fields_records_and_tables(self):
        self.scope_family()
        before = self.current()
        result = self.revoke_scope()
        self.assert_scope_snapshot(result, {'first', 'field', 'record'}, 6)
        self.assertEqual(self.revoke_scope(expected=before).returncode, 2)
        self.assertEqual(self.revoke_scope().returncode, 1)
        self.assertEqual(self.allocate(lookup='child', level=3, parent='field',
                                      expected=self.current()).returncode, 1)

    def test_storage_revocation_covers_both_external_roles(self):
        self.scope_family()
        self.assert_scope_snapshot(self.revoke_scope(lookup='raw', scope=2),
                                   {'first', 'field', 'record', 'raw'}, 6)
        before = self.current()
        for parent in ('first', 'field', 'record', 'raw'):
            self.assertEqual(self.allocate(lookup='child', level=2, parent=parent,
                                          expected=before).returncode, 1)
        self.assertEqual(self.current(), before)

    def test_internal_resource_scope_never_cascades_zero_storage(self):
        self.allocated(lookup='internal', level=2, role=1)
        self.allocated(lookup='field', level=4, role=1, parent='internal', field='other', expected=self.current())
        self.allocated(lookup='row', level=3, role=1, parent='internal', expected=self.current())
        for role in (1, 2, 3):
            self.allocated(lookup=f'database/{role}', level=2, role=role, expected=self.current())
        before = self.current()
        self.assertEqual(self.revoke_scope(lookup='internal', scope=2).returncode, 1)
        self.assertEqual(self.current(), before)
        self.assert_scope_snapshot(self.revoke_scope(lookup='internal'), {'internal', 'field', 'row'}, 7)

    def test_scope_revocation_uses_authenticated_ids_not_lookup_prefixes(self):
        first = dict(lookup='same/prefix', state='active', context=self.context)
        same_resource = dict(lookup='unrelated/name', state='active', context=dict(self.context, field='other'))
        other_role = dict(lookup='role', state='active', context=dict(self.context, role='RawPart',
                                                                   table='payload', field='bytes'))
        other_storage = dict(lookup='same/prefix/child', state='active',
                             context=dict(self.context, storage='aa' * 16))
        snapshot = dict(self.snapshot, entries=[first, same_resource, other_role, other_storage])
        self.assertEqual(self.publish(snapshot).returncode, 0)
        result = self.revoke_scope(lookup='same/prefix')
        updated = self.assert_scope_snapshot(result, {'same/prefix', 'unrelated/name'}, 2)
        self.assertEqual({e['lookup']: e['context'] for e in updated['entries']},
                         {e['lookup']: e['context'] for e in snapshot['entries']})
        self.assert_scope_snapshot(self.revoke_scope(lookup='role', scope=2),
                                   {'same/prefix', 'unrelated/name', 'role'}, 3)

    def test_scope_revocation_bounds_aliasing_and_missing_seeds(self):
        self.assertEqual(self.revoke_scope(expected='-').returncode, 1)
        self.scope_family()
        before = self.current()
        for scope in (0, 3, 2147483647):
            self.assertEqual(self.revoke_scope(scope=scope, expected=before).returncode, 1)
        for lookup in ('', 'missing', 'x' * 129, 'a.b'):
            self.assertEqual(self.revoke_scope(lookup=lookup, expected=before).returncode, 1)
        self.assertEqual(self.revoke_scope(expected='-').returncode, 2)
        self.assertEqual(self.current(), before)
        self.assert_scope_snapshot(self.revoke_scope(env={'CDSE_CONTEXT_MANAGER_ALIAS': '1'}),
                                   {'first', 'field', 'record'}, 6)

    def test_scope_revocation_retains_tombstones_floor_and_prevents_revival(self):
        self.bootstrap()
        self.assertEqual(self.publish(dict(self.snapshot, generation=2, minimumFormat=2), self.anchor).returncode, 0)
        self.allocated(lookup='field', level=4, parent='column/record/value', field='other', expected=self.current())
        self.assertEqual(self.command('revoke', 'field', self.current()).returncode, 0)
        snapshot = self.assert_scope_snapshot(self.revoke_scope(lookup='column/record/value'),
                                              {'column/record/value', 'field'}, 5)
        self.assertEqual(snapshot['minimumFormat'], 2)
        before = self.current()
        _, _, anchor = contract.issue(snapshot, b'k' * 32)
        revived = copy.deepcopy(snapshot)
        revived['generation'] += 1
        revived['entries'][0]['state'] = 'active'
        self.assertEqual(self.publish(revived, anchor).returncode, 1)
        for lookup in ('column/record/value', 'field'):
            self.assertEqual(self.allocate(lookup=lookup, expected=before).returncode, 1)
        self.assertEqual(self.current(), before)

    def test_scope_revocation_process_crashes_are_all_or_none(self):
        self.scope_family()
        before = self.current()
        for point in ('after-begin', 'after-write', 'after-commit'):
            with self.subTest(point=point):
                result = self.revoke_scope(scope=2, expected=before,
                                           env={'CDSE_CONTEXT_MANAGER_CRASH': point})
                self.assertEqual(result.returncode, 86, result.stderr)
                committed = point == 'after-commit'
                self.assertEqual(self.current() == before, not committed)
                for lookup in ('first', 'field', 'record', 'raw'):
                    self.assertEqual(self.command('read', lookup).returncode, 1 if committed else 0)
                self.assertEqual(self.command('read', 'other-storage').returncode, 0)
        self.assertEqual(self.revoke_scope(scope=2, expected=before).returncode, 2)
        self.assertEqual(self.revoke_scope(scope=2).returncode, 1)

    def test_scope_revocation_and_child_creation_share_one_cas(self):
        self.scope_family()
        before = self.current()
        commands = [self.args('revoke-scope', 'first', 1, before),
                    self.args('provision', 'child', 3, 4, 'data', 'value', 'first', before)]
        processes = []
        try:
            for command in commands:
                processes.append(subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE))
            for process in processes:
                process.communicate(timeout=30)
            self.assertEqual(sorted(process.returncode for process in processes), [0, 2])
            if processes[0].returncode == 0:
                self.assertEqual(self.command('read', 'child').returncode, 1)
            else:
                self.assertEqual(self.command('read', 'child').returncode, 0)
                self.assert_scope_snapshot(self.revoke_scope(), {'first', 'field', 'record', 'child'}, 7)
        finally:
            for process in processes:
                if process.poll() is None:
                    process.kill()
                process.communicate()

    def test_scope_revocation_rejects_overflow_corrupt_state_and_stale_candidate(self):
        self.bootstrap()
        candidate = self.publish_args()[0]
        self.assertEqual(self.revoke_scope(lookup='column/record/value').returncode, 0)
        self.assertEqual(self.command('verify', candidate, self.tag.hex(), 'column/record/value').returncode, 1)
        snapshot = dict(self.snapshot, generation=0xffffffffffffffff)
        body, tag, anchor = contract.issue(snapshot, b'k' * 32)
        with closing(sqlite3.connect(self.authority / 'registry.sqlite')) as db, db:
            db.execute('update registry_current set body=?,tag=?,anchor=?', (body, tag, bytes.fromhex(token(anchor))))
        before = self.current()
        self.assertEqual(self.revoke_scope(lookup='column/record/value').returncode, 1)
        self.assertEqual(self.current(), before)
        with closing(sqlite3.connect(self.authority / 'registry.sqlite')) as db, db:
            db.execute('update registry_current set tag=?', (bytes(32),))
        self.assertEqual(self.revoke_scope(lookup='column/record/value', expected=before).returncode, 1)
    def test_scope_revocation_capacity_failure_never_partially_revokes(self):
        entries = [dict(lookup=f'record/{i:04}', state='active',
                        context=dict(self.context, record=i.to_bytes(16, 'big').hex()))
                   for i in range(1, contract.MAX_ENTRIES + 1)]
        low, high = 1, len(entries)
        while low < high:
            middle = (low + high + 1) // 2
            try:
                contract.canonical(dict(self.snapshot, entries=entries[:middle]))
                low = middle
            except ValueError:
                high = middle - 1
        snapshot = dict(self.snapshot, entries=entries[:low])
        self.assertEqual(self.publish(snapshot).returncode, 0)
        revoked = copy.deepcopy(snapshot)
        revoked['generation'] = 2
        for entry in revoked['entries']:
            entry['state'] = 'revoked'
        with self.assertRaises(ValueError):
            contract.canonical(revoked)
        before = self.current()
        self.assertEqual(self.revoke_scope(lookup='record/0001', scope=2).returncode, 1)
        self.assertEqual(self.current(), before)
        for lookup in ('record/0001', entries[low - 1]['lookup']):
            self.assertEqual(self.command('read', lookup).returncode, 0)


    def bind(self, slots, queries=(), resource='first', role=4, expected=None, env=None):
        args = [resource, role, self.current() if expected is None else expected, len(slots)]
        for lookup, table, row, field in slots:
            args.extend((lookup, table, row, field))
        args.append(len(queries))
        for table, row, field in queries:
            args.extend((table, row, field))
        return self.command('bind', *args, env=env)

    def bound(self, slots, queries=(), **options):
        result = self.bind(slots, queries, **options)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def binding_family(self):
        first, _ = self.allocated(lookup='first')
        self.allocated(lookup='field', level=4, parent='first', field='other', expected=self.current())
        second, _ = self.allocated(lookup='second', level=3, parent='first', expected=self.current())
        meta, _ = self.allocated(lookup='meta', level=3, parent='first', table='meta',
                                 field='attribute', expected=self.current())
        return first, second, meta

    def test_binding_copies_unsorted_owner_slots_and_preserves_context(self):
        first, second, meta = self.binding_family()
        before = self.current()
        slots = [('second', 'data', 20, 'value'), ('field', 'data', 10, 'other'),
                 ('meta', 'meta', 10, 'attribute'), ('first', 'data', 10, 'value')]
        queries = [('data', 10, 'value'), ('data', 10, 'other'), ('data', 20, 'value'), ('meta', 10, 'attribute')]
        result = self.bound(slots, queries)
        self.assertEqual((result['current'], result['fresh']), (0, 0))
        for entry, context in zip(result['results'], (first, first, second, meta)):
            self.assertEqual(entry, dict(result=0, floor=1, record=context['record'].hex(),
                                         resource=context['resource'].hex()))
        self.assertEqual(self.current(), before)

    def test_binding_rejects_schema_and_role_mismatches(self):
        self.binding_family()
        for table, field in (('meta', 'value'), ('Data', 'value'), ('data', 'other')):
            self.assertEqual(self.bind([('first', table, 1, field)]).returncode, 1)
        for role in (0, 1, 5, 6):
            self.assertEqual(self.bind([('first', 'data', 1, 'value')], role=role).returncode, 1)

    def test_binding_rejects_other_resources_storages_and_roles(self):
        self.binding_family()
        self.allocated(lookup='other-resource', level=2, parent='first', expected=self.current())
        self.allocated(lookup='other-storage', expected=self.current())
        self.allocated(lookup='raw', level=2, role=5, parent='first', table='payload', field='bytes',
                       expected=self.current())
        for lookup, table, field in (('other-resource', 'data', 'value'), ('other-storage', 'data', 'value'),
                                      ('raw', 'payload', 'bytes')):
            self.assertEqual(self.bind([('first', 'data', 1, 'value'),
                                        (lookup, table, 2, field)]).returncode, 1)

    def test_binding_rejects_revoked_resource_or_slot_without_partial_handle(self):
        self.binding_family()
        self.assertEqual(self.command('revoke', 'second', self.current()).returncode, 0)
        self.assertEqual(self.bind([('first', 'data', 1, 'value'),
                                    ('second', 'data', 2, 'value')]).returncode, 1)
        self.assertEqual(self.command('revoke', 'first', self.current()).returncode, 0)
        self.assertEqual(self.bind([('field', 'data', 1, 'other')]).returncode, 1)

    def test_binding_rejects_duplicate_slots(self):
        self.binding_family()
        for duplicate in ('first', 'second'):
            self.assertEqual(self.bind([('first', 'data', 1, 'value'),
                                        (duplicate, 'data', 1, 'value')]).returncode, 1)

    def test_binding_one_physical_row_cannot_mix_record_ids(self):
        self.binding_family()
        self.allocated(lookup='second-field', level=4, parent='second', field='other', expected=self.current())
        self.assertEqual(self.bind([('first', 'data', 1, 'value'),
                                    ('second-field', 'data', 1, 'other')]).returncode, 1)

    def test_binding_record_cannot_be_split_between_physical_rows(self):
        self.binding_family()
        for field, name in (('other', 'field'), ('value', 'first')):
            self.assertEqual(self.bind([('first', 'data', 1, 'value'),
                                        (name, 'data', 2, field)]).returncode, 1)

    def test_binding_table_is_part_of_physical_row_identity(self):
        entries = [dict(lookup='first', state='active', context=self.context),
                   dict(lookup='meta', state='active', context=dict(self.context, table='meta', field='attribute'))]
        self.assertEqual(self.publish(dict(self.snapshot, entries=entries)).returncode, 0)
        result = self.bound([('first', 'data', 1, 'value'), ('meta', 'meta', 99, 'attribute')],
                            [('data', 1, 'value'), ('meta', 99, 'attribute')])
        self.assertEqual([entry['record'] for entry in result['results']], [self.context['record']] * 2)

    def test_binding_signed_slot_extremes_and_schema_name_bounds(self):
        first, _ = self.allocated(lookup='first', table='T' * 64, field='F' * 64)
        second, _ = self.allocated(lookup='second', level=3, parent='first', table='T' * 64,
                                   field='F' * 64, expected=self.current())
        slots = [('second', 'T' * 64, (1 << 63) - 1, 'F' * 64), ('first', 'T' * 64, -(1 << 63), 'F' * 64)]
        queries = [('T' * 64, -(1 << 63), 'F' * 64), ('T' * 64, (1 << 63) - 1, 'F' * 64)]
        result = self.bound(slots, queries)
        self.assertEqual([entry['record'] for entry in result['results']],
                         [first['record'].hex(), second['record'].hex()])

    def test_binding_requires_exact_current_anchor(self):
        self.binding_family()
        slots = [('first', 'data', 1, 'value')]
        self.assertEqual(self.bind(slots, expected=token(self.anchor)).returncode, 2)
        current = self.current()
        altered = current[:-2] + ('00' if current[-2:] != '00' else '01')
        self.assertEqual(self.bind(slots, expected=altered).returncode, 2)
        self.assertEqual(self.bind(slots, expected='00' * 73).returncode, 1)
        self.assertEqual(self.current(), current)

    def test_binding_supports_every_storage_role(self):
        for role in range(1, 6):
            table, field = ('payload', 'bytes') if role == 5 else ('data', 'value')
            root = f'role/{role}'
            context, _ = self.allocated(lookup=root, level=2 if role < 4 else 1, role=role,
                                        table=table, field=field, expected='-' if role == 1 else self.current())
            result = self.bound([(root, table, 0, field)], [(table, 0, field)], resource=root, role=role)
            self.assertEqual(result['results'][0]['record'], context['record'].hex())

    def test_binding_recheck_detects_revocation_and_unrelated_updates(self):
        self.binding_family()
        slots = [('first', 'data', 1, 'value'), ('second', 'data', 2, 'value')]
        queries = [('data', 1, 'value'), ('data', 2, 'value')]
        result = self.bound(slots, queries, env={'CDSE_CONTEXT_BIND_UPDATE': '1'})
        self.assertEqual((result['current'], result['fresh']), (2, 0))
        result = self.bound(slots, queries, env={'CDSE_CONTEXT_BIND_REVOKE': 'second'})
        self.assertEqual((result['current'], result['fresh']), (2, 1))
        # A copied operation handle is not a lease. It retains its old context;
        # the explicit recheck/rebind, not local lookup, observes revocation.
        self.assertEqual([entry['result'] for entry in result['results']], [0, 0])

    def test_owner_binding_survives_sqlite_rename_shuffle_and_staging(self):
        first, second, _ = self.binding_family()
        database = self.root / 'column.sqlite'
        with closing(sqlite3.connect(database)) as db, db:
            db.execute('create table data(id integer primary key, value text, candidateLookup text)')
            db.executemany('insert into data values(?,?,?)', [(10, 'alpha', 'second'), (20, 'beta', 'first')])
        approved = {'alpha': 'first', 'beta': 'second'}
        contexts = {'alpha': first['record'].hex(), 'beta': second['record'].hex()}

        def verify(path):
            with closing(sqlite3.connect(path)) as db:
                rows = db.execute('select id,value from data order by id').fetchall()
            slots = [(approved[value], 'data', row, 'value') for row, value in rows]
            result = self.bound(slots, [('data', row, 'value') for row, _ in rows])
            self.assertEqual([entry['record'] for entry in result['results']], [contexts[value] for _, value in rows])

        verify(database)
        staged = self.root / 'staged-renamed.sqlite'
        database.rename(staged)
        verify(staged)
        with closing(sqlite3.connect(staged)) as db, db:
            db.execute('update data set id=-id')
            db.execute('update data set id=case id when -10 then 20 else 10 end')
        verify(staged)
        # Only the synthetic trusted owner uses these plaintext fixture labels
        # to construct a map; candidateLookup is deliberately never authority.

    def test_binding_partial_map_missing_invalid_slots_and_floor(self):
        self.bootstrap()
        self.assertEqual(self.publish(dict(self.snapshot, generation=2, minimumFormat=2), self.anchor).returncode, 0)
        result = self.bound([('column/record/value', 'data', 0, 'value')],
                            [('data', 0, 'value'), ('data', 1, 'value'), ('meta', 0, 'value'),
                             ('data', 0, 'other'), ('data', 0, 'x' * 65), ('bad.table', 0, 'value')],
                            resource='column/record/value')
        self.assertEqual(result['results'][0]['floor'], 2)
        for entry in result['results'][1:]:
            self.assertEqual(entry, dict(result=1, floor=0, record='00' * 16, resource='00' * 16))

    def test_binding_input_limits_and_unknown_handles(self):
        self.binding_family()
        for slots in ([], [('missing', 'data', 0, 'value')], [('x' * 129, 'data', 0, 'value')],
                      [('first', 'x' * 65, 0, 'value')], [('first', 'data', 0, '')],
                      [('first', 'data', 0, 'value')] * (contract.MAX_ENTRIES + 1)):
            self.assertEqual(self.bind(slots).returncode, 1)
        for root in ('missing', '', 'x' * 129):
            self.assertEqual(self.bind([('first', 'data', 0, 'value')], resource=root).returncode, 1)

    def test_binding_recheck_fails_closed_on_corrupt_authority(self):
        self.binding_family()
        result = self.bound([('first', 'data', 0, 'value')], env={'CDSE_CONTEXT_BIND_CORRUPT': '1'})
        self.assertEqual((result['current'], result['fresh']), (1, 1))

    def test_binding_large_valid_map_sorting_and_binary_search(self):
        entries = [dict(lookup=f'record/{i:04}', state='active',
                        context=dict(self.context, record=i.to_bytes(16, 'big').hex()))
                   for i in range(1, 1025)]
        self.assertEqual(self.publish(dict(self.snapshot, entries=entries)).returncode, 0)
        before = self.current()
        slots = [(entry['lookup'], 'data', i * 101, 'value')
                 for i, entry in reversed(list(enumerate(entries, 1)))]
        queries = [('data', i * 101, 'value') for i in (1, 513, 1024, 0)]
        result = self.bound(slots, queries, resource='record/0001')
        self.assertEqual([entry['record'] for entry in result['results']],
                         [i.to_bytes(16, 'big').hex() for i in (1, 513, 1024, 0)])
        self.assertEqual([entry['result'] for entry in result['results']], [0, 0, 0, 1])
        self.assertEqual(self.current(), before)


if __name__ == '__main__':
    unittest.main()
