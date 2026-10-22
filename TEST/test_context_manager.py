#!/usr/bin/env python3
"""Synthetic owner-side publication, fresh C reader and process-crash checks."""
import copy
from contextlib import closing
from dataclasses import replace
import hashlib
import hmac
import json
import os
import select
import shutil
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


def catalog_bytes(deployment, organization, revision, maps, slots, shuffles=None, targets=(), pairs=None):
    def text(value):
        data = value.encode('ascii')
        return bytes([len(data)]) + data

    domain = b'CDSE-HKX-MAP-v1\0' if shuffles is None else b'CDSE-HKX-MAP-v2\0'
    if pairs is not None:
        domain = b'CDSE-HKX-MAP-v3\0'
    body = bytearray(domain + bytes.fromhex(deployment) + bytes.fromhex(organization))
    body.extend(struct.pack('>QI', revision, len(maps)))
    grouped = {}
    for name, table, row, field, lookup in slots:
        grouped.setdefault(name, []).append((table, row, field, lookup))
    for name, resource, role, active in sorted(maps):
        entries = sorted(grouped.get(name, []))
        body.extend(text(name) + text(resource) + struct.pack('>BBI', role, active, len(entries)))
        for table, row, field, lookup in entries:
            body.extend(text(table) + struct.pack('>q', row) + text(field) + text(lookup))
    if shuffles is not None:
        body.extend(struct.pack('>I', len(shuffles)))
        for name, job, state, finished, active, staged, source, target in sorted(shuffles):
            body.extend(text(name) + job + bytes([state]) + finished)
            for path in (active, staged):
                encoded = path.encode('utf-8')
                body.extend(struct.pack('>H', len(encoded)) + encoded)
            entries = sorted((table, row, field, lookup) for owner, table, row, field, lookup in targets
                             if owner == name)
            body.extend(source + target + struct.pack('>I', len(entries)))
            for table, row, field, lookup in entries:
                body.extend(text(table) + struct.pack('>q', row) + text(field) + text(lookup))
    if pairs is not None:
        body.extend(struct.pack('>I', len(pairs)))
        for name, active, staged, source, target, selection in sorted(pairs):
            body.extend(text(name))
            for path in (active, staged):
                encoded = path.encode('utf-8')
                body.extend(struct.pack('>H', len(encoded)) + encoded)
            body.extend(source + target + selection)
    return bytes(body)


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


    def map_current(self):
        result = self.command('map-anchor')
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.decode().strip()

    def map_init(self):
        result = self.command('map-init', self.current())
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.decode().strip()

    def map_store_args(self, slots, name='view', resource='first', role=4, registry=None, catalog=None):
        args = [name, resource, role, registry or self.current(), catalog or self.map_current(), len(slots)]
        for slot in slots:
            args.extend(slot)
        return args

    def map_store(self, slots, env=None, **options):
        return self.command('map-store', *self.map_store_args(slots, **options), env=env)

    def map_bind(self, queries=(), name='view', registry=None, catalog=None, env=None):
        args = [name, registry or self.current(), catalog or self.map_current(), len(queries)]
        for query in queries:
            args.extend(query)
        return self.command('map-bind', *args, env=env)

    def map_remove(self, name='view', catalog=None, env=None):
        return self.command('map-remove', name, self.current(), catalog or self.map_current(), env=env)

    def map_read(self, name='view', catalog=None):
        return self.command('map-read', name, self.current(), catalog or self.map_current())

    def catalog_rows(self):
        with closing(sqlite3.connect(self.authority / 'registry.sqlite')) as db:
            maps = db.execute('select name,resource,role,active from context_maps').fetchall()
            slots = db.execute('select map_name,table_name,slot,field_name,lookup from context_map_slots').fetchall()
            revision, tag = db.execute('select revision,tag from context_map_head').fetchone()
        return maps, slots, int.from_bytes(revision, 'big'), tag

    def assert_catalog(self):
        maps, slots, revision, tag = self.catalog_rows()
        body = catalog_bytes(self.anchor.deployment, self.anchor.organization, revision, maps, slots)
        self.assertLessEqual(len(body), contract.MAX_BYTES)
        self.assertEqual(tag, hmac.digest(b'k' * 32, body, 'sha256'))
        expected = (struct.pack('>Q', revision) + hashlib.sha256(body).digest()).hex()
        self.assertEqual(self.map_current(), expected)
        return expected

    def install_catalog(self, maps, slots, revision):
        body = catalog_bytes(self.anchor.deployment, self.anchor.organization, revision, maps, slots)
        with closing(sqlite3.connect(self.authority / 'registry.sqlite')) as db, db:
            db.execute('delete from context_map_slots')
            db.execute('delete from context_maps')
            db.executemany('insert into context_maps values(?,?,?,?)', maps)
            db.executemany('insert into context_map_slots values(?,?,?,?,?)', slots)
            db.execute('update context_map_head set revision=?,tag=?',
                       (struct.pack('>Q', revision), hmac.digest(b'k' * 32, body, 'sha256')))

    def test_map_opt_in_initialization_and_legacy_compatibility(self):
        self.binding_family()
        before = self.current()
        self.assertEqual(self.command('map-anchor').returncode, 1)
        self.assertEqual(self.command('map-init', token(self.anchor)).returncode, 2)
        self.assertEqual(self.bound([('first', 'data', 1, 'value')])['current'], 0)
        self.map_init()
        self.assert_catalog()
        self.assertEqual(self.catalog_rows()[:3], ([], [], 1))
        self.assertEqual(self.command('map-init', before).returncode, 1)
        self.assertEqual(self.current(), before)

    def test_map_durable_reopen_codec_and_signed_slots(self):
        first, second, meta = self.binding_family()
        self.map_init()
        slots = [('second', 'data', (1 << 63) - 1, 'value'), ('field', 'data', -(1 << 63), 'other'),
                 ('first', 'data', -(1 << 63), 'value'), ('meta', 'meta', 0, 'attribute')]
        for name in ('z-view', 'a-view'):
            self.assertEqual(self.map_store(slots, name=name).returncode, 0)
            self.assert_catalog()
        result = self.map_bind([('data', -(1 << 63), 'value'), ('data', (1 << 63) - 1, 'value'),
                                ('meta', 0, 'attribute')], name='a-view')
        self.assertEqual(result.returncode, 0, result.stderr)
        bound = json.loads(result.stdout)
        self.assertEqual(bound['current'], 0)
        self.assertEqual([r['record'] for r in bound['results']],
                         [c['record'].hex() for c in (first, second, meta)])
        self.assertEqual(self.catalog_rows()[2], 3)
        metadata = self.map_read(name='a-view')
        self.assertEqual(metadata.returncode, 0, metadata.stderr)
        self.assertEqual(json.loads(metadata.stdout), dict(resource='first', role=4, active=1,
                         slots=[list(s) for s in sorted(slots, key=lambda s: (s[1], s[2], s[3]))]))

    def test_map_dual_cas_and_output_alias(self):
        self.binding_family()
        self.map_init()
        old = self.map_current()
        slots = [('first', 'data', 1, 'value')]
        self.assertEqual(self.map_store(slots, env={'CDSE_CONTEXT_MANAGER_ALIAS': '1'}).returncode, 0)
        current = self.assert_catalog()
        self.assertEqual(self.map_store(slots, catalog=old).returncode, 2)
        self.assertEqual(self.map_store(slots, registry=token(self.anchor)).returncode, 2)
        self.assertEqual(self.map_store(slots, catalog='00' * 40).returncode, 1)
        self.assertEqual(self.map_bind(catalog=old).returncode, 2)
        self.assertEqual(self.map_read(catalog=old).returncode, 2)
        self.assertEqual(self.map_bind(registry=token(self.anchor)).returncode, 2)
        self.assertEqual(self.map_current(), current)

    def test_map_rejects_bad_bindings_without_catalog_change(self):
        self.binding_family()
        self.map_init()
        self.allocated(lookup='other', expected=self.current())
        before = self.map_current()
        for slots in ([], [('missing', 'data', 1, 'value')], [('first', 'meta', 1, 'value')],
                      [('first', 'data', 1, 'value'), ('second', 'data', 1, 'value')],
                      [('first', 'data', 1, 'value'), ('field', 'data', 2, 'other')],
                      [('other', 'data', 1, 'value')]):
            self.assertEqual(self.map_store(slots).returncode, 1)
            self.assertEqual(self.map_current(), before)
        for name in ('', 'bad.name', 'x' * 129):
            self.assertEqual(self.map_store([('first', 'data', 1, 'value')], name=name).returncode, 1)
        self.assert_catalog()

    def test_map_names_cannot_retarget_or_revive(self):
        self.binding_family()
        self.map_init()
        slots = [('first', 'data', 1, 'value')]
        self.assertEqual(self.map_store(slots).returncode, 0)
        self.allocated(lookup='other', expected=self.current())
        before = self.map_current()
        self.assertEqual(self.map_store([('other', 'data', 1, 'value')], resource='other').returncode, 1)
        self.assertEqual(self.map_remove(name='missing').returncode, 1)
        self.assertEqual(self.map_current(), before)
        self.assertEqual(self.map_remove(env={'CDSE_CONTEXT_MANAGER_ALIAS': '1'}).returncode, 0)
        self.assertEqual(self.map_bind().returncode, 1)
        self.assertEqual(self.map_store(slots).returncode, 1)
        self.assertEqual(self.map_remove().returncode, 1)
        self.assertEqual(self.catalog_rows()[:2], ([('view', 'first', 4, 0)], []))
        metadata = self.map_read()
        self.assertEqual(metadata.returncode, 0, metadata.stderr)
        self.assertEqual(json.loads(metadata.stdout), dict(resource='first', role=4, active=0, slots=[]))
        self.assertEqual(self.map_read(name='missing').returncode, 1)
        self.assert_catalog()

    def test_map_stored_binding_rechecks_both_authorities(self):
        self.binding_family()
        self.map_init()
        self.assertEqual(self.map_store([('first', 'data', 1, 'value')]).returncode, 0)
        for env in ({'CDSE_CONTEXT_MAP_UPDATE': 'other-view'}, {'CDSE_CONTEXT_MAP_REVOKE': 'second'},
                    {'CDSE_CONTEXT_MAP_REMOVE': '1'}):
            result = self.map_bind([('data', 1, 'value')], env=env)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)['current'], 2)
            self.assertEqual(json.loads(result.stdout)['results'][0]['result'], 0)
        self.assertEqual(self.map_bind().returncode, 1)

    def test_map_revalidation_rejects_revoked_slots_and_seed(self):
        self.binding_family()
        self.map_init()
        self.assertEqual(self.map_store([('first', 'data', 1, 'value'), ('second', 'data', 2, 'value')]).returncode, 0)
        before = self.map_current()
        self.assertEqual(self.command('revoke', 'second', self.current()).returncode, 0)
        self.assertEqual(self.map_bind().returncode, 1)
        self.assertEqual(self.map_current(), before)
        metadata = self.map_read()
        self.assertEqual(metadata.returncode, 0, metadata.stderr)
        self.assertEqual(len(json.loads(metadata.stdout)['slots']), 2)
        self.assertEqual(self.map_store([('first', 'data', 1, 'value')]).returncode, 0)
        self.assertEqual(self.command('revoke', 'first', self.current()).returncode, 0)
        self.assertEqual(self.map_bind().returncode, 1)
        self.assertEqual(self.map_remove().returncode, 0)
        self.assert_catalog()

    def test_map_authentication_rejects_corruption_types_and_foreign_scope(self):
        self.binding_family()
        self.map_init()
        self.assertEqual(self.map_store([('first', 'data', 1, 'value')]).returncode, 0)
        original = self.map_current()
        updates = [('context_map_head', 'tag', bytes(32)), ('context_map_head', 'revision', bytes(8)),
                   ('context_maps', 'resource', 'second'), ('context_maps', 'resource', b'first'),
                   ('context_maps', 'role', 3), ('context_maps', 'role', b'4'),
                   ('context_map_slots', 'table_name', b'data'),
                   ('context_map_slots', 'lookup', 'first\0hidden'), ('context_map_slots', 'slot', 'not-an-integer')]
        maps, slots, revision, tag = self.catalog_rows()
        for table, field, changed in updates:
            with self.subTest(field=field), closing(sqlite3.connect(self.authority / 'registry.sqlite')) as db, db:
                previous = db.execute(f'select {field} from {table}').fetchone()[0]
                db.execute(f'update {table} set {field}=?', (changed,))
                db.commit()
                self.assertEqual(self.command('map-anchor').returncode, 1)
                self.assertEqual(self.map_bind(catalog=original).returncode, 1)
                db.execute(f'update {table} set {field}=?', (previous,))
        foreign = catalog_bytes(self.anchor.deployment, 'aa' * 16, revision, maps, slots)
        with closing(sqlite3.connect(self.authority / 'registry.sqlite')) as db, db:
            db.execute('update context_map_head set tag=?', (hmac.digest(b'k' * 32, foreign, 'sha256'),))
        self.assertEqual(self.command('map-anchor').returncode, 1)

    def test_map_missing_state_never_reinitializes(self):
        self.binding_family()
        self.map_init()
        before = self.map_current()
        with closing(sqlite3.connect(self.authority / 'registry.sqlite')) as db, db:
            db.execute('delete from context_map_head')
        self.assertEqual(self.command('map-anchor').returncode, 1)
        self.assertEqual(self.command('map-init', self.current()).returncode, 1)
        self.assertEqual(self.map_store([('first', 'data', 1, 'value')], catalog=before).returncode, 1)
        with closing(sqlite3.connect(self.authority / 'registry.sqlite')) as db, db:
            db.execute('drop table context_map_slots')
        self.assertEqual(self.command('map-init', self.current()).returncode, 1)
        self.assertEqual(self.map_bind(catalog=before).returncode, 1)

    def test_map_initialization_process_crashes(self):
        for point in ('after-begin', 'after-write', 'after-commit'):
            with self.subTest(point=point):
                directory = self.root / point
                directory.mkdir(mode=0o700)
                self.assertEqual(self.command('init', directory=directory).returncode, 0)
                self.assertEqual(self.command('publish', *self.publish_args(), directory=directory).returncode, 0)
                result = self.command('map-init', token(self.anchor), directory=directory,
                                      env={'CDSE_CONTEXT_MANAGER_CRASH': point})
                self.assertEqual(result.returncode, 86)
                committed = point == 'after-commit'
                self.assertEqual(self.command('map-anchor', directory=directory).returncode, 0 if committed else 1)
                self.assertEqual(self.command('map-init', token(self.anchor), directory=directory).returncode,
                                 1 if committed else 0)

    def test_map_replacement_process_crashes_are_all_or_none(self):
        first, second, _ = self.binding_family()
        self.map_init()
        original = [('first', 'data', 1, 'value'), ('second', 'data', 2, 'value')]
        replacement = [('first', 'data', 2, 'value'), ('second', 'data', 1, 'value')]
        self.assertEqual(self.map_store(original).returncode, 0)
        before = self.map_current()
        for point in ('after-begin', 'after-write', 'after-commit'):
            result = self.map_store(replacement, catalog=before, env={'CDSE_CONTEXT_MANAGER_CRASH': point})
            self.assertEqual(result.returncode, 86)
            committed = point == 'after-commit'
            self.assertEqual(self.map_current() == before, not committed)
            bound = self.map_bind([('data', 1, 'value'), ('data', 2, 'value')])
            self.assertEqual(bound.returncode, 0, bound.stderr)
            expected = (second, first) if committed else (first, second)
            self.assertEqual([r['record'] for r in json.loads(bound.stdout)['results']],
                             [c['record'].hex() for c in expected])
            self.assert_catalog()
        self.assertEqual(self.map_store(replacement, catalog=before).returncode, 2)

    def test_map_removal_process_crashes_retain_tombstones(self):
        self.binding_family()
        self.map_init()
        self.assertEqual(self.map_store([('first', 'data', 1, 'value')]).returncode, 0)
        before = self.map_current()
        for point in ('after-begin', 'after-write', 'after-commit'):
            self.assertEqual(self.map_remove(catalog=before, env={'CDSE_CONTEXT_MANAGER_CRASH': point}).returncode, 86)
            committed = point == 'after-commit'
            self.assertEqual(self.map_bind().returncode, 1 if committed else 0)
            self.assertEqual(self.map_current() == before, not committed)
            self.assert_catalog()
        self.assertEqual(self.map_remove(catalog=before).returncode, 2)

    def test_map_two_owner_writers_share_one_catalog_cas(self):
        self.binding_family()
        self.map_init()
        commands = [self.args('map-store', *self.map_store_args([('first', 'data', row, 'value')])) for row in (5, 6)]
        processes = []
        try:
            for command in commands:
                processes.append(subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE))
            for process in processes:
                process.communicate(timeout=30)
            self.assertEqual(sorted(p.returncode for p in processes), [0, 2])
        finally:
            for process in processes:
                if process.poll() is None:
                    process.kill()
                process.communicate()
        self.assert_catalog()
        self.assertEqual(self.catalog_rows()[2], 2)
        self.assertIn(self.catalog_rows()[1][0][2], (5, 6))

    def test_map_uint64_overflow_fails_without_changes(self):
        self.binding_family()
        self.map_init()
        self.assertEqual(self.map_store([('first', 'data', 1, 'value')]).returncode, 0)
        maps, slots, _, _ = self.catalog_rows()
        self.install_catalog(maps, slots, (1 << 64) - 1)
        before = self.assert_catalog()
        self.assertEqual(self.map_store([('first', 'data', 9, 'value')]).returncode, 1)
        self.assertEqual(self.map_remove().returncode, 1)
        self.assertEqual(self.map_current(), before)

    def test_map_count_capacity_and_reserved_names(self):
        self.binding_family()
        self.map_init()
        maps = [(f'view/{i:04}', 'first', 4, 1) for i in range(contract.MAX_ENTRIES)]
        slots = [(name, 'data', 1, 'value', 'first') for name, _, _, _ in maps]
        self.install_catalog(maps, slots, 2)
        before = self.assert_catalog()
        self.assertEqual(self.map_store([('first', 'data', 1, 'value')], name='overflow').returncode, 1)
        self.assertEqual(self.map_current(), before)
        self.assertEqual(self.map_remove(name=maps[0][0]).returncode, 0)
        self.assertEqual(self.map_store([('first', 'data', 1, 'value')], name='overflow').returncode, 1)
        self.assert_catalog()

    def test_map_each_role_and_registry_floor_changes(self):
        self.bootstrap()
        self.map_init()
        for role in range(1, 6):
            root = f'role/{role}'
            table, field = ('payload', 'bytes') if role == 5 else ('data', 'value')
            self.allocated(lookup=root, role=role, level=2 if role < 4 else 1,
                           table=table, field=field, expected=self.current())
            self.assertEqual(self.map_store([(root, table, 1, field)], name=root, resource=root, role=role).returncode, 0)
            self.assertEqual(self.map_bind([(table, 1, field)], name=root).returncode, 0)
        # Raising the registry floor does not rewrite the independent catalog.
        before = self.map_current()
        with closing(sqlite3.connect(self.authority / 'registry.sqlite')) as db:
            snapshot = json.loads(db.execute('select body from registry_current').fetchone()[0])
        _, _, anchor = contract.issue(snapshot, b'k' * 32)
        snapshot.update(generation=snapshot['generation'] + 1, minimumFormat=2)
        self.assertEqual(self.publish(snapshot, anchor).returncode, 0)
        bound = self.map_bind([('data', 1, 'value')], name='role/1')
        self.assertEqual(bound.returncode, 0, bound.stderr)
        self.assertEqual(json.loads(bound.stdout)['results'][0]['floor'], 2)
        self.assertEqual(self.map_current(), before)


    def test_map_byte_capacity_failure_is_atomic(self):
        resource, table, field = 'r' * 128, 'T' * 64, 'F' * 64
        self.allocated(lookup=resource, table=table, field=field)
        self.map_init()
        maps = [(f'{i:04}' + 'v' * 124, resource, 4, 1) for i in range(contract.MAX_ENTRIES)]
        slots = [(name, table, 1, field, resource) for name, _, _, _ in maps]
        low, high = 0, len(maps)
        while low < high:
            middle = (low + high + 1) // 2
            size = len(catalog_bytes(self.anchor.deployment, self.anchor.organization, 2, maps[:middle], slots[:middle]))
            if size <= contract.MAX_BYTES:
                low = middle
            else:
                high = middle - 1
        self.install_catalog(maps[:low], slots[:low], 2)
        before = self.assert_catalog()
        self.assertGreater(len(catalog_bytes(self.anchor.deployment, self.anchor.organization, 3,
                                             maps[:low + 1], slots[:low + 1])), contract.MAX_BYTES)
        result = self.map_store([(resource, table, 1, field)], name=maps[low][0], resource=resource)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(self.map_current(), before)
        self.assertEqual(len(self.catalog_rows()[0]), low)

    def test_map_signed_invalid_semantics_and_orphan_rows_fail_closed(self):
        self.binding_family()
        self.map_init()
        maps = [('view', 'first', 4, 1)]
        slots = [('view', 'data', 1, 'value', 'first'), ('view', 'data', 2, 'other', 'field')]
        self.install_catalog(maps, slots, 2)
        self.assert_catalog()
        self.assertEqual(self.map_bind().returncode, 1)
        with closing(sqlite3.connect(self.authority / 'registry.sqlite')) as db, db:
            db.execute('insert into context_map_slots values(?,?,?,?,?)',
                       ('missing-view', 'data', 3, 'value', 'first'))
        self.assertEqual(self.command('map-anchor').returncode, 1)

    def test_map_registry_revocation_race_never_returns_usable_stale_map(self):
        self.binding_family()
        self.map_init()
        commands = [self.args('map-store', *self.map_store_args([('first', 'data', 1, 'value')])),
                    self.args('revoke', 'first', self.current())]
        processes = []
        try:
            for command in commands:
                processes.append(subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE))
            for process in processes:
                process.communicate(timeout=30)
            self.assertIn(processes[0].returncode, (0, 2))
            self.assertEqual(processes[1].returncode, 0)
            self.assertEqual(self.catalog_rows()[2], 2 if processes[0].returncode == 0 else 1)
        finally:
            for process in processes:
                if process.poll() is None:
                    process.kill()
                process.communicate()
        self.assert_catalog()
        self.assertEqual(self.map_bind().returncode, 1)


class ShuffleTests(ManagerTests):
    # Inherit helpers, not the legacy test cases (selected below).
    def shuffle_setup(self):
        self.binding_family()
        self.map_init()
        self.source_slots = [('first', 'data', 10, 'value'), ('second', 'data', 20, 'value')]
        self.target_slots = [('first', 'data', 20, 'value'), ('second', 'data', 10, 'value')]
        self.assertEqual(self.map_store(self.source_slots).returncode, 0)
        self.assertEqual(self.command('shuffle-init', self.current(), self.map_current()).returncode, 0)
        self.active = self.root / 'export' / 'data.sqlite'
        self.staged = self.root / 'staging' / 'next.sqlite'
        for path, slots in ((self.active, self.source_slots), (self.staged, self.target_slots)):
            path.parent.mkdir(mode=0o700)
            with closing(sqlite3.connect(path)) as db, db:
                db.execute('create table data(value text)')
                db.executemany('insert into data(rowid,value) values(?,?)', [(s[2], s[0]) for s in slots])
            path.chmod(0o600)
        self.source_hash = hashlib.sha256(self.active.read_bytes()).hexdigest()
        self.target_hash = hashlib.sha256(self.staged.read_bytes()).hexdigest()
        self.assert_shuffle_catalog()

    def prepare(self, env=None, **changes):
        slots = changes.get('slots', self.target_slots)
        args = [changes.get('name', 'view'), changes.get('active', self.active), changes.get('staged', self.staged),
                changes.get('source', self.source_hash), changes.get('target', self.target_hash),
                changes.get('registry', self.current()), changes.get('catalog', self.map_current()), len(slots)]
        for slot in slots:
            args.extend(slot)
        return self.command('shuffle-prepare', *args, env=env)

    def prepared(self):
        result = self.prepare()
        self.assertEqual(result.returncode, 0, result.stderr)
        job, anchor = result.stdout.decode().splitlines()
        self.assertEqual(anchor, self.assert_shuffle_catalog())
        self.assertEqual(self.map_bind().returncode, 1)
        return job

    def shuffle_read(self):
        result = self.command('shuffle-read', 'view', self.current(), self.map_current())
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def recover(self, job, complete=1, env=None, catalog=None):
        return self.command('shuffle-recover', 'view', job, complete, self.current(),
                            catalog or self.map_current(), env=env)

    def assert_shuffle_catalog(self):
        maps, slots, revision, tag = self.catalog_rows()
        with closing(sqlite3.connect(self.authority / 'registry.sqlite')) as db:
            jobs = db.execute('select * from context_shuffles').fetchall()
            targets = db.execute('select * from context_shuffle_slots').fetchall()
            paired = any(row[1] == 'pair_version' for row in db.execute('pragma table_info(registry_meta)'))
            pairs = db.execute('select * from context_shuffle_pairs').fetchall() if paired else None
        body = catalog_bytes(self.anchor.deployment, self.anchor.organization, revision, maps, slots, jobs, targets, pairs)
        self.assertEqual(tag, hmac.digest(b'k' * 32, body, 'sha256'))
        anchor = (struct.pack('>Q', revision) + hashlib.sha256(body).digest()).hex()
        self.assertEqual(self.map_current(), anchor)
        return anchor

    def test_shuffle_complete_authenticated_receipt_and_uuid_preservation(self):
        self.shuffle_setup()
        registry = self.current()
        job = self.prepared()
        self.assertEqual(self.recover(job, env={'CDSE_CONTEXT_MANAGER_ALIAS': '1'}).returncode, 0)
        self.assertEqual(hashlib.sha256(self.active.read_bytes()).hexdigest(), self.target_hash)
        self.assertFalse(self.staged.exists())
        with closing(sqlite3.connect(self.active)) as db:
            self.assertEqual(db.execute('select rowid,value from data order by rowid').fetchall(),
                             [(10, 'second'), (20, 'first')])
        self.assertEqual(self.map_bind().returncode, 0)
        self.assertEqual(self.current(), registry)
        self.assertEqual(self.shuffle_read()['state'], 2)
        before = self.assert_shuffle_catalog()
        self.assertEqual(self.recover(job).returncode, 0)
        self.assertEqual(self.assert_shuffle_catalog(), before)
        self.assertEqual(self.recover(job, 0).returncode, 1)

    def test_shuffle_abort_and_new_job_replace_receipt(self):
        self.shuffle_setup()
        job = self.prepared()
        self.assertEqual(self.recover(job, 0).returncode, 0)
        before = self.assert_shuffle_catalog()
        self.assertEqual(self.recover(job, 0).returncode, 0)
        self.assertEqual(self.map_current(), before)
        self.assertEqual(self.shuffle_read()['state'], 3)
        self.assertEqual(self.map_bind().returncode, 0)
        new = self.prepared()
        self.assertNotEqual(new, job)
        self.assertEqual(self.recover(job).returncode, 1)
        self.assertEqual(self.recover(new).returncode, 0)

    def test_shuffle_pending_blocks_map_edits_and_reserves_paths(self):
        self.shuffle_setup()
        job = self.prepared()
        self.assertEqual(self.map_store(self.source_slots).returncode, 1)
        self.assertEqual(self.map_remove().returncode, 1)
        self.assertEqual(self.prepare().returncode, 1)
        self.assertEqual(self.map_store(self.source_slots, name='other').returncode, 0)
        self.assertEqual(self.prepare(name='other').returncode, 1)
        self.assertEqual(self.recover(job).returncode, 0)
        self.assert_shuffle_catalog()

    def test_shuffle_exact_cas_nonce_and_late_receipt_retry(self):
        self.shuffle_setup()
        old = self.map_current()
        job = self.prepared()
        self.assertEqual(self.recover(job, catalog=old).returncode, 2)
        self.assertEqual(self.recover('00' * 32).returncode, 1)
        self.assertEqual(self.recover(job).returncode, 0)
        self.assertEqual(self.map_store(self.target_slots, name='other').returncode, 0)
        self.assertEqual(self.recover(job).returncode, 2)
        self.assert_shuffle_catalog()

    def test_shuffle_prepare_process_crashes(self):
        self.shuffle_setup()
        for point in ('after-begin', 'after-write', 'after-commit'):
            before = self.map_current()
            self.assertEqual(self.prepare(env={'CDSE_CONTEXT_MANAGER_CRASH': point}).returncode, 86)
            if point == 'after-commit':
                self.assertEqual(self.map_bind().returncode, 1)
                self.assertEqual(self.recover(self.shuffle_read()['job'], 0).returncode, 0)
            else:
                self.assertEqual(self.map_current(), before)
                self.assertEqual(self.map_bind().returncode, 0)
            self.assertEqual(hashlib.sha256(self.active.read_bytes()).hexdigest(), self.source_hash)
            self.assert_shuffle_catalog()

    def test_shuffle_recovery_process_crashes(self):
        self.shuffle_setup()
        original = self.active.read_bytes()
        candidate = self.staged.read_bytes()
        for point in ('after-begin', 'after-rename', 'after-artifact-sync', 'after-write', 'after-commit'):
            with self.subTest(point=point):
                job = self.prepared()
                key = 'CDSE_CONTEXT_OFFLINE_CRASH' if point == 'after-rename' else 'CDSE_CONTEXT_MANAGER_CRASH'
                self.assertEqual(self.recover(job, env={key: point}).returncode, 86)
                self.assertEqual(self.map_bind().returncode, 0 if point == 'after-commit' else 1)
                self.assertEqual(self.recover(job).returncode, 0)
                self.assertEqual(self.shuffle_read()['state'], 2)
                self.assert_shuffle_catalog()
                self.active.write_bytes(original)
                self.staged.write_bytes(candidate)
                self.staged.chmod(0o600)
                self.assertEqual(self.map_store(self.source_slots).returncode, 0)

    def test_shuffle_installed_target_requires_forward_recovery(self):
        self.shuffle_setup()
        job = self.prepared()
        self.staged.replace(self.active)
        self.assertEqual(self.recover(job, 0).returncode, 1)
        self.assertEqual(self.map_bind().returncode, 1)
        self.assertEqual(self.recover(job).returncode, 0)

    def test_shuffle_unknown_active_and_missing_stage_fail_closed(self):
        self.shuffle_setup()
        original = self.active.read_bytes()
        staged = self.staged.read_bytes()
        job = self.prepared()
        self.active.write_bytes(original + b'unknown')
        self.assertEqual(self.recover(job).returncode, 1)
        self.assertEqual(self.recover(job, 0).returncode, 1)
        self.active.write_bytes(original)
        self.staged.unlink()
        self.assertEqual(self.recover(job).returncode, 1)
        self.staged.write_bytes(staged + b'unknown')
        self.staged.chmod(0o600)
        self.assertEqual(self.recover(job).returncode, 1)
        self.assertEqual(self.map_bind().returncode, 1)
        self.assertEqual(self.recover(job, 0).returncode, 0)

    def test_shuffle_revocation_before_install_preserves_source(self):
        self.shuffle_setup()
        job = self.prepared()
        self.assertEqual(self.command('revoke', 'second', self.current()).returncode, 0)
        self.assertEqual(self.recover(job).returncode, 1)
        self.assertEqual(hashlib.sha256(self.active.read_bytes()).hexdigest(), self.source_hash)
        self.assertEqual(self.recover(job, 0).returncode, 0)
        self.assertEqual(self.map_bind().returncode, 1)

    def test_shuffle_prepare_rejects_nonpermutation_and_bad_pins(self):
        self.shuffle_setup()
        before = self.map_current()
        for changes in (dict(slots=self.target_slots[:1]), dict(slots=[('first', 'data', 1, 'other')]),
                        dict(slots=[('first', 'data', 1, 'value'), ('second', 'data', 1, 'value')]),
                        dict(source='00' * 32), dict(target='00' * 32), dict(target=self.source_hash),
                        dict(staged=self.active), dict(active=self.authority / 'registry.sqlite')):
            with self.subTest(changes=changes):
                self.assertEqual(self.prepare(**changes).returncode, 1)
                self.assertEqual(self.map_current(), before)
        self.assertEqual(self.prepare(env={'CDSE_CONTEXT_MANAGER_RANDOM': 'fail'}).returncode, 1)
        self.assertEqual(self.prepare(registry=token(self.anchor)).returncode, 2)
        self.assertEqual(self.prepare(env={'CDSE_CONTEXT_MANAGER_ALIAS': '1'}).returncode, 0)

    def test_shuffle_private_files_sidecars_and_header_checks(self):
        self.shuffle_setup()
        candidate = self.staged.read_bytes()
        for mode in (0o644, 0o400, 0o660):
            self.staged.chmod(mode)
            self.assertEqual(self.prepare().returncode, 1)
        self.staged.chmod(0o600)
        self.staged.parent.chmod(0o755)
        self.assertEqual(self.prepare().returncode, 1)
        self.staged.parent.chmod(0o700)
        for suffix in ('-wal', '-shm', '-journal'):
            sidecar = Path(str(self.staged) + suffix)
            sidecar.touch()
            self.assertEqual(self.prepare().returncode, 1)
            sidecar.unlink()
        for data in (b'x' * 100, candidate[:18] + b'\x02\x02' + candidate[20:]):
            self.staged.write_bytes(data)
            self.assertEqual(self.prepare(target=hashlib.sha256(data).hexdigest()).returncode, 1)
        self.staged.write_bytes(candidate)
        same = self.active.parent / 'next.sqlite'
        same.write_bytes(candidate)
        same.chmod(0o600)
        self.assertEqual(self.prepare(staged=same).returncode, 1)
        self.assert_shuffle_catalog()

    def test_shuffle_symlinks_hardlinks_fifo_and_size_limit(self):
        self.shuffle_setup()
        alias = self.staged.parent / 'alias.sqlite'
        alias.symlink_to(self.staged)
        self.assertEqual(self.prepare(staged=alias).returncode, 1)
        alias.unlink()
        os.link(self.staged, alias)
        self.assertEqual(self.prepare().returncode, 1)
        alias.unlink()
        os.mkfifo(alias, 0o600)
        self.assertEqual(self.prepare(staged=alias).returncode, 1)
        alias.unlink()
        with self.staged.open('r+b') as stream:
            stream.truncate(256 * 1024 * 1024 + 1)
        self.assertEqual(self.prepare().returncode, 1)

    def test_shuffle_corrupt_intent_or_target_fails_authentication(self):
        self.shuffle_setup()
        self.prepared()
        with closing(sqlite3.connect(self.authority / 'registry.sqlite')) as db, db:
            db.execute("update context_shuffle_slots set slot=slot+1")
        self.assertEqual(self.command('map-anchor').returncode, 1)
        self.assertEqual(self.map_bind(catalog='00' * 40).returncode, 1)
        self.assertEqual(self.command('shuffle-init', self.current(), '00' * 40).returncode, 1)

    def test_shuffle_opt_in_crashes_and_missing_state(self):
        self.binding_family()
        self.map_init()
        for point in ('after-begin', 'after-write'):
            before = self.map_current()
            self.assertEqual(self.command('shuffle-init', self.current(), before,
                                         env={'CDSE_CONTEXT_MANAGER_CRASH': point}).returncode, 86)
            self.assertEqual(self.assert_catalog(), before)
        self.assertEqual(self.command('shuffle-init', self.current(), self.map_current(),
                                     env={'CDSE_CONTEXT_MANAGER_CRASH': 'after-commit'}).returncode, 86)
        self.assert_shuffle_catalog()
        self.assertEqual(self.command('shuffle-init', self.current(), self.map_current()).returncode, 1)
        with closing(sqlite3.connect(self.authority / 'registry.sqlite')) as db, db:
            db.execute('drop table context_shuffles')
        self.assertEqual(self.command('map-anchor').returncode, 1)
        self.assertEqual(self.command('shuffle-init', self.current(), '00' * 40).returncode, 1)

    def resign_shuffle(self, revision):
        maps, slots, _, _ = self.catalog_rows()
        with closing(sqlite3.connect(self.authority / 'registry.sqlite')) as db, db:
            jobs = db.execute('select * from context_shuffles').fetchall()
            targets = db.execute('select * from context_shuffle_slots').fetchall()
            body = catalog_bytes(self.anchor.deployment, self.anchor.organization, revision, maps, slots, jobs, targets)
            db.execute('update context_map_head set revision=?,tag=?',
                       (struct.pack('>Q', revision), hmac.digest(b'k' * 32, body, 'sha256')))

    def test_shuffle_signed_invalid_state_types_and_orphans(self):
        self.shuffle_setup()
        self.prepared()
        database = self.authority / 'registry.sqlite'
        pristine = database.read_bytes()
        mutations = ("update context_shuffles set job=zeroblob(32)",
                     "update context_shuffles set state=4294967297",
                     "update context_shuffles set active_path=cast(active_path as blob)",
                     "update context_shuffles set active_path=active_path||char(0)||'extra'",
                     "update context_shuffles set staged_path=active_path",
                     "update context_shuffles set target=source",
                     "update context_shuffles set finished=x'0000000000000001'",
                     "update context_shuffle_slots set slot=cast(slot as blob)",
                     "update context_shuffle_slots set lookup=cast(lookup as blob)",
                     "update context_maps set active=0",
                     "update context_maps set role=5",
                     "update context_shuffles set map_name='orphan'",
                     "update context_shuffle_slots set map_name='orphan'",
                     "update registry_meta set shuffle_version=2")
        for sql in mutations:
            with self.subTest(sql=sql):
                with closing(sqlite3.connect(database)) as db, db:
                    db.execute('pragma ignore_check_constraints=on')
                    db.execute(sql)
                self.assertEqual(self.command('map-anchor').returncode, 1)
                database.write_bytes(pristine)
        # Even a valid HMAC must not authorize a pending intent on a tombstone.
        with closing(sqlite3.connect(database)) as db, db:
            db.execute('update context_maps set active=0')
        self.resign_shuffle(self.catalog_rows()[2])
        self.assertEqual(self.command('map-anchor').returncode, 1)

    def test_shuffle_revision_overflow_never_installs_target(self):
        self.shuffle_setup()
        job = self.prepared()
        self.resign_shuffle(2**64 - 1)
        before = self.assert_shuffle_catalog()
        self.assertEqual(self.recover(job).returncode, 1)
        self.assertEqual(self.map_current(), before)
        self.assertEqual(hashlib.sha256(self.active.read_bytes()).hexdigest(), self.source_hash)
        self.assertTrue(self.staged.exists())

    def test_shuffle_competing_recoveries_share_exact_catalog_cas(self):
        self.shuffle_setup()
        job = self.prepared()
        args = self.args('shuffle-recover', 'view', job, 1, self.current(), self.map_current())
        processes = []
        try:
            for _ in range(2):
                processes.append(subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE))
            for process in processes:
                process.communicate(timeout=30)
            self.assertEqual(sorted(p.returncode for p in processes), [0, 2])
        finally:
            for process in processes:
                if process.poll() is None:
                    process.kill()
                process.communicate()
        self.assertEqual(self.map_bind().returncode, 0)
        self.assert_shuffle_catalog()

    def test_shuffle_abort_crashes_keep_source_and_tombstone_is_final(self):
        self.shuffle_setup()
        job = self.prepared()
        for point in ('after-artifact-sync', 'after-write', 'after-commit'):
            self.assertEqual(self.recover(job, 0, env={'CDSE_CONTEXT_MANAGER_CRASH': point}).returncode, 86)
            self.assertEqual(self.map_bind().returncode, 0 if point == 'after-commit' else 1)
            self.assertEqual(hashlib.sha256(self.active.read_bytes()).hexdigest(), self.source_hash)
            self.assert_shuffle_catalog()
        self.assertEqual(self.recover(job, 0).returncode, 0)
        self.assertEqual(self.map_remove().returncode, 0)
        self.assertEqual(self.prepare().returncode, 1)
        self.assertEqual(self.recover(job, 0).returncode, 2)
        self.assertEqual(self.map_store(self.source_slots).returncode, 1)
        self.assert_shuffle_catalog()

    def test_shuffle_only_columnfile_role_and_explicit_upgrade(self):
        self.binding_family()
        self.map_init()
        self.assertEqual(self.command('shuffle-read', 'view', self.current(), self.map_current()).returncode, 1)
        self.assertEqual(self.command('shuffle-init', token(self.anchor), self.map_current()).returncode, 2)
        self.assertEqual(self.command('shuffle-init', self.current(), self.map_current()).returncode, 0)
        self.allocated(lookup='internal', level=2, role=1, table='internal', field='value', expected=self.current())
        slots = [('internal', 'internal', 1, 'value')]
        self.assertEqual(self.map_store(slots, name='internal', resource='internal', role=1).returncode, 0)
        self.assertEqual(self.command('shuffle-prepare', 'internal', '/missing/a', '/missing/b', '11' * 32,
                                     '22' * 32, self.current(), self.map_current(), 1, *slots[0]).returncode, 1)
        self.assert_shuffle_catalog()


# Reuse the fixture setup/helpers without running the inherited legacy suite twice.
for _name in tuple(vars(ManagerTests)):
    if _name.startswith('test_'):
        setattr(ShuffleTests, _name, None)


class PairShuffleTests(ShuffleTests):
    """Manager primitives only: payload registration validation remains an owner gate."""

    def pair_setup(self, upgrade=True):
        self.shuffle_setup()
        self.assertEqual(self.map_store(self.source_slots, name='other').returncode, 0)
        self.resources = self.active.with_name('ResourcesDB')
        self.staged_resources = self.staged.with_name('ResourcesDB')
        for path, mac in ((self.resources, 'source-mac'), (self.staged_resources, 'target-mac')):
            with closing(sqlite3.connect(path)) as db, db:
                db.execute('create table documents(id integer primary key, partMAC text)')
                db.execute('insert into documents values(1,?)', (mac,))
            path.chmod(0o600)
        self.resources_source = hashlib.sha256(self.resources.read_bytes()).hexdigest()
        self.resources_target = hashlib.sha256(self.staged_resources.read_bytes()).hexdigest()
        self.selection = hashlib.sha256(b'owner-reviewed-registration-and-profile').hexdigest()
        if upgrade:
            self.assertEqual(self.command('shuffle-pair-init', self.current(), self.map_current()).returncode, 0)
            self.assert_shuffle_catalog()

    def pair_prepare(self, env=None, **changes):
        slots = changes.get('slots', self.target_slots)
        args = [changes.get('name', 'view'), self.active, self.staged, self.source_hash, self.target_hash,
                changes.get('registry', self.current()), changes.get('catalog', self.map_current()), len(slots)]
        for slot in slots:
            args.extend(slot)
        args.extend((changes.get('resources', self.resources), changes.get('staged_resources', self.staged_resources),
                     changes.get('source', self.resources_source), changes.get('target', self.resources_target),
                     changes.get('selection', self.selection)))
        return self.command('shuffle-pair-prepare', *args, env=env)

    def pair_prepared(self):
        result = self.pair_prepare()
        self.assertEqual(result.returncode, 0, result.stderr)
        job, anchor = result.stdout.decode().splitlines()
        self.assertEqual(anchor, self.assert_shuffle_catalog())
        self.assertEqual(self.map_bind().returncode, 1)
        self.assertEqual(self.map_bind(name='other').returncode, 1)
        receipt = self.shuffle_read()
        self.assertTrue(receipt['paired'])
        self.assertEqual(receipt['selection'], self.selection)
        self.assertEqual(receipt['resourcesSource'], self.resources_source)
        self.assertEqual(receipt['resourcesTarget'], self.resources_target)
        return job

    def pair_recover(self, job, complete=1, env=None, catalog=None):
        return self.command('shuffle-pair-recover', 'view', job, complete, self.current(),
                            catalog or self.map_current(), env=env)

    def assert_sources(self):
        self.assertEqual(hashlib.sha256(self.active.read_bytes()).hexdigest(), self.source_hash)
        self.assertEqual(hashlib.sha256(self.resources.read_bytes()).hexdigest(), self.resources_source)

    def assert_targets(self):
        self.assertEqual(hashlib.sha256(self.active.read_bytes()).hexdigest(), self.target_hash)
        self.assertEqual(hashlib.sha256(self.resources.read_bytes()).hexdigest(), self.resources_target)
        self.assertEqual(self.map_bind().returncode, 0)
        self.assertEqual(self.map_bind(name='other').returncode, 0)
        self.assert_shuffle_catalog()

    def test_pair_complete_receipt_and_single_file_refusal(self):
        self.pair_setup()
        registry = self.current()
        job = self.pair_prepared()
        self.assertEqual(self.recover(job).returncode, 1)
        self.assertEqual(self.recover(job, 0).returncode, 1)
        self.assert_sources()
        self.assertEqual(self.pair_recover(job, env={'CDSE_CONTEXT_MANAGER_ALIAS': '1'}).returncode, 0)
        self.assert_targets()
        self.assertEqual(self.current(), registry)
        self.assertFalse(self.staged.exists())
        self.assertFalse(self.staged_resources.exists())
        before = self.map_current()
        self.assertEqual(self.pair_recover(job).returncode, 0)
        self.assertEqual(self.map_current(), before)
        self.assertEqual(self.pair_recover(job, 0).returncode, 1)
        self.assertEqual(self.shuffle_read()['state'], 2)

    def test_pair_abort_requires_sources_and_can_replace_receipt(self):
        self.pair_setup()
        job = self.pair_prepared()
        self.assertEqual(self.pair_recover(job, 0).returncode, 0)
        self.assert_sources()
        self.assertEqual(self.shuffle_read()['state'], 3)
        before = self.map_current()
        self.assertEqual(self.pair_recover(job, 0).returncode, 0)
        self.assertEqual(self.map_current(), before)
        self.assertEqual(self.map_bind(name='other').returncode, 0)
        new_job = self.pair_prepared()
        self.assertNotEqual(new_job, job)
        self.assertEqual(self.pair_recover(job).returncode, 1)
        self.assertEqual(self.pair_recover(new_job).returncode, 0)
        self.assert_targets()

    def test_pair_global_block_and_no_parallel_intents(self):
        self.pair_setup()
        job = self.pair_prepared()
        self.assertEqual(self.map_store(self.source_slots, name='other').returncode, 1)
        self.assertEqual(self.map_store(self.source_slots, name='new').returncode, 1)
        self.assertEqual(self.map_remove(name='other').returncode, 1)
        self.assertEqual(self.prepare(name='other').returncode, 1)
        self.assertEqual(self.pair_prepare(name='other').returncode, 1)
        self.assertEqual(self.pair_recover(job, 0).returncode, 0)
        single = self.prepared()
        self.assertEqual(self.pair_prepare(name='other').returncode, 1)
        self.assertEqual(self.pair_recover(single).returncode, 1)
        self.assertEqual(self.recover(single, 0).returncode, 0)

    def test_pair_explicit_upgrade_requires_idle_v2(self):
        self.pair_setup(upgrade=False)
        self.assertEqual(self.pair_prepare().returncode, 1)
        single = self.prepared()
        self.assertEqual(self.command('shuffle-pair-init', self.current(), self.map_current()).returncode, 1)
        self.assertEqual(self.recover(single, 0).returncode, 0)
        self.assertEqual(self.command('shuffle-pair-init', self.current(), self.map_current()).returncode, 0)
        self.assertEqual(self.command('shuffle-pair-init', self.current(), self.map_current()).returncode, 1)
        self.assert_shuffle_catalog()

    def test_pair_rejects_bad_paths_digests_selection_and_permutation(self):
        self.pair_setup()
        before = self.map_current()
        for changes in ({'resources': self.active}, {'staged_resources': self.resources},
                        {'resources': self.resources.parent / '..' / 'export' / 'ResourcesDB'},
                        {'selection': '00' * 32}, {'source': '00' * 32}, {'target': self.resources_source},
                        {'slots': self.source_slots[:1]}, {'catalog': '00' * 40}):
            with self.subTest(changes=changes):
                self.assertNotEqual(self.pair_prepare(**changes).returncode, 0)
                self.assertEqual(self.map_current(), before)
                self.assert_sources()

    def test_pair_rejects_unsafe_companion_and_sidecars(self):
        self.pair_setup()
        for path in (self.resources, self.staged_resources):
            path.chmod(0o644)
            self.assertEqual(self.pair_prepare().returncode, 1)
            path.chmod(0o600)
            for suffix in ('-wal', '-shm', '-journal'):
                sidecar = Path(str(path) + suffix)
                sidecar.touch()
                self.assertEqual(self.pair_prepare().returncode, 1)
                sidecar.unlink()
        self.assert_sources()

    def test_pair_checks_both_candidates_before_first_install(self):
        self.pair_setup()
        job = self.pair_prepared()
        saved = self.staged_resources.read_bytes()
        self.staged_resources.write_bytes(self.resources.read_bytes())
        self.assertEqual(self.pair_recover(job).returncode, 1)
        self.assert_sources()
        self.assertEqual(self.map_bind(name='other').returncode, 1)
        self.staged_resources.write_bytes(saved)
        self.assertEqual(self.pair_recover(job).returncode, 0)
        self.assert_targets()

    def test_pair_resources_first_state_rejected(self):
        self.pair_setup()
        job = self.pair_prepared()
        self.staged_resources.replace(self.resources)
        self.assertEqual(self.pair_recover(job).returncode, 1)
        self.assertEqual(self.pair_recover(job, 0).returncode, 1)
        self.assertEqual(self.map_bind(name='other').returncode, 1)

    def test_pair_partial_unknown_bytes_remain_blocked(self):
        self.pair_setup()
        job = self.pair_prepared()
        self.staged.replace(self.active)
        saved = self.resources.read_bytes()
        with closing(sqlite3.connect(self.resources)) as db, db:
            db.execute("update documents set partMAC='unknown'")
        self.assertEqual(self.pair_recover(job).returncode, 1)
        self.assertEqual(self.map_bind(name='other').returncode, 1)
        self.resources.write_bytes(saved)
        self.assertEqual(self.pair_recover(job, 0).returncode, 1)
        self.assertEqual(self.pair_recover(job).returncode, 0)
        self.assert_targets()

    def test_pair_receipt_requires_both_active_digests_and_exact_revision(self):
        self.pair_setup()
        job = self.pair_prepared()
        self.assertEqual(self.pair_recover(job).returncode, 0)
        saved = self.resources.read_bytes()
        with closing(sqlite3.connect(self.resources)) as db, db:
            db.execute("update documents set partMAC='unknown'")
        self.assertEqual(self.pair_recover(job).returncode, 1)
        self.resources.write_bytes(saved)
        self.assertEqual(self.pair_recover(job).returncode, 0)
        self.assertEqual(self.map_store(self.target_slots, name='other').returncode, 0)
        self.assertEqual(self.pair_recover(job).returncode, 2)

    def test_pair_tampering_and_missing_table_fail_authentication(self):
        self.pair_setup()
        self.pair_prepared()
        saved = (self.authority / 'registry.sqlite').read_bytes()
        for mutation in ("update context_shuffle_pairs set selection=zeroblob(32)",
                         "update context_shuffle_pairs set active_path=staged_path",
                         "update context_shuffle_pairs set source=target",
                         "update context_shuffle_pairs set map_name='orphan'",
                         "update registry_meta set pair_version=2", "drop table context_shuffle_pairs"):
            with self.subTest(mutation=mutation):
                with closing(sqlite3.connect(self.authority / 'registry.sqlite')) as db, db:
                    db.execute('pragma ignore_check_constraints=on')
                    db.execute(mutation)
                self.assertEqual(self.command('map-anchor').returncode, 1)
                self.assertEqual(self.map_bind(name='other', catalog='00' * 40).returncode, 1)
                (self.authority / 'registry.sqlite').write_bytes(saved)
        self.assert_shuffle_catalog()

    def test_pair_competing_completion_cas(self):
        self.pair_setup()
        job = self.pair_prepared()
        args = self.args('shuffle-pair-recover', 'view', job, 1, self.current(), self.map_current())
        with subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as first, \
                subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as second:
            first.communicate(timeout=30)
            second.communicate(timeout=30)
            self.assertEqual(sorted((first.returncode, second.returncode)), [0, 2])
        self.assert_targets()

    def test_pair_companion_links_missing_candidate_and_abort(self):
        self.pair_setup()
        saved = self.staged_resources.read_bytes()
        self.staged_resources.unlink()
        self.staged_resources.symlink_to(self.resources)
        self.assertEqual(self.pair_prepare().returncode, 1)
        self.staged_resources.unlink()
        os.link(self.resources, self.staged_resources)
        self.assertEqual(self.pair_prepare().returncode, 1)
        self.staged_resources.unlink()
        self.staged_resources.write_bytes(saved)
        self.staged_resources.chmod(0o600)
        job = self.pair_prepared()
        self.staged_resources.unlink()
        self.assertEqual(self.pair_recover(job).returncode, 1)
        self.assert_sources()
        self.assertEqual(self.pair_recover(job, 0).returncode, 0)
        self.assert_sources()

    def test_pair_revocation_before_install_leaves_sources(self):
        self.pair_setup()
        job = self.pair_prepared()
        self.assertEqual(self.command('revoke', 'first', self.current()).returncode, 0)
        self.assertEqual(self.pair_recover(job).returncode, 1)
        self.assert_sources()
        self.assertEqual(self.pair_recover(job, 0).returncode, 0)

    def resign_pair(self, revision):
        maps, slots, _, _ = self.catalog_rows()
        with closing(sqlite3.connect(self.authority / 'registry.sqlite')) as db, db:
            jobs = db.execute('select * from context_shuffles').fetchall()
            targets = db.execute('select * from context_shuffle_slots').fetchall()
            pairs = db.execute('select * from context_shuffle_pairs').fetchall()
            body = catalog_bytes(self.anchor.deployment, self.anchor.organization, revision, maps, slots, jobs, targets, pairs)
            db.execute('update context_map_head set revision=?,tag=?',
                       (struct.pack('>Q', revision), hmac.digest(b'k' * 32, body, 'sha256')))

    def test_pair_revision_overflow_never_installs(self):
        self.pair_setup()
        job = self.pair_prepared()
        self.resign_pair(2**64 - 1)
        self.assert_shuffle_catalog()
        self.assertEqual(self.pair_recover(job).returncode, 1)
        self.assertEqual(self.pair_recover(job, 0).returncode, 1)
        self.assert_sources()
        self.assertEqual(self.map_bind(name='other').returncode, 1)

    def test_pair_signed_invalid_metadata_rejected(self):
        self.pair_setup()
        self.pair_prepared()
        database = self.authority / 'registry.sqlite'
        saved = database.read_bytes()
        revision = self.catalog_rows()[2]
        for mutation in ("update context_shuffle_pairs set selection=zeroblob(32)",
                         "update context_shuffle_pairs set active_path=active_path||char(0)||'extra'",
                         "update context_shuffle_pairs set active_path=replace(active_path,'ResourcesDB','other')",
                         "update context_shuffle_pairs set staged_path=active_path",
                         "update context_shuffle_pairs set target=source",
                         "update context_shuffle_pairs set map_name='orphan'"):
            with self.subTest(mutation=mutation):
                with closing(sqlite3.connect(database)) as db, db:
                    db.execute(mutation)
                self.resign_pair(revision)
                self.assertEqual(self.command('map-anchor').returncode, 1)
                database.write_bytes(saved)
        self.assert_shuffle_catalog()

    def test_pair_witness_advancement_and_lost_ack_remain_explicit(self):
        self.pair_setup()
        witness = self.root / 'witness'
        witness.mkdir(mode=0o700)

        def wcommand(action, *args, env=None):
            return self.command(action, *args, directory=witness, env=env)

        initial = wcommand('witness-init', self.current(), self.map_current())
        self.assertEqual(initial.returncode, 0)
        retained = initial.stdout.decode().strip()
        job = self.pair_prepared()
        self.assertEqual(wcommand('witness-anchor').stdout.decode().strip(), retained)
        self.assertEqual(wcommand('witness-reconcile', self.current(), self.map_current(), retained).stdout.decode().splitlines(),
                         ['2', retained])
        advance = wcommand('witness-advance', self.current(), self.map_current(), retained,
                           env={'CDSE_CONTEXT_WITNESS_CRASH': 'after-commit'})
        self.assertEqual(advance.returncode, 86)
        current = wcommand('witness-anchor').stdout.decode().strip()
        self.assertEqual(wcommand('witness-reconcile', self.current(), self.map_current(), retained).stdout.decode().splitlines(),
                         ['3', current])
        self.assertEqual(self.pair_recover(job, env={'CDSE_CONTEXT_MANAGER_CRASH': 'after-column-install'}).returncode, 86)
        self.assertEqual(wcommand('witness-reconcile', self.current(), self.map_current(), current).stdout.decode().splitlines(),
                         ['1', current])
        self.assertEqual(self.map_bind(name='other').returncode, 1)
        self.assertEqual(self.pair_recover(job).returncode, 0)
        self.assertEqual(wcommand('witness-anchor').stdout.decode().strip(), current)
        self.assertEqual(wcommand('witness-reconcile', self.current(), self.map_current(), current).stdout.decode().splitlines(),
                         ['2', current])
        self.assertEqual(wcommand('witness-advance', self.current(), self.map_current(), current).returncode, 0)
        self.assert_targets()

    def check_pair_rename_crash(self, checkpoint):
        self.pair_setup()
        job = self.pair_prepared()
        result = self.pair_recover(job, env={'CDSE_CONTEXT_OFFLINE_CRASH': checkpoint})
        self.assertEqual(result.returncode, 86)
        self.assertEqual(self.map_bind(name='other').returncode, 1)
        self.assertEqual(self.pair_recover(job, 0).returncode, 1)
        self.assertEqual(self.pair_recover(job).returncode, 0)
        self.assert_targets()

    def test_pair_crash_after_column_rename_before_sync(self):
        self.check_pair_rename_crash('after-rename')

    def test_pair_crash_after_resources_rename_before_sync(self):
        self.check_pair_rename_crash('after-resources-rename')

    def check_pair_crash(self, action, checkpoint):
        self.pair_setup(upgrade=action != 'init')
        before = self.map_current()
        env = {'CDSE_CONTEXT_MANAGER_CRASH': checkpoint}
        if action == 'init':
            result = self.command('shuffle-pair-init', self.current(), before, env=env)
        elif action == 'prepare':
            result = self.pair_prepare(env=env)
        else:
            job = self.pair_prepared()
            result = self.pair_recover(job, int(action != 'abort'), env=env)
        self.assertEqual(result.returncode, 86, result.stderr)
        self.assert_shuffle_catalog()
        if action in ('init', 'prepare'):
            self.assert_sources()
            if checkpoint != 'after-commit':
                self.assertEqual(self.map_current(), before)
                self.assertEqual(self.map_bind().returncode, 0)
                return
            if action == 'init':
                self.assertEqual(self.map_bind().returncode, 0)
                return
            job = self.shuffle_read()['job']
        if checkpoint != 'after-commit' or action == 'prepare':
            self.assertEqual(self.map_bind(name='other').returncode, 1)
        if action == 'abort':
            self.assertEqual(self.pair_recover(job, 0).returncode, 0)
            self.assert_sources()
        else:
            if action == 'complete' and checkpoint in ('after-column-install', 'after-resources-install',
                                                       'after-artifact-sync', 'after-write', 'after-commit'):
                self.assertEqual(self.pair_recover(job, 0).returncode, 1)
            self.assertEqual(self.pair_recover(job).returncode, 0)
            self.assert_targets()


for _name in tuple(vars(ShuffleTests)):
    if _name.startswith('test_'):
        setattr(PairShuffleTests, _name, None)

for _action, _points in (
        ('init', ('after-begin', 'after-write', 'after-commit')),
        ('prepare', ('after-begin', 'after-write', 'after-commit')),
        ('complete', ('after-begin', 'after-column-install', 'after-resources-install',
                      'after-artifact-sync', 'after-write', 'after-commit')),
        ('abort', ('after-begin', 'after-column-install', 'after-resources-install',
                   'after-artifact-sync', 'after-write', 'after-commit'))):
    for _point in _points:
        def _crash_case(self, action=_action, point=_point):
            self.check_pair_crash(action, point)
        setattr(PairShuffleTests, 'test_pair_crash_' + _action + '_' + _point.replace('-', '_'), _crash_case)


class CopyProvisionTests(ManagerTests):
    def copy_setup(self):
        self.binding_family()
        self.map_init()
        self.source_slots = [('first', 'data', 10, 'value'), ('field', 'data', 10, 'other'),
                             ('second', 'data', 20, 'value'), ('meta', 'meta', 10, 'attribute')]
        self.assertEqual(self.map_store(self.source_slots).returncode, 0)
        self.ordered = json.loads(self.map_read().stdout)['slots']
        self.lookups = [f'copy/{i}' for i in range(len(self.ordered))]

    def copy_args(self, names=None, registry=None, catalog=None, name='view'):
        lookups = self.lookups if names is None else names
        return [name, registry or self.current(), catalog or self.map_current(), len(lookups), *lookups]

    def copy_provision(self, env=None, **changes):
        return self.command('copy-provision', *self.copy_args(**changes), env=env)

    def copy_snapshot(self):
        with closing(sqlite3.connect(self.authority / 'registry.sqlite')) as db:
            body, tag = db.execute('select body,tag from registry_current').fetchone()
        snapshot = json.loads(body)
        canonical, expected_tag, anchor = contract.issue(snapshot, b'k' * 32)
        self.assertEqual(body, canonical)
        self.assertEqual(tag, expected_tag)
        self.assertEqual(self.current(), token(anchor))
        return snapshot

    def copied(self, **options):
        before = self.copy_snapshot()
        catalog = self.map_current()
        result = self.copy_provision(**options)
        self.assertEqual(result.returncode, 0, result.stderr)
        descriptor = json.loads(result.stdout)
        after = self.copy_snapshot()
        self.assertEqual(descriptor['registry'], self.current())
        self.assertEqual(after['generation'], before['generation'] + 1)
        self.assertEqual(self.map_current(), catalog)
        old = {entry['lookup']: entry for entry in before['entries']}
        new = {entry['lookup']: entry for entry in after['entries']}
        for lookup, entry in old.items():
            self.assertEqual(new[lookup], entry)
        self.assertEqual(len(new), len(old) + len(self.lookups))
        old_ids = {entry['context'][key] for entry in old.values() for key in contract.UUID_FIELDS}
        records = {}
        resource = None
        for source_slot, target_slot in zip(self.ordered, descriptor['slots']):
            source = old[source_slot[0]]['context']
            target = new[target_slot[0]]['context']
            self.assertEqual(source_slot[1:], target_slot[1:])
            for key in ('deployment', 'organization', 'storage', 'role', 'table', 'field'):
                self.assertEqual(source[key], target[key])
            if resource is None:
                resource = target['resource']
            self.assertEqual(target['resource'], resource)
            self.assertNotIn(target['resource'], old_ids)
            self.assertNotIn(target['record'], old_ids)
            self.assertNotEqual(target['resource'], target['record'])
            for key in ('resource', 'record'):
                value = uuid.UUID(hex=target[key])
                self.assertEqual(value.version, 4)
                self.assertEqual(value.variant, uuid.RFC_4122)
            group = tuple(source_slot[1:3])
            if group in records:
                self.assertEqual(records[group], target['record'])
            else:
                self.assertNotIn(target['record'], records.values())
                records[group] = target['record']
        self.assertEqual(descriptor['resource'], self.lookups[0])
        self.assertEqual(descriptor['role'], 4)
        self.assertEqual([slot[0] for slot in descriptor['slots']], self.lookups)
        return descriptor

    def test_copy_allocates_one_fresh_resource_and_grouped_records(self):
        self.copy_setup()
        descriptor = self.copied(env={'CDSE_CONTEXT_MANAGER_ALIAS': '1'})
        self.assertEqual(self.map_bind().returncode, 0)
        self.assertEqual(self.map_read(name='copy').returncode, 1)  # No catalog publication yet.
        self.assertEqual(self.map_store(descriptor['slots'], name='copy', resource=descriptor['resource']).returncode, 0)
        self.assertEqual(self.map_bind(name='copy').returncode, 0)
        self.assertEqual(self.bind(descriptor['slots'], resource='first').returncode, 1)
        self.assertEqual(self.bind(self.source_slots, resource=descriptor['resource']).returncode, 1)
        self.assert_catalog()

    def test_copy_reopen_cas_and_no_blind_retry_after_commit(self):
        self.copy_setup()
        before = self.current()
        self.copied()
        committed = self.current()
        self.assertEqual(self.copy_provision(registry=before).returncode, 2)
        self.assertEqual(self.copy_provision().returncode, 1)
        self.assertEqual(self.current(), committed)
        self.assertEqual(self.command('read', self.lookups[-1]).returncode, 0)

    def test_copy_invalid_names_counts_stale_pins_and_scope_fail_without_ids(self):
        self.copy_setup()
        before = self.copy_snapshot()
        for changes in (dict(names=[]), dict(names=self.lookups[:-1]), dict(names=['same'] * 4),
                        dict(names=['invalid name', *self.lookups[1:]]), dict(names=[None]),
                        dict(names=['first', *self.lookups[1:]]), dict(name='missing'),
                        dict(registry='00' * 73), dict(catalog='00' * 40)):
            with self.subTest(changes=changes):
                self.assertNotEqual(self.copy_provision(**changes).returncode, 0)
                self.assertEqual(self.copy_snapshot(), before)

    def test_copy_retained_tombstones_are_not_reused(self):
        self.copy_setup()
        self.allocated(lookup='retired', level=2, parent='first', expected=self.current())
        self.assertEqual(self.command('revoke', 'retired', self.current()).returncode, 0)
        before = self.copy_snapshot()
        self.assertEqual(self.copy_provision(names=['retired', *self.lookups[1:]]).returncode, 1)
        self.assertEqual(self.copy_snapshot(), before)

    def test_copy_revoked_removed_and_internal_maps_fail(self):
        self.copy_setup()
        self.allocated(lookup='internal', level=2, role=1, table='users', field='value', expected=self.current())
        self.assertEqual(self.map_store([('internal', 'users', 1, 'value')], name='internal', resource='internal', role=1).returncode, 0)
        self.assertEqual(self.copy_provision(name='internal', names=['new/internal']).returncode, 1)
        self.assertEqual(self.command('revoke', 'first', self.current()).returncode, 0)
        self.assertEqual(self.copy_provision().returncode, 1)
        self.assertEqual(self.map_remove().returncode, 0)
        self.assertEqual(self.copy_provision().returncode, 1)

    def test_copy_rng_failure_and_retained_or_batch_collisions_are_atomic(self):
        self.copy_setup()
        before = self.copy_snapshot()
        for mode in ('fail', 'collision', 'aa' * 16):
            with self.subTest(mode=mode):
                self.assertEqual(self.copy_provision(env={'CDSE_CONTEXT_MANAGER_RANDOM': mode}).returncode, 1)
                self.assertEqual(self.copy_snapshot(), before)
        self.copied()

    def test_copy_floor_two_and_generation_overflow_refuse_allocation(self):
        self.copy_setup()
        snapshot = self.copy_snapshot()
        _, _, anchor = contract.issue(snapshot, b'k' * 32)
        raised = dict(snapshot, generation=snapshot['generation'] + 1, minimumFormat=2)
        self.assertEqual(self.publish(raised, anchor).returncode, 0)
        self.assertEqual(self.copy_provision().returncode, 1)
        database = self.authority / 'registry.sqlite'
        maximum = dict(raised, generation=2**64 - 1, minimumFormat=1)
        body, tag, anchor = contract.issue(maximum, b'k' * 32)
        with closing(sqlite3.connect(database)) as db, db:
            db.execute('update registry_current set body=?,tag=?,anchor=?', (body, tag, bytes.fromhex(token(anchor))))
        self.assertEqual(self.copy_provision().returncode, 1)
        self.assertEqual(self.copy_snapshot(), maximum)

    def test_copy_witness_separates_registry_and_catalog_publications(self):
        self.copy_setup()
        witness = self.root / 'witness'
        witness.mkdir(mode=0o700)
        first = self.command('witness-init', self.current(), self.map_current(), directory=witness)
        self.assertEqual(first.returncode, 0)
        retained = first.stdout.decode().strip()
        descriptor = self.copied()
        self.assertEqual(self.command('witness-check', self.current(), self.map_current(), directory=witness).returncode, 2)
        advanced = self.command('witness-advance', self.current(), self.map_current(), retained, directory=witness)
        self.assertEqual(advanced.returncode, 0)
        self.assertEqual(self.map_store(descriptor['slots'], name='copy', resource=descriptor['resource']).returncode, 0)
        self.assertEqual(self.command('witness-advance', self.current(), self.map_current(),
                                      advanced.stdout.decode().strip(), directory=witness).returncode, 0)

    def test_copy_pending_shuffle_blocks_identity_allocation(self):
        self.copy_setup()
        self.assertEqual(self.command('shuffle-init', self.current(), self.map_current()).returncode, 0)
        active, staged = self.root / 'export' / 'column.sqlite', self.root / 'staging' / 'column.sqlite'
        for path, order in ((active, (10, 20)), (staged, (20, 10))):
            path.parent.mkdir(mode=0o700)
            with closing(sqlite3.connect(path)) as db, db:
                db.execute('create table data(value text, other text)')
                db.execute('create table meta(attribute text)')
                db.executemany('insert into data(rowid,value,other) values(?,?,?)',
                               [(row, str(index), 'field') for index, row in enumerate(order)])
                db.execute("insert into meta(rowid,attribute) values(10,'meta')")
            path.chmod(0o600)
        slots = [(lookup, table, 30-row if table == 'data' else row, field)
                 for lookup, table, row, field in self.source_slots]
        args = ['view', active, staged, hashlib.sha256(active.read_bytes()).hexdigest(),
                hashlib.sha256(staged.read_bytes()).hexdigest(), self.current(), self.map_current(), len(slots)]
        for slot in slots:
            args.extend(slot)
        self.assertEqual(self.command('shuffle-prepare', *args).returncode, 0)
        before = self.copy_snapshot()
        self.assertEqual(self.copy_provision().returncode, 1)
        self.assertEqual(self.copy_snapshot(), before)

    def test_copy_encoding_capacity_never_leaves_partial_allocations(self):
        self.copy_setup()
        original = self.copy_snapshot()
        extra = [dict(lookup=f'capacity/{i:04}', state='active',
                      context=dict(original['entries'][0]['context'], record=(i + 1000).to_bytes(16, 'big').hex()))
                 for i in range(contract.MAX_ENTRIES)]
        low, high = 0, len(extra)
        while low < high:
            middle = (low + high + 1) // 2
            try:
                contract.canonical(dict(original, entries=sorted(original['entries'] + extra[:middle], key=lambda e: e['lookup'])))
                low = middle
            except ValueError:
                high = middle - 1
        full = dict(original, generation=original['generation'] + 1,
                    entries=sorted(original['entries'] + extra[:low], key=lambda e: e['lookup']))
        _, _, anchor = contract.issue(original, b'k' * 32)
        self.assertEqual(self.publish(full, anchor).returncode, 0)
        self.assertEqual(self.copy_provision().returncode, 1)
        self.assertEqual(self.copy_snapshot(), full)

    def test_copy_final_publication_rechecks_both_pins_against_concurrent_writers(self):
        self.copy_setup()
        database = self.authority / 'registry.sqlite'
        saved = database.read_bytes()
        for change in ('catalog', 'remove', 'registry'):
            with self.subTest(change=change):
                database.write_bytes(saved)
                ready_read, ready_write = os.pipe()
                resume_read, resume_write = os.pipe()
                try:
                    env = dict(os.environ, CDSE_CONTEXT_MANAGER_PAUSE='copy-before-publish',
                               CDSE_CONTEXT_MANAGER_READY_FD=str(ready_write), CDSE_CONTEXT_MANAGER_RESUME_FD=str(resume_read))
                    with subprocess.Popen(self.args('copy-provision', *self.copy_args()), env=env,
                                          pass_fds=(ready_write, resume_read), stdout=subprocess.PIPE, stderr=subprocess.PIPE) as child:
                        try:
                            self.assertTrue(select.select([ready_read], [], [], 30)[0])
                            self.assertEqual(os.read(ready_read, 1), b'1')
                            if change == 'catalog':
                                self.assertEqual(self.map_store(self.source_slots).returncode, 0)
                            elif change == 'remove':
                                self.assertEqual(self.map_remove().returncode, 0)
                            else:
                                self.assertEqual(self.command('revoke', 'first', self.current()).returncode, 0)
                            os.write(resume_write, b'1')
                            child.communicate(timeout=30)
                            self.assertEqual(child.returncode, 2)
                        finally:
                            if child.poll() is None:
                                child.kill()
                                child.communicate(timeout=30)
                    self.assertTrue(all(not e['lookup'].startswith('copy/') for e in self.copy_snapshot()['entries']))
                finally:
                    for fd in (ready_read, ready_write, resume_read, resume_write):
                        os.close(fd)

    def test_owner_slot_shuffle_retains_ids_before_copy(self):
        self.copy_setup()
        before = self.copy_snapshot()
        self.source_slots = [(lookup, table, row + 100, field) for lookup, table, row, field in self.source_slots]
        self.assertEqual(self.map_store(self.source_slots).returncode, 0)
        self.assertEqual(self.copy_snapshot(), before)
        self.ordered = json.loads(self.map_read().stdout)['slots']
        self.copied()

    def test_rename_and_copy_preserve_legacy_readback_without_v2_claim(self):
        self.copy_setup()
        payload = str(Path(os.environ.get('CDSE_CONTEXT_OWNER_PAYLOAD', './reprotect-fixture')).resolve())
        admin = str(Path(os.environ.get('CDSE_CONTEXT_OWNER_ADMIN', './caumedse-admin')).resolve())
        artifact = self.root / 'legacy.sqlite'
        self.assertEqual(subprocess.run([payload, str(artifact), 'normal'], capture_output=True, timeout=30).returncode, 0)
        renamed = self.root / 'renamed.sqlite'
        artifact.rename(renamed)
        legacy_bytes = renamed.read_bytes()
        target = self.root / 'copied.sqlite'
        shutil.copyfile(renamed, target)
        key = self.root / 'org.key'
        key.write_text('fixture-source-key\n')
        key.chmod(0o600)
        descriptor = self.copied()
        self.assertEqual(target.read_bytes(), legacy_bytes)
        for path in (renamed, target):
            path.chmod(0o600)
            result = subprocess.run([admin, 'reprotect-columnfile', '--database', str(path), '--confirmed-scope', str(path),
                                     '--source-key-file', str(key), '--target-key-file', str(key),
                                     '--target-profile', 'aes-256-gcm', '--dry-run'], capture_output=True, timeout=30)
            self.assertEqual(result.returncode, 0, 'legacy persisted readback failed')
        self.assertNotEqual(descriptor['resource'], 'first')

    def check_copy_crash(self, point):
        self.copy_setup()
        before = self.copy_snapshot()
        result = self.copy_provision(env={'CDSE_CONTEXT_MANAGER_CRASH': point})
        self.assertEqual(result.returncode, 86)
        after = self.copy_snapshot()
        if point == 'after-commit':
            self.assertEqual(len(after['entries']), len(before['entries']) + len(self.lookups))
            self.assertEqual(after['generation'], before['generation'] + 1)
        else:
            self.assertEqual(after, before)
            self.copied()


for _name in tuple(vars(ManagerTests)):
    if _name.startswith('test_'):
        setattr(CopyProvisionTests, _name, None)

for _point in ('after-copy-entry', 'copy-before-publish', 'after-begin', 'after-write', 'after-commit'):
    def _copy_crash_case(self, point=_point):
        self.check_copy_crash(point)
    setattr(CopyProvisionTests, 'test_copy_crash_' + _point.replace('-', '_'), _copy_crash_case)


class CopyPlanTests(CopyProvisionTests):
    def plan_setup(self):
        self.copy_setup()
        self.plan_registry = self.current()
        self.plan_catalog = self.map_current()
        self.plan_path = self.root / 'allocation.plan'
        self.prepare_plan()

    def prepare_plan(self, path=None, names=None):
        result = self.command('copy-plan-prepare', *self.copy_args(names=names))
        self.assertEqual(result.returncode, 0, result.stderr)
        digest, plan = result.stdout[:32], result.stdout[32:]
        self.assertEqual(digest, hashlib.sha256(plan).digest())
        path = path or self.plan_path
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(descriptor, 'wb') as output:
            output.write(plan)
            output.flush()
            os.fsync(output.fileno())
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        if path == self.plan_path:
            self.plan_digest = digest.hex()
        return digest.hex(), plan

    def plan_action(self, action='status', path=None, digest=None, registry=None, catalog=None, witness=None, env=None):
        args = [path or self.plan_path, digest or self.plan_digest,
                registry or self.plan_registry, catalog or self.plan_catalog]
        if witness is not None:
            action = 'guard'
            args.extend(witness)
        return self.command('copy-plan-' + action, *args, env=env)

    def plan_result(self, action='status', **options):
        result = self.plan_action(action, **options)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def init_plan_witness(self):
        directory = self.root / 'copy-witness'
        directory.mkdir(mode=0o700)
        result = self.command('witness-init', self.current(), self.map_current(), directory=directory)
        self.assertEqual(result.returncode, 0)
        return directory, result.stdout.decode().strip()

    def decode_plan(self):
        plan = self.plan_path.read_bytes()
        self.assertEqual(plan[:17], b'CDSE-HKX-COPY-v1\0')
        self.assertEqual(plan[-32:], hmac.digest(b'k' * 32, plan[:-32], 'sha256'))
        offset = 17

        def take(length):
            nonlocal offset
            value = plan[offset:offset + length]
            self.assertEqual(len(value), length)
            offset += length
            return value

        def text():
            return take(take(1)[0]).decode('ascii')

        previous, catalog, following, snapshot_tag = take(73), take(40), take(73), take(32)
        source = text()
        slots = []
        for _ in range(struct.unpack('>I', take(4))[0]):
            lookup, table = text(), text()
            row = struct.unpack('>q', take(8))[0]
            slots.append([lookup, table, row, text()])
        snapshot = take(struct.unpack('>I', take(4))[0])
        self.assertEqual(offset, len(plan) - 32)
        body, tag, anchor = contract.issue(json.loads(snapshot), b'k' * 32)
        self.assertEqual(body, snapshot)
        self.assertEqual(tag, snapshot_tag)
        self.assertEqual(token(anchor), following.hex())
        self.assertEqual(previous.hex(), self.plan_registry)
        self.assertEqual(catalog.hex(), self.plan_catalog)
        self.assertEqual(source, 'view')
        return following.hex(), slots, json.loads(snapshot)

    def test_plan_preparation_is_read_only_and_independently_encoded(self):
        self.plan_setup()
        before = self.copy_snapshot()
        following, slots, candidate = self.decode_plan()
        self.assertEqual(self.copy_snapshot(), before)
        self.assertEqual(self.current(), self.plan_registry)
        self.assertEqual(self.map_current(), self.plan_catalog)
        self.assertEqual(candidate['generation'], before['generation'] + 1)
        self.assertEqual(len(candidate['entries']), len(before['entries']) + len(self.lookups))
        self.assertEqual([slot[0] for slot in slots], self.lookups)
        result = self.plan_result(env={'CDSE_CONTEXT_MANAGER_ALIAS': '1'})
        self.assertEqual(result, dict(state=1, registry=following, resource=self.lookups[0], slots=slots))
        self.assertEqual(self.map_read(name='copy').returncode, 1)

    def test_plan_commit_and_exact_retry_preserve_bytes_and_generation(self):
        self.plan_setup()
        following, slots, candidate = self.decode_plan()
        result = self.plan_result('commit', env={'CDSE_CONTEXT_MANAGER_ALIAS': '1'})
        self.assertEqual(result['registry'], following)
        self.assertEqual(result['slots'], slots)
        self.assertEqual(self.copy_snapshot(), candidate)
        committed = (self.authority / 'registry.sqlite').read_bytes()
        for action in ('status', 'commit', 'commit'):
            self.assertEqual(self.plan_result(action), result)
            self.assertEqual((self.authority / 'registry.sqlite').read_bytes(), committed)
        self.assertEqual(self.map_current(), self.plan_catalog)

    def test_plan_guard_requires_current_witness_and_never_advances_it(self):
        self.plan_setup()
        directory, retained = self.init_plan_witness()
        witness_bytes = (directory / 'witness.sqlite').read_bytes()
        result = self.plan_result(witness=(directory, retained))
        self.assertEqual((directory / 'witness.sqlite').read_bytes(), witness_bytes)
        self.assertEqual(self.plan_result(witness=(directory, retained)), result)
        self.assertEqual(self.command('witness-check', self.current(), self.map_current(), directory=directory).returncode, 2)
        advanced = self.command('witness-advance', self.current(), self.map_current(), retained, directory=directory)
        self.assertEqual(advanced.returncode, 0)
        for token_text in (retained, advanced.stdout.decode().strip()):
            self.assertEqual(self.plan_result(witness=(directory, token_text)), result)
        self.assertEqual(self.plan_action(witness=(directory, '00' * 40)).returncode, 1)

    def test_plan_guard_refuses_unapproved_witness_step_before_allocation(self):
        self.copy_setup()
        directory, retained = self.init_plan_witness()
        self.allocated(lookup='unrelated', level=3, parent='first', expected=self.current())
        self.plan_registry, self.plan_catalog = self.current(), self.map_current()
        self.plan_path = self.root / 'allocation.plan'
        self.prepare_plan()
        before = self.copy_snapshot()
        self.assertEqual(self.plan_action(witness=(directory, retained)).returncode, 2)
        self.assertEqual(self.copy_snapshot(), before)
        advanced = self.command('witness-advance', self.current(), self.map_current(), retained, directory=directory)
        self.assertEqual(advanced.returncode, 0)
        self.plan_result(witness=(directory, advanced.stdout.decode().strip()))

    def test_plan_competitors_cannot_adopt_each_others_allocations(self):
        self.plan_setup()
        second = self.root / 'other.plan'
        digest, plan = self.prepare_plan(second)
        self.assertNotEqual(plan, self.plan_path.read_bytes())
        self.plan_result('commit')
        committed = self.copy_snapshot()
        for action in ('status', 'commit'):
            self.assertEqual(self.plan_action(action, path=second, digest=digest).returncode, 2)
        self.assertEqual(self.copy_snapshot(), committed)

    def test_plan_stale_registry_catalog_and_source_removal_conflict(self):
        self.plan_setup()
        database = self.authority / 'registry.sqlite'
        saved = database.read_bytes()
        for change in ('registry', 'catalog', 'remove'):
            with self.subTest(change=change):
                database.write_bytes(saved)
                if change == 'registry':
                    self.assertEqual(self.command('revoke', 'first', self.current()).returncode, 0)
                elif change == 'catalog':
                    self.assertEqual(self.map_store(self.source_slots).returncode, 0)
                else:
                    self.assertEqual(self.map_remove().returncode, 0)
                for action in ('status', 'commit'):
                    self.assertEqual(self.plan_action(action).returncode, 2)
                self.assertFalse(any(e['lookup'].startswith('copy/') for e in self.copy_snapshot()['entries']))

    def test_plan_committed_receipt_expires_after_later_catalog_publication(self):
        self.plan_setup()
        descriptor = self.plan_result('commit')
        self.assertEqual(self.map_store(descriptor['slots'], name='copy', resource=descriptor['resource']).returncode, 0)
        for action in ('status', 'commit'):
            self.assertEqual(self.plan_action(action).returncode, 2)

    def test_plan_tampering_cannot_be_authorized_by_rehashing(self):
        self.plan_setup()
        original = self.plan_path.read_bytes()
        before = self.copy_snapshot()
        for offset in (0, 17, 90, 130, 203, len(original)//2, len(original)-1):
            with self.subTest(offset=offset):
                damaged = bytearray(original)
                damaged[offset] ^= 1
                self.plan_path.write_bytes(damaged)
                digest = hashlib.sha256(damaged).hexdigest()
                self.assertEqual(self.plan_action('commit', digest=digest).returncode, 1)
                self.assertEqual(self.copy_snapshot(), before)

    def test_plan_wrong_approval_digest_pins_and_key_refuse(self):
        self.plan_setup()
        for options in (dict(digest='00' * 32), dict(registry='00' * 73), dict(catalog='00' * 40),
                        dict(env={'CDSE_REGISTRY_WRONG_KEY': '1'})):
            self.assertEqual(self.plan_action('commit', **options).returncode, 1)
        self.assertEqual(self.current(), self.plan_registry)

    def test_plan_truncation_trailing_bytes_and_signed_unknown_domain_refuse(self):
        self.plan_setup()
        original = self.plan_path.read_bytes()
        mutated = bytearray(original)
        mutated[14] = ord('2')
        mutated[-32:] = hmac.digest(b'k' * 32, mutated[:-32], 'sha256')
        for plan in (b'', original[:100], original[:-1], original + b'\0', bytes(mutated)):
            self.plan_path.write_bytes(plan)
            self.assertEqual(self.plan_action('commit', digest=hashlib.sha256(plan).hexdigest()).returncode, 1)
        self.assertEqual(self.current(), self.plan_registry)

    def test_plan_preparation_rng_failure_has_no_reservation(self):
        self.copy_setup()
        before = self.copy_snapshot()
        for mode in ('fail', 'collision', 'aa' * 16):
            result = self.command('copy-plan-prepare', *self.copy_args(), env={'CDSE_CONTEXT_MANAGER_RANDOM': mode})
            self.assertEqual(result.returncode, 1)
            self.assertEqual(result.stdout, b'')
            self.assertEqual(self.copy_snapshot(), before)

    def test_plan_signed_invalid_counts_names_and_size_fail_closed(self):
        self.plan_setup()
        original = self.plan_path.read_bytes()
        variants = []
        for offset, value in ((235, b'\0'), (240, struct.pack('>I', 0)),
                              (240, struct.pack('>I', 4097)), (245, b'!'), (203, b'\0' * 32)):
            damaged = bytearray(original)
            damaged[offset:offset + len(value)] = value
            damaged[-32:] = hmac.digest(b'k' * 32, damaged[:-32], 'sha256')
            variants.append(damaged)
        offset = 244
        lookup_positions, row_positions = [], []
        for _ in self.lookups:
            lookup_positions.append((offset + 1, original[offset]))
            offset += 1 + original[offset]
            offset += 1 + original[offset]
            row_positions.append(offset)
            offset += 8
            offset += 1 + original[offset]
        for position, value in ((offset, struct.pack('>I', len(original))),
                                (lookup_positions[1][0], original[lookup_positions[0][0]:
                                  lookup_positions[0][0] + lookup_positions[0][1]]),
                                (row_positions[1], struct.pack('>q', -(2**63)))):
            damaged = bytearray(original)
            damaged[position:position + len(value)] = value
            damaged[-32:] = hmac.digest(b'k' * 32, damaged[:-32], 'sha256')
            variants.append(damaged)
        variants.append(b'\0' * (2 * contract.MAX_BYTES + 33))
        for plan in variants:
            self.plan_path.write_bytes(plan)
            self.assertEqual(self.plan_action('commit', digest=hashlib.sha256(plan).hexdigest()).returncode, 1)
        self.assertEqual(self.current(), self.plan_registry)

    def test_plan_signed_slot_extremes_round_trip(self):
        self.copy_setup()
        self.source_slots = [(lookup, table, -(2**63) if row == 10 else 2**63-1, field)
                             for lookup, table, row, field in self.source_slots]
        self.assertEqual(self.map_store(self.source_slots).returncode, 0)
        self.ordered = json.loads(self.map_read().stdout)['slots']
        self.plan_registry, self.plan_catalog = self.current(), self.map_current()
        self.plan_path = self.root / 'allocation.plan'
        self.prepare_plan()
        _, slots, _ = self.decode_plan()
        self.assertEqual(self.plan_result('commit')['slots'], slots)
        self.assertEqual([slot[1:] for slot in slots], [slot[1:] for slot in self.ordered])

    def test_plan_guard_rejects_rolled_back_witness_with_retained_new_token(self):
        self.plan_setup()
        directory, retained = self.init_plan_witness()
        database = directory / 'witness.sqlite'
        old = database.read_bytes()
        self.plan_result(witness=(directory, retained))
        advanced = self.command('witness-advance', self.current(), self.map_current(), retained, directory=directory)
        self.assertEqual(advanced.returncode, 0)
        database.write_bytes(old)
        before = self.copy_snapshot()
        self.assertEqual(self.plan_action(witness=(directory, advanced.stdout.decode().strip())).returncode, 2)
        self.assertEqual(self.copy_snapshot(), before)

    def test_plan_committed_retry_refuses_divergent_previous_witness_digest(self):
        self.plan_setup()
        directory = self.root / 'divergent-witness'
        directory.mkdir(mode=0o700)
        divergent = self.plan_registry[:-64] + 'ff' * 32
        retained = self.command('witness-init', divergent, self.plan_catalog, directory=directory)
        self.assertEqual(retained.returncode, 0)
        self.plan_result('commit')
        before = self.copy_snapshot()
        self.assertEqual(self.plan_action(witness=(directory, retained.stdout.decode().strip())).returncode, 2)
        self.assertEqual(self.copy_snapshot(), before)

    def test_plan_prepare_crash_does_not_allocate_or_return_partial_plan(self):
        self.copy_setup()
        before = self.copy_snapshot()
        result = self.command('copy-plan-prepare', *self.copy_args(), env={'CDSE_CONTEXT_MANAGER_CRASH': 'after-copy-entry'})
        self.assertEqual(result.returncode, 86)
        self.assertEqual(result.stdout, b'')
        self.assertEqual(self.copy_snapshot(), before)

    def check_plan_crash(self, point):
        self.plan_setup()
        directory, retained = self.init_plan_witness()
        before = self.plan_registry
        result = self.plan_action(witness=(directory, retained), env={'CDSE_CONTEXT_MANAGER_CRASH': point})
        self.assertEqual(result.returncode, 86)
        self.assertEqual(self.plan_result()['state'], 2 if point == 'after-commit' else 1)
        result = self.plan_result(witness=(directory, retained))
        self.assertNotEqual(result['registry'], before)
        committed = self.copy_snapshot()
        self.assertEqual(self.plan_result(witness=(directory, retained)), result)
        self.assertEqual(self.copy_snapshot(), committed)


for _name in tuple(vars(CopyProvisionTests)):
    if _name.startswith('test_'):
        setattr(CopyPlanTests, _name, None)

for _point in ('after-begin', 'after-write', 'after-commit'):
    def _plan_crash_case(self, point=_point):
        self.check_plan_crash(point)
    setattr(CopyPlanTests, 'test_plan_crash_' + _point.replace('-', '_'), _plan_crash_case)


if __name__ == '__main__':
    unittest.main()
