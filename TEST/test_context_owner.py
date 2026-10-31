#!/usr/bin/env python3
"""Private local owner approvals; no candidate-derived identity or V2 claims."""
from contextlib import closing
import copy
import base64
import hashlib
import json
import os
import resource
import signal
from pathlib import Path
import shutil
import sqlite3
import subprocess
import unittest

import test_context_manager as manager_tests

ADMIN = str(Path(os.environ.get('CDSE_CONTEXT_OWNER_ADMIN', './caumedse-admin')).resolve())
PAYLOAD = str(Path(os.environ.get('CDSE_CONTEXT_OWNER_PAYLOAD', './reprotect-fixture')).resolve())


class OwnerTests(manager_tests.ManagerTests):
    def setUp(self):
        super().setUp()
        self.binding_family()
        self.allocated(lookup='meta-second', level=3, parent='meta', table='meta', field='attribute',
                       expected=self.current())
        self.map_init()
        self.original_slots = [('first', 'data', 1, 'value'), ('second', 'data', 2, 'value'),
                               ('meta', 'meta', 1, 'attribute'), ('meta-second', 'meta', 2, 'attribute')]
        self.target_slots = [(lookup, table, 3-row, field) for lookup, table, row, field in self.original_slots]
        self.assertEqual(self.map_store(self.original_slots).returncode, 0)
        self.active = self.root / 'export' / 'column.sqlite'
        self.staged = self.root / 'staging' / 'column.sqlite'
        self.active.parent.mkdir(mode=0o700)
        self.staged.parent.mkdir(mode=0o700)
        result = subprocess.run([PAYLOAD, str(self.active), 'normal'], capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, 'synthetic encrypted payload creation failed')
        self.active.chmod(0o600)
        shutil.copyfile(self.active, self.staged)
        self.staged.chmod(0o600)
        with closing(sqlite3.connect(self.staged)) as db, db:
            for table in ('data', 'meta'):
                db.execute(f'update {table} set id=-id')
                db.execute(f'update {table} set id=3+id')
        self.key = self.root / 'registry.key'
        self.key.write_text((b'k' * 32).hex() + '\n')
        self.key.chmod(0o600)
        self.approval_file = self.root / 'approval.json'
        self.approval = dict(schema=1, manager=str(self.authority), deployment=self.anchor.deployment,
                             organization=self.anchor.organization, map='view', registry=self.current(),
                             catalog=self.map_current(), active=str(self.active), staged=str(self.staged),
                             source=hashlib.sha256(self.active.read_bytes()).hexdigest(),
                             target=hashlib.sha256(self.staged.read_bytes()).hexdigest(), slots=self.target_slots)
        self.write_approval()

    def write_approval(self):
        self.approval_file.write_text(json.dumps(self.approval))
        self.approval_file.chmod(0o600)

    def owner(self, *action, approval=None, key=None, confirmation=None, env=None, extra=()):
        path = approval or self.approval_file
        result = subprocess.run([ADMIN, 'context-shuffle', '--approval', str(path), '--registry-key-file', str(key or self.key),
                                 '--confirmed-offline', str(confirmation or path), *action, *extra], capture_output=True,
                                env=dict(os.environ, **(env or {})), timeout=30)
        for secret in ('fixture-source-key', 'fixture-alpha', 'fixture-beta', 'fixtureUser', (b'k' * 32).hex(),
                       str(self.active), str(self.authority), str(self.approval_file)):
            self.assertNotIn(secret.encode(), result.stdout + result.stderr)
        return result

    def accepted(self, *action):
        result = self.owner(*action)
        self.assertEqual(result.returncode, 0, result.stderr)
        data = dict(line.split('=', 1) for line in result.stdout.decode().splitlines())
        self.assertEqual(data['catalog'], self.map_current())
        self.approval['catalog'] = data['catalog']
        self.write_approval()
        return data

    def initialized(self):
        self.accepted('--init')

    def prepared(self):
        self.initialized()
        return self.accepted('--prepare')['job']

    def pin_target(self):
        self.approval['target'] = hashlib.sha256(self.staged.read_bytes()).hexdigest()
        self.write_approval()

    def test_owner_complete_status_retry_and_encrypted_readback(self):
        original = self.active.read_bytes()
        job = self.prepared()
        self.assertEqual(self.active.read_bytes(), original)
        self.assertEqual(self.map_bind().returncode, 1)
        self.assertEqual(self.accepted('--status')['state'], 'prepared')
        self.accepted('--complete', job)
        self.assertEqual(self.accepted('--status')['state'], 'completed')
        before = self.map_current()
        self.accepted('--complete', job)
        self.assertEqual(self.map_current(), before)
        self.assertEqual(self.map_bind().returncode, 0)
        self.assertEqual(hashlib.sha256(self.active.read_bytes()).hexdigest(), self.approval['target'])
        self.assertFalse(self.staged.exists())
        source = self.root / 'source.key'
        source.write_text('fixture-source-key\n')
        source.chmod(0o600)
        result = subprocess.run([ADMIN, 'reprotect-columnfile', '--database', str(self.active), '--confirmed-scope',
                                 str(self.active), '--source-key-file', str(source), '--target-key-file', str(source),
                                 '--target-profile', 'aes-256-gcm', '--dry-run'], capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, 'persisted encrypted readback failed')

    def test_owner_abort_keeps_source_and_candidate(self):
        original = self.active.read_bytes()
        job = self.prepared()
        self.accepted('--abort', job)
        self.assertEqual(self.accepted('--status')['state'], 'aborted')
        self.accepted('--abort', job)
        self.assertEqual(self.active.read_bytes(), original)
        self.assertTrue(self.staged.exists())
        self.assertEqual(self.map_bind().returncode, 0)

    def test_owner_requires_explicit_reapproval_after_publication(self):
        self.initialized()
        result = self.owner('--prepare')
        self.assertEqual(result.returncode, 0)
        self.assertEqual(self.owner('--status').returncode, 2)
        self.assertEqual(self.owner('--prepare').returncode, 2)
        self.approval['catalog'] = self.map_current()
        self.write_approval()
        self.assertEqual(self.accepted('--status')['state'], 'prepared')

    def test_owner_wrong_scope_key_and_job_fail_closed(self):
        job = self.prepared()
        self.assertEqual(self.owner('--complete', '00' * 32).returncode, 1)
        self.key.write_text('78' * 32)
        self.assertEqual(self.owner('--complete', job).returncode, 1)
        self.key.write_text('6b' * 32)
        self.approval['organization'] = 'aa' * 16
        self.write_approval()
        self.assertEqual(self.owner('--status').returncode, 1)
        self.assertEqual(self.map_bind().returncode, 1)

    def test_owner_manifest_duplicate_unknown_and_missing_fields(self):
        original = self.approval_file.read_text()
        invalid = ('[]', '{}', original[:-1] + ',"schema":1}', original[:-1] + ',"unknown":1}',
                   original[:-1] + ',"\\u0073chema":1}', original + 'junk', original + '\x00',
                   '/* approval */' + original, original[:-1] + ',}')
        for body in invalid:
            self.approval_file.write_text(body)
            self.assertEqual(self.owner('--init').returncode, 1)
        self.assertEqual(self.command('shuffle-read', 'view', self.current(), self.map_current()).returncode, 1)

    def test_owner_manifest_typed_slot_and_anchor_bounds(self):
        original = copy.deepcopy(self.approval)
        for field, value in (('schema', True), ('schema', 1.0), ('slots', []), ('slots', {}),
                             ('registry', '00' * 73), ('catalog', '0' * 79), ('source', 'G' * 64),
                             ('deployment', 'AA' * 16)):
            self.approval = dict(original, **{field: value})
            self.write_approval()
            self.assertNotEqual(self.owner('--init').returncode, 0)
        for row in (True, 1.0, '1', 2**63):
            self.approval = copy.deepcopy(original)
            self.approval['slots'][0] = ['first', 'data', row, 'value']
            self.write_approval()
            self.assertEqual(self.owner('--init').returncode, 1)
        for slot in (['first', 'data', 1], ['first', 'data', 1, 'value', 'extra'],
                     ['first\x00hidden', 'data', 1, 'value'], ['first', 'data', 1, {}]):
            self.approval = dict(original, slots=[slot])
            self.write_approval()
            self.assertEqual(self.owner('--init').returncode, 1)
        for slots in ([self.target_slots[0]] * 2,
                      [(f'record{i}', 'data', i, 'value') for i in range(4097)]):
            self.approval = dict(original, slots=slots)
            self.write_approval()
            self.assertEqual(self.owner('--init').returncode, 1)

    def test_owner_private_approval_key_links_and_fifos(self):
        for path in (self.approval_file, self.key):
            path.chmod(0o644)
            self.assertEqual(self.owner('--init').returncode, 1)
            path.chmod(0o600)
            alias = self.root / 'alias'
            alias.symlink_to(path)
            self.assertEqual(self.owner('--init', **({'approval': alias} if path == self.approval_file else {'key': alias})).returncode, 1)
            alias.unlink()
            os.link(path, alias)
            self.assertEqual(self.owner('--init').returncode, 1)
            alias.unlink()
        fifo = self.root / 'fifo'
        os.mkfifo(fifo, 0o600)
        self.assertEqual(self.owner('--init', approval=fifo).returncode, 1)
        self.assertEqual(self.owner('--init', key=fifo).returncode, 1)
        self.root.chmod(0o755)
        self.assertEqual(self.owner('--init').returncode, 1)
        self.root.chmod(0o700)

    def test_owner_argument_and_confirmation_contract(self):
        for action in ((), ('--unknown',), ('--init', '--prepare'), ('--complete',), ('--abort', 'not-hex')):
            self.assertEqual(self.owner(*action).returncode, 1)
        self.assertEqual(self.owner('--init', confirmation=self.root).returncode, 1)
        self.assertEqual(self.owner('--init', extra=('--approval', str(self.approval_file))).returncode, 1)
        self.assertEqual(subprocess.run([ADMIN, 'context-shuffle', '--help'], capture_output=True).returncode, 0)
        self.assertEqual(subprocess.run([ADMIN, '--help'], capture_output=True).returncode, 0)

    def test_owner_control_files_and_staging_outside_export(self):
        for field in ('manager', 'staged'):
            original = self.approval[field]
            self.approval[field] = str(self.active.parent / Path(original).name)
            self.write_approval()
            self.assertEqual(self.owner('--init').returncode, 1)
            self.approval[field] = original
        self.write_approval()
        inside = self.active.parent / 'approval.json'
        shutil.copyfile(self.approval_file, inside)
        inside.chmod(0o600)
        self.assertEqual(self.owner('--init', approval=inside).returncode, 1)
        key = self.active.parent / 'registry.key'
        shutil.copyfile(self.key, key)
        key.chmod(0o600)
        self.assertEqual(self.owner('--init', key=key).returncode, 1)

    def test_owner_complete_inventory_rejects_partial_map(self):
        self.assertEqual(self.map_store(self.original_slots[:2]).returncode, 0)
        self.approval['catalog'] = self.map_current()
        self.approval['slots'] = self.target_slots[:2]
        self.write_approval()
        self.initialized()
        before = self.map_current()
        self.assertEqual(self.owner('--prepare').returncode, 1)
        self.assertEqual(self.map_current(), before)

    def test_owner_wrong_permutation_rejected_even_with_valid_digest(self):
        self.initialized()
        self.approval['slots'] = self.original_slots
        self.write_approval()
        self.assertEqual(self.owner('--prepare').returncode, 1)
        self.assertEqual(self.map_bind().returncode, 0)

    def test_owner_rejects_altered_cells_salts_tags_and_roworder(self):
        self.initialized()
        original = self.staged.read_bytes()
        for table, field, expression in (('data', 'value', "'modified'"), ('data', 'salt', "'modified'"),
                                          ('data', 'rowOrder', "'modified'"), ('data', 'MAC', "'modified'"),
                                          ('meta', 'attributeData', "'modified'"), ('data', 'value', 'NULL'),
                                          ('data', 'value', 'cast(value as blob)'),
                                          ('data', 'value', 'hex(zeroblob(600000))')):
            with closing(sqlite3.connect(self.staged)) as db, db:
                db.execute(f'update {table} set {field}={expression} where id=1')
            self.pin_target()
            self.assertEqual(self.owner('--prepare').returncode, 1)
            self.staged.write_bytes(original)

    def test_owner_rejects_extra_missing_rows_and_schema_objects(self):
        self.initialized()
        original = self.staged.read_bytes()
        for sql in ("delete from meta where id=1", "insert into data select 3,userId,orgId,salt,value,rowOrder,MAC,sign,MACProtected,signProtected,otphDKey from data where id=1",
                    "create table extra(value text)", "create trigger extra after update on data begin select 1; end",
                    "create index extra on data(value)", "alter table meta add column extra text"):
            with closing(sqlite3.connect(self.staged)) as db, db:
                db.execute(sql)
            self.pin_target()
            self.assertEqual(self.owner('--prepare').returncode, 1)
            self.staged.write_bytes(original)

    def test_owner_receipt_must_match_entire_approval(self):
        self.prepared()
        original = copy.deepcopy(self.approval)
        for field, value in (('source', '00' * 32), ('target', '00' * 32), ('active', str(self.root / 'wrong.sqlite')),
                             ('slots', [self.target_slots[0]] * 4), ('slots', self.original_slots)):
            self.approval = dict(original, **{field: value})
            self.write_approval()
            self.assertEqual(self.owner('--status').returncode, 1)
        self.assertEqual(self.map_bind().returncode, 1)

    def test_owner_interrupted_install_rolls_forward_without_candidate(self):
        job = self.prepared()
        result = self.command('shuffle-recover', 'view', job, 1, self.current(), self.map_current(),
                              env={'CDSE_CONTEXT_OFFLINE_CRASH': 'after-rename'})
        self.assertEqual(result.returncode, 86)
        self.assertFalse(self.staged.exists())
        self.assertEqual(self.owner('--abort', job).returncode, 1)
        self.accepted('--complete', job)
        self.assertEqual(self.map_bind().returncode, 0)

    def test_owner_revocation_fails_before_install_but_allows_source_abort(self):
        original = self.active.read_bytes()
        job = self.prepared()
        self.assertEqual(self.command('revoke', 'second', self.current()).returncode, 0)
        self.assertEqual(self.owner('--complete', job).returncode, 2)
        self.approval['registry'] = self.current()
        self.write_approval()
        self.assertEqual(self.owner('--complete', job).returncode, 1)
        self.assertEqual(self.active.read_bytes(), original)
        self.accepted('--abort', job)
        self.assertEqual(self.map_bind().returncode, 1)

    def test_owner_bounds_corrupt_authority_and_no_automatic_reset(self):
        self.approval_file.write_bytes(b' ' * (1024 * 1024 + 1))
        self.assertEqual(self.owner('--init').returncode, 1)
        self.write_approval()
        self.key.write_text('6b' * 32 + '\n\n')
        self.assertEqual(self.owner('--init').returncode, 1)
        self.key.write_text('6b' * 32)
        self.initialized()
        with closing(sqlite3.connect(self.authority / 'registry.sqlite')) as db, db:
            db.execute('delete from context_map_head')
        self.assertEqual(self.owner('--init').returncode, 1)
        self.assertEqual(self.owner('--prepare').returncode, 1)

    def test_owner_unsafe_candidate_and_wrong_pins_leave_map_usable(self):
        self.initialized()
        self.staged.chmod(0o644)
        self.assertEqual(self.owner('--prepare').returncode, 1)
        self.staged.chmod(0o600)
        sidecar = Path(str(self.staged) + '-wal')
        sidecar.touch()
        self.assertEqual(self.owner('--prepare').returncode, 1)
        sidecar.unlink()
        self.approval['target'] = '00' * 32
        self.write_approval()
        self.assertEqual(self.owner('--prepare').returncode, 1)
        self.assertEqual(self.map_bind().returncode, 0)


for _name in vars(manager_tests.ManagerTests):
    if _name.startswith('test_'):
        setattr(OwnerTests, _name, None)


class CopyOwnerTests(manager_tests.CopyProvisionTests):
    def setUp(self):
        manager_tests.ManagerTests.setUp(self)
        self.copy_setup()
        self.export = self.root / 'export'
        self.custody = self.root / 'custody'
        self.witness = self.root / 'witness'
        for path in (self.export, self.custody, self.witness):
            path.mkdir(mode=0o700)
        self.plan = self.custody / 'allocation.plan'
        self.key = self.root / 'registry.key'
        self.witness_key = self.root / 'witness.key'
        for path, value in ((self.key, b'k'), (self.witness_key, b'w')):
            path.write_text((value * 32).hex() + '\n')
            path.chmod(0o600)
        result = self.command('witness-init', self.current(), self.map_current(), directory=self.witness)
        self.assertEqual(result.returncode, 0)
        self.retained = result.stdout.decode().strip()
        self.approval_file = self.root / 'copy-approval.json'
        self.approval = dict(schema=1, manager=str(self.authority), deployment=self.anchor.deployment,
                             organization=self.anchor.organization, map='view', registry=self.current(),
                             catalog=self.map_current(), witness=str(self.witness), export=str(self.export),
                             plan=str(self.plan), lookups=self.lookups)
        self.digest = None
        self.write_copy_approval()

    def write_copy_approval(self):
        self.approval_file.write_text(json.dumps(self.approval))
        self.approval_file.chmod(0o600)

    def copy_owner(self, action, *, digest=None, token=None, extra=(), preexec_fn=None):
        args = [ADMIN, 'context-copy-plan', '--approval', str(self.approval_file),
                '--confirmed-offline', str(self.approval_file), '--registry-key-file', str(self.key),
                '--witness-directory', str(self.witness), '--witness-key-file', str(self.witness_key),
                '--retained-witness-token', token or self.retained, action]
        if action != '--prepare' and (digest or self.digest):
            args.extend(['--plan-digest', digest or self.digest])
        result = subprocess.run([*args, *extra], capture_output=True, timeout=30, preexec_fn=preexec_fn)
        for secret in (str(self.authority), str(self.plan), str(self.approval_file), str(self.export),
                       str(self.witness), (b'k' * 32).hex(), (b'w' * 32).hex()):
            self.assertNotIn(secret.encode(), result.stdout + result.stderr)
        if result.returncode:
            self.assertEqual(result.stdout, b'')
        return result

    def copy_accepted(self, action, **options):
        result = self.copy_owner(action, **options)
        self.assertEqual(result.returncode, 0, result.stderr)
        return dict(line.split('=', 1) for line in result.stdout.decode().splitlines())

    def prepare_copy(self):
        before = self.current(), self.map_current()
        data = self.copy_accepted('--prepare')
        self.digest = data['plan-digest']
        self.assertEqual(self.digest, hashlib.sha256(self.plan.read_bytes()).hexdigest())
        self.assertEqual((self.current(), self.map_current()), before)
        self.assertEqual(self.plan.stat().st_mode & 0o7777, 0o600)
        return data

    def test_copy_command_prepare_status_commit_and_explicit_witness_advance(self):
        prepared = self.prepare_copy()
        witness_bytes = (self.witness / 'witness.sqlite').read_bytes()
        self.assertEqual(self.copy_accepted('--status')['state'], 'ready')
        committed = self.copy_accepted('--commit')
        self.assertEqual(committed['registry'], prepared['registry'])
        self.assertEqual(committed['witness-state'], 'advance-required')
        self.assertEqual((self.witness / 'witness.sqlite').read_bytes(), witness_bytes)
        before = self.copy_snapshot()
        for action in ('--status', '--commit'):
            self.assertEqual(self.copy_accepted(action)['state'], 'committed')
            self.assertEqual(self.copy_snapshot(), before)
        self.assertEqual(self.map_current(), self.approval['catalog'])
        advanced = self.copy_accepted('--advance-witness', extra=('--approved-registry', committed['registry']))
        self.assertEqual(advanced['state'], 'witness-advanced')
        self.assertIn('witness-token', advanced)
        witness_bytes = (self.witness / 'witness.sqlite').read_bytes()
        for retained in (self.retained, advanced['witness-token']):
            self.copy_accepted('--advance-witness', token=retained, extra=('--approved-registry', committed['registry']))
            self.assertEqual((self.witness / 'witness.sqlite').read_bytes(), witness_bytes)

    def test_copy_prepare_never_overwrites_even_after_lost_acknowledgement(self):
        self.prepare_copy()
        plan = self.plan.read_bytes()
        self.assertEqual(self.copy_owner('--prepare').returncode, 1)
        self.assertEqual(self.plan.read_bytes(), plan)
        self.digest = hashlib.sha256(plan).hexdigest()  # Independently review/retain after a lost prepare acknowledgement.
        self.copy_accepted('--commit')

    def test_copy_missing_receipt_never_allocates_or_recreates(self):
        before = self.copy_snapshot()
        for action in ('--status', '--commit'):
            self.assertEqual(self.copy_owner(action, digest='00' * 32).returncode, 1)
            self.assertFalse(self.plan.exists())
            self.assertEqual(self.copy_snapshot(), before)

    def test_copy_partial_write_retains_private_file_and_no_ids(self):
        def limit_file_size():
            signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
            resource.setrlimit(resource.RLIMIT_FSIZE, (128, 128))

        before = self.copy_snapshot()
        result = self.copy_owner('--prepare', preexec_fn=limit_file_size)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(self.plan.stat().st_size, 128)
        self.assertEqual(self.plan.stat().st_mode & 0o7777, 0o600)
        retained = self.plan.read_bytes()
        self.assertEqual(self.copy_owner('--prepare').returncode, 1)
        self.assertEqual(self.plan.read_bytes(), retained)
        self.assertEqual(self.copy_owner('--commit', digest=hashlib.sha256(retained).hexdigest()).returncode, 1)
        self.assertEqual(self.copy_snapshot(), before)

    def test_copy_tampered_or_substituted_plan_digest_cannot_commit(self):
        self.prepare_copy()
        before = self.copy_snapshot()
        self.assertEqual(self.copy_owner('--commit', digest='00' * 32).returncode, 1)
        plan = bytearray(self.plan.read_bytes())
        plan[-1] ^= 1
        self.plan.write_bytes(plan)
        self.assertEqual(self.copy_owner('--commit', digest=hashlib.sha256(plan).hexdigest()).returncode, 1)
        self.assertEqual(self.copy_snapshot(), before)

    def test_copy_request_match_rejects_changed_source_and_lookup_order(self):
        self.assertEqual(self.map_store(self.source_slots, name='alias').returncode, 0)
        advanced = self.command('witness-advance', self.current(), self.map_current(), self.retained, directory=self.witness)
        self.assertEqual(advanced.returncode, 0)
        self.retained = advanced.stdout.decode().strip()
        self.approval['catalog'] = self.map_current()
        self.write_copy_approval()
        self.prepare_copy()
        for key, value in (('map', 'alias'), ('lookups', list(reversed(self.lookups))),
                           ('lookups', self.lookups[:-1]), ('lookups', ['different', *self.lookups[1:]])):
            with self.subTest(key=key, value=value):
                old = self.approval[key]
                self.approval[key] = value
                self.write_copy_approval()
                self.assertEqual(self.copy_owner('--commit').returncode, 1)
                self.approval[key] = old
        self.write_copy_approval()
        self.copy_accepted('--commit')

    def test_copy_advance_requires_committed_plan_and_exact_separate_pin(self):
        prepared = self.prepare_copy()
        self.assertEqual(self.copy_owner('--advance-witness').returncode, 1)
        self.assertEqual(self.copy_owner('--advance-witness', extra=('--approved-registry', prepared['registry'])).returncode, 1)
        self.copy_accepted('--commit')
        witness_bytes = (self.witness / 'witness.sqlite').read_bytes()
        self.assertEqual(self.copy_owner('--advance-witness', extra=('--approved-registry', self.approval['registry'])).returncode, 1)
        self.assertEqual((self.witness / 'witness.sqlite').read_bytes(), witness_bytes)

    def test_copy_unsafe_receipt_types_modes_and_links_fail_closed(self):
        self.prepare_copy()
        content = self.plan.read_bytes()
        for kind in ('public', 'symlink', 'hardlink', 'fifo', 'directory'):
            with self.subTest(kind=kind):
                self.plan.unlink()
                other = self.custody / 'other'
                if other.exists():
                    other.unlink()
                if kind == 'public':
                    self.plan.write_bytes(content)
                    self.plan.chmod(0o644)
                elif kind in ('symlink', 'hardlink'):
                    other.write_bytes(content)
                    other.chmod(0o600)
                    if kind == 'symlink':
                        self.plan.symlink_to(other)
                    else:
                        os.link(other, self.plan)
                elif kind == 'fifo':
                    os.mkfifo(self.plan, 0o600)
                else:
                    self.plan.mkdir(mode=0o700)
                self.assertEqual(self.copy_owner('--commit').returncode, 1)
                if kind == 'directory':
                    self.plan.rmdir()
                    self.plan.touch(mode=0o600)
        self.assertEqual(self.current(), self.approval['registry'])

    def test_copy_prepare_refuses_existing_unsafe_receipt_names(self):
        for kind in ('file', 'symlink', 'fifo', 'directory'):
            with self.subTest(kind=kind):
                if kind == 'file':
                    self.plan.write_bytes(b'retained owner evidence')
                elif kind == 'symlink':
                    self.plan.symlink_to(self.key)
                elif kind == 'fifo':
                    os.mkfifo(self.plan, 0o600)
                else:
                    self.plan.mkdir(mode=0o700)
                self.assertEqual(self.copy_owner('--prepare').returncode, 1)
                if kind == 'directory':
                    self.plan.rmdir()
                else:
                    self.plan.unlink()
        self.assertEqual(self.current(), self.approval['registry'])

    def test_copy_receipt_and_authority_directories_must_be_disjoint(self):
        for directory in (self.authority, self.witness, self.export):
            self.approval['plan'] = str(directory / 'allocation.plan')
            self.write_copy_approval()
            self.assertEqual(self.copy_owner('--prepare').returncode, 1)
            self.assertFalse((directory / 'allocation.plan').exists())
        self.approval['plan'] = str(self.plan)
        for directory in (self.authority, self.witness, self.custody):
            self.approval['export'] = str(directory)
            self.write_copy_approval()
            self.assertEqual(self.copy_owner('--prepare').returncode, 1)

    def test_copy_noncanonical_private_directory_and_key_rules(self):
        self.custody.chmod(0o755)
        self.assertEqual(self.copy_owner('--prepare').returncode, 1)
        self.custody.chmod(0o700)
        self.approval['plan'] = str(self.custody) + '/../custody/allocation.plan'
        self.write_copy_approval()
        self.assertEqual(self.copy_owner('--prepare').returncode, 1)
        self.approval['plan'] = str(self.plan)
        self.write_copy_approval()
        self.key.chmod(0o644)
        self.assertEqual(self.copy_owner('--prepare').returncode, 1)
        self.key.chmod(0o600)
        self.witness_key.write_bytes(self.key.read_bytes())
        self.assertEqual(self.copy_owner('--prepare').returncode, 1)

    def test_copy_strict_schema_and_invalid_lookup_types(self):
        original = copy.deepcopy(self.approval)
        for key, value in (('schema', True), ('schema', 1.0), ('schema', 2), ('lookups', []),
                           ('lookups', [False]), ('lookups', ['same'] * len(self.lookups)),
                           ('lookups', ['invalid lookup']), ('extra', 'unsupported'), ('registry', '00' * 73)):
            self.approval = dict(original, **{key: value})
            self.write_copy_approval()
            self.assertEqual(self.copy_owner('--prepare').returncode, 1)
            self.assertFalse(self.plan.exists())
        self.approval = original
        self.write_copy_approval()
        text = self.approval_file.read_text()
        self.approval_file.write_text(text[:-1] + ',"schema":1}')
        self.assertEqual(self.copy_owner('--prepare').returncode, 1)

    def test_copy_strict_options_require_independent_approvals(self):
        for action, extra in (('--prepare', ('--prepare',)), ('--prepare', ('--plan-digest', '00' * 32)),
                              ('--prepare', ('--approved-registry', self.approval['registry'])),
                              ('--prepare', ('--unknown', 'value')), ('--status', ())):
            self.assertEqual(self.copy_owner(action, extra=extra).returncode, 1)
        self.assertEqual(self.copy_owner('--prepare', token='00' * 40).returncode, 1)

    def test_copy_stale_registry_or_catalog_refuses_without_publication(self):
        self.prepare_copy()
        self.assertEqual(self.command('revoke', 'first', self.current()).returncode, 0)
        self.assertEqual(self.copy_owner('--commit').returncode, 2)
        self.assertFalse(any(e['lookup'].startswith('copy/') for e in self.copy_snapshot()['entries']))

    def test_copy_committed_receipt_expires_after_catalog_publication(self):
        self.prepare_copy()
        self.copy_accepted('--commit')
        slots = [(lookup, *source[1:]) for lookup, source in zip(self.lookups, self.ordered)]
        self.assertEqual(self.map_store(slots, name='copy', resource=self.lookups[0]).returncode, 0)
        self.assertEqual(self.copy_owner('--status').returncode, 2)
        self.assertEqual(self.copy_owner('--commit').returncode, 2)

    def test_copy_missing_authority_is_never_reinitialized(self):
        self.prepare_copy()
        database = self.witness / 'witness.sqlite'
        database.rename(self.witness / 'retained.sqlite')
        self.assertEqual(self.copy_owner('--commit').returncode, 1)
        self.assertFalse(database.exists())

    def test_copy_retained_witness_rejects_replayed_checkpoint(self):
        prepared = self.prepare_copy()
        old = (self.witness / 'witness.sqlite').read_bytes()
        self.copy_accepted('--commit')
        advanced = self.copy_accepted('--advance-witness', extra=('--approved-registry', prepared['registry']))
        (self.witness / 'witness.sqlite').write_bytes(old)
        self.assertEqual(self.copy_owner('--commit', token=advanced['witness-token']).returncode, 2)

    def test_copy_help_names_offline_boundaries(self):
        result = subprocess.run([ADMIN, 'context-copy-plan', '--help'], capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0)
        self.assertIn(b'No physical copy', result.stdout)

    def check_installed_copy_crash_recovery(self, point):
        self.prepare_copy()
        result = self.command('copy-plan-guard', self.plan, self.digest, self.approval['registry'],
                              self.approval['catalog'], self.witness, self.retained,
                              env={'CDSE_CONTEXT_MANAGER_CRASH': point})
        self.assertEqual(result.returncode, 86)
        self.assertEqual(self.copy_accepted('--status')['state'], 'committed' if point == 'after-commit' else 'ready')
        self.copy_accepted('--commit')
        committed = self.copy_snapshot()
        self.copy_accepted('--commit')
        self.assertEqual(self.copy_snapshot(), committed)


for _name in vars(manager_tests.CopyProvisionTests):
    if _name.startswith('test_'):
        setattr(CopyOwnerTests, _name, None)

for _point in ('after-write', 'after-commit'):
    def _copy_owner_crash(self, point=_point):
        self.check_installed_copy_crash_recovery(point)
    setattr(CopyOwnerTests, 'test_copy_installed_recovery_' + _point.replace('-', '_'), _copy_owner_crash)


class CopyCandidateTests(CopyOwnerTests):
    def setUp(self):
        super().setUp()
        self.profile = 'aes-256-cbc' if self._testMethodName.endswith('_cbc') else 'aes-256-gcm'
        self.source_file = self.export / 'source.sqlite'
        self.candidate_directory = self.root / 'candidates'
        self.candidate_directory.mkdir(mode=0o700)
        self.candidate_file = self.candidate_directory / 'candidate.sqlite'
        self.org_key = self.root / 'org.key'
        self.org_key.write_text('fixture-source-key\n')
        self.org_key.chmod(0o600)
        env = dict(os.environ, CDSE_DEFAULT_ENC_ALG=self.profile)
        result = subprocess.run([PAYLOAD, str(self.source_file), 'registered-column'], capture_output=True, env=env, timeout=30)
        self.assertEqual(result.returncode, 0, 'synthetic legacy ColumnFile creation failed')
        self.source_file.chmod(0o600)
        self.cells = []
        seed = None
        for table, fields in (('data', ('value', 'userId', 'orgId', 'rowOrder')),
                              ('meta', ('attribute', 'attributeData', 'userId', 'orgId'))):
            for row in (1, 2):
                record = None
                for field in fields:
                    if self._testMethodName.endswith('_unknown_field') and table == 'data' and row == 1 and field == 'value':
                        field = 'salt'
                    lookup = f'preflight/{table}/{row}/{field}'
                    self.allocated(lookup=lookup, level=2 if seed is None else (3 if record is None else 4),
                                   parent=(seed or 'first') if record is None else record, table=table, field=field, expected=self.current())
                    seed = seed or lookup
                    record = record or lookup
                    self.cells.append((lookup, table, row, field))
        if self._testMethodName.endswith('_partial_map'):
            self.cells = [cell for cell in self.cells if cell[3] in ('value', 'attribute')]
        elif self._testMethodName.endswith('_missing_row'):
            self.cells = [cell for cell in self.cells if cell[1:3] != ('meta', 2)]
        self.assertEqual(self.map_store(self.cells, name='inventory', resource=seed).returncode, 0)
        self.approval.update(map='inventory', registry=self.current(), catalog=self.map_current(),
                             lookups=[f'candidate/{i}' for i in range(len(self.cells))])
        self.lookups = self.approval['lookups']
        # Establish a fresh synthetic checkpoint AFTER constructing this test's source authority.
        self.witness = self.root / 'preflight-witness'
        self.witness.mkdir(mode=0o700)
        checkpoint = self.command('witness-init', self.current(), self.map_current(), directory=self.witness)
        self.assertEqual(checkpoint.returncode, 0)
        self.retained = checkpoint.stdout.decode().strip()
        self.approval['witness'] = str(self.witness)
        self.write_copy_approval()
        self.prepare_copy()
        self.allocation_approval = copy.deepcopy(self.approval)
        self.approval.update(schema=2, source=str(self.source_file), candidate=str(self.candidate_file), profile=self.profile)
        self.clone_and_pin()

    def clone_and_pin(self):
        shutil.copyfile(self.source_file, self.candidate_file)
        self.candidate_file.chmod(0o600)
        self.pin_candidates()

    def pin_candidates(self):
        self.approval.update(sourceDigest=hashlib.sha256(self.source_file.read_bytes()).hexdigest(),
                             candidateDigest=hashlib.sha256(self.candidate_file.read_bytes()).hexdigest())
        self.write_copy_approval()

    def candidate(self, **options):
        return self.copy_owner('--check-candidate', extra=('--org-key-file', str(self.org_key)), **options)

    def verified_candidate(self):
        result = self.candidate()
        self.assertEqual(result.returncode, 0, result.stderr)
        for secret in ('fixture-source-key', 'fixture-alpha', 'fixture-beta', str(self.source_file), str(self.candidate_file)):
            self.assertNotIn(secret.encode(), result.stdout + result.stderr)
        data = dict(line.split('=', 1) for line in result.stdout.decode().splitlines())
        self.assertEqual(data['state'], 'verified-legacy-candidate')
        self.assertEqual(data['publication'], 'disabled')
        self.assertEqual(data['context-authentication'], 'absent')
        return data

    def commit_allocation(self):
        selection = self.approval
        self.approval = self.allocation_approval
        self.write_copy_approval()
        result = self.copy_accepted('--commit')
        self.approval = selection
        self.write_copy_approval()
        return result

    def test_candidate_complete_ready_preflight_is_read_only(self):
        paths = (self.source_file, self.candidate_file, self.plan,
                 self.authority / 'registry.sqlite', self.witness / 'witness.sqlite')
        before = [path.read_bytes() for path in paths]
        self.verified_candidate()
        self.assertEqual([path.read_bytes() for path in paths], before)
        self.assertEqual(self.current(), self.approval['registry'])
        self.assertEqual(self.map_current(), self.approval['catalog'])

    def test_candidate_complete_preflight_cbc(self):
        self.verified_candidate()

    def test_candidate_committed_allocation_still_requires_witness_and_plan(self):
        self.commit_allocation()
        before = self.copy_snapshot()
        self.verified_candidate()
        self.assertEqual(self.copy_snapshot(), before)
        self.assertEqual(self.command('witness-check', self.current(), self.map_current(), directory=self.witness).returncode, 2)
        self.assertEqual(self.candidate(digest='00' * 32).returncode, 1)

    def test_candidate_rejects_partial_map(self):
        self.assertEqual(self.candidate().returncode, 1)

    def test_candidate_rejects_missing_row(self):
        self.assertEqual(self.candidate().returncode, 1)

    def test_candidate_rejects_unknown_field(self):
        self.assertEqual(self.candidate().returncode, 1)

    def test_candidate_rejects_unmapped_rows_even_with_approved_hashes(self):
        with closing(sqlite3.connect(self.source_file)) as db, db:
            db.execute("insert into data select 3,userId,orgId,salt,value,'3',MAC,sign,MACProtected,signProtected,otphDKey from data where id=1")
        self.clone_and_pin()
        self.assertEqual(self.candidate().returncode, 1)

    def test_candidate_rejects_cryptographic_tampering_even_in_equal_copies(self):
        for value in ('invalid ciphertext', base64.b64encode(b'CDSEHKX2' + b'\0' * 64).decode()):
            with closing(sqlite3.connect(self.source_file)) as db, db:
                db.execute('update data set value=? where id=1', (value,))
            self.clone_and_pin()
            result = self.candidate()
            self.assertEqual(result.returncode, 1)
            self.assertNotIn(b'invalid ciphertext', result.stdout + result.stderr)
            self.assertNotIn(b'fixture-source-key', result.stdout + result.stderr)

    def test_candidate_rejects_rehashed_nonidentical_clone(self):
        with closing(sqlite3.connect(self.candidate_file)) as db, db:
            db.execute('update data set id=3 where id=1')
        self.pin_candidates()
        self.assertEqual(self.candidate().returncode, 1)

    def test_candidate_rejects_stale_file_pins(self):
        self.approval['sourceDigest'] = '00' * 32
        self.write_copy_approval()
        self.assertEqual(self.candidate().returncode, 1)

    def test_candidate_rejects_unknown_schema_objects(self):
        with closing(sqlite3.connect(self.source_file)) as db, db:
            db.execute('create table unexpected(value text)')
        self.clone_and_pin()
        self.assertEqual(self.candidate().returncode, 1)

    def test_candidate_rejects_sidecars_public_files_and_links(self):
        self.candidate_file.chmod(0o644)
        self.assertEqual(self.candidate().returncode, 1)
        self.candidate_file.chmod(0o600)
        sidecar = Path(str(self.candidate_file) + '-wal')
        sidecar.touch(mode=0o600)
        self.assertEqual(self.candidate().returncode, 1)
        sidecar.unlink()
        self.candidate_file.unlink()
        self.candidate_file.symlink_to(self.source_file)
        self.assertEqual(self.candidate().returncode, 1)
        self.candidate_file.unlink()
        os.link(self.source_file, self.candidate_file)
        self.assertEqual(self.candidate().returncode, 1)

    def test_candidate_paths_cannot_alias_export_custody_or_authority(self):
        for directory in (self.export, self.custody, self.authority, self.witness):
            self.approval['candidate'] = str(directory / 'candidate.sqlite')
            self.write_copy_approval()
            self.assertEqual(self.candidate().returncode, 1)
            self.assertFalse((directory / 'candidate.sqlite').exists())

    def test_candidate_rejects_wrong_or_public_org_key(self):
        self.org_key.write_text('wrong-organization-key\n')
        self.assertEqual(self.candidate().returncode, 1)
        self.org_key.write_text('fixture-source-key\n')
        self.org_key.chmod(0o644)
        self.assertEqual(self.candidate().returncode, 1)

    def test_candidate_schema_cannot_authorize_allocation_or_witness_mutations(self):
        before = self.copy_snapshot()
        for action in ('--commit', '--prepare', '--status', '--advance-witness'):
            self.assertEqual(self.copy_owner(action).returncode, 1)
        self.assertEqual(self.copy_snapshot(), before)

    def test_candidate_rejects_v2_and_unapproved_profiles(self):
        for profile in ('aes-128-gcm', 'herradura-hske-nla1-aead-256', 'CDSEHKX2', 'unknown'):
            self.approval['profile'] = profile
            self.write_copy_approval()
            self.assertEqual(self.candidate().returncode, 1)

    def test_candidate_rejects_stale_authority(self):
        self.assertEqual(self.command('revoke', self.cells[0][0], self.current()).returncode, 0)
        self.assertEqual(self.candidate().returncode, 2)

    def test_candidate_request_substitution_is_rejected(self):
        self.approval['lookups'] = list(reversed(self.lookups))
        self.write_copy_approval()
        self.assertEqual(self.candidate().returncode, 1)


for _name in vars(CopyOwnerTests):
    if _name.startswith('test_'):
        setattr(CopyCandidateTests, _name, None)


class CopyRegistrationTests(CopyCandidateTests):
    def setUp(self):
        super().setUp()
        self.resources = self.export / 'ResourcesDB'
        fixture_root = Path(__file__).resolve().parents[1] / 'TEST' / 'testDB_opt_cdse'
        for name in ('ResourcesDB', 'RolesDB', 'LogsDB'):
            with closing(sqlite3.connect(fixture_root / name)) as original, \
                    closing(sqlite3.connect(self.export / name)) as target, target:
                for sql, in original.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name!='schema_meta'"):
                    target.execute(sql)
                if name != 'ResourcesDB':
                    continue
                for field in ('documentIdLookup', 'storageIdLookup', 'orgResourceIdLookup'):
                    target.execute(f'alter table documents add column {field} TEXT')
                for table in ('documents', 'storage', 'users'):
                    columns = [row[1] for row in target.execute(f'pragma table_info({table})')]
                    values = dict.fromkeys(columns, '')
                    values.update(id=1, userId='fixtureUser', orgId='fixtureOrg', orgResourceId='fixtureOrg')
                    if table == 'documents':
                        values.update(columnFile=self.source_file.name, type='file.csv', documentId='fixture-document',
                                      storageId='fixtureStorage', columnId='1', partId='1', totalParts='1')
                        for field in columns:
                            if field.endswith('Lookup'):
                                values[field] = None
                        if self._testMethodName.endswith('_multipart'):
                            values['totalParts'] = '2'
                        if self._testMethodName.endswith('_wrong_filename'):
                            values['columnFile'] = 'other.sqlite'
                            shutil.copyfile(self.source_file, self.export / 'other.sqlite')
                    elif table == 'storage':
                        values.update(storageId='fixtureStorage', type='local', accessPath='/offline-original/')
                        if self._testMethodName.endswith('_remote_storage'):
                            values['type'] = 'remote'
                        if self._testMethodName.endswith('_wrong_storage_org'):
                            values['orgResourceId'] = 'another-org'
                    rows = [values]
                    if table == 'documents' and (self._testMethodName.endswith('_duplicate_filename') or
                                                  self._testMethodName.endswith('_duplicate_selector')):
                        duplicate = dict(values, id=2)
                        if self._testMethodName.endswith('_duplicate_selector'):
                            duplicate['columnFile'] = 'other.sqlite'
                            shutil.copyfile(self.source_file, self.export / 'other.sqlite')
                        rows.append(duplicate)
                    if table == 'storage' and self._testMethodName.endswith('_duplicate_storage'):
                        rows.append(dict(values, id=2))
                    for row in rows:
                        target.execute(f"insert into {table} ({','.join(columns)}) values ({','.join('?' for _ in columns)})",
                                       [row[field] for field in columns])
        self.prepare_registration_inventory()
        self.registration_fixture('bundle')
        with closing(sqlite3.connect(self.resources)) as db:
            db.execute('pragma journal_mode=DELETE')
        self.registration_fixture('registered-lookups')
        self.resources.chmod(0o600)
        self.approval.update(schema=3, resources=str(self.resources), registration=[
            1, 'fixture-document', 'fixtureStorage', 'fixtureOrg', '1'], storageAccessPath='/offline-original/')
        self.pin_resources()

    def prepare_registration_inventory(self):
        pass

    def registration_fixture(self, action):
        result = subprocess.run([PAYLOAD, str(self.export), action], capture_output=True, timeout=30,
                                env=dict(os.environ, CDSE_DEFAULT_ENC_ALG=self.profile))
        self.assertEqual(result.returncode, 0, f'synthetic registration {action} failed')

    def pin_resources(self):
        self.approval['resourcesDigest'] = hashlib.sha256(self.resources.read_bytes()).hexdigest()
        self.write_copy_approval()

    def registration_check(self, **options):
        result = self.copy_owner('--check-registration', extra=('--org-key-file', str(self.org_key)), **options)
        for secret in ('fixture-document', 'fixtureStorage', 'fixtureOrg', 'fixture-source-key', '/offline-original/'):
            self.assertNotIn(secret.encode(), result.stdout + result.stderr)
        return result

    def verified_registration(self):
        result = self.registration_check()
        self.assertEqual(result.returncode, 0, result.stderr)
        data = dict(line.split('=', 1) for line in result.stdout.decode().splitlines())
        self.assertEqual(data['state'], 'verified-legacy-registration')
        self.assertEqual(data['registration'], 'selected-source-columnfile')
        self.assertEqual(data['resources-digest'], self.approval['resourcesDigest'])
        self.assertEqual(data['publication'], 'disabled')
        self.assertEqual(data['context-authentication'], 'absent')
        return data

    def test_registration_ready_preflight_is_read_only(self):
        paths = (self.resources, self.source_file, self.candidate_file, self.plan,
                 self.authority / 'registry.sqlite', self.witness / 'witness.sqlite')
        before = [path.read_bytes() for path in paths]
        self.verified_registration()
        self.assertEqual([path.read_bytes() for path in paths], before)

    def test_registration_preflight_cbc(self):
        self.verified_registration()

    def test_registration_committed_preflight_does_not_advance_witness(self):
        self.commit_allocation()
        before = self.copy_snapshot()
        self.verified_registration()
        self.assertEqual(self.copy_snapshot(), before)
        self.assertEqual(self.command('witness-check', self.current(), self.map_current(), directory=self.witness).returncode, 2)

    def test_registration_rejects_wrong_independent_selector(self):
        original = list(self.approval['registration'])
        for index, value in enumerate((2, 'another-document', 'another-storage', 'another-org', '2')):
            self.approval['registration'] = list(original)
            self.approval['registration'][index] = value
            self.write_copy_approval()
            self.assertEqual(self.registration_check().returncode, 1)

    def test_registration_rejects_lookup_tampering_despite_reapproved_hash(self):
        original = self.resources.read_bytes()
        for field in ('documentIdLookup', 'storageIdLookup', 'orgResourceIdLookup'):
            self.resources.write_bytes(original)
            with closing(sqlite3.connect(self.resources)) as db, db:
                db.execute(f'update documents set {field}=? where id=1', ('00' * 32,))
            self.pin_resources()
            self.assertEqual(self.registration_check().returncode, 1)

    def test_registration_rejects_valid_new_ciphertext_with_old_file_mac(self):
        self.source_file.unlink()
        result = subprocess.run([PAYLOAD, str(self.source_file), 'registered-column'], capture_output=True, timeout=30,
                                env=dict(os.environ, CDSE_DEFAULT_ENC_ALG=self.profile))
        self.assertEqual(result.returncode, 0)
        self.source_file.chmod(0o600)
        self.clone_and_pin()
        registered = self.approval
        self.approval = {key: value for key, value in registered.items() if key not in (
            'resources', 'resourcesDigest', 'registration', 'storageAccessPath')}
        self.approval['schema'] = 2
        self.write_copy_approval()
        self.verified_candidate()  # Full ColumnFile crypto/inventory remains valid.
        self.approval = registered
        self.write_copy_approval()
        self.assertEqual(self.registration_check().returncode, 1)

    def test_registration_rejects_wrong_filename(self):
        self.assertEqual(self.registration_check().returncode, 1)

    def test_registration_rejects_duplicate_filename(self):
        self.assertEqual(self.registration_check().returncode, 1)

    def test_registration_rejects_duplicate_selector(self):
        self.assertEqual(self.registration_check().returncode, 1)

    def test_registration_rejects_multipart(self):
        self.assertEqual(self.registration_check().returncode, 1)

    def test_registration_rejects_remote_storage(self):
        self.assertEqual(self.registration_check().returncode, 1)

    def test_registration_rejects_duplicate_storage(self):
        self.assertEqual(self.registration_check().returncode, 1)

    def test_registration_rejects_wrong_storage_org(self):
        self.assertEqual(self.registration_check().returncode, 1)

    def test_registration_rejects_unapproved_stored_access_path(self):
        self.approval['storageAccessPath'] = '/different-original/'
        self.write_copy_approval()
        self.assertEqual(self.registration_check().returncode, 1)

    def test_registration_rejects_stale_resources_digest(self):
        self.approval['resourcesDigest'] = '00' * 32
        self.write_copy_approval()
        self.assertEqual(self.registration_check().returncode, 1)

    def test_registration_rejects_public_sidecar_and_linked_resources(self):
        self.resources.chmod(0o644)
        self.assertEqual(self.registration_check().returncode, 1)
        self.resources.chmod(0o600)
        sidecar = Path(str(self.resources) + '-wal')
        sidecar.touch(mode=0o600)
        self.assertEqual(self.registration_check().returncode, 1)
        sidecar.unlink()
        retained = self.custody / 'retained-resources'
        self.resources.rename(retained)
        self.resources.symlink_to(retained)
        self.assertEqual(self.registration_check().returncode, 1)

    def test_registration_rejects_unapproved_resources_path(self):
        self.approval['resources'] = str(self.source_file)
        self.write_copy_approval()
        self.assertEqual(self.registration_check().returncode, 1)

    def test_registration_rejects_schema_objects_and_metadata_downgrade(self):
        original = self.resources.read_bytes()
        for sql in ("create table unexpected(value text)", "update schema_meta set value='0' where key='definitionsVersion'"):
            self.resources.write_bytes(original)
            with closing(sqlite3.connect(self.resources)) as db, db:
                db.execute(sql)
            self.pin_resources()
            self.assertEqual(self.registration_check().returncode, 1)

    def test_registration_strict_schema_cannot_publish_or_skip_plan_approval(self):
        before = self.copy_snapshot()
        for action in ('--prepare', '--commit', '--status', '--advance-witness', '--check-candidate'):
            self.assertEqual(self.copy_owner(action, extra=('--org-key-file', str(self.org_key))).returncode, 1)
        original = copy.deepcopy(self.approval)
        for key, value in (('registration', [True, 'd', 's', 'o', '1']), ('registration', [1.0, 'd', 's', 'o', '1']),
                           ('registration', [2**63, 'd', 's', 'o', '1']), ('registration', [1, '', 's', 'o', '1']),
                           ('resourcesDigest', 'not-hex'), ('storageAccessPath', 'relative/path')):
            self.approval = dict(original, **{key: value})
            self.write_copy_approval()
            self.assertEqual(self.registration_check().returncode, 1)
        self.approval = original
        self.write_copy_approval()
        self.assertEqual(self.registration_check(digest='00' * 32).returncode, 1)
        self.assertEqual(self.registration_check(token='00' * 40).returncode, 1)
        self.assertEqual(self.copy_snapshot(), before)


for _name in vars(CopyCandidateTests):
    if _name.startswith('test_'):
        setattr(CopyRegistrationTests, _name, None)


class CopyExportTests(CopyRegistrationTests):
    def prepare_registration_inventory(self):
        with closing(sqlite3.connect(self.resources)) as db, db:
            db.row_factory = sqlite3.Row
            original = dict(db.execute('select * from documents').fetchone())
            for part in (1, 2):
                name = f'raw-{part}.bin'
                if self._testMethodName.endswith('_path_traversal') and part == 1:
                    name = '../outside.bin'
                (self.export / name).write_bytes(b'private raw payload\x00' + bytes([part]))
                values = dict(original, id=part + 1, columnFile=name, type='file.raw',
                              documentId='raw-document', columnId='0', partId=str(part), totalParts='2')
                if self._testMethodName.endswith('_missing_part'):
                    values['totalParts'] = '3'
                if self._testMethodName.endswith('_duplicate_part'):
                    values['partId'] = '1'
                if self._testMethodName.endswith('_inconsistent_total') and part == 2:
                    values['totalParts'] = '3'
                if self._testMethodName.endswith('_invalid_part') and part == 2:
                    values['partId'] = '2x'
                if self._testMethodName.endswith('_orphan_storage'):
                    values['storageId'] = 'unregistered-storage'
                columns = list(values)
                db.execute(f"insert into documents ({','.join(columns)}) values ({','.join('?' for _ in columns)})",
                           [values[field] for field in columns])
            if self._testMethodName.endswith('_duplicate_name'):
                values = dict(original, id=4, documentId='duplicate-document')
                columns = list(values)
                db.execute(f"insert into documents ({','.join(columns)}) values ({','.join('?' for _ in columns)})",
                           [values[field] for field in columns])
            if self._testMethodName.endswith('_unrelated_remote') or self._testMethodName.endswith('_unrelated_path'):
                storage = dict(db.execute('select * from storage').fetchone())
                storage.update(id=2, storageId='unused-storage')
                if self._testMethodName.endswith('_unrelated_remote'):
                    storage['type'] = 'remote'
                else:
                    storage['accessPath'] = '/different-root/'
                columns = list(storage)
                db.execute(f"insert into storage ({','.join(columns)}) values ({','.join('?' for _ in columns)})",
                           [storage[field] for field in columns])

    def setUp(self):
        super().setUp()
        for path in self.export.iterdir():
            path.chmod(0o600)
            if path.name in ('RolesDB', 'LogsDB'):
                with closing(sqlite3.connect(path)) as db:
                    db.execute('pragma journal_mode=DELETE')
        self.approval['schema'] = 4
        self.write_copy_approval()

    def export_check(self, **options):
        return self.copy_owner('--check-export', extra=('--org-key-file', str(self.org_key)), **options)

    def verified_export(self):
        result = self.export_check()
        self.assertEqual(result.returncode, 0, result.stderr)
        data = dict(line.split('=', 1) for line in result.stdout.decode().splitlines())
        self.assertEqual(data['state'], 'verified-legacy-export')
        self.assertEqual(data['export-inventory'], 'complete-registered-payloads')
        self.assertEqual(data['payload-authentication'], 'registered-file-macs')
        self.assertEqual(data['publication'], 'disabled')
        self.assertEqual(data['context-authentication'], 'absent')
        for secret in ('raw-document', 'fixtureStorage', 'fixtureOrg', 'fixture-source-key', '/offline-original/'):
            self.assertNotIn(secret.encode(), result.stdout + result.stderr)

    def test_export_complete_inventory_is_read_only(self):
        paths = [*self.export.iterdir(), self.candidate_file, self.plan,
                 self.authority / 'registry.sqlite', self.witness / 'witness.sqlite']
        before = [path.read_bytes() for path in paths]
        self.verified_export()
        self.assertEqual([path.read_bytes() for path in paths], before)

    def test_export_complete_inventory_cbc(self):
        self.verified_export()

    def test_export_committed_inventory_does_not_advance_witness(self):
        self.commit_allocation()
        before = self.copy_snapshot()
        self.verified_export()
        self.assertEqual(self.copy_snapshot(), before)

    def test_export_missing_payload(self):
        (self.export / 'raw-2.bin').unlink()
        self.assertEqual(self.export_check().returncode, 1)

    def test_export_extra_file_and_directory(self):
        extra = self.export / 'unregistered'
        extra.write_text('extra')
        self.assertEqual(self.export_check().returncode, 1)
        extra.unlink()
        extra.mkdir()
        self.assertEqual(self.export_check().returncode, 1)

    def test_export_tampered_payload_despite_approved_resources(self):
        path = self.export / 'raw-2.bin'
        payload = bytearray(path.read_bytes())
        payload[-1] ^= 1
        path.write_bytes(payload)
        self.assertEqual(self.export_check().returncode, 1)

    def test_export_unrelated_lookup_and_field_tampering(self):
        original = self.resources.read_bytes()
        for sql in ("update documents set storageIdLookup=printf('%064d',0) where id=2",
                    "update documents set resourceInfo=resourceInfo||'x' where id=2"):
            self.resources.write_bytes(original)
            with closing(sqlite3.connect(self.resources)) as db, db:
                db.execute(sql)
            self.pin_resources()
            self.assertEqual(self.export_check().returncode, 1)

    def test_export_missing_part(self):
        self.assertEqual(self.export_check().returncode, 1)

    def test_export_duplicate_part(self):
        self.assertEqual(self.export_check().returncode, 1)

    def test_export_inconsistent_total(self):
        self.assertEqual(self.export_check().returncode, 1)

    def test_export_invalid_part(self):
        self.assertEqual(self.export_check().returncode, 1)

    def test_export_orphan_storage(self):
        self.assertEqual(self.export_check().returncode, 1)

    def test_export_unrelated_remote(self):
        self.assertEqual(self.export_check().returncode, 1)

    def test_export_unrelated_path(self):
        self.assertEqual(self.export_check().returncode, 1)

    def test_export_duplicate_name(self):
        self.assertEqual(self.export_check().returncode, 1)

    def test_export_path_traversal(self):
        self.assertEqual(self.export_check().returncode, 1)

    def test_export_unsafe_payload_modes_links_sidecars_and_fifo(self):
        path = self.export / 'raw-2.bin'
        content = path.read_bytes()
        path.chmod(0o644)
        self.assertEqual(self.export_check().returncode, 1)
        path.chmod(0o600)
        sidecar = Path(str(path) + '-wal')
        sidecar.touch()
        self.assertEqual(self.export_check().returncode, 1)
        sidecar.unlink()
        path.unlink()
        path.symlink_to(self.export / 'raw-1.bin')
        self.assertEqual(self.export_check().returncode, 1)
        path.unlink()
        os.link(self.export / 'raw-1.bin', path)
        self.assertEqual(self.export_check().returncode, 1)
        path.unlink()
        os.mkfifo(path, 0o600)
        self.assertEqual(self.export_check().returncode, 1)
        path.unlink()
        path.write_bytes(content)
        path.chmod(0o600)
        self.verified_export()

    def test_export_requires_private_internal_databases(self):
        for name in ('RolesDB', 'LogsDB'):
            path = self.export / name
            path.chmod(0o644)
            self.assertEqual(self.export_check().returncode, 1)
            path.chmod(0o600)
            content = path.read_bytes()
            path.unlink()
            self.assertEqual(self.export_check().returncode, 1)
            path.write_bytes(content)
            path.chmod(0o600)

    def test_export_schema_action_and_retained_approval_isolation(self):
        before = self.copy_snapshot()
        for action in ('--prepare', '--commit', '--status', '--advance-witness', '--check-candidate', '--check-registration'):
            self.assertEqual(self.copy_owner(action, extra=('--org-key-file', str(self.org_key))).returncode, 1)
        for schema in (1, 2, 3):
            self.approval['schema'] = schema
            self.write_copy_approval()
            self.assertEqual(self.export_check().returncode, 1)
        self.approval['schema'] = 4
        self.write_copy_approval()
        self.assertEqual(self.export_check(digest='00' * 32).returncode, 1)
        self.assertEqual(self.export_check(token='00' * 40).returncode, 1)
        self.assertEqual(self.copy_snapshot(), before)


for _name in vars(CopyRegistrationTests):
    if _name.startswith('test_'):
        setattr(CopyExportTests, _name, None)


class CopyDestinationTests(CopyExportTests):
    def setUp(self):
        super().setUp()
        self.destination_resources = self.candidate_directory / 'ResourcesDB'
        self.registration_scratch = self.root / 'new-registration'
        self.registration_scratch.mkdir(mode=0o700)
        fixture_root = Path(__file__).resolve().parents[1] / 'TEST' / 'testDB_opt_cdse'
        for name in ('ResourcesDB', 'RolesDB', 'LogsDB'):
            with closing(sqlite3.connect(fixture_root / name)) as source, \
                    closing(sqlite3.connect(self.registration_scratch / name)) as target, target:
                for sql, in source.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name!='schema_meta'"):
                    target.execute(sql)
                if name != 'ResourcesDB':
                    continue
                for field in ('documentIdLookup', 'storageIdLookup', 'orgResourceIdLookup'):
                    target.execute(f'alter table documents add column {field} TEXT')
                columns = [row[1] for row in target.execute('pragma table_info(documents)')]
                values = dict.fromkeys(columns, '')
                values.update(id=4, userId='fixtureUser', orgId='fixtureOrg', columnFile=self.candidate_file.name,
                              type='file.csv', documentId='copy-document', storageId='fixtureStorage',
                              orgResourceId='fixtureOrg', columnId='1', partId='1', totalParts='1')
                for field in columns:
                    if field.endswith('Lookup'):
                        values[field] = None
                if self._testMethodName.endswith('_changed_metadata'):
                    values['userId'] = 'changed-user'
                if self._testMethodName.endswith('_multipart_copy'):
                    values['totalParts'] = '2'
                if self._testMethodName.endswith('_wrong_basename'):
                    values['columnFile'] = 'wrong.sqlite'
                if self._testMethodName.endswith('_existing_document_id'):
                    values['documentId'] = 'raw-document'
                payload = self.registration_scratch / values['columnFile']
                shutil.copyfile(self.candidate_file, payload)
                if self._testMethodName.endswith('_wrong_file_mac'):
                    data = bytearray(payload.read_bytes())
                    data[-1] ^= 1
                    payload.write_bytes(data)
                target.execute(f"insert into documents ({','.join(columns)}) values ({','.join('?' for _ in columns)})",
                               [values[field] for field in columns])
        for action in ('bundle', 'registered-lookups'):
            result = subprocess.run([PAYLOAD, str(self.registration_scratch), action], capture_output=True,
                                    timeout=30, env=dict(os.environ, CDSE_DEFAULT_ENC_ALG=self.profile))
            self.assertEqual(result.returncode, 0, 'synthetic destination registration failed')
        shutil.copyfile(self.resources, self.destination_resources)
        self.destination_resources.chmod(0o600)
        with closing(sqlite3.connect(self.registration_scratch / 'ResourcesDB')) as generated, \
                closing(sqlite3.connect(self.destination_resources)) as target, target:
            row = generated.execute('select * from documents where id=4').fetchone()
            target.execute(f"insert into documents values ({','.join('?' for _ in row)})", row)
        self.approval.update(schema=5, destinationResources=str(self.destination_resources),
                             destinationRegistration=[4, 'copy-document', 'fixtureStorage', 'fixtureOrg', '1'],
                             destinationStorageAccessPath='/offline-original/')
        if self._testMethodName.endswith('_existing_document_id'):
            self.approval['destinationRegistration'][1] = 'raw-document'
        self.pin_destination()

    def pin_destination(self):
        self.approval['destinationResourcesDigest'] = hashlib.sha256(self.destination_resources.read_bytes()).hexdigest()
        self.write_copy_approval()

    def destination_check(self, **options):
        result = self.copy_owner('--check-destination', extra=('--org-key-file', str(self.org_key)), **options)
        for secret in ('copy-document', 'fixture-document', 'fixtureStorage', 'fixtureOrg',
                       'fixture-source-key', '/offline-original/', str(self.destination_resources)):
            self.assertNotIn(secret.encode(), result.stdout + result.stderr)
        return result

    def verified_destination(self):
        result = self.destination_check()
        self.assertEqual(result.returncode, 0, result.stderr)
        data = dict(line.split('=', 1) for line in result.stdout.decode().splitlines())
        self.assertEqual(data['state'], 'verified-legacy-destination')
        self.assertEqual(data['destination-registration'], 'verified-add-only-copy')
        self.assertEqual(data['destination-resources-digest'], self.approval['destinationResourcesDigest'])
        self.assertEqual(data['export-inventory'], 'complete-registered-payloads')
        self.assertEqual(data['context-authentication'], 'absent')
        self.assertEqual(data['publication'], 'disabled')

    def test_destination_ready_preflight_is_read_only(self):
        paths = [*self.export.iterdir(), self.destination_resources, self.candidate_file, self.plan,
                 self.authority / 'registry.sqlite', self.witness / 'witness.sqlite']
        before = [path.read_bytes() for path in paths]
        self.verified_destination()
        self.assertEqual([path.read_bytes() for path in paths], before)

    def test_destination_preflight_cbc(self):
        self.verified_destination()

    def test_destination_committed_preflight_does_not_advance_witness(self):
        self.commit_allocation()
        before = self.copy_snapshot()
        self.verified_destination()
        self.assertEqual(self.copy_snapshot(), before)

    def test_destination_requires_independent_selectors(self):
        original = list(self.approval['destinationRegistration'])
        for index, value in enumerate((5, 'another-document', 'another-storage', 'another-org', '2')):
            self.approval['destinationRegistration'] = list(original)
            self.approval['destinationRegistration'][index] = value
            self.write_copy_approval()
            self.assertEqual(self.destination_check().returncode, 1)

    def test_destination_requires_same_approved_storage_path(self):
        self.approval['destinationStorageAccessPath'] = '/another-storage/'
        self.write_copy_approval()
        self.assertEqual(self.destination_check().returncode, 1)

    def test_destination_lookup_tampering_despite_reapproved_digest(self):
        original = self.destination_resources.read_bytes()
        for field in ('documentIdLookup', 'storageIdLookup', 'orgResourceIdLookup'):
            self.destination_resources.write_bytes(original)
            with closing(sqlite3.connect(self.destination_resources)) as db, db:
                db.execute(f"update documents set {field}=printf('%064d',0) where id=4")
            self.pin_destination()
            self.assertEqual(self.destination_check().returncode, 1)

    def test_destination_wrong_file_mac(self):
        self.assertEqual(self.destination_check().returncode, 1)

    def test_destination_changed_metadata(self):
        self.assertEqual(self.destination_check().returncode, 1)

    def test_destination_multipart_copy(self):
        self.assertEqual(self.destination_check().returncode, 1)

    def test_destination_wrong_basename(self):
        self.assertEqual(self.destination_check().returncode, 1)

    def test_destination_existing_document_id(self):
        self.assertEqual(self.destination_check().returncode, 1)

    def test_destination_rejects_missing_new_registration(self):
        with closing(sqlite3.connect(self.destination_resources)) as db, db:
            db.execute('delete from documents where id=4')
        self.pin_destination()
        self.assertEqual(self.destination_check().returncode, 1)

    def test_destination_rejects_extra_and_replaced_rows(self):
        original = self.destination_resources.read_bytes()
        for sql in ('insert into documents select 5,' + ','.join(f'"{field}"' for field in (
                        'userId', 'orgId', 'salt', 'resourceInfo', 'columnFile', 'type', 'documentId', 'storageId',
                        'orgResourceId', 'partMAC', 'totalParts', 'partId', 'lastModified', 'columnId',
                        'documentIdLookup', 'storageIdLookup', 'orgResourceIdLookup')) + ' from documents where id=4',
                    'delete from documents where id=1',
                    "update documents set resourceInfo=resourceInfo||'x' where id=2",
                    "update users set userId=userId||'x' where id=1",
                    "update storage set accessPath=accessPath||'x' where id=1"):
            self.destination_resources.write_bytes(original)
            with closing(sqlite3.connect(self.destination_resources)) as db, db:
                db.execute(sql)
            self.pin_destination()
            self.assertEqual(self.destination_check().returncode, 1)

    def test_destination_preserves_sql_types_and_schema(self):
        original = self.destination_resources.read_bytes()
        for sql in ("update users set resourceInfo=NULL where id=1",
                    'create index extra_index on documents(type)',
                    'create view unapproved as select * from documents',
                    "update schema_meta set value='0' where key='schemaVersion'"):
            self.destination_resources.write_bytes(original)
            with closing(sqlite3.connect(self.destination_resources)) as db, db:
                db.execute(sql)
            self.pin_destination()
            self.assertEqual(self.destination_check().returncode, 1)

    def test_destination_stale_digest(self):
        self.approval['destinationResourcesDigest'] = '00' * 32
        self.write_copy_approval()
        self.assertEqual(self.destination_check().returncode, 1)

    def test_destination_private_paths_modes_links_and_sidecars(self):
        path = self.destination_resources
        path.chmod(0o644)
        self.assertEqual(self.destination_check().returncode, 1)
        path.chmod(0o600)
        sidecar = Path(str(path) + '-wal')
        sidecar.touch()
        self.assertEqual(self.destination_check().returncode, 1)
        sidecar.unlink()
        content = path.read_bytes()
        path.unlink()
        path.symlink_to(self.resources)
        self.assertEqual(self.destination_check().returncode, 1)
        path.unlink()
        os.link(self.resources, path)
        self.assertEqual(self.destination_check().returncode, 1)
        path.unlink()
        os.mkfifo(path, 0o600)
        self.assertEqual(self.destination_check().returncode, 1)
        path.unlink()
        path.write_bytes(content)
        path.chmod(0o600)
        self.verified_destination()

    def test_destination_cannot_substitute_source_or_arbitrary_db_path(self):
        for path in (self.resources, self.candidate_file, self.registration_scratch / 'ResourcesDB'):
            self.approval['destinationResources'] = str(path)
            self.write_copy_approval()
            self.assertEqual(self.destination_check().returncode, 1)

    def test_destination_requires_full_source_export_inventory(self):
        (self.export / 'raw-2.bin').unlink()
        self.assertEqual(self.destination_check().returncode, 1)

    def test_destination_strict_approval_and_action_isolation(self):
        before = self.copy_snapshot()
        for action in ('--prepare', '--commit', '--status', '--advance-witness', '--check-candidate',
                       '--check-registration', '--check-export'):
            self.assertEqual(self.copy_owner(action, extra=('--org-key-file', str(self.org_key))).returncode, 1)
        original = copy.deepcopy(self.approval)
        serialized = json.dumps(original)
        for key in ('destinationResources', 'destinationResourcesDigest', 'destinationRegistration', 'destinationStorageAccessPath'):
            self.approval_file.write_text(serialized[:-1] + ',' + json.dumps(key) + ':' + json.dumps(original[key]) + '}')
            self.assertEqual(self.destination_check().returncode, 1)
        self.write_copy_approval()
        for key, value in (('destinationRegistration', [True, 'd', 's', 'o', '1']),
                           ('destinationRegistration', [4.0, 'd', 's', 'o', '1']),
                           ('destinationRegistration', [2**63, 'd', 's', 'o', '1']),
                           ('destinationRegistration', [0, 'd', 's', 'o', '1']),
                           ('destinationRegistration', [4, '', 'fixtureStorage', 'fixtureOrg', '1']),
                           ('destinationRegistration', [1, 'fixture-document', 'fixtureStorage', 'fixtureOrg', '1']),
                           ('destinationResourcesDigest', 'invalid'), ('unexpected', 'value')):
            self.approval = dict(original, **{key: value})
            self.write_copy_approval()
            self.assertEqual(self.destination_check().returncode, 1)
        self.approval = original
        del self.approval['destinationRegistration']
        self.write_copy_approval()
        self.assertEqual(self.destination_check().returncode, 1)
        self.approval = original
        self.approval['destinationRegistration'] = [4, 'copy-document', 'fixtureStorage', 'fixtureOrg', '1']
        self.write_copy_approval()
        self.assertEqual(self.destination_check(digest='00' * 32).returncode, 1)
        self.assertEqual(self.destination_check(token='00' * 40).returncode, 1)
        self.assertEqual(self.copy_snapshot(), before)


for _name in vars(CopyExportTests):
    if _name.startswith('test_'):
        setattr(CopyDestinationTests, _name, None)


if __name__ == '__main__':
    unittest.main()
