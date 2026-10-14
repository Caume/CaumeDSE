#!/usr/bin/env python3
"""Private local owner approvals; no candidate-derived identity or V2 claims."""
from contextlib import closing
import copy
import hashlib
import json
import os
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


if __name__ == '__main__':
    unittest.main()
