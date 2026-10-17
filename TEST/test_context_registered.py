#!/usr/bin/env python3
"""Guarded registered preflight/publication; synthetic keys and registrations."""
from contextlib import closing
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import struct
import subprocess
import time
import unittest

import test_context_owner as owner_tests
import test_context_witness as witness_tests

ROOT = Path(__file__).resolve().parents[1]


class RegisteredTests(witness_tests.GuardedOwnerTests):
    def setUp(self):
        super().setUp()
        self.profile = 'aes-256-gcm'
        if self._testMethodName == 'test_cbc_registered_pair' or self._testMethodName.endswith('_cbc'):
            self.profile = 'aes-256-cbc'
        if self._testMethodName == 'test_optional_nla1_registered_pair' or self._testMethodName.endswith('_nla1'):
            probe = subprocess.run([owner_tests.PAYLOAD, 'unused', 'nla1-provider'], capture_output=True, timeout=30)
            if probe.returncode or probe.stdout.strip() != b'1':
                self.skipTest('NLA1 provider not compiled in')
            self.profile = 'herradura-hske-nla1-aead-256'
        self.env = dict(os.environ, CDSE_DEFAULT_ENC_ALG=self.profile)
        meta_count = 2
        if self._testMethodName.endswith('encrypted_row_order'):
            self.env['CDSE_FIXTURE_REGISTERED_SHUFFLE'] = '1'
            meta_count = 3
        if self._testMethodName.endswith('mac_and_sign_integrity'):
            self.env['CDSE_FIXTURE_REGISTERED_TAGS'] = '1'
            meta_count = 6
        if meta_count > 2:
            for row in range(3, meta_count + 1):
                lookup = f'meta-{row}'
                self.allocated(lookup=lookup, level=3, parent='meta', table='meta', field='attribute', expected=self.current())
                self.original_slots.append((lookup, 'meta', row, 'attribute'))
            self.target_slots = [(lookup, table, (meta_count + 1 if table == 'meta' else 3) - row, field)
                                 for lookup, table, row, field in self.original_slots]
            self.assertEqual(self.map_store(self.original_slots).returncode, 0)
        self.active.unlink()
        self.fixture(self.active, 'registered-column')
        self.active.chmod(0o600)
        shutil.copyfile(self.active, self.staged)
        self.staged.chmod(0o600)
        with closing(sqlite3.connect(self.staged)) as db, db:
            for table in ('data', 'meta'):
                db.execute(f'update {table} set id=-id')
                db.execute(f'update {table} set id={meta_count + 1 if table == "meta" else 3}+id')
        self.resources = self.active.parent / 'ResourcesDB'
        self.candidate = self.staged.parent / 'ResourcesDB'
        for name in ('ResourcesDB', 'RolesDB', 'LogsDB'):
            with closing(sqlite3.connect(ROOT / 'TEST/testDB_opt_cdse' / name)) as original, \
                    closing(sqlite3.connect(self.active.parent / name)) as target, target:
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
                        values.update(columnFile=self.active.name, type='file.csv', documentId='fixture-document',
                                      storageId='fixtureStorage', columnId='1', partId='1', totalParts='1')
                        if self._testMethodName == 'test_multipart_registration_is_not_supported':
                            values['totalParts'] = '2'
                        for field in columns:
                            if field.endswith('Lookup'):
                                values[field] = None
                    elif table == 'storage':
                        values.update(storageId='fixtureStorage', type='local', accessPath='/offline-original/')
                        if self._testMethodName == 'test_remote_registration_is_not_supported':
                            values['type'] = 'remote'
                    target.execute(f"insert into {table} ({','.join(columns)}) values ({','.join('?' for _ in columns)})",
                                   [values[field] for field in columns])
        self.fixture(self.active.parent, 'bundle')
        with closing(sqlite3.connect(self.resources)) as db:
            db.execute('pragma journal_mode=DELETE')
        self.fixture(self.active.parent, 'registered-lookups')
        self.resources.chmod(0o600)
        shutil.copyfile(self.resources, self.candidate)
        self.candidate.chmod(0o600)
        self.fixture(self.staged.parent, 'registered-target')
        self.org_key = self.root / 'org.key'
        self.org_key.write_text('fixture-source-key\n')
        self.org_key.chmod(0o600)
        self.approval.update(source=self.digest(self.active), target=self.digest(self.staged),
                             registry=self.current(), catalog=self.map_current(), slots=self.target_slots)
        self.write_approval()
        self.token = self.accepted_guarded('context-witness', '--init')['witness']
        self.approval.update(schema=3, resources=str(self.resources), stagedResources=str(self.candidate),
                             resourcesSource=self.digest(self.resources), resourcesTarget=self.digest(self.candidate),
                             registration=[1, 'fixture-document', 'fixtureStorage', 'fixtureOrg', '1'], profile=self.profile)
        self.write_approval()

    def fixture(self, path, action):
        result = subprocess.run([owner_tests.PAYLOAD, str(path), action], env=self.env, capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, f'synthetic {action} fixture failed')

    @staticmethod
    def digest(path):
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def check(self, *action, token=None, org_key=None, extra=(), env=None):
        result = self.guarded('context-registered-shuffle', *(action or ('--check',)), extra=(
            '--org-key-file', str(org_key or self.org_key), '--retained-witness-token', token or self.token, *extra), env=env)
        for secret in ('fixture-source-key', 'fixture-document', 'fixtureOrg', 'fixtureStorage', str(self.resources), str(self.candidate)):
            self.assertNotIn(secret.encode(), result.stdout + result.stderr)
        return result

    def accepted_pair(self):
        result = self.check()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b'state=verified-pair\npublication=disabled\n')

    def repin(self):
        self.approval.update(source=self.digest(self.active), target=self.digest(self.staged),
                             resourcesSource=self.digest(self.resources), resourcesTarget=self.digest(self.candidate))
        self.write_approval()

    def fingerprint(self):
        paths = (self.active, self.staged, self.resources, self.candidate, self.approval_file,
                 self.authority / 'registry.sqlite', self.witness / 'witness.sqlite')
        return {str(path): path.read_bytes() for path in paths}

    def test_verified_pair_is_readonly_repeatable_and_preserves_lookup_cells(self):
        before = self.fingerprint()
        self.accepted_pair()
        self.accepted_pair()
        self.assertEqual(self.fingerprint(), before)
        self.assertEqual(self.map_bind().returncode, 0)
        with closing(sqlite3.connect(self.resources)) as source, closing(sqlite3.connect(self.candidate)) as target:
            left = source.execute('select * from documents').fetchone()
            right = target.execute('select * from documents').fetchone()
            self.assertNotEqual(left[10], right[10])
            self.assertEqual(left[:10] + left[11:], right[:10] + right[11:])

    def test_cbc_registered_pair(self):
        self.accepted_pair()

    def test_optional_nla1_registered_pair(self):
        self.accepted_pair()

    def test_registered_encrypted_row_order(self):
        self.accepted_pair()

    def test_registered_mac_and_sign_integrity(self):
        self.accepted_pair()

    def test_multipart_registration_is_not_supported(self):
        self.assertEqual(self.check().returncode, 1)

    def test_remote_registration_is_not_supported(self):
        self.assertEqual(self.check().returncode, 1)

    def test_recomputed_file_mac_does_not_hide_payload_corruption_or_nul_aliases(self):
        source, target = self.active.read_bytes(), self.staged.read_bytes()
        native = base64.b64encode(b'CDSEHKX1\x01' + bytes(80)).decode()
        for sql in ("update data set value='BAD'||substr(value,4)",
                    f"update data set value='{native}'",
                    "update data set value=value||char(0)||'hidden'", "update data set MAC='DEAD'"):
            self.active.write_bytes(source)
            self.staged.write_bytes(target)
            for path in (self.active, self.staged):
                with closing(sqlite3.connect(path)) as db, db:
                    db.execute(sql)
            self.fixture(self.active.parent, 'registered-target')
            self.fixture(self.staged.parent, 'registered-target')
            self.repin()
            self.assertEqual(self.check().returncode, 1)

    def test_schema_three_rejects_other_commands_and_uninitialized_publication(self):
        for command, action in (('context-shuffle', '--prepare'), ('context-shuffle', '--init'),
                                ('context-witness', '--status'), ('context-witness', '--init')):
            self.assertEqual(self.guarded(command, action).returncode, 1)
        for action in (('--prepare',), ('--complete', '00' * 32), ('--abort', '00' * 32),
                       ('--check', '--status'), ('--init',)):
            self.assertEqual(self.check(*action).returncode, 1)
        self.assertEqual(self.map_bind().returncode, 0)

    def test_requires_explicit_profile_identity_pins_and_strict_schema(self):
        original = copy.deepcopy(self.approval)
        for field in ('resources', 'stagedResources', 'resourcesSource', 'resourcesTarget', 'registration', 'profile'):
            self.approval = copy.deepcopy(original)
            del self.approval[field]
            self.write_approval()
            self.assertEqual(self.check().returncode, 1)
        for field, value in (('schema', 2), ('resourcesTarget', 'G' * 64), ('profile', 'aes-128-gcm'),
                             ('registration', [True, 'fixture-document', 'fixtureStorage', 'fixtureOrg', '1']),
                             ('registration', [1.0, 'fixture-document', 'fixtureStorage', 'fixtureOrg', '1']),
                             ('registration', [2**63, 'fixture-document', 'fixtureStorage', 'fixtureOrg', '1']),
                             ('registration', [1, 'fixture-document']), ('registration', [1, '', 'a', 'b', 'c'])):
            self.approval = dict(original, **{field: value})
            self.write_approval()
            self.assertEqual(self.check().returncode, 1)
        self.approval = original
        self.write_approval()
        body = self.approval_file.read_text()
        for bad in (body[:-1] + ',"registration":[]}', body[:-1] + ',"extra":1}', body + 'junk', body[:-1] + ',}'):
            self.approval_file.write_text(bad)
            self.assertEqual(self.check().returncode, 1)

    def test_wrong_key_or_protected_field_tag_fails_without_diagnostics(self):
        self.org_key.write_text('wrong-key\n')
        self.assertEqual(self.check().returncode, 1)
        self.org_key.write_text('fixture-source-key\n')
        original = self.candidate.read_bytes()
        for field in ('partMAC', 'documentId', 'storageId', 'orgResourceId'):
            self.candidate.write_bytes(original)
            with closing(sqlite3.connect(self.candidate)) as db, db:
                db.execute(f"update documents set {field}='BAD'||substr({field},4)")
            self.repin()
            self.assertEqual(self.check().returncode, 1)

    def test_registered_source_and_candidate_mac_must_match_exact_payload_bytes(self):
        original = self.candidate.read_bytes()
        self.candidate.write_bytes(self.resources.read_bytes())
        self.repin()
        self.assertEqual(self.check().returncode, 1)
        self.candidate.write_bytes(original)
        with closing(sqlite3.connect(self.active)) as db, db:
            db.execute('pragma user_version=42')
        self.repin()
        self.assertEqual(self.check().returncode, 1)

    def test_changes_to_lookup_salt_other_fields_or_unrelated_tables_are_refused(self):
        original = self.candidate.read_bytes()
        for sql in ("update documents set documentIdLookup='bad'", "update documents set storageIdLookup=NULL",
                    "update documents set orgResourceIdLookup='bad'", "update documents set salt='00'",
                    "update documents set lastModified='bad'", "update users set resourceInfo=NULL",
                    "delete from users", "update schema_meta set value='bad' where key='definitionsVersion'"):
            self.candidate.write_bytes(original)
            with closing(sqlite3.connect(self.candidate)) as db, db:
                db.execute(sql)
            self.repin()
            self.assertEqual(self.check().returncode, 1)

    def test_candidate_permutation_and_slot_identity_are_checked_before_crypto(self):
        with closing(sqlite3.connect(self.staged)) as db, db:
            db.execute("update data set rowOrder='changed'")
        self.repin()
        self.assertEqual(self.check().returncode, 1)
        self.approval['slots'][0] = ('untrusted', *self.approval['slots'][0][1:])
        self.write_approval()
        self.assertEqual(self.check().returncode, 1)

    def test_registration_selectors_cannot_be_adopted_from_candidate(self):
        original = copy.deepcopy(self.approval)
        for index, value in ((0, 2), (1, 'wrong-document'), (2, 'wrong-storage'), (3, 'wrong-org'), (4, 'wrong-column')):
            self.approval = copy.deepcopy(original)
            self.approval['registration'][index] = value
            self.write_approval()
            self.assertEqual(self.check().returncode, 1)

    def test_extra_objects_duplicate_registration_and_unsupported_schema_fail_closed(self):
        source = self.resources.read_bytes()
        target = self.candidate.read_bytes()
        for sql in ("create trigger unexpected after update on documents begin select 1; end",
                    "create table extra (id INTEGER PRIMARY KEY)", "alter table users add column extra TEXT",
                    "update schema_meta set value='1hidden' where key='schemaVersion'",
                    "update schema_meta set value='unknown' where key='definitionsVersion'",
                    "insert into documents select 2,userId,orgId,salt,resourceInfo,columnFile,type,documentId,storageId,orgResourceId,partMAC,totalParts,partId,lastModified,columnId,documentIdLookup,storageIdLookup,orgResourceIdLookup from documents"):
            self.resources.write_bytes(source)
            self.candidate.write_bytes(target)
            for path in (self.resources, self.candidate):
                with closing(sqlite3.connect(path)) as db, db:
                    db.execute(sql)
            if sql.startswith('insert into documents'):
                with closing(sqlite3.connect(self.resources)) as source_db, closing(sqlite3.connect(self.candidate)) as target_db, target_db:
                    duplicate = source_db.execute('select * from documents where id=2').fetchone()
                    target_db.execute('delete from documents where id=2')
                    target_db.execute('insert into documents values (' + ','.join('?' for _ in duplicate) + ')', duplicate)
            self.repin()
            self.assertEqual(self.check().returncode, 1)

    def test_private_key_resources_and_staging_boundaries(self):
        for path in (self.org_key, self.resources, self.candidate):
            path.chmod(0o644)
            self.assertEqual(self.check().returncode, 1)
            path.chmod(0o600)
            alias = self.root / 'alias'
            os.link(path, alias)
            self.assertEqual(self.check().returncode, 1)
            alias.unlink()
        for directory in (self.active.parent, self.staged.parent, self.authority, self.witness):
            copied_key = directory / 'org.key'
            copied_key.write_bytes(self.org_key.read_bytes())
            copied_key.chmod(0o600)
            self.assertEqual(self.check(org_key=copied_key).returncode, 1)
            copied_key.unlink()
        self.approval['stagedResources'] = str(self.resources)
        self.write_approval()
        self.assertEqual(self.check().returncode, 1)

    def test_sidecars_missing_candidate_and_pins_fail_closed(self):
        for path in (self.resources, self.candidate):
            for suffix in ('-wal', '-shm', '-journal'):
                sidecar = Path(str(path) + suffix)
                sidecar.touch(mode=0o600)
                self.assertEqual(self.check().returncode, 1)
                sidecar.unlink()
        original = self.candidate.read_bytes()
        self.candidate.unlink()
        self.assertEqual(self.check().returncode, 1)
        self.candidate.write_bytes(original)
        self.candidate.chmod(0o600)
        self.approval['resourcesTarget'] = '00' * 32
        self.write_approval()
        self.assertEqual(self.check().returncode, 1)

    def test_stale_pins_retained_token_and_revocation_are_not_refreshed(self):
        wrong = bytearray.fromhex(self.token)
        wrong[-1] ^= 1
        self.assertEqual(self.check(token=wrong.hex()).returncode, 2)
        self.assertEqual(self.check(token='00' * 40).returncode, 1)
        self.assertEqual(self.command('revoke', 'second', self.current()).returncode, 0)
        self.assertEqual(self.check().returncode, 2)
        self.approval['registry'] = self.current()
        self.write_approval()
        self.assertEqual(self.check().returncode, 2)

    def test_v2_only_floor_cannot_be_bypassed_by_legacy_preflight(self):
        with closing(sqlite3.connect(self.authority / 'registry.sqlite')) as db:
            snapshot = json.loads(db.execute('select body from registry_current').fetchone()[0])
        _, _, anchor = witness_tests.manager_tests.contract.issue(snapshot, b'k' * 32)
        snapshot.update(generation=snapshot['generation'] + 1, minimumFormat=2)
        self.assertEqual(self.publish(snapshot, anchor).returncode, 0)
        original = dict(self.approval, registry=self.current())
        self.approval = dict(original, schema=2)
        for field in ('resources', 'stagedResources', 'resourcesSource', 'resourcesTarget', 'registration', 'profile'):
            del self.approval[field]
        self.write_approval()
        self.token = self.accepted_guarded('context-witness', '--advance', self.token)['witness']
        self.approval = original
        self.write_approval()
        self.assertEqual(self.check().returncode, 1)

    def test_interrupted_check_can_be_repeated_without_recovery_publication(self):
        before = self.fingerprint()
        flags = [owner_tests.ADMIN, 'context-registered-shuffle', '--approval', str(self.approval_file),
                 '--registry-key-file', str(self.key), '--witness-directory', str(self.witness),
                 '--witness-key-file', str(self.witness_key), '--confirmed-offline', str(self.approval_file),
                 '--org-key-file', str(self.org_key), '--retained-witness-token', self.token, '--check']
        with subprocess.Popen(flags, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as process:
            time.sleep(0.02)
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=30)
        self.assertEqual(self.fingerprint(), before)
        self.accepted_pair()
        self.assertEqual(self.fingerprint(), before)


for _class in (owner_tests.OwnerTests, witness_tests.GuardedOwnerTests):
    for _name in vars(_class):
        if _name.startswith('test_'):
            setattr(RegisteredTests, _name, None)
del _class


class RegisteredPublisherTests(RegisteredTests):
    def accepted_action(self, *action):
        result = self.check(*action)
        self.assertEqual(result.returncode, 0, result.stderr)
        return dict(line.split('=', 1) for line in result.stdout.decode().splitlines())

    def witness_approval(self):
        approval = dict(self.approval, schema=2)
        for field in ('resources', 'stagedResources', 'resourcesSource', 'resourcesTarget', 'registration', 'profile'):
            del approval[field]
        return approval

    def reapprove(self, advance=True):
        self.approval.update(registry=self.current(), catalog=self.map_current())
        if advance:
            registered = self.approval
            self.approval = self.witness_approval()
            self.write_approval()
            self.token = self.accepted_guarded('context-witness', '--advance', self.token)['witness']
            self.approval = registered
        self.write_approval()

    def upgraded(self):
        # Catalog-v2 bootstrap remains the existing schema-2 single-file upgrade.
        registered = self.approval
        self.approval = self.witness_approval()
        self.write_approval()
        self.accepted_guarded('context-shuffle', '--init')
        self.approval = registered
        self.reapprove()
        result = self.accepted_action('--init')
        self.assertEqual(result['catalog'], self.map_current())
        self.assertEqual(self.check('--prepare').returncode, 2)
        self.reapprove()

    def prepared_pair(self):
        self.upgraded()
        result = self.accepted_action('--prepare')
        self.assertEqual(result['catalog'], self.map_current())
        self.assertEqual(self.map_bind().returncode, 1)
        self.assertEqual(self.check('--status').returncode, 2)
        self.reapprove()
        self.assertEqual(self.accepted_action('--status')['state'], 'prepared')
        return result['job']

    def selection_digest(self):
        body = b'CDSE-REGISTERED-SHUFFLE-v1\0' + struct.pack('>Q', self.approval['registration'][0])
        for value in (*self.approval['registration'][1:], self.approval['profile']):
            encoded = value.encode('utf-8')
            body += struct.pack('>H', len(encoded)) + encoded
        return hashlib.sha256(body).digest()

    def test_publish_complete_and_exact_lost_ack_receipt(self):
        job = self.prepared_pair()
        with closing(sqlite3.connect(self.authority / 'registry.sqlite')) as db:
            self.assertEqual(db.execute('select selection from context_shuffle_pairs').fetchone()[0], self.selection_digest())
        result = self.accepted_action('--complete', job)
        self.assertEqual(result['catalog'], self.map_current())
        self.assertFalse(self.staged.exists())
        self.assertFalse(self.candidate.exists())
        self.assertEqual(self.digest(self.active), self.approval['target'])
        self.assertEqual(self.digest(self.resources), self.approval['resourcesTarget'])
        self.assertEqual(self.check('--complete', job).returncode, 2)
        self.reapprove()
        self.assertEqual(self.accepted_action('--status')['state'], 'completed')
        before = (self.map_current(), self.resources.read_bytes(), self.active.read_bytes())
        self.accepted_action('--complete', job)
        self.assertEqual((self.map_current(), self.resources.read_bytes(), self.active.read_bytes()), before)
        self.assertEqual(self.check('--abort', job).returncode, 1)
        self.assertEqual(self.map_bind().returncode, 0)
        self.assertEqual(self.check().returncode, 1)  # No candidates means no new preflight.

    def complete_profile(self):
        job = self.prepared_pair()
        self.accepted_action('--complete', job)
        self.reapprove()
        self.assertEqual(self.accepted_action('--status')['state'], 'completed')

    def test_publish_complete_cbc(self):
        self.complete_profile()

    def test_publish_optional_nla1(self):
        self.complete_profile()

    def test_publish_encrypted_row_order(self):
        self.complete_profile()

    def test_publish_mac_and_sign_integrity(self):
        self.complete_profile()

    def test_publish_abort_retry_and_new_job(self):
        job = self.prepared_pair()
        sources = self.active.read_bytes(), self.resources.read_bytes()
        self.accepted_action('--abort', job)
        self.reapprove()
        self.assertEqual(self.accepted_action('--status')['state'], 'aborted')
        self.accepted_action('--abort', job)
        self.assertEqual((self.active.read_bytes(), self.resources.read_bytes()), sources)
        self.assertTrue(self.staged.exists())
        new_job = self.accepted_action('--prepare')['job']
        self.assertNotEqual(job, new_job)
        self.reapprove()
        self.assertEqual(self.check('--complete', job).returncode, 1)
        self.accepted_action('--complete', new_job)

    def test_recovery_binds_every_selector_profile_digest_path_and_slot(self):
        job = self.prepared_pair()
        original = copy.deepcopy(self.approval)
        changes = [dict(profile='aes-256-cbc'), dict(resourcesSource='11' * 32), dict(resourcesTarget='11' * 32),
                   dict(source='11' * 32), dict(target='11' * 32), dict(resources=str(self.active)),
                   dict(stagedResources=str(self.resources)), dict(slots=self.original_slots)]
        for index in range(5):
            registration = list(original['registration'])
            registration[index] = registration[index] + 1 if index == 0 else registration[index] + '-changed'
            changes.append(dict(registration=registration))
        for change in changes:
            with self.subTest(change=change):
                self.approval = dict(original, **change)
                self.write_approval()
                self.assertEqual(self.check('--status').returncode, 1)
                self.assertEqual(self.check('--complete', job).returncode, 1)
                self.assertEqual(self.check('--abort', job).returncode, 1)
                self.assertEqual(self.map_bind().returncode, 1)
        self.approval = original
        self.write_approval()
        self.accepted_action('--complete', job)

    def test_json_order_and_escaping_do_not_change_commitment(self):
        job = self.prepared_pair()
        text = json.dumps(dict(reversed(list(self.approval.items()))), indent=2)
        self.approval_file.write_text(text.replace('fixture-document', '\\u0066ixture-document'))
        self.assertEqual(self.accepted_action('--status')['job'], job)
        self.accepted_action('--complete', job)

    def test_prepare_rechecks_crypto_and_does_not_reuse_prior_check(self):
        self.upgraded()
        self.accepted_pair()
        before = self.map_current()
        with closing(sqlite3.connect(self.candidate)) as db, db:
            db.execute("update documents set partMAC='corrupt'")
        self.repin()
        self.assertEqual(self.check('--prepare').returncode, 1)
        self.assertEqual(self.map_current(), before)
        self.assertEqual(self.map_bind().returncode, 0)

    def test_prepare_wrong_org_key_cannot_publish(self):
        self.upgraded()
        before = self.map_current()
        self.org_key.write_text('wrong-key\n')
        self.assertEqual(self.check('--prepare').returncode, 1)
        self.assertEqual(self.map_current(), before)

    def test_single_file_commands_reject_paired_receipts(self):
        job = self.prepared_pair()
        registered = self.approval
        self.approval = self.witness_approval()
        self.write_approval()
        for action in (('--status',), ('--prepare',), ('--complete', job), ('--abort', job)):
            self.assertEqual(self.guarded('context-shuffle', *action).returncode, 1)
        self.approval = registered
        self.write_approval()
        self.accepted_action('--abort', job)

    def test_stale_witness_token_blocks_install_even_after_reapproval(self):
        self.upgraded()
        old = self.token
        job = self.accepted_action('--prepare')['job']
        self.reapprove(advance=False)
        sources = self.active.read_bytes(), self.resources.read_bytes()
        self.assertEqual(self.check('--complete', job).returncode, 2)
        self.reapprove()
        self.assertEqual(self.check('--complete', job, token=old).returncode, 2)
        self.assertEqual((self.active.read_bytes(), self.resources.read_bytes()), sources)
        self.accepted_action('--complete', job)

    def test_missing_remaining_candidate_keeps_binding_blocked(self):
        job = self.prepared_pair()
        saved = self.candidate.read_bytes()
        self.candidate.unlink()
        self.assertEqual(self.check('--complete', job).returncode, 1)
        self.assertEqual(self.map_bind().returncode, 1)
        self.candidate.write_bytes(saved)
        self.candidate.chmod(0o600)
        self.accepted_action('--complete', job)

    def test_status_metadata_does_not_certify_unknown_active_bytes(self):
        job = self.prepared_pair()
        saved = self.active.read_bytes()
        with closing(sqlite3.connect(self.active)) as db, db:
            db.execute('pragma user_version=77')
        self.assertEqual(self.accepted_action('--status')['state'], 'prepared')
        self.assertEqual(self.check('--complete', job).returncode, 1)
        self.assertEqual(self.check('--abort', job).returncode, 1)
        self.assertEqual(self.map_bind().returncode, 1)
        self.active.write_bytes(saved)
        self.accepted_action('--complete', job)

    def test_registered_recovery_rejects_single_file_intents(self):
        self.upgraded()
        self.assertEqual(self.check('--status').returncode, 1)
        registered = self.approval
        self.approval = self.witness_approval()
        self.write_approval()
        job = self.accepted_guarded('context-shuffle', '--prepare')['job']
        self.approval = registered
        self.reapprove()
        for action in (('--status',), ('--complete', job), ('--abort', job)):
            self.assertEqual(self.check(*action).returncode, 1)

    def test_finished_receipt_expires_after_later_catalog_publication(self):
        job = self.prepared_pair()
        self.accepted_action('--complete', job)
        self.reapprove()
        self.assertEqual(self.map_store(self.target_slots, name='other').returncode, 0)
        self.reapprove()
        self.assertEqual(self.check('--complete', job).returncode, 2)

    def test_registered_actions_cannot_bypass_raised_floor(self):
        job = self.prepared_pair()
        with closing(sqlite3.connect(self.authority / 'registry.sqlite')) as db:
            snapshot = json.loads(db.execute('select body from registry_current').fetchone()[0])
        _, _, anchor = witness_tests.manager_tests.contract.issue(snapshot, b'k' * 32)
        snapshot.update(generation=snapshot['generation'] + 1, minimumFormat=2)
        self.assertEqual(self.publish(snapshot, anchor).returncode, 0)
        self.reapprove()
        for action in (('--check',), ('--init',), ('--prepare',), ('--status',), ('--complete', job), ('--abort', job)):
            self.assertEqual(self.check(*action).returncode, 1)
        self.assertEqual(self.map_bind().returncode, 1)

    def test_restore_cannot_use_retained_newer_witness(self):
        self.upgraded()
        backup = (self.authority / 'registry.sqlite').read_bytes()
        previous = copy.deepcopy(self.approval)
        self.accepted_action('--prepare')
        self.reapprove()
        (self.authority / 'registry.sqlite').write_bytes(backup)
        self.approval = previous
        self.write_approval()
        self.assertEqual(self.check('--prepare').returncode, 2)

    def check_interrupted_install(self, checkpoint, offline=False):
        job = self.prepared_pair()
        before = self.map_current()
        env = {'CDSE_CONTEXT_OFFLINE_CRASH' if offline else 'CDSE_CONTEXT_MANAGER_CRASH': checkpoint}
        # Fault injection belongs only to the non-installed fixture. Prepare and
        # final reconciliation use the installed owner boundary and real crypto.
        result = self.command('shuffle-pair-recover', 'view', job, 1, self.current(), before, env=env)
        self.assertEqual(result.returncode, 86)
        self.assertEqual(self.map_bind().returncode, 1 if checkpoint != 'after-commit' else 0)
        if checkpoint == 'after-commit':
            self.assertEqual(self.check('--complete', job).returncode, 2)
            self.reapprove()
        else:
            self.assertEqual(self.map_current(), before)
            self.assertEqual(self.accepted_action('--status')['state'], 'prepared')
            self.assertEqual(self.check('--abort', job).returncode, 1)
        self.accepted_action('--complete', job)
        if checkpoint != 'after-commit':
            self.reapprove()
        self.assertEqual(self.accepted_action('--status')['state'], 'completed')
        self.assertEqual(self.digest(self.active), self.approval['target'])
        self.assertEqual(self.digest(self.resources), self.approval['resourcesTarget'])


for _name in tuple(vars(RegisteredTests)):
    if _name.startswith('test_'):
        setattr(RegisteredPublisherTests, _name, None)

for _point, _offline in (('after-rename', True), ('after-resources-rename', True),
                         ('after-column-install', False), ('after-resources-install', False),
                         ('after-artifact-sync', False), ('after-write', False), ('after-commit', False)):
    def _recovery_case(self, point=_point, offline=_offline):
        self.check_interrupted_install(point, offline)
    setattr(RegisteredPublisherTests, 'test_owner_recovery_' + _point.replace('-', '_'), _recovery_case)


if __name__ == '__main__':
    unittest.main()
