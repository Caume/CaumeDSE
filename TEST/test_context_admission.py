#!/usr/bin/env python3
"""Trusted-core blocked map admission; synthetic authority, no physical-file claim."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import hashlib
import hmac
import json
import os
import sqlite3
import struct
import unittest

import test_context_manager as manager

DOMAIN = b'CDSE-HKX-COLUMN-MAP-ADMISSION-v1\0'


class AdmissionTests(manager.CopyPlanTests):
    def command(self, action, *args, env=None, **options):
        result = super().command(action, *args, env=env, **options)
        injected = env and any(key in env for key in
                              ('CDSE_CONTEXT_MANAGER_CRASH', 'CDSE_CONTEXT_WITNESS_CRASH'))
        self.assertIn(result.returncode, (0, 1, 2, 86) if injected else (0, 1, 2),
                      'unexpected fixture/sanitizer exit')
        for diagnostic in (b'AddressSanitizer', b'LeakSanitizer', b'UndefinedBehaviorSanitizer', b'runtime error:'):
            self.assertNotIn(diagnostic, result.stderr)
        return result

    def copy_setup(self):
        super().copy_setup()
        if not self._testMethodName.endswith('_v1'):
            for action in ('shuffle-init', 'shuffle-pair-init', 'copy-install-init'):
                result = self.command(action, self.current(), self.map_current())
                self.assertEqual(result.returncode, 0, result.stderr)

    def setUp(self):
        manager.ManagerTests.setUp(self)
        self.plan_setup()
        if not self._testMethodName.endswith('_ready'):
            self.allocation = self.plan_result('commit')
        self.registry = self.current()
        self.catalog = self.map_current()
        self.witness, self.retained = self.init_plan_witness()
        self.evidence = hashlib.sha256(b'independently verified publication evidence').hexdigest()
        self.destination = 'admitted-copy'
        self.ticket_path = self.root/'admission.ticket'

    def map_read(self, name='view', catalog=None):
        return self.command('admission-map-read', name, self.current(), catalog or self.map_current())

    def prepare(self, **changes):
        args = dict(plan=self.plan_path, digest=self.plan_digest, original=self.plan_registry,
                    registry=self.registry, catalog=self.catalog, name=self.destination, evidence=self.evidence)
        args.update(changes)
        return self.command('admission-plan', *args.values())

    def retain(self):
        result = self.prepare()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.digest, self.next_catalog, encoded = result.stdout.decode().split()
        self.ticket = bytes.fromhex(encoded)
        self.assertEqual(hashlib.sha256(self.ticket).hexdigest(), self.digest)
        fd = os.open(self.ticket_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'wb') as output:
            output.write(self.ticket)
            output.flush()
            os.fsync(output.fileno())
        directory = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)

    def step(self, *, guard=False, commit=0, env=None, **changes):
        args = dict(registry=self.registry, catalog=self.catalog, next=self.next_catalog,
                    name=self.destination, evidence=self.evidence, ticket=self.ticket_path, digest=self.digest)
        token = changes.pop('retained', self.retained)
        args.update(changes)
        tail = (self.witness, token) if guard else (commit,)
        result = self.command('admission-guard' if guard else 'admission-step', *args.values(), *tail, env=env)
        if result.returncode:
            self.assertEqual(result.stdout, b'')
            self.assertNotEqual(result.returncode, 3, 'fixture output-clear contract failed')
        return result

    def committed(self, **options):
        result = self.step(guard=True, **options)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b'2\n')
        self.assertEqual(self.current(), self.registry)
        self.assertEqual(self.map_current(), self.next_catalog)

    def advance(self):
        result = self.command('witness-advance', self.registry, self.next_catalog, self.retained,
                              directory=self.witness)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.decode().strip()

    def assert_blocked(self):
        for name in ('view', self.destination):
            read = self.map_read(name=name)
            self.assertEqual(read.returncode, 0, read.stderr)
            self.assertEqual(json.loads(read.stdout)['blocked'], 1)
            self.assertNotEqual(self.map_bind(name=name).returncode, 0)
        self.assertNotEqual(self.map_remove().returncode, 0)
        self.assertNotEqual(self.map_remove(name=self.destination).returncode, 0)
        self.assertNotEqual(self.map_store(self.source_slots, name='other').returncode, 0)
        self.assertNotEqual(self.command('revoke', self.lookups[0], self.registry).returncode, 0)
        self.assertNotEqual(self.plan_action().returncode, 0)

    def test_preview_independent_encoding_and_no_authority_write(self):
        before = (self.authority/'registry.sqlite').read_bytes(), (self.witness/'witness.sqlite').read_bytes()
        self.retain()
        def text(value):
            encoded = value.encode('ascii')
            return bytes([len(encoded)]) + encoded
        expected = bytearray(DOMAIN + bytes.fromhex(self.registry + self.catalog + self.evidence))
        expected.extend(text(self.destination) + text(self.allocation['resource']))
        expected.extend(struct.pack('>I', len(self.allocation['slots'])))
        for lookup, table, row, field in self.allocation['slots']:
            expected.extend(text(lookup) + text(table) + struct.pack('>Q', row) + text(field))
        expected.extend(hmac.digest(b'k'*32, expected, 'sha256'))
        self.assertEqual(self.ticket, expected)
        self.assertEqual(((self.authority/'registry.sqlite').read_bytes(),
                          (self.witness/'witness.sqlite').read_bytes()), before)
        self.assertEqual(self.map_read(name=self.destination).returncode, 1)
        self.assertEqual(self.prepare().stdout.decode().split()[0], self.digest)
        self.assertEqual(self.step().stdout, b'1\n')
        self.assertEqual(self.map_bind().returncode, 0)

    def test_commit_exact_descriptor_global_block_and_independent_catalog(self):
        self.retain()
        source = json.loads(self.map_read().stdout)
        self.committed()
        self.assert_blocked()
        result = json.loads(self.map_read(name=self.destination).stdout)
        self.assertEqual(result['slots'], self.allocation['slots'])
        self.assertEqual(result['resource'], self.allocation['resource'])
        source['blocked'] = 1
        self.assertEqual(json.loads(self.map_read().stdout), source)
        with closing(sqlite3.connect(self.authority/'registry.sqlite')) as db:
            maps = db.execute('select name,resource,role,active from context_maps').fetchall()
            slots = db.execute('select map_name,table_name,slot,field_name,lookup from context_map_slots').fetchall()
            rows = db.execute('select name,job,body,state,finished from context_copies').fetchall()
            revision, tag = db.execute('select revision,tag from context_map_head').fetchone()
        # Independently extend the established v3 wire encoding with the v4 job.
        revision = int.from_bytes(revision, 'big')
        body = manager.catalog_bytes(self.anchor.deployment, self.anchor.organization, revision,
                                     maps, slots, shuffles=[], pairs=[])
        body = body.replace(b'CDSE-HKX-MAP-v3\0', b'CDSE-HKX-MAP-v4\0', 1)
        body += struct.pack('>I', len(rows))
        for name, digest, ticket, state, finished in rows:
            body += bytes([len(name)]) + name.encode() + digest + struct.pack('>I', len(ticket)) + ticket
            body += bytes([state]) + finished
        self.assertEqual(tag, hmac.digest(b'k'*32, body, 'sha256'))
        self.assertEqual(self.next_catalog, (struct.pack('>Q', revision) + hashlib.sha256(body).digest()).hex())
        self.assertEqual(rows, [(self.destination, bytes.fromhex(self.digest), self.ticket, 1, bytes(8))])

    def test_guard_retry_requires_explicit_witness_ack_and_stays_blocked(self):
        self.retain()
        before = (self.witness/'witness.sqlite').read_bytes()
        self.committed()
        self.assertEqual((self.witness/'witness.sqlite').read_bytes(), before)
        self.committed()
        acknowledged = self.advance()
        self.assertNotEqual(acknowledged, self.retained)
        self.committed()  # exact previous-token lost acknowledgement
        self.committed(retained=acknowledged)  # independently retained current acknowledgement
        self.assertEqual(self.advance(), acknowledged)
        self.assert_blocked()

    def test_guard_refuses_future_witness_before_catalog_commit(self):
        self.retain()
        self.advance()  # synthetic independently approved future witness; manager has not committed
        self.assertNotEqual(self.step(guard=True).returncode, 0)
        self.assertEqual(self.map_current(), self.catalog)
        self.assertEqual(self.map_read(name=self.destination).returncode, 1)

    def test_guard_refuses_unrelated_original_catalog_even_one_step_behind(self):
        self.retain()
        alternate = self.catalog[:16] + '55'*32
        other = self.root/'wrong-witness'
        other.mkdir(mode=0o700)
        result = self.command('witness-init', self.registry, alternate, directory=other)
        self.assertEqual(result.returncode, 0)
        self.witness, self.retained = other, result.stdout.decode().strip()
        self.assertEqual(self.step(guard=True).returncode, 2)
        self.committed_unchecked()
        self.assertEqual(self.step(guard=True).returncode, 2)
        self.assert_blocked()

    def committed_unchecked(self):
        self.assertEqual(self.step(commit=1).returncode, 0)

    def test_retained_ticket_required_and_uncommitted_plan_refused_ready(self):
        self.assertEqual(self.prepare().returncode, 2)
        self.assertEqual(self.current(), self.registry)

    def test_catalog_v4_required_without_implicit_upgrade_v1(self):
        self.assertNotEqual(self.prepare().returncode, 0)
        self.assertEqual(self.map_current(), self.catalog)
        with closing(sqlite3.connect(self.authority/'registry.sqlite')) as db:
            self.assertEqual(db.execute("select count(*) from sqlite_master where name='context_copies'").fetchone()[0], 0)

    def test_preparation_rejects_forged_allocation_and_original_pins(self):
        before = self.current(), self.map_current()
        for changes in (dict(digest='00'*32), dict(original=self.registry),
                        dict(registry=self.plan_registry), dict(catalog='00'*40), dict(name='view')):
            with self.subTest(changes=changes):
                self.assertNotEqual(self.prepare(**changes).returncode, 0)
                self.assertEqual((self.current(), self.map_current()), before)

    def test_ticket_and_external_pins_substitution_refused(self):
        self.retain()
        for changes in (dict(digest='00'*32), dict(evidence='11'*32), dict(name='different'),
                        dict(registry=self.plan_registry), dict(catalog='00'*40), dict(next='00'*40),
                        dict(next=self.catalog), dict(retained='00'*40)):
            with self.subTest(changes=changes):
                self.assertNotEqual(self.step(guard=True, **changes).returncode, 0)
                self.assertEqual(self.map_current(), self.catalog)
        for payload in (self.ticket[:-1], self.ticket+b'\0', b'\0', self.ticket[:40]+b'\0'+self.ticket[41:]):
            self.ticket_path.write_bytes(payload)
            self.digest = hashlib.sha256(payload).hexdigest()
            self.assertNotEqual(self.step(commit=1).returncode, 0)
            self.assertEqual(self.map_current(), self.catalog)

    def test_signed_noncanonical_descriptor_refused(self):
        self.retain()
        offset = len(DOMAIN)+73+40+32
        for _ in range(2):
            offset += 1+self.ticket[offset]
        count_offset = offset
        offset += 4
        first = offset
        for _ in range(2):
            offset += 1+self.ticket[offset]
        row_offset = offset
        for label, change in (
                ('zero-slots', lambda b: b.__setitem__(slice(count_offset,count_offset+4), bytes(4))),
                ('zero-row', lambda b: b.__setitem__(slice(row_offset,row_offset+8), bytes(8))),
                ('negative-row', lambda b: b.__setitem__(slice(row_offset,row_offset+8), b'\xff'*8)),
                ('nul-lookup', lambda b: b.__setitem__(first+1, 0))):
            with self.subTest(label=label):
                body = bytearray(self.ticket[:-32])
                change(body)
                payload = body + hmac.digest(b'k'*32, body, 'sha256')
                self.ticket_path.write_bytes(payload)
                self.digest = hashlib.sha256(payload).hexdigest()
                self.assertNotEqual(self.step(commit=1).returncode, 0)
                self.assertEqual(self.map_current(), self.catalog)

    def test_stale_registry_and_competing_catalog_do_not_publish(self):
        self.retain()
        self.assertEqual(self.map_store(self.source_slots, name='competitor').returncode, 0)
        current = self.map_current()
        self.assertEqual(self.step(guard=True).returncode, 2)
        self.assertEqual(self.map_current(), current)
        self.assertEqual(self.map_read(name=self.destination).returncode, 1)

    def test_registry_revocation_expires_ticket(self):
        self.retain()
        self.assertEqual(self.command('revoke', self.lookups[0], self.registry).returncode, 0)
        self.assertEqual(self.step(guard=True).returncode, 2)
        self.assertEqual(self.map_current(), self.catalog)

    def test_legacy_copy_recovery_cannot_release_admission(self):
        self.retain()
        self.committed()
        self.assertNotEqual(self.command('copy-install-read', self.destination, self.registry, self.next_catalog).returncode, 0)
        for complete in (0, 1):
            self.assertNotEqual(self.command('copy-install-recover', self.destination, self.digest, complete,
                                             self.registry, self.next_catalog).returncode, 0)
            self.assertEqual(self.map_current(), self.next_catalog)
            self.assert_blocked()

    def test_job_tampering_refused_without_repair(self):
        self.retain()
        self.committed()
        path = self.authority/'registry.sqlite'
        before = path.read_bytes()
        for sql in ("update context_copies set job=zeroblob(32)",
                    "update context_copies set body=x'00'", "delete from context_copies",
                    "update context_copies set state=2,finished=x'0000000000000001'",
                    "update context_maps set resource='first' where name='admitted-copy'"):
            with self.subTest(sql=sql):
                path.write_bytes(before)
                with closing(sqlite3.connect(path)) as db:
                    db.execute(sql)
                    db.commit()
                self.assertNotEqual(self.step(guard=True).returncode, 0)
                self.assertNotEqual(self.map_bind(registry=self.registry, catalog=self.next_catalog).returncode, 0)

    def test_competing_retained_tickets_only_one_catalog_commit(self):
        self.retain()
        second = self.prepare(name='another-copy')
        self.assertEqual(second.returncode, 0)
        digest, following, encoded = second.stdout.decode().split()
        path = self.root/'another.ticket'
        path.write_bytes(bytes.fromhex(encoded))
        path.chmod(0o600)
        with ThreadPoolExecutor(max_workers=2) as workers:
            first = workers.submit(self.step, commit=1)
            other = workers.submit(self.step, commit=1, name='another-copy', ticket=path,
                                   digest=digest, next=following)
            results = first.result(), other.result()
        self.assertEqual(sorted(r.returncode for r in results), [0, 2])
        winner = self.destination if results[0].returncode==0 else 'another-copy'
        loser = 'another-copy' if results[0].returncode==0 else self.destination
        self.assertEqual(self.map_current(), self.next_catalog if results[0].returncode==0 else following)
        self.assertEqual(json.loads(self.map_read(name=winner).stdout)['blocked'], 1)
        self.assertEqual(self.map_read(name=loser).returncode, 1)
        with closing(sqlite3.connect(self.authority/'registry.sqlite')) as db:
            self.assertEqual(db.execute('select count(*) from context_copies').fetchone()[0], 1)

    def test_retained_acknowledgement_refuses_witness_rollback(self):
        self.retain()
        self.committed()
        before = (self.witness/'witness.sqlite').read_bytes()
        acknowledged = self.advance()
        (self.witness/'witness.sqlite').write_bytes(before)
        self.assertEqual(self.step(guard=True, retained=acknowledged).returncode, 2)
        self.assertEqual(self.map_current(), self.next_catalog)
        self.assert_blocked()

    def check_witness_crash(self, point):
        self.retain()
        self.committed()
        result = self.command('witness-advance', self.registry, self.next_catalog, self.retained,
                              directory=self.witness, env={'CDSE_CONTEXT_WITNESS_CRASH': point})
        self.assertEqual(result.returncode, 86)
        self.committed()
        acknowledged = self.advance()
        self.committed(retained=acknowledged)
        self.assert_blocked()

    def check_crash(self, point):
        self.retain()
        result = self.step(guard=True, env={'CDSE_CONTEXT_MANAGER_CRASH': point})
        self.assertEqual(result.returncode, 86)
        self.assertEqual(self.map_current(), self.next_catalog if point=='after-commit' else self.catalog)
        self.assertEqual(self.step().stdout, b'2\n' if point=='after-commit' else b'1\n')
        self.committed()
        self.assert_blocked()
        self.advance()
        self.committed()


# Reuse setup/helpers without rediscovering the parent's broad suites.
for _cls in (manager.ManagerTests, manager.CopyProvisionTests, manager.CopyPlanTests):
    for _name in vars(_cls):
        if _name.startswith('test_'):
            setattr(AdmissionTests, _name, None)
del _cls
for _point in ('after-begin', 'after-write', 'after-commit'):
    def _crash(self, point=_point):
        self.check_crash(point)
    setattr(AdmissionTests, 'test_admission_crash_'+_point.replace('-', '_'), _crash)

for _point in ('after-begin', 'after-write', 'after-commit'):
    def _witness_crash(self, point=_point):
        self.check_witness_crash(point)
    setattr(AdmissionTests, 'test_witness_crash_'+_point.replace('-', '_'), _witness_crash)

if __name__ == '__main__':
    unittest.main()
