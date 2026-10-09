#!/usr/bin/env python3
"""Python-issued authenticated snapshots checked by the C registry boundary."""
import copy
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

import herradura_registry_contract as contract
from herradura_context_contract import ROLES

FIXTURE = str(Path(os.environ.get('CDSE_REGISTRY_FIXTURE', './context-registry-fixture')).resolve())


class CRegistryTests(unittest.TestCase):
    def setUp(self):
        self.context = dict(zip(contract.UUID_FIELDS, (bytes([i]).hex() * 16 for i in range(1, 6))))
        self.context.update(role='ColumnFile', table='data', field='value')
        self.snapshot = dict(schema=1, deployment=self.context['deployment'],
                             organization=self.context['organization'], generation=1, minimumFormat=1,
                             entries=[dict(lookup='column/record/value', state='active', context=self.context)])
        self.key = b'k' * 32
        self.body, self.tag, self.anchor = contract.issue(self.snapshot, self.key)

    def run_fixture(self, body=None, tag=None, anchor=None, lookup='column/record/value', env=None):
        body = self.body if body is None else body
        tag = self.tag if tag is None else tag
        anchor = self.anchor if anchor is None else anchor
        with tempfile.TemporaryDirectory() as work:
            path = Path(work) / 'snapshot.json'
            path.write_bytes(body)
            return subprocess.run([FIXTURE, str(path), tag.hex(), anchor.digest.hex(),
                                   str(anchor.generation), str(anchor.minimum_format), lookup,
                                   anchor.deployment, anchor.organization], capture_output=True,
                                  env=dict(os.environ, **(env or {})), timeout=20)

    def signed(self, snapshot):
        body = json.dumps(snapshot, sort_keys=True, separators=(',', ':')).encode()
        return body, contract.authenticate(body, self.key), replace(self.anchor, digest=hashlib.sha256(body).digest())

    def test_active_context_matches_reference_and_is_owned(self):
        result = self.run_fixture()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.decode().strip(), '1 ' + contract.context_bytes(
            contract.decode_context(self.context)).hex())

    def test_mac_key_tag_and_body_authentication(self):
        for args in (dict(tag=bytes(32)), dict(body=self.body.replace(b'value', b'other')),
                     dict(env={'CDSE_REGISTRY_WRONG_KEY': '1'})):
            with self.subTest(args=args):
                self.assertEqual(self.run_fixture(**args).returncode, 1)

    def test_independent_pin_and_anchor_metadata(self):
        changed = copy.deepcopy(self.snapshot)
        changed['entries'][0]['context']['record'] = 'aa' * 16
        body, tag, _ = contract.issue(changed, self.key)
        self.assertEqual(self.run_fixture(body=body, tag=tag).returncode, 1)
        for anchor in (replace(self.anchor, generation=2), replace(self.anchor, minimum_format=2),
                       replace(self.anchor, organization='aa' * 16)):
            with self.subTest(anchor=anchor):
                self.assertEqual(self.run_fixture(anchor=anchor).returncode, 1)
        current = dict(self.snapshot, generation=2, minimumFormat=2)
        _, _, current_anchor = contract.issue(current, self.key)
        self.assertEqual(self.run_fixture(anchor=current_anchor).returncode, 1)

    def test_missing_revoked_and_manager_failure(self):
        self.assertEqual(self.run_fixture(lookup='missing').returncode, 1)
        for option in ('CDSE_REGISTRY_MANAGER_FAIL', 'CDSE_REGISTRY_MANAGER_FOREIGN'):
            self.assertEqual(self.run_fixture(env={option: '1'}).returncode, 1)
        snapshot = copy.deepcopy(self.snapshot)
        snapshot['entries'][0]['state'] = 'revoked'
        body, tag, anchor = contract.issue(snapshot, self.key)
        self.assertEqual(self.run_fixture(body, tag, anchor).returncode, 1)

    def test_all_roles_and_format_floors(self):
        for role in ROLES:
            for floor in (1, 2):
                snapshot = copy.deepcopy(self.snapshot)
                context = snapshot['entries'][0]['context']
                context['role'] = role
                if role in ('ResourcesDB', 'RolesDB', 'LogsDB'):
                    context['storage'] = '00' * 16
                if role == 'RawPart':
                    context.update(table='payload', field='bytes')
                if role == 'ColumnFile' and floor == 2:
                    context.update(table='_' + 'a' * 63, field='_' + 'b' * 63)
                snapshot['minimumFormat'] = floor
                body, tag, anchor = contract.issue(snapshot, self.key)
                result = self.run_fixture(body, tag, anchor)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.decode().strip(), str(floor) + ' ' +
                                 contract.context_bytes(contract.decode_context(context)).hex())

    def test_unsigned_generation_extremes(self):
        for generation in (1, 2**63, 2**64 - 1):
            snapshot = dict(self.snapshot, generation=generation)
            body, tag, anchor = contract.issue(snapshot, self.key)
            result = self.run_fixture(body, tag, anchor)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_exact_schema_and_types_even_with_valid_mac_and_pin(self):
        snapshots = []
        for field, value in (('schema', True), ('schema', 2), ('generation', 1.0),
                             ('minimumFormat', True), ('minimumFormat', 3), ('entries', {})):
            snapshots.append(dict(self.snapshot, **{field: value}))
        snapshots.append(dict(self.snapshot, extra=1))
        for field, value in (('role', 'unknown'), ('table', 'bad-name'), ('field', 'a\x00b'),
                             ('record', '00' * 16), ('deployment', 'aa' * 16),
                             ('storage', 'FF' * 16), ('role', 'ResourcesDB'), ('role', 'RawPart'),
                             ('field', 'a' * 65), ('table', 'caf\u00e9')):
            snapshot = copy.deepcopy(self.snapshot)
            snapshot['entries'][0]['context'][field] = value
            snapshots.append(snapshot)
        for target, field, value in (('entry', 'lookup', 'bad!'), ('entry', 'state', 'deleted'),
                                     ('entry', 'extra', 1), ('context', 'extra', 1)):
            snapshot = copy.deepcopy(self.snapshot)
            entry = snapshot['entries'][0]
            (entry if target == 'entry' else entry['context'])[field] = value
            snapshots.append(snapshot)
        snapshot = copy.deepcopy(self.snapshot)
        del snapshot['entries'][0]['context']['field']
        snapshots.append(snapshot)
        for snapshot in snapshots:
            with self.subTest(snapshot=snapshot):
                self.assertEqual(self.run_fixture(*self.signed(snapshot)).returncode, 1)

    def test_canonical_bytes_duplicates_and_ordering(self):
        bodies = [json.dumps(self.snapshot).encode(), self.body + b'\n',
                  self.body.replace(b'"schema":1', b'"schema":1,"schema":1'),
                  self.body.replace(b'"value"', b'"val\\u0075e"'),
                  self.body.replace(b'"schema":1', b'"schema":1.0')]
        second = copy.deepcopy(self.snapshot['entries'][0])
        second['lookup'] = 'another'
        snapshot = copy.deepcopy(self.snapshot)
        snapshot['entries'].append(second)
        bodies.append(self.signed(snapshot)[0])  # Unsorted handles and duplicate context.
        snapshot['entries'].sort(key=lambda entry: entry['lookup'])
        bodies.append(self.signed(snapshot)[0])  # Sorted but duplicate context.
        snapshot['entries'][1]['lookup'] = 'another'
        snapshot['entries'][1]['context']['record'] = 'aa' * 16
        bodies.append(self.signed(snapshot)[0])  # Duplicate handle, distinct context.
        for body in bodies:
            with self.subTest(body=body[:30]):
                tag = contract.authenticate(body, self.key)
                anchor = replace(self.anchor, digest=hashlib.sha256(body).digest())
                self.assertEqual(self.run_fixture(body, tag, anchor).returncode, 1)

    def test_multiple_entries_and_empty_registry(self):
        snapshot = copy.deepcopy(self.snapshot)
        for index in range(10):
            entry = copy.deepcopy(snapshot['entries'][0])
            entry['lookup'] = f'other/{index}'
            entry['context']['record'] = bytes([index + 30]).hex() * 16
            if index == 3:
                entry['state'] = 'revoked'
            snapshot['entries'].append(entry)
        body, tag, anchor = contract.issue(snapshot, self.key)
        for index in range(10):
            self.assertEqual(self.run_fixture(body, tag, anchor, lookup=f'other/{index}').returncode,
                             1 if index == 3 else 0)
        body, tag, anchor = contract.issue(dict(self.snapshot, entries=[]), self.key)
        self.assertEqual(self.run_fixture(body, tag, anchor, lookup='@open-only').returncode, 0)
        self.assertEqual(self.run_fixture(body, tag, anchor).returncode, 1)

    def test_size_bounds_and_malformed_json(self):
        for body in (b'', b'x' * (contract.MAX_BYTES + 1), b'{', b'null', b'[]', b'{}\x00'):
            with self.subTest(length=len(body)):
                tag = contract.authenticate(body, self.key)
                anchor = replace(self.anchor, digest=hashlib.sha256(body).digest())
                self.assertEqual(self.run_fixture(body, tag, anchor).returncode, 1)


if __name__ == '__main__':
    unittest.main()
