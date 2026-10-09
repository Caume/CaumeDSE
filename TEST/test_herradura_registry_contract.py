#!/usr/bin/env python3
"""Authenticated registry reference tests; synthetic keys, no storage integration."""
import copy
from dataclasses import replace
import hashlib
import json
import unittest

import herradura_registry_contract as registry


class RegistryTests(unittest.TestCase):
    def setUp(self):
        self.key = b'k' * 32
        self.context = dict(zip(registry.UUID_FIELDS, (bytes([i]).hex() * 16 for i in range(1, 6))))
        self.context.update(role='ColumnFile', table='data', field='value')
        self.snapshot = {'schema': 1, 'deployment': self.context['deployment'],
                         'organization': self.context['organization'], 'generation': 1, 'minimumFormat': 1,
                         'entries': [{'lookup': 'column/record/value', 'state': 'active', 'context': self.context}]}
        self.body, self.tag, self.anchor = registry.issue(self.snapshot, self.key)
        self.verified = registry.verify(self.body, self.tag, self.key, self.anchor)

    def test_authenticated_lookup_returns_independent_context(self):
        context = self.verified.expected_context('column/record/value')
        self.assertEqual(context['resource'], b'\x04' * 16)
        context['resource'] = b'x' * 16
        self.assertEqual(self.verified.expected_context('column/record/value')['resource'], b'\x04' * 16)
        with self.assertRaises(ValueError):
            self.verified.expected_context('unregistered')

    def test_modified_payload_tag_and_key_are_rejected(self):
        for body, tag, key in ((self.body.replace(b'"value"', b'"other"'), self.tag, self.key),
                               (self.body, bytes(32), self.key), (self.body, self.tag, b'x' * 32)):
            with self.subTest(body=body[:10]), self.assertRaises(ValueError):
                registry.verify(body, tag, key, self.anchor)

    def test_authentic_foreign_scope_is_rejected(self):
        other = copy.deepcopy(self.snapshot)
        other['organization'] = other['entries'][0]['context']['organization'] = 'aa' * 16
        body, tag, _ = registry.issue(other, self.key)
        with self.assertRaises(ValueError):
            registry.verify(body, tag, self.key, self.anchor)

    def test_pin_rejects_same_generation_alternate_mapping(self):
        changed = copy.deepcopy(self.snapshot)
        changed['entries'][0]['context']['record'] = 'aa' * 16
        body, tag, _ = registry.issue(changed, self.key)
        with self.assertRaises(ValueError):
            registry.verify(body, tag, self.key, self.anchor)

    def test_anchor_metadata_must_match(self):
        for change in ({'generation': 2}, {'minimum_format': 2}, {'deployment': 'aa' * 16}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                registry.verify(self.body, self.tag, self.key, replace(self.anchor, **change))

    def test_generation_and_format_floor_are_monotonic(self):
        next_snapshot = copy.deepcopy(self.snapshot)
        next_snapshot.update(generation=2, minimumFormat=2)
        body, tag, anchor = registry.issue(next_snapshot, self.key, self.verified)
        current = registry.verify(body, tag, self.key, anchor)
        with self.assertRaises(ValueError):
            registry.verify(self.body, self.tag, self.key, anchor)
        for generation, floor in ((2, 2), (4, 2), (3, 1)):
            with self.subTest(generation=generation, floor=floor), self.assertRaises(ValueError):
                registry.issue(dict(next_snapshot, generation=generation, minimumFormat=floor), self.key, current)
        with self.assertRaises(ValueError):
            current.read_kind('column/record/value', b'old-aes')
        self.assertEqual(self.verified.read_kind('column/record/value', b'old-aes'), 'legacy-aes')

    def test_revoke_retains_tombstone_and_blocks_reads_and_revival(self):
        revoked = copy.deepcopy(self.snapshot)
        revoked['generation'] = 2
        revoked['entries'][0]['state'] = 'revoked'
        body, tag, anchor = registry.issue(revoked, self.key, self.verified)
        current = registry.verify(body, tag, self.key, anchor)
        with self.assertRaises(ValueError):
            current.read_kind('column/record/value', b'old-aes')
        revived = copy.deepcopy(self.snapshot)
        revived['generation'] = 3
        with self.assertRaises(ValueError):
            registry.issue(revived, self.key, current)
        with self.assertRaises(ValueError):
            registry.issue(dict(revoked, generation=3, entries=[]), self.key, current)

    def test_context_cannot_mutate_across_generations(self):
        for field in ('storage', 'resource', 'record'):
            changed = copy.deepcopy(self.snapshot)
            changed['generation'] = 2
            changed['entries'][0]['context'][field] = 'aa' * 16
            with self.subTest(field=field), self.assertRaises(ValueError):
                registry.issue(changed, self.key, self.verified)

    def test_duplicate_entries_and_namespace_mismatch_are_rejected(self):
        duplicate = copy.deepcopy(self.snapshot)
        duplicate['entries'].append(copy.deepcopy(duplicate['entries'][0]))
        with self.assertRaises(ValueError):
            registry.issue(duplicate, self.key)
        duplicate['entries'][1]['lookup'] = 'different'
        with self.assertRaises(ValueError):
            registry.issue(duplicate, self.key)
        changed = copy.deepcopy(self.snapshot)
        changed['entries'][0]['context']['deployment'] = 'aa' * 16
        with self.assertRaises(ValueError):
            registry.issue(changed, self.key)

    def test_bounds_and_strict_schema(self):
        for change in ({'schema': True}, {'generation': True}, {'generation': 0},
                       {'minimumFormat': 0}, {'entries': [{}] * (registry.MAX_ENTRIES + 1)},
                       {'unexpected': 'data'}):
            with self.subTest(change=list(change)), self.assertRaises(ValueError):
                registry.issue(dict(self.snapshot, **change), self.key)
        with self.assertRaises(ValueError):
            registry.verify(b'x' * (registry.MAX_BYTES + 1), self.tag, self.key, self.anchor)
        with self.assertRaises(ValueError):
            registry.issue(self.snapshot, b'short')
        for change in ({'generation': True}, {'minimum_format': True}, {'digest': b'short'}):
            with self.subTest(anchor=change), self.assertRaises(ValueError):
                replace(self.anchor, **change)

    def test_even_signed_noncanonical_payload_is_rejected(self):
        body = json.dumps(self.snapshot).encode()
        anchor = replace(self.anchor, digest=hashlib.sha256(body).digest())
        with self.assertRaises(ValueError):
            registry.verify(body, registry.authenticate(body, self.key), self.key, anchor)

    def test_entry_order_is_canonical(self):
        other = copy.deepcopy(self.snapshot['entries'][0])
        other['lookup'] = 'another'
        other['context']['record'] = 'aa' * 16
        one = dict(self.snapshot, entries=[self.snapshot['entries'][0], other])
        two = dict(self.snapshot, entries=list(reversed(one['entries'])))
        self.assertEqual(registry.issue(one, self.key), registry.issue(two, self.key))


if __name__ == '__main__':
    unittest.main()
