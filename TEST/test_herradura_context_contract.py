#!/usr/bin/env python3
"""Draft serialization/dispatch tests, not AEAD authentication proofs."""
import copy
import struct
import unittest

import herradura_context_contract as contract


class ContextContractTests(unittest.TestCase):
    def setUp(self):
        self.context = dict(zip(contract.UUID_FIELDS, (bytes([i]) * 16 for i in range(1, 6))))
        self.context.update(role='ColumnFile', table='data', field='value')
        self.nonce = bytes(range(32))
        self.salt = bytes(range(16))
        self.frame = contract.HEADER.pack(contract.MAGIC, 1, 0, 1, 1, 3, self.nonce, bytes(32)) + b'abc'

    def encode(self, context=None):
        return contract.aad(context or self.context, self.salt, self.nonce, 3)

    def test_fixed_serialization_vector(self):
        expected = (b'CDSE-HKX-AAD-v2\x00' + b'CDSEHKX2\x01\x00\x01\x01\x00\x00\x00\x03' +
                    bytes(range(32)) + bytes(range(16)) + b'\x04' +
                    b'\x01' * 16 + b'\x02' * 16 + b'\x03' * 16 + b'\x04' * 16 + b'\x05' * 16 +
                    b'\x04data\x05value')
        self.assertEqual(self.encode(), expected)
        self.assertEqual(contract.HEADER.size, 80)

    def test_cross_context_substitution_changes_aad(self):
        for name in contract.UUID_FIELDS:
            changed = copy.deepcopy(self.context)
            changed[name] = b'\x06' * 16
            with self.subTest(field=name):
                self.assertNotEqual(self.encode(changed), self.encode())
        for name, value in (('role', 'RawPart'), ('table', 'meta'), ('field', 'orgId')):
            changed = dict(self.context, **{name: value})
            if name == 'role':
                changed.update(table='payload', field='bytes')
            with self.subTest(field=name):
                self.assertNotEqual(self.encode(changed), self.encode())

    def test_names_cannot_have_concatenation_collisions(self):
        left = dict(self.context, table='ab', field='c')
        right = dict(self.context, table='a', field='bc')
        self.assertNotEqual(self.encode(left), self.encode(right))

    def test_missing_or_mutable_context_is_rejected(self):
        for name in self.context:
            changed = dict(self.context)
            del changed[name]
            with self.subTest(missing=name), self.assertRaises(ValueError):
                self.encode(changed)
        for name in ('lastModified', 'rowOrder', 'filename', 'requestOrgId'):
            with self.subTest(extra=name), self.assertRaises(ValueError):
                self.encode(dict(self.context, **{name: 'mutable'}))

    def test_identifier_and_name_bounds(self):
        for value in (bytes(16), b'x', b'x' * 17, 'identifier'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.encode(dict(self.context, resource=value))
        for value in ('', 'a' * 65, 'data|value', 'data\x00', 'data.value', '1data'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.encode(dict(self.context, table=value))

    def test_role_specific_identifiers(self):
        for role in ('ResourcesDB', 'RolesDB', 'LogsDB'):
            with self.subTest(role=role):
                context = dict(self.context, role=role, storage=bytes(16))
                self.encode(context)
                with self.assertRaises(ValueError):
                    self.encode(dict(context, storage=b'x' * 16))
        self.encode(dict(self.context, role='RolesDB', storage=bytes(16), table='documents', field='_get'))
        with self.assertRaises(ValueError):
            self.encode(dict(self.context, role='unknown'))
        with self.assertRaises(ValueError):
            self.encode(dict(self.context, role='RawPart'))

    def test_header_and_salt_are_authenticated_inputs(self):
        for name, value in (('salt', b'x' * 16), ('nonce', b'x' * 32), ('size', 4)):
            args = dict(context=self.context, salt=self.salt, nonce=self.nonce, size=3)
            args[name] = value
            with self.subTest(name=name):
                self.assertNotEqual(contract.aad(**args), self.encode())

    def test_invalid_header_metadata_is_rejected(self):
        for name, value in (('profile', 2), ('kdf', 2), ('schema', 2), ('flags', 1),
                            ('size', -1), ('size', 0x7fffffff), ('nonce', b'x'), ('salt', b'x')):
            args = dict(context=self.context, salt=self.salt, nonce=self.nonce, size=3)
            args[name] = value
            with self.subTest(name=name), self.assertRaises(ValueError):
                contract.aad(**args)
        contract.aad(self.context, self.salt, self.nonce, 0x7fffffff - contract.HEADER.size)
        with self.assertRaises(ValueError):
            contract.aad(self.context, self.salt, self.nonce, 0x7fffffff - contract.HEADER.size + 1)

    def test_frame_lengths_and_trailing_bytes_fail_closed(self):
        self.assertEqual(contract.parse_frame(self.frame)['ciphertext'], b'abc')
        for frame in (self.frame[:79], self.frame[:-1], self.frame + b'x',
                      self.frame[:12] + struct.pack('>I', 0x80000000) + self.frame[16:]):
            with self.subTest(size=len(frame)), self.assertRaises(ValueError):
                contract.parse_frame(frame)

    def test_version_dispatch_and_downgrade_policy(self):
        legacy = b'CDSEHKX1\x01\x00' + bytes(64) + b'ciphertext'
        self.assertEqual(contract.read_kind(legacy), 'legacy-v1')
        self.assertEqual(contract.read_kind(b'old-aes'), 'legacy-aes')
        self.assertEqual(contract.read_kind(self.frame, 2), 'draft-v2')
        for frame in (legacy, b'old-aes', b'CDSEHKX3' + bytes(80), self.frame[:-1]):
            with self.subTest(frame=frame[:8]), self.assertRaises(ValueError):
                contract.read_kind(frame, 2)
        for frame in (b'CDSEHKX1', b'CDSEHKX3' + bytes(80)):
            with self.assertRaises(ValueError):
                contract.read_kind(frame)

    def test_frozen_legacy_aad_and_salt_spelling(self):
        algorithm = 'herradura-hske-nla1-aead-256'
        salt = 'AB' * 16
        self.assertEqual(contract.legacy_aad(algorithm, salt),
                         b'CDSE-HKX-AAD-v1|herradura-hske-nla1-aead-256|' + b'AB' * 16)
        self.assertNotEqual(contract.legacy_aad(algorithm, salt), contract.legacy_aad(algorithm, salt.lower()))
        self.assertEqual(self.encode(), contract.aad(self.context, bytes.fromhex(self.salt.hex()), self.nonce, 3))


if __name__ == '__main__':
    unittest.main()
