#!/usr/bin/env python3
"""Test-only draft codec acceptance, never production V2 storage activation."""
import copy
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

import herradura_context_contract as contract
import herradura_registry_contract as registry_contract
import test_context_registry as registry_tests

FIXTURE = str(Path(os.environ.get('CDSE_CONTEXT_FRAME_FIXTURE', './context-frame-fixture')).resolve())
VECTORS = json.loads((Path(__file__).parent / 'testfiles/herradurakex-context-v2-vectors.json').read_text())
CONTEXT = {k: bytes.fromhex(v) if k in contract.UUID_FIELDS else v for k, v in VECTORS['context'].items()}
SALT = bytes.fromhex(VECTORS['salt'])
PASSWORD = bytes.fromhex(VECTORS['password'])


def command(action, *args):
    return subprocess.run([FIXTURE, action, *(x.hex() for x in args)], capture_output=True, timeout=30)


def available():
    result = subprocess.run([FIXTURE, 'available'], capture_output=True, timeout=30)
    if result.returncode or result.stdout not in (b'0\n', b'1\n'):
        raise AssertionError('provider availability probe failed')
    return result.stdout == b'1\n'


class FrameChecks:
    def invoke(self, action, *args):
        result = command(action, *args)
        if result.returncode:
            self.assertEqual(result.stdout, b'')
            self.assertNotIn(PASSWORD.hex().encode(), result.stderr)
        return result

    def accepted(self, action, *args):
        result = self.invoke(action, *args)
        self.assertEqual(result.returncode, 0, result.stderr)
        return bytes.fromhex(result.stdout.decode().strip())

    def refused(self, action, *args):
        self.assertEqual(self.invoke(action, *args).returncode, 1)

    def frame(self):
        return bytes.fromhex(VECTORS['cases'][-1]['frame'])

    def context(self, **changes):
        return contract.context_bytes(dict(CONTEXT, **changes))

    def open_frame(self, frame=None, context=None, salt=SALT, password=PASSWORD, floor=2):
        return self.invoke('open', context or self.context(), salt, password, bytes([floor]),
                           self.frame() if frame is None else frame)


class V2ContractTests(FrameChecks, unittest.TestCase):
    def test_c_aad_matches_independent_serialization_and_python_vectors(self):
        for case in VECTORS['cases']:
            frame, nonce = bytes.fromhex(case['frame']), bytes.fromhex(case['nonce'])
            actual = self.accepted('aad', self.context(), SALT, frame)
            self.assertEqual(actual, contract.aad(CONTEXT, SALT, nonce, len(bytes.fromhex(case['plaintext']))))

    def test_all_role_encodings_and_storage_sentinel(self):
        for role in contract.ROLES:
            selected = dict(CONTEXT, role=role)
            if role in ('ResourcesDB', 'RolesDB', 'LogsDB'):
                selected['storage'] = bytes(16)
            if role == 'RawPart':
                selected.update(table='payload', field='bytes')
            encoded = contract.context_bytes(selected)
            self.assertEqual(self.accepted('aad', encoded, SALT, self.frame()),
                             contract.aad(selected, SALT, self.frame()[16:48], len(self.frame())-80))
            bad = bytearray(encoded)
            bad[33:49] = b'\x01'*16 if role in ('ResourcesDB', 'RolesDB', 'LogsDB') else bytes(16)
            self.refused('aad', bytes(bad), SALT, self.frame())

    def test_zero_identifiers_and_unknown_roles_refuse(self):
        for index in range(5):
            context = bytearray(self.context())
            context[1+16*index:17+16*index] = bytes(16)
            self.refused('aad', bytes(context), SALT, self.frame())
        for role in (0, 6, 255):
            self.refused('aad', bytes([role])+self.context()[1:], SALT, self.frame())

    def test_name_lengths_spelling_and_trailing_context_bytes(self):
        for table, field in (('a'*64, 'b'*64), ('_', '_get'), ('ab', 'c'), ('a', 'bc')):
            self.accepted('aad', self.context(table=table, field=field), SALT, self.frame())
        prefix = self.context()[:81]
        for name in (b'', b'a'*65, b'1data', b'a-b', b'a\x00b', b'\xff'):
            encoded = prefix+bytes([len(name)])+name+b'\x05value'
            self.refused('aad', encoded, SALT, self.frame())
        self.refused('aad', self.context()+b'\x00', SALT, self.frame())
        self.refused('aad', self.context()[:-1], SALT, self.frame())

    def test_raw_role_requires_payload_bytes(self):
        context = bytearray(self.context())
        context[0] = 5
        self.refused('aad', bytes(context), SALT, self.frame())

    def test_strict_frame_dispatch_and_header_parameters(self):
        original = self.frame()
        for offset in range(12):
            mutated = bytearray(original)
            mutated[offset] ^= 1
            self.refused('aad', self.context(), SALT, bytes(mutated))
        for length in (0, 1, 79, 80, len(original)-1):
            self.refused('aad', self.context(), SALT, original[:length])
        self.refused('aad', self.context(), SALT, original+b'\x00')
        for length in (0, 98, 0x7fffffff, 0x80000000, 0xffffffff):
            mutated = original[:12]+struct.pack('>I', length)+original[16:]
            self.refused('aad', self.context(), SALT, mutated)

    def test_strict_salt_and_hex_bounds(self):
        for salt in (b'', bytes(15), bytes(17)):
            self.refused('aad', self.context(), salt, self.frame())
        for bad in ('z0', '0', 'AA'):
            result = subprocess.run([FIXTURE, 'aad', self.context().hex(), bad, self.frame().hex()],
                                    capture_output=True, timeout=30)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(result.stdout, b'')
        self.refused('aad', self.context(), SALT, bytes(16385))

    def test_unknown_action_and_wrong_arity_refuse(self):
        for action, args in (('unknown', ()), ('aad', (self.context(),)), ('seal', ())):
            self.refused(action, *args)

    def test_provider_availability_controls_codec(self):
        result = self.invoke('seal', self.context(), SALT, bytes(32), PASSWORD, b'fixture')
        self.assertEqual(result.returncode, 0 if available() else 77)


class V2ProviderTests(FrameChecks, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not available():
            raise unittest.SkipTest('optional Herradura provider unavailable')

    def test_cross_language_known_answers_and_frozen_kdf(self):
        for case in VECTORS['cases']:
            plain, nonce, frame = (bytes.fromhex(case[name]) for name in ('plaintext', 'nonce', 'frame'))
            self.assertEqual(self.accepted('seal', self.context(), SALT, nonce, PASSWORD, plain), frame)
            self.assertEqual(self.accepted('open', self.context(), SALT, PASSWORD, b'\x02', frame), plain)
        self.assertEqual(VECTORS['reference_revision'], 'ad42138af14a40eb3b47127872f39509723c789f')

    def test_every_context_identifier_authenticates(self):
        for name in contract.UUID_FIELDS:
            changed = self.context(**{name: b'\x09'*16})
            self.assertEqual(self.open_frame(context=changed).returncode, 1)

    def test_role_table_field_and_name_delimiters_authenticate(self):
        for changes in (dict(table='meta'), dict(field='orgId'),
                        dict(role='RawPart', table='payload', field='bytes'),
                        dict(role='ResourcesDB', storage=bytes(16))):
            self.assertEqual(self.open_frame(context=self.context(**changes)).returncode, 1)
        source = self.context(table='ab', field='c')
        frame = self.accepted('seal', source, SALT, bytes(32), PASSWORD, b'fixture')
        self.refused('open', self.context(table='a', field='bc'), SALT, PASSWORD, b'\x02', frame)

    def test_salt_key_nonce_tag_and_each_ciphertext_byte_authenticate(self):
        self.assertEqual(self.open_frame(salt=b'\x09'*16).returncode, 1)
        self.assertEqual(self.open_frame(password=b'wrong-fixture-key').returncode, 1)
        for offset in range(16, len(self.frame())):
            frame = bytearray(self.frame())
            frame[offset] ^= 1
            self.assertEqual(self.open_frame(frame=bytes(frame)).returncode, 1, offset)

    def test_floor_never_accepts_legacy_or_unknown_versions(self):
        for floor in (1, 2):
            self.assertEqual(self.open_frame(floor=floor).returncode, 0)
            for legacy in (b'CDSEHKX1'+bytes(96), b'CDSEHKX3'+bytes(96), b'legacy-aes-frame'):
                self.assertEqual(self.open_frame(frame=legacy, floor=floor).returncode, 1)
        for floor in (0, 3, 255):
            self.assertEqual(self.open_frame(floor=floor).returncode, 1)

    def test_boundary_sizes_and_all_roles(self):
        for size in (0, 1, 16, 31, 32, 33, 4097, 16304):
            plain = b'x'*size
            nonce = hashlib.sha256(str(size).encode()).digest()
            frame = self.accepted('seal', self.context(), SALT, nonce, PASSWORD, plain)
            self.assertEqual(self.accepted('open', self.context(), SALT, PASSWORD, b'\x02', frame), plain)
        for role in contract.ROLES:
            changes = dict(role=role)
            if role in ('ResourcesDB', 'RolesDB', 'LogsDB'):
                changes['storage'] = bytes(16)
            if role == 'RawPart':
                changes.update(table='payload', field='bytes')
            context = self.context(**changes)
            frame = self.accepted('seal', context, SALT, bytes(32), PASSWORD, b'fixture')
            self.assertEqual(self.accepted('open', context, SALT, PASSWORD, b'\x02', frame), b'fixture')

    def test_invalid_password_nonce_and_plaintext_bounds(self):
        for password in (b'', bytes(257)):
            self.refused('seal', self.context(), SALT, bytes(32), password, b'x')
        for nonce in (bytes(31), bytes(33)):
            self.refused('seal', self.context(), SALT, nonce, PASSWORD, b'x')
        self.refused('seal', self.context(), SALT, bytes(32), PASSWORD, bytes(16305))

    def test_persisted_copy_reencrypts_fresh_context_and_preserves_source(self):
        source = self.context()
        destination = self.context(resource=b'\x06'*16, record=b'\x07'*16)
        with tempfile.TemporaryDirectory() as directory:
            old, new = Path(directory)/'source.frame', Path(directory)/'copy.frame'
            old.write_bytes(self.frame())
            result = self.accepted('copy', source, destination, SALT, b'\x40'*16,
                                   b'\x50'*32, PASSWORD, old.read_bytes())
            new.write_bytes(result)
            self.assertEqual(old.read_bytes(), self.frame())
            self.assertNotEqual(new.read_bytes(), old.read_bytes())
            self.assertEqual(self.accepted('open', destination, b'\x40'*16, PASSWORD, b'\x02', new.read_bytes()),
                             bytes.fromhex(VECTORS['cases'][-1]['plaintext']))
            self.refused('open', source, b'\x40'*16, PASSWORD, b'\x02', new.read_bytes())
            self.refused('open', destination, SALT, PASSWORD, b'\x02', old.read_bytes())

    def test_copy_requires_new_resource_record_nonce_and_salt(self):
        destination = self.context(resource=b'\x06'*16, record=b'\x07'*16)
        for target, salt, nonce in ((self.context(), b'\x40'*16, b'\x50'*32),
                                    (self.context(resource=b'\x06'*16), b'\x40'*16, b'\x50'*32),
                                    (self.context(record=b'\x07'*16), b'\x40'*16, b'\x50'*32),
                                    (destination, SALT, b'\x50'*32),
                                    (destination, b'\x40'*16, self.frame()[16:48]),
                                    (self.context(resource=b'\x06'*16, record=b'\x07'*16, table='meta'), b'\x40'*16, b'\x50'*32),
                                    (self.context(resource=b'\x06'*16, record=b'\x07'*16, organization=b'\x08'*16), b'\x40'*16, b'\x50'*32)):
            self.refused('copy', self.context(), target, SALT, salt, nonce, PASSWORD, self.frame())

    def test_copy_does_not_release_plaintext_on_source_auth_failure(self):
        destination = self.context(resource=b'\x06'*16, record=b'\x07'*16)
        for source, password, frame in ((self.context(record=b'\x08'*16), PASSWORD, self.frame()),
                                        (self.context(), b'wrong', self.frame()),
                                        (self.context(), PASSWORD, self.frame()[:-1])):
            self.refused('copy', source, destination, SALT, b'\x40'*16, b'\x50'*32, password, frame)


class AuthenticatedFrameTests(FrameChecks, registry_tests.CRegistryTests):
    @classmethod
    def setUpClass(cls):
        if not available():
            raise unittest.SkipTest('optional Herradura provider unavailable')

    def test_c_authenticated_registry_supplies_context_and_floor_for_copy(self):
        snapshot = copy.deepcopy(self.snapshot)
        snapshot.update(minimumFormat=2)
        target = copy.deepcopy(snapshot['entries'][0])
        target['lookup'] = 'copied/record/value'
        target['context'].update(resource='06'*16, record='07'*16)
        snapshot['entries'].append(target)
        body, tag, anchor = registry_contract.issue(snapshot, self.key)
        contexts = []
        for lookup in ('column/record/value', 'copied/record/value'):
            result = self.run_fixture(body, tag, anchor, lookup=lookup)
            self.assertEqual(result.returncode, 0, result.stderr)
            floor, encoded = result.stdout.decode().split()
            self.assertEqual(floor, '2')
            contexts.append(bytes.fromhex(encoded))
        result = self.accepted('copy', *contexts, SALT, b'\x40'*16, b'\x50'*32, PASSWORD, self.frame())
        self.accepted('open', contexts[1], b'\x40'*16, PASSWORD, b'\x02', result)
        self.refused('open', contexts[0], b'\x40'*16, PASSWORD, b'\x02', result)
        self.assertEqual(self.run_fixture(body, bytes(32), anchor).returncode, 1)


for _name in vars(registry_tests.CRegistryTests):
    if _name.startswith('test_'):
        setattr(AuthenticatedFrameTests, _name, None)


if __name__ == '__main__':
    unittest.main()
