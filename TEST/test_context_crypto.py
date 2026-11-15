#!/usr/bin/env python3
"""Explicit runtime V2 codec guarded by current authenticated stored-map bindings."""
import os
from pathlib import Path
import select
import subprocess
import unittest

import test_context_manager as manager_tests
import herradura_registry_contract as registry_contract
from test_context_frame import VECTORS, CONTEXT, SALT, PASSWORD, FIXTURE as FRAME_FIXTURE
import herradura_context_contract as wire

FIXTURE = str(Path(os.environ.get('CDSE_CONTEXT_CRYPTO_FIXTURE', './context-crypto-fixture')).resolve())


def available():
    result = subprocess.run([FIXTURE, 'available'], capture_output=True, timeout=30)
    if result.returncode or result.stdout not in (b'0\n', b'1\n'):
        raise AssertionError('runtime codec availability probe failed')
    return result.stdout == b'1\n'


class CryptoTests(manager_tests.ManagerTests):
    def setUp(self):
        super().setUp()
        self.bootstrap()
        self.map_init()
        self.slots = [('column/record/value', 'data', 1, 'value')]
        self.store(self.slots)

    def store(self, slots, **options):
        result = self.map_store(slots, resource='column/record/value', **options)
        self.assertEqual(result.returncode, 0, result.stderr)

    def crypto_args(self, action, data=b'', *, salt=SALT, password=PASSWORD, table='data', row=1,
                    field='value', registry=None, catalog=None, name='view'):
        args = [FIXTURE, str(self.authority), action, self.anchor.deployment, self.anchor.organization,
                registry or self.current(), catalog or self.map_current(), name]
        if action == 'contract':
            return args
        args.extend([table, str(row), field, password.hex()])
        if action == 'open':
            args.append(salt.hex())
        return [*args, data.hex()]

    def crypto(self, action, data=b'', *, env=None, **options):
        result = subprocess.run(self.crypto_args(action, data, **options), capture_output=True,
                                env=dict(os.environ, **(env or {})), timeout=30)
        if result.returncode:
            self.assertEqual(result.stdout, b'')
        for secret in (str(self.authority).encode(), PASSWORD.hex().encode()):
            self.assertNotIn(secret, result.stderr)
        return result

    def sealed(self, data=b'fixture-plaintext', **options):
        result = self.crypto('seal', data, **options)
        self.assertEqual(result.returncode, 0, result.stderr)
        salt, frame = result.stdout.decode().split()
        return bytes.fromhex(salt), bytes.fromhex(frame)

    def assert_open(self, frame, plain, *, salt=SALT, **options):
        result = self.crypto('open', frame, salt=salt, **options)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(bytes.fromhex(result.stdout.decode().strip()), plain)

    def test_contract_clears_outputs_and_handles_nulls_and_bounds(self):
        self.assertEqual(self.crypto('contract').returncode, 0)

    def test_raw_registry_binding_is_never_a_codec_binding(self):
        self.assertEqual(self.crypto('raw-seal', b'fixture').returncode, 1)

    def test_wrong_slot_name_missing_map_and_stale_pins_refuse(self):
        frame = bytes.fromhex(VECTORS['cases'][0]['frame'])
        for options in (dict(row=2), dict(table='meta'), dict(field='other'), dict(name='missing')):
            self.assertEqual(self.crypto('open', frame, **options).returncode, 1)
        old = self.map_current()
        self.store(self.slots)
        self.assertEqual(self.crypto('open', frame, catalog=old).returncode, 2)

    def test_malformed_and_legacy_frames_never_fall_back(self):
        frame = bytes.fromhex(VECTORS['cases'][-1]['frame'])
        for value in (b'', b'CDSEHKX1'+bytes(96), b'legacy-aes', b'CDSEHKX3'+bytes(96),
                      frame[:-1], frame+b'\x00', frame[:12]+b'\xff'*4+frame[16:]):
            self.assertEqual(self.crypto('open', value).returncode, 1)
        for offset in range(12):
            changed = bytearray(frame)
            changed[offset] ^= 1
            self.assertEqual(self.crypto('open', bytes(changed)).returncode, 1)

    def test_provider_unavailable_is_explicit(self):
        result = self.crypto('open', bytes.fromhex(VECTORS['cases'][0]['frame']))
        self.assertEqual(result.returncode, 0 if available() else 3)
        result = self.crypto('seal', b'fixture')
        self.assertEqual(result.returncode, 0 if available() else 3)


for _name in vars(manager_tests.ManagerTests):
    if _name.startswith('test_'):
        setattr(CryptoTests, _name, None)


class ProviderCryptoTests(CryptoTests):
    @classmethod
    def setUpClass(cls):
        if not available():
            raise unittest.SkipTest('optional NLA1 provider unavailable')

    def test_independent_python_known_answers_open_at_both_floors(self):
        for case in VECTORS['cases']:
            self.assert_open(bytes.fromhex(case['frame']), bytes.fromhex(case['plaintext']))
        next_snapshot = dict(self.snapshot, generation=2, minimumFormat=2)
        self.assertEqual(self.publish(next_snapshot, self.anchor).returncode, 0)
        for case in VECTORS['cases']:
            self.assert_open(bytes.fromhex(case['frame']), bytes.fromhex(case['plaintext']))
        self.assertEqual(self.crypto('open', b'legacy-aes').returncode, 1)

    def test_randomized_seal_roundtrips_and_interoperates_with_acceptance_codec(self):
        for length in (0, 1, 31, 32, 33, 4097, 20000):
            plain = b'x'*length
            salt, frame = self.sealed(plain)
            self.assertEqual(len(frame), 80+length)
            self.assert_open(frame, plain, salt=salt)
            if len(frame)<=16384:  # The independent acceptance fixture has a smaller test cap.
                result = subprocess.run([FRAME_FIXTURE, 'open', wire.context_bytes(CONTEXT).hex(), salt.hex(),
                                         PASSWORD.hex(), '02', frame.hex()], capture_output=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(bytes.fromhex(result.stdout.decode().strip()), plain)
        first = self.sealed(b'fixture')
        second = self.sealed(b'fixture')
        self.assertNotEqual(first[0], second[0])
        self.assertNotEqual(first[1][16:48], second[1][16:48])
        self.assertNotEqual(first[1], second[1])

    def test_all_roles_use_authenticated_binding_contexts(self):
        for role in range(1, 6):
            table, field = ('payload', 'bytes') if role==5 else ('data', 'value')
            lookup = f'role/{role}'
            context, _ = self.allocated(lookup=lookup, level=2, role=role, table=table, field=field,
                                        parent='column/record/value' if role>=4 else '-', expected=self.current())
            result = self.map_store([(lookup, table, 1, field)], name=f'role{role}', resource=lookup, role=role)
            self.assertEqual(result.returncode, 0, result.stderr)
            salt, frame = self.sealed(b'fixture', name=f'role{role}', table=table, field=field)
            self.assert_open(frame, b'fixture', salt=salt, name=f'role{role}', table=table, field=field)
            result = subprocess.run([FRAME_FIXTURE, 'open', wire.context_bytes(context).hex(), salt.hex(),
                                     PASSWORD.hex(), '02', frame.hex()], capture_output=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(bytes.fromhex(result.stdout.decode().strip()), b'fixture')

    def test_counted_password_and_plaintext_preserve_embedded_zero_bytes(self):
        password, plain = b'fixture\x00password', b'fixture\x00plaintext'
        salt, frame = self.sealed(plain, password=password)
        self.assert_open(frame, plain, salt=salt, password=password)
        self.assertEqual(self.crypto('open', frame, salt=salt, password=b'fixture').returncode, 1)

    def test_rng_failure_clears_salt_and_frame(self):
        for stage in ('salt', 'nonce', 'all'):
            self.assertEqual(self.crypto('seal', b'fixture', env={'CDSE_CONTEXT_CRYPTO_RNG_FAIL': stage}).returncode, 1)

    def test_key_salt_nonce_tag_and_ciphertext_fail_without_output(self):
        frame = bytes.fromhex(VECTORS['cases'][-1]['frame'])
        for options in (dict(password=b'wrong-fixture'), dict(salt=b'\x09'*16)):
            self.assertEqual(self.crypto('open', frame, **options).returncode, 1)
        for offset in range(16, len(frame)):
            changed = bytearray(frame)
            changed[offset] ^= 1
            self.assertEqual(self.crypto('open', bytes(changed)).returncode, 1, offset)

    def test_authenticated_context_substitutions_fail(self):
        original = bytes.fromhex(VECTORS['cases'][-1]['frame'])
        for field in registry_contract.UUID_FIELDS:
            # Candidate frames never supply the authority's expected identifiers.
            selected = dict(CONTEXT, **{field: b'\x09'*16})
            result = subprocess.run([FRAME_FIXTURE, 'seal', wire.context_bytes(selected).hex(), SALT.hex(),
                                     bytes(32).hex(), PASSWORD.hex(), b'fixture'.hex()], capture_output=True, timeout=30)
            self.assertEqual(result.returncode, 0)
            self.assertEqual(self.crypto('open', bytes.fromhex(result.stdout.decode())).returncode, 1)
        for changes in (dict(table='meta'), dict(field='other'),
                        dict(role='RawPart', table='payload', field='bytes'),
                        dict(role='ResourcesDB', storage=bytes(16))):
            result = subprocess.run([FRAME_FIXTURE, 'seal', wire.context_bytes(dict(CONTEXT, **changes)).hex(),
                                     SALT.hex(), bytes(32).hex(), PASSWORD.hex(), b'fixture'.hex()],
                                    capture_output=True, timeout=30)
            self.assertEqual(result.returncode, 0)
            self.assertEqual(self.crypto('open', bytes.fromhex(result.stdout.decode())).returncode, 1)
        self.assert_open(original, bytes.fromhex(VECTORS['cases'][-1]['plaintext']))

    def test_physical_row_move_preserves_crypto_identity(self):
        salt, frame = self.sealed(b'fixture')
        self.store([('column/record/value', 'data', 99, 'value')])
        self.assertEqual(self.crypto('open', frame, salt=salt).returncode, 1)
        self.assert_open(frame, b'fixture', salt=salt, row=99)

    def test_private_authority_tampering_is_not_accepted(self):
        registry, catalog = self.current(), self.map_current()
        self.authority.chmod(0o755)
        self.assertNotEqual(self.crypto('seal', b'fixture', registry=registry, catalog=catalog).returncode, 0)
        self.authority.chmod(0o700)

    def paused_change(self, action, stage, change):
        salt, frame = self.sealed(b'fixture')
        read_ready, write_ready = os.pipe()
        read_resume, write_resume = os.pipe()
        proc = None
        try:
            args = self.crypto_args(action, frame if action == 'open' else b'fixture', salt=salt)
            env = dict(os.environ, CDSE_CONTEXT_CRYPTO_PAUSE=stage,
                       CDSE_CONTEXT_CRYPTO_READY_FD=str(write_ready), CDSE_CONTEXT_CRYPTO_RESUME_FD=str(read_resume))
            if stage == 'before-check':
                env['CDSE_CONTEXT_CRYPTO_RNG_FAIL'] = 'all'
            proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env,
                                    pass_fds=(write_ready, read_resume))
            os.close(write_ready); write_ready = -1
            os.close(read_resume); read_resume = -1
            self.assertTrue(select.select([read_ready], [], [], 30)[0], 'codec did not reach checkpoint')
            self.assertEqual(os.read(read_ready, 1), b'1')
            if change == 'revoke':
                result = self.command('revoke', 'column/record/value', self.current())
            else:
                result = self.map_remove()
            self.assertEqual(result.returncode, 0, result.stderr)
            os.write(write_resume, b'1')
            stdout, stderr = proc.communicate(timeout=30)
            self.assertEqual(proc.returncode, 2, stderr)
            self.assertEqual(stdout, b'')
        finally:
            for fd in (read_ready, write_ready, read_resume, write_resume):
                if fd>=0: os.close(fd)
            if proc:
                if proc.poll() is None: proc.kill()
                proc.communicate()

    def test_stale_binding_is_refused_before_rng(self):
        self.paused_change('seal', 'before-check', 'revoke')

    def test_revoke_after_seal_discards_encrypted_result(self):
        self.paused_change('seal', 'after-crypto', 'revoke')

    def test_revoke_after_open_discards_plaintext(self):
        self.paused_change('open', 'after-crypto', 'revoke')

    def test_map_change_after_open_discards_plaintext(self):
        self.paused_change('open', 'after-crypto', 'map')

    def test_change_after_precheck_is_detected_by_postcheck(self):
        self.paused_change('open', 'before-crypto', 'map')


for _name in vars(CryptoTests):
    if _name.startswith('test_'):
        setattr(ProviderCryptoTests, _name, None)


if __name__ == '__main__':
    unittest.main()
