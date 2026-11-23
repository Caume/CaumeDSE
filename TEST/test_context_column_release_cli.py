#!/usr/bin/env python3
"""Installed v5 release preparation, completion, and recovery."""
import hashlib
import os
from pathlib import Path
import struct
import subprocess
import unittest

import test_context_column_admission as admission
from test_context_column_global import GLOBAL
from test_context_frame import PASSWORD


ADMIN = str(Path(os.environ.get('CDSE_CONTEXT_OWNER_ADMIN', './caumedse-admin')).resolve())
COMMAND = [ADMIN, 'context-column-release']


class ReleaseCommandTests(unittest.TestCase):
    def test_help_describes_the_approval_boundaries(self):
        main = subprocess.run([ADMIN, '--help'], capture_output=True, timeout=30, check=True)
        self.assertIn(b'context-column-release --help', main.stdout)
        result = subprocess.run([*COMMAND, '--help'], capture_output=True, timeout=30, check=True)
        for text in (b'prepare | complete', b'--admission-digest', b'--release-digest',
                     b'Retain the digest separately', b'Retain the witness token separately'):
            self.assertIn(text, result.stdout)
        self.assertEqual(result.stderr, b'')

    def test_incomplete_or_unknown_actions_emit_no_release_results(self):
        for args in ([], ['prepare'], ['complete'], ['reset'], ['--help', 'extra']):
            with self.subTest(args=args):
                result = subprocess.run([*COMMAND, *args], capture_output=True, timeout=30)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stdout, b'')


class InstalledReleaseTests(admission.AdmissionTests):
    def setUp(self):
        super().setUp()
        self.w1 = self.completed()
        self.envelope = self.root/'release.envelope'
        self.registry_key = self.private_file('registry.key', (b'k'*32).hex().encode() + b'\n')
        self.witness_key = self.private_file('witness.key', (b'w'*32).hex().encode())
        self.password_file = self.private_file('password', PASSWORD)

    def private_file(self, name, contents):
        path = self.root/name
        with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb') as stream:
            stream.write(contents)
        return path

    def common(self):
        return dict(registry_directory=self.authority, witness_directory=self.witness,
                    deployment=self.anchor.deployment, organization=self.anchor.organization,
                    registry_key_file=self.registry_key, witness_key_file=self.witness_key,
                    source_export=self.source_root, published_export=self.published)

    @staticmethod
    def flags(options):
        return [arg for name, value in options.items() if value is not None
                for arg in ('--' + name.replace('_', '-'), str(value))]

    def release_args(self, action, **changes):
        options = dict(self.common(), release_envelope=self.envelope)
        if action == 'prepare':
            options.update(admission_journal=self.journal_path, admission_digest=self.pin, retained_witness_token=self.w1)
        else:
            options['release_digest'] = getattr(self, 'release_pin', None)
        options.update(changes)
        return [*COMMAND, action, *self.flags(options)]

    def execute(self, action, **changes):
        result = self.invoke(self.release_args(action, **changes))
        for secret in (self.registry_key.read_bytes().strip(), self.witness_key.read_bytes().strip(),
                       str(self.root).encode(), b'fixture-alpha'):
            self.assertNotIn(secret, result.stdout + result.stderr)
        return result

    def prepare_release(self):
        before = self.authority_files()
        result = self.execute('prepare')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, b'')
        self.assertEqual(self.envelope.stat().st_mode & 0o7777, 0o600)
        self.assertEqual(self.envelope.stat().st_nlink, 1)
        self.release_bytes = self.envelope.read_bytes()
        self.release_pin = hashlib.sha256(self.release_bytes).hexdigest()
        self.assertEqual(result.stdout, f'release-digest={self.release_pin}\n'.encode())
        expected_prefix = GLOBAL + struct.pack('>I', len(self.journal)) + self.journal + bytes.fromhex(self.w1)
        self.assertEqual(self.release_bytes[:-40], expected_prefix)
        self.c2 = self.release_bytes[-40:].hex()
        self.assertEqual(self.authority_files(), before)

    def authority_files(self):
        return ((self.authority/'registry.sqlite').read_bytes(), (self.witness/'witness.sqlite').read_bytes(),
                [p.read_bytes() for directory in (self.source_root, self.published) for p in sorted(directory.iterdir())])

    def complete_release(self):
        result = self.execute('complete')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, b'')
        lines = result.stdout.decode().splitlines()
        self.assertEqual(len(lines), 2)
        self.assertEqual(lines[0], 'catalog=' + self.c2)
        prefix, w2 = lines[1].split('=')
        self.assertEqual(prefix, 'witness-token')
        self.assertEqual(len(bytes.fromhex(w2)), 40)
        self.assertEqual(int(w2[:16], 16), int(self.w1[:16], 16)+1)
        self.assertEqual(self.current(), self.registry)
        self.assertEqual(self.map_current(), self.c2)
        self.assertEqual(self.envelope.read_bytes(), self.release_bytes)
        return w2

    def read_cell(self, token):
        options = dict(self.common(), release_envelope=self.envelope, release_digest=self.release_pin,
                       retained_witness_token=token, password_file=self.password_file, table='data', row=1, field='value')
        return self.invoke([ADMIN, 'context-column-read', *self.flags(options)])

    def assert_cell(self, token):
        result = self.read_cell(token)
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, b'fixture-alpha', b''))

    def test_prepare_complete_and_explicit_read_acknowledgement(self):
        self.prepare_release()
        self.assertEqual(self.read_cell(self.w1).returncode, 2)
        w2 = self.complete_release()
        self.assertEqual(self.read_cell(self.w1).returncode, 2)
        self.assert_cell(w2)
        before = self.authority_files()
        self.assertEqual(self.complete_release(), w2)
        self.assertEqual(self.authority_files(), before)

    def test_recover_after_catalog_commit_using_installed_command(self):
        self.prepare_release()
        witness = (self.witness/'witness.sqlite').read_bytes()
        args = self.run_args()
        args[2], args[8], args[9] = 'column-global-run', str(self.envelope), self.release_pin
        self.assertEqual(self.invoke(args, {'CDSE_CONTEXT_ADMISSION_CRASH': 'global-after-catalog'}).returncode, 86)
        self.assertEqual(self.map_current(), self.c2)
        self.assertEqual((self.witness/'witness.sqlite').read_bytes(), witness)
        self.assertEqual(self.read_cell(self.w1).returncode, 2)
        self.assert_cell(self.complete_release())

    def test_lost_stdout_acknowledgement_recovers_same_authority_state(self):
        self.prepare_release()
        read_end, write_end = os.pipe()
        os.close(read_end)
        try:
            result = subprocess.run(self.release_args('complete'), stdout=write_end, stderr=subprocess.PIPE, timeout=90)
        finally:
            os.close(write_end)
        self.assertEqual(result.returncode, 1)
        self.assertIn(b'could not write release results', result.stderr)
        self.assertEqual(self.map_current(), self.c2)
        self.assertEqual(self.read_cell(self.w1).returncode, 2)
        before = self.authority_files()
        self.assert_cell(self.complete_release())
        self.assertEqual(self.authority_files(), before)

    def test_prepare_verifies_original_admission_and_witness_inputs(self):
        before = self.authority_files()
        for overrides, code in (
            (dict(admission_digest='00'*32), 1),
            (dict(admission_digest=None), 1),
            (dict(retained_witness_token=self.retained), 2),
            (dict(release_digest='00'*32), 1),
            (dict(witness_key_file=self.registry_key), 1),
        ):
            with self.subTest(overrides=overrides):
                self.assertEqual(self.execute('prepare', **overrides).returncode, code)
                self.assertFalse(self.envelope.exists())
        self.assertEqual(self.authority_files(), before)

    def test_prepare_preserves_existing_file_and_rejects_in_export_output(self):
        before = self.authority_files()
        for directory in (self.source_root, self.published, self.authority, self.witness):
            dest = directory/'new-release'
            self.assertEqual(self.execute('prepare', release_envelope=dest).returncode, 1)
            self.assertFalse(dest.exists())
        link = self.root/'linked-envelope'
        link.symlink_to(self.envelope)
        self.assertEqual(self.execute('prepare', release_envelope=link).returncode, 1)
        self.assertTrue(link.is_symlink())
        self.prepare_release()
        inode = self.envelope.stat().st_ino
        self.assertEqual(self.execute('prepare').returncode, 1)
        self.assertEqual(self.envelope.stat().st_ino, inode)
        self.assertEqual(self.envelope.read_bytes(), self.release_bytes)
        self.assertEqual(self.authority_files(), before)

    def test_complete_requires_retained_digest_and_private_envelope(self):
        self.prepare_release()
        before = self.authority_files()
        for overrides in (dict(release_digest=None), dict(release_digest='00'*32),
                          dict(retained_witness_token=self.w1), dict(password_file=self.password_file)):
            self.assertEqual(self.execute('complete', **overrides).returncode, 1)
        self.envelope.chmod(0o644)
        self.assertEqual(self.execute('complete').returncode, 1)
        self.envelope.chmod(0o600)
        self.assertEqual(self.authority_files(), before)
        self.assert_cell(self.complete_release())

    def test_complete_refuses_replaced_published_file(self):
        self.prepare_release()
        image = self.published/'candidate.sqlite'
        replacement = self.private_file('replacement', image.read_bytes())
        os.replace(replacement, image)
        before = self.authority_files()
        self.assertEqual(self.execute('complete').returncode, 1)
        self.assertEqual(self.authority_files(), before)


for _parent in InstalledReleaseTests.__mro__[1:]:
    for _name in vars(_parent):
        if _name.startswith('test_') and _name not in vars(InstalledReleaseTests):
            setattr(InstalledReleaseTests, _name, None)
del _parent

if __name__ == '__main__':
    unittest.main()
