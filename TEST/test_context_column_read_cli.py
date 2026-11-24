#!/usr/bin/env python3
"""Exercise the installed command with retained release evidence and private inputs."""
import hashlib
import os
from pathlib import Path
import subprocess
import unittest

import test_context_column_released_read as released
from test_context_frame import PASSWORD


ADMIN = str(Path(os.environ.get('CDSE_CONTEXT_OWNER_ADMIN', './caumedse-admin')).resolve())
COMMAND = [ADMIN, 'context-column-read']
REGISTER = [ADMIN, 'context-column-register']
UNREGISTER = [ADMIN, 'context-column-unregister']
REVOKE = [ADMIN, 'context-column-revoke']


class CommandTests(unittest.TestCase):
    def test_revoke_help_and_incomplete_invocation(self):
        main = subprocess.run([ADMIN, '--help'], capture_output=True, timeout=30, check=True)
        self.assertIn(b'context-column-revoke --help', main.stdout)
        usage = subprocess.run([*REVOKE, '--help'], capture_output=True, timeout=30, check=True)
        for option in (b'--release-envelope', b'--release-digest', b'--retained-witness-token',
                       b'--revocation-envelope', b'--revocation-digest'):
            self.assertIn(option, usage.stdout)
        for action in ('prepare', 'complete', 'recover'):
            result = subprocess.run([*REVOKE, action], capture_output=True, timeout=30)
            self.assertEqual((result.returncode, result.stdout), (1, b''))

    def test_register_help_and_incomplete_invocation(self):
        main = subprocess.run([ADMIN, '--help'], capture_output=True, timeout=30, check=True)
        for command, outcome in ((REGISTER, b'present'), (UNREGISTER, b'absent')):
            with self.subTest(command=command[1]):
                self.assertIn(f'{command[1]} --help'.encode(), main.stdout)
                usage = subprocess.run([*command, '--help'], capture_output=True, timeout=30, check=True)
                for option in (b'--active-resources', b'--retained-witness-token', b'--registration-key-file',
                               b'registration=' + outcome):
                    self.assertIn(option, usage.stdout)
                bad = subprocess.run([*command, '--release-digest', '00' * 32], capture_output=True, timeout=30)
                self.assertEqual((bad.returncode, bad.stdout), (1, b''))

    def test_help_lists_installed_command_and_required_approvals(self):
        main = subprocess.run([ADMIN, '--help'], capture_output=True, timeout=30, check=True)
        self.assertIn(b'context-column-read --help', main.stdout)
        result = subprocess.run([*COMMAND, '--help'], capture_output=True, timeout=30, check=True)
        for option in (b'--release-digest', b'--retained-witness-token', b'--password-file'):
            self.assertIn(option, result.stdout)
        self.assertEqual(result.stderr, b'')

    def test_incomplete_or_unknown_invocations_emit_no_cell(self):
        for args in ([], ['--table'], ['--password', 'literal-test-value'], ['--help', 'extra']):
            with self.subTest(args=args):
                result = subprocess.run([*COMMAND, *args], capture_output=True, timeout=30)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stdout, b'')
                self.assertNotIn(b'literal-test-value', result.stderr)


class ReleasedReadCommandTests(released.ReleasedReadTests):
    def setUp(self):
        super().setUp()
        self.registry_key = self.private('registry.key', (b'k' * 32).hex().encode() + b'\n')
        self.witness_key = self.private('witness.key', (b'w' * 32).hex().encode())
        self.password_file = self.private('target.password', PASSWORD)

    def private(self, name, contents):
        path = self.root / name
        with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb') as stream:
            stream.write(contents)
        return path

    def command_options(self, **overrides):
        options = {
            'registry-directory': self.authority,
            'witness-directory': self.witness,
            'deployment': self.anchor.deployment,
            'organization': self.anchor.organization,
            'registry-key-file': self.registry_key,
            'witness-key-file': self.witness_key,
            'source-export': self.source_root,
            'published-export': self.published,
            'release-envelope': self.global_path,
            'release-digest': self.global_pin,
            'retained-witness-token': getattr(self, 'final_token', self.acknowledged),
            'password-file': self.password_file,
            'table': 'data',
            'row': 1,
            'field': 'value',
        }
        options.update({name.replace('_', '-'): value for name, value in overrides.items()})
        return [arg for name, value in options.items() if value is not None for arg in (f'--{name}', str(value))]

    def cli(self, *, extra=(), **options):
        result = self.invoke([*COMMAND, *self.command_options(**options), *extra])
        for sensitive in (PASSWORD, PASSWORD.hex().encode(), self.registry_key.read_bytes().strip(),
                          self.witness_key.read_bytes().strip(), str(self.root).encode(), b'fixture-alpha'):
            self.assertNotIn(sensitive, result.stderr)
        if result.returncode:
            self.assertEqual(result.stdout, b'')
        return result

    def read_cell(self, expected=b'fixture-alpha', **options):
        result = self.cli(**options)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, expected)
        self.assertEqual(result.stderr, b'')

    def test_installed_raw_read_preserves_authority_and_artifacts(self):
        before = self.authority_files(), self.global_path.read_bytes(), (self.authority/'registry.sqlite').read_bytes()
        self.read_cell()
        self.read_cell(b'fixture-beta', row=2)
        self.read_cell(b'fixture-column', table='meta', row=2, field='attributeData')
        self.assertEqual((self.authority_files(), self.global_path.read_bytes(),
                          (self.authority/'registry.sqlite').read_bytes()), before)

    def test_installed_read_metadata_cbc(self):
        self.read_cell()

    def test_supplied_pins_and_original_envelope_are_required(self):
        for options, code in (
            ({'release_digest': None}, 1),
            ({'release_digest': '00' * 32}, 1),
            ({'retained_witness_token': None}, 1),
            ({'retained_witness_token': self.acknowledged}, 2),
            ({'organization': '23' * 16}, 1),
        ):
            with self.subTest(options=options):
                self.assertEqual(self.cli(**options).returncode, code)
        changed = self.global_bytes[:-1] + bytes([self.global_bytes[-1] ^ 1])
        forged = self.private('forged-envelope', changed)
        self.assertNotEqual(self.cli(release_envelope=forged, release_digest=hashlib.sha256(changed).hexdigest()).returncode, 0)
        self.read_cell()

    def test_missing_or_unacknowledged_release_stays_pending(self):
        before = self.authority_files()
        self.assertEqual(self.cli().returncode, 2)
        self.assertEqual(self.authority_files(), before)
        self.assertEqual(self.invoke(self.global_args(), {'CDSE_CONTEXT_ADMISSION_CRASH': 'global-after-catalog'}).returncode, 86)
        before = self.authority_files()
        self.assertEqual(self.cli().returncode, 2)
        self.assertEqual(self.authority_files(), before)
        self.released()
        self.read_cell()

    def test_selector_and_credential_failures_emit_no_plaintext(self):
        wrong = self.private('wrong-password', b'incorrect')
        oversized = self.private('large-password', b'x' * 257)
        # A terminal zero alone is equivalent under HMAC key padding.
        nul_suffix = self.private('nul-and-suffix-password', PASSWORD + b'\0x')
        for options in (dict(password_file=wrong), dict(password_file=oversized), dict(password_file=nul_suffix),
                        dict(row=0),
                        dict(row='+1'), dict(row=2**63), dict(field='MAC'),
                        dict(extra=('--row', '1')), dict(witness_key_file=self.registry_key)):
            with self.subTest(options=options):
                self.assertEqual(self.cli(**options).returncode, 1)
        self.read_cell()

    def test_private_file_and_canonical_namespace_checks(self):
        link = self.root / 'password-symlink'
        link.symlink_to(self.password_file)
        hard = self.root / 'password-hardlink'
        os.link(self.password_file, hard)
        self.assertEqual(self.cli(password_file=link).returncode, 1)
        self.assertEqual(self.cli().returncode, 1)
        hard.unlink()
        self.password_file.chmod(0o644)
        self.assertEqual(self.cli().returncode, 1)
        self.password_file.chmod(0o600)
        self.global_path.chmod(0o644)
        self.assertEqual(self.cli().returncode, 1)
        self.global_path.chmod(0o600)
        alias = self.root / 'export-alias'
        alias.symlink_to(self.published, target_is_directory=True)
        self.assertEqual(self.cli(published_export=alias).returncode, 1)
        self.read_cell()

    def test_same_bytes_image_replacement_refuses(self):
        image = self.published / 'candidate.sqlite'
        replacement = self.private('replacement', image.read_bytes())
        os.replace(replacement, image)
        self.assertEqual(self.cli().returncode, 1)

    @unittest.skipUnless(Path('/dev/full').exists(), 'requires /dev/full')
    def test_stdout_write_failure_fails_command(self):
        with open('/dev/full', 'wb') as output:
            result = subprocess.run([*COMMAND, *self.command_options()], stdout=output,
                                    stderr=subprocess.PIPE, timeout=90)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stderr, b'context-column-read: could not write cell to stdout\n')
        read_end, write_end = os.pipe()
        os.close(read_end)
        try:
            result = subprocess.run([*COMMAND, *self.command_options()], stdout=write_end,
                                    stderr=subprocess.PIPE, timeout=90)
        finally:
            os.close(write_end)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stderr, b'context-column-read: could not write cell to stdout\n')


for _parent in ReleasedReadCommandTests.__mro__[1:]:
    for _name in vars(_parent):
        if _name.startswith('test_') and _name not in vars(ReleasedReadCommandTests):
            setattr(ReleasedReadCommandTests, _name, None)
del _parent

if __name__ == '__main__':
    unittest.main()
