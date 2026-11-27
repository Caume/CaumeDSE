#!/usr/bin/env python3
"""Exercise the installed command with retained release evidence and private inputs."""
import hashlib
import hmac
import io
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import unittest
from contextlib import closing

import herradura_registry_contract as registry_contract
import test_context_column_released_read as released
from test_context_manager import token
from test_context_frame import PASSWORD


ADMIN = str(Path(os.environ.get('CDSE_CONTEXT_OWNER_ADMIN', './caumedse-admin')).resolve())
COMMAND = [ADMIN, 'context-column-read']
REGISTER = [ADMIN, 'context-column-register']
UNREGISTER = [ADMIN, 'context-column-unregister']
REVOKE = [ADMIN, 'context-column-revoke']


class CommandTests(unittest.TestCase):
    def test_copy_preview_help_and_incomplete_invocation(self):
        args = [ADMIN, 'context-copy-plan']
        usage = subprocess.run([*args, '--help'], capture_output=True, timeout=30, check=True)
        for action in ('--preview-v2', '--status-v2', '--commit-v2', '--advance-v2-witness'):
            self.assertIn(action.encode(), usage.stdout)
            result = subprocess.run([*args, action], capture_output=True, timeout=30)
            self.assertEqual((result.returncode, result.stdout), (1, b''))

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

    def test_floor_two_copy_preview_and_witnessed_allocation(self):
        previous = self.copy_snapshot()
        _, _, anchor = registry_contract.issue(previous, b'k' * 32)
        self.assertEqual(self.current(), token(anchor))
        floor_two = dict(previous, generation=previous['generation'] + 1, minimumFormat=2)
        self.assertEqual(self.publish(floor_two, anchor).returncode, 0)
        registry, catalog = self.current(), self.map_current()
        source = self.published / 'candidate.sqlite'
        image_digest = hashlib.sha256(source.read_bytes()).hexdigest()
        control = self.root / 'preview-control'
        control.mkdir(mode=0o700)
        plan = control / 'copy.preview'
        manifest = self.private('copy-approval.json', b'{}')
        lookups = [f'next/cell/{i}' for i in range(len(self.ordered))]
        approval = dict(schema=7, manager=str(self.authority), deployment=self.anchor.deployment,
                        organization=self.anchor.organization, map=self.destination, registry=registry,
                        catalog=catalog, witness=str(self.witness), export=str(self.published), plan=str(plan),
                        lookups=lookups, source=str(source), sourceDigest=image_digest)

        def preview(witness_token, *, changes=None, password=self.password_file, action='--preview-v2',
                    digest=None, approved_registry=None, output=None):
            manifest.write_text(json.dumps(dict(approval, **(changes or {}))))
            args = [ADMIN, 'context-copy-plan', '--approval', manifest, '--confirmed-offline', manifest,
                    '--registry-key-file', self.registry_key, '--witness-directory', self.witness,
                    '--witness-key-file', self.witness_key, '--retained-witness-token', witness_token, action]
            if action == '--preview-v2':
                args.extend(['--password-file', password])
            if digest:
                args.extend(['--plan-digest', digest])
            if approved_registry:
                args.extend(['--approved-registry', approved_registry])
            result = self.invoke(args) if output is None else subprocess.run(args, stdout=output,
                                                                            stderr=subprocess.PIPE, timeout=90)
            self.assertNotIn(PASSWORD, result.stderr)
            self.assertNotIn(b'fixture-alpha', (result.stdout or b'') + result.stderr)
            return result

        waiting = preview(self.final_token)
        self.assertEqual((waiting.returncode, waiting.stdout), (2, b''))
        self.assertFalse(plan.exists())
        advanced = self.command('witness-advance', registry, catalog, self.final_token, directory=self.witness)
        self.assertEqual(advanced.returncode, 0, advanced.stderr)
        witness_token = advanced.stdout.decode().strip()
        witness_file = self.witness / 'witness.sqlite'
        registry_file = self.authority / 'registry.sqlite'
        wrong_password = self.private('wrong.password', b'fixture-wrong-key')
        altered = self.published / 'other.sqlite'
        altered.write_bytes(source.read_bytes())
        altered.chmod(0o600)
        with closing(sqlite3.connect(altered)) as db, db:
            db.execute('UPDATE cdse_column_v2_cells SET frame=zeroblob(length(frame)) WHERE ordinal='
                       '(SELECT max(ordinal) FROM cdse_column_v2_cells)')
        before = self.authority_files(), registry_file.read_bytes(), witness_file.read_bytes()
        negatives = (
            (self.final_token, {}, self.password_file, 2),
            (witness_token, {'registry': token(anchor)}, self.password_file, 1),
            (witness_token, {'sourceDigest': '00' * 32}, self.password_file, 1),
            (witness_token, {}, wrong_password, 1),
            (witness_token, {'source': str(altered), 'sourceDigest': hashlib.sha256(altered.read_bytes()).hexdigest()},
             self.password_file, 1),
            (witness_token, {'lookups': [lookups[0]] * len(lookups)}, self.password_file, 1),
        )
        for supplied, changes, password, code in negatives:
            denied = preview(supplied, changes=changes, password=password)
            self.assertEqual((denied.returncode, denied.stdout), (code, b''), denied.stderr)
            self.assertFalse(plan.exists())

        outcome = preview(witness_token)
        self.assertEqual(outcome.returncode, 0, outcome.stderr)
        encoded = plan.read_bytes()
        digest = hashlib.sha256(encoded).hexdigest()
        self.assertEqual(outcome.stdout, f'state=previewed-v2\npreview-digest={digest}\n'.encode())
        self.assertEqual(outcome.stderr, b'')
        self.assertEqual(plan.stat().st_mode & 0o777, 0o600)
        self.assertEqual(encoded[-32:], hmac.digest(b'k' * 32, encoded[:-32], 'sha256'))
        wire = io.BytesIO(encoded[:-32])
        prefix = b'CDSE-HKX-COPY-PREVIEW-v2\0' + bytes.fromhex(registry + catalog + witness_token + image_digest)
        self.assertEqual(wire.read(len(prefix)), prefix)
        planned, tag = wire.read(73), wire.read(32)

        def read_text():
            return wire.read(wire.read(1)[0]).decode('ascii')

        self.assertEqual(read_text(), self.destination)
        self.assertEqual(int.from_bytes(wire.read(4), 'big'), len(self.ordered))
        for lookup, (_, table, row, field) in zip(lookups, self.ordered):
            self.assertEqual([read_text(), read_text(), int.from_bytes(wire.read(8), 'big'), read_text()],
                             [lookup, table, row, field])
        body = wire.read(int.from_bytes(wire.read(4), 'big'))
        self.assertEqual(wire.read(), b'')
        snapshot = json.loads(body)
        self.assertEqual(snapshot['minimumFormat'], 2)
        self.assertEqual(snapshot['generation'], floor_two['generation'] + 1)
        self.assertEqual(len(snapshot['entries']), len(floor_two['entries']) + len(lookups))
        issued_body, issued_tag, issued_anchor = registry_contract.issue(snapshot, b'k' * 32)
        self.assertEqual((body, tag, planned.hex()), (issued_body, issued_tag, token(issued_anchor)))
        entries = {entry['lookup']: entry for entry in snapshot['entries']}
        for entry in floor_two['entries']:
            self.assertEqual(entries[entry['lookup']], entry)
        allocated = [entries[lookup]['context'] for lookup in lookups]
        self.assertEqual(len({item['resource'] for item in allocated}), 1)
        self.assertNotIn(allocated[0]['resource'], {entry['context']['resource'] for entry in floor_two['entries']})

        duplicate = preview(witness_token)
        self.assertEqual((duplicate.returncode, duplicate.stdout), (1, b''))
        for action in ('--status', '--commit'):
            denied = preview(witness_token, action=action, digest=digest)
            self.assertEqual((denied.returncode, denied.stdout), (1, b''))
            direct = self.command(f'copy-plan-{action[2:]}', plan, digest, registry, catalog)
            self.assertEqual((direct.returncode, direct.stdout), (1, b''))
        self.assertEqual(plan.read_bytes(), encoded)
        self.assertEqual((self.authority_files(), registry_file.read_bytes(), witness_file.read_bytes()), before)
        self.check_floor_two_allocation(preview, approval, witness_token, digest, planned.hex(), snapshot)

    def check_floor_two_allocation(self, run_plan, approval, witness_token, digest, planned, snapshot):
        registry_file = self.authority / 'registry.sqlite'
        witness_file = self.witness / 'witness.sqlite'
        source = Path(approval['source'])
        image = source.read_bytes()
        plan = Path(approval['plan'])
        before = self.authority_files(), registry_file.read_bytes()

        def command(action, **options):
            pins = dict(digest=digest, witness_token=witness_token, action=action)
            return run_plan(**(pins | options))

        def accepted(action, **options):
            result = command(action, **options)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stderr, b'')
            return dict(line.split('=', 1) for line in result.stdout.decode().splitlines())

        ready = dict(state='ready', registry=planned, catalog=approval['catalog'],
                     **{'preview-digest': digest, 'witness-state': 'current'})
        self.assertEqual(accepted('--status-v2'), ready)
        denied = command('--advance-v2-witness', approved_registry=planned)
        self.assertEqual((denied.returncode, denied.stdout), (2, b''))
        bad_plan = self.private('preview-control/changed.preview', plan.read_bytes() + b'\0')
        for options in (
            {'digest': '00' * 32},
            {'witness_token': self.final_token},
            {'changes': {'map': 'view'}},
            {'changes': {'lookups': list(reversed(approval['lookups']))}},
            {'changes': {'sourceDigest': '00' * 32}},
            {'changes': {'plan': str(bad_plan)}, 'digest': hashlib.sha256(bad_plan.read_bytes()).hexdigest()},
        ):
            denied = command('--commit-v2', **options)
            self.assertEqual((denied.returncode, denied.stdout), (1, b''), denied.stderr)
        try:
            source.write_bytes(image[:-1] + bytes([image[-1] ^ 1]))
            denied = command('--commit-v2')
            self.assertEqual((denied.returncode, denied.stdout), (1, b''))
        finally:
            source.write_bytes(image)
        self.assertEqual((self.authority_files(), registry_file.read_bytes()), before)

        if Path('/dev/full').exists():
            with open('/dev/full', 'wb') as output:
                lost = command('--commit-v2', output=output)
            self.assertEqual(lost.returncode, 1, lost.stderr)
        else:
            accepted('--commit-v2')
        self.assertEqual(self.copy_snapshot(), snapshot)
        self.assertEqual(self.current(), planned)
        self.assertEqual(self.map_current(), approval['catalog'])
        self.assertEqual(witness_file.read_bytes(), before[0][2])
        self.assertEqual(self.authority_files()[3], before[0][3])
        committed = ready | {'state': 'committed', 'witness-state': 'advance-required'}
        self.assertEqual(accepted('--status-v2'), committed)
        self.assertNotEqual(registry_file.read_bytes(), before[1])
        committed_registry = registry_file.read_bytes()

        backup = source.with_suffix('.retained')
        source.rename(backup)
        try:
            self.assertEqual(accepted('--commit-v2'), committed)
            denied = command('--advance-v2-witness', approved_registry=approval['registry'])
            self.assertEqual((denied.returncode, denied.stdout), (1, b''))
            with closing(sqlite3.connect(witness_file)) as db:
                db.execute('BEGIN IMMEDIATE')
                denied = command('--advance-v2-witness', approved_registry=planned)
                self.assertEqual((denied.returncode, denied.stdout), (1, b''))
                db.rollback()
            self.assertEqual(witness_file.read_bytes(), before[0][2])
            self.assertEqual(accepted('--status-v2'), committed)
            advanced = accepted('--advance-v2-witness', approved_registry=planned)
            new_token = advanced.pop('witness-token')
            self.assertEqual(int(new_token[:16], 16), int(witness_token[:16], 16) + 1)
            self.assertEqual(advanced, ready | {'state': 'witness-advanced'})
            self.assertEqual(accepted('--advance-v2-witness', approved_registry=planned),
                             advanced | {'witness-token': new_token})
            self.assertEqual(accepted('--commit-v2'), committed | {'witness-state': 'already-advanced'})
        finally:
            backup.rename(source)
        self.assertEqual(registry_file.read_bytes(), committed_registry)
        self.assertEqual(self.authority_files()[3], before[0][3])
        self.assertNotEqual(witness_file.read_bytes(), before[0][2])
        checked = self.command('witness-check', planned, approval['catalog'], directory=self.witness)
        self.assertEqual(checked.returncode, 0, checked.stderr)

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
