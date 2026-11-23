#!/usr/bin/env python3
"""Exercise installed admission against a published export and retained approvals."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import unittest

import test_context_column_admission as admission
from test_context_frame import PASSWORD


ADMIN = str(Path(os.environ.get('CDSE_CONTEXT_OWNER_ADMIN', './caumedse-admin')).resolve())


class AdmissionHelpTests(unittest.TestCase):
    def test_help_and_invalid_actions(self):
        main = subprocess.run([ADMIN, '--help'], capture_output=True, timeout=30, check=True)
        self.assertIn(b'context-column-admission --help', main.stdout)
        command = [ADMIN, 'context-column-admission']
        help_result = subprocess.run([*command, '--help'], capture_output=True, timeout=30, check=True)
        for field in (b'prepare | complete', b'--approval-digest', b'--admission-digest', b'blocked catalog'):
            self.assertIn(field, help_result.stdout)
        for args in ([], ['prepare'], ['complete'], ['reset']):
            with self.subTest(args=args):
                result = subprocess.run([*command, *args], capture_output=True, timeout=30)
                self.assertEqual((result.returncode, result.stdout), (1, b''))


class InstalledAdmissionTests(admission.AdmissionTests):
    def retain(self):
        # AdmissionTests still builds and physically publishes the verified export.
        # The installed command must create the journal for these cases.
        pass

    def setUp(self):
        super().setUp()
        self.plan_path.chmod(0o600)
        self.receipt.chmod(0o600)
        self.acceptance.chmod(0o600)
        self.manifest_path = self.private('admission.json', b'{}')
        self.registry_key = self.private('registry.key', (b'k'*32).hex().encode())
        self.witness_key = self.private('witness.key', (b'w'*32).hex().encode() + b'\n')
        self.source_key = self.private('source.key', b'fixture-source-key')
        self.registration_key = self.private('registration.key', b'fixture-source-key')
        self.password_file = self.private('target.password', PASSWORD)
        fields = self.fields()
        self.manifest = dict(
            schema=1, originalRegistry=self.plan_registry, catalog=self.plan_catalog,
            sourceMap='view', lookups=self.lookups, allocationPlan=str(self.plan_path),
            allocationDigest=self.plan_digest, sourceProfile=fields['profile'], destinationMap=self.destination,
            sourceDigest=fields['source_digest'], candidateDigest=fields['image_digest'],
            registrationEvidenceDigest=self.registration_digest(), metadataProfile=fields['metadata_profile'],
            sourceFile=fields['source_file'], destinationFile=fields['destination_file'],
            sourceDocument=fields['source_document'], destinationDocument=fields['destination_document'],
            storageId=fields['storage_id'], organizationResource=fields['organization_resource'],
            columnId=fields['column_id'], storagePath=fields['storage_path'], sourceRow=fields['source_row'],
            destinationRow=fields['destination_row'], sourceResourcesDigest=fields['source_resources_digest'],
            candidateResourcesDigest=fields['candidate_resources_digest'], exportDigest=self.export_digest(),
            registrationReceipt=str(self.receipt), registrationReceiptDigest=self.sha(self.receipt.read_bytes()),
            companions=[[name, source.stat().st_size, digest] for name, source, _, digest in self.companions],
            acceptanceReceipt=str(self.acceptance), acceptanceDigest=self.sha(self.acceptance.read_bytes()),
            publicationDirectory=str(self.control), publicationJob=self.job, publicationDigest=self.intent,
            staging=self.candidate_root.name,
        )
        self.approval_pin = self.write_manifest()

    @staticmethod
    def sha(content):
        return hashlib.sha256(content).hexdigest()

    def private(self, name, content):
        path = self.root/name
        with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb') as stream:
            stream.write(content)
        return path

    def write_manifest(self, **changes):
        body = json.dumps(dict(self.manifest, **changes)).encode()
        self.manifest_path.write_bytes(body)
        return self.sha(body)

    def common(self):
        return dict(registry_directory=self.authority, witness_directory=self.witness,
                    deployment=self.anchor.deployment, organization=self.anchor.organization,
                    source_export=self.source_root, published_export=self.published,
                    registry_key_file=self.registry_key, witness_key_file=self.witness_key)

    @staticmethod
    def flags(options):
        return [arg for name, value in options.items() if value is not None
                for arg in ('--' + name.replace('_', '-'), str(value))]

    def args_for(self, action, **changes):
        options = dict(self.common(), admission_journal=self.journal_path)
        if action == 'prepare':
            options.update(approval=self.manifest_path, approval_digest=self.approval_pin,
                           retained_witness_token=self.retained, source_key_file=self.source_key,
                           registration_key_file=self.registration_key, password_file=self.password_file)
        else:
            options['admission_digest'] = getattr(self, 'pin', None)
        options.update(changes)
        return [ADMIN, 'context-column-admission', action, *self.flags(options)]

    def cli(self, action, **changes):
        result = self.invoke(self.args_for(action, **changes))
        for secret in (str(self.root).encode(), b'fixture-source-key', self.registry_key.read_bytes(),
                       self.witness_key.read_bytes().strip(), PASSWORD.hex().encode(), b'fixture-alpha'):
            self.assertNotIn(secret, result.stdout + result.stderr)
        return result

    def snapshots(self):
        return ((self.authority/'registry.sqlite').read_bytes(), (self.witness/'witness.sqlite').read_bytes(),
                [p.read_bytes() for root in (self.source_root, self.published) for p in sorted(root.iterdir())])

    def prepare_journal(self):
        before = self.snapshots()
        result = self.cli('prepare')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, b'')
        self.journal = self.journal_path.read_bytes()
        self.pin = self.sha(self.journal)
        self.assertEqual(result.stdout, f'admission-digest={self.pin}\n'.encode())
        self.assertEqual(self.journal_path.stat().st_mode & 0o7777, 0o600)
        self.assertEqual(self.journal_path.stat().st_nlink, 1)
        prefix = admission.DOMAIN + bytes.fromhex(self.registry + self.plan_catalog + self.retained)
        self.assertTrue(self.journal.startswith(prefix))
        self.next_catalog = self.journal[len(prefix):len(prefix)+40].hex()
        self.assertTrue(self.journal.endswith(self.physical_proof_bytes()))
        self.assertEqual(self.snapshots(), before)

    def run_admission_cli(self):
        result = self.cli('complete')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, b'')
        catalog, witness = result.stdout.decode().splitlines()
        self.assertEqual(catalog, 'catalog=' + self.next_catalog)
        prefix, token = witness.split('=')
        self.assertEqual(prefix, 'witness-token')
        self.assertEqual(len(bytes.fromhex(token)), 40)
        self.assertEqual(int(token[:16], 16), int(self.retained[:16], 16)+1)
        self.assertEqual(self.map_current(), self.next_catalog)
        self.assertEqual(self.current(), self.registry)
        self.assertEqual(self.journal_path.read_bytes(), self.journal)
        for name in ('view', self.destination):
            record = self.command('admission-map-read', name, self.registry, self.next_catalog)
            self.assertEqual(record.returncode, 0)
            self.assertEqual(json.loads(record.stdout)['blocked'], 1)
            self.assertNotEqual(self.map_bind(name=name).returncode, 0)
        return token

    def test_admit_release_and_read_with_separate_acknowledgements(self):
        self.prepare_journal()
        w1 = self.run_admission_cli()
        after = self.snapshots()
        self.assertEqual(self.run_admission_cli(), w1)
        self.assertEqual(self.snapshots(), after)

        envelope = self.root/'release.envelope'
        common = dict(self.common(), release_envelope=envelope)
        result = self.invoke([ADMIN, 'context-column-release', 'prepare',
                              *self.flags(dict(common, admission_journal=self.journal_path,
                                               admission_digest=self.pin, retained_witness_token=w1))])
        self.assertEqual(result.returncode, 0, result.stderr)
        digest = self.sha(envelope.read_bytes())
        self.assertEqual(result.stdout, f'release-digest={digest}\n'.encode())
        def read(token):
            return self.invoke([ADMIN, 'context-column-read',
                                *self.flags(dict(common, release_digest=digest, retained_witness_token=token,
                                                 password_file=self.password_file, table='data', row=1, field='value'))])
        self.assertEqual(read(w1).returncode, 2)
        result = self.invoke([ADMIN, 'context-column-release', 'complete', *self.flags(dict(common, release_digest=digest))])
        self.assertEqual(result.returncode, 0, result.stderr)
        w2 = dict(line.split('=') for line in result.stdout.decode().splitlines())['witness-token']
        self.assertEqual(read(w1).returncode, 2)
        result = read(w2)
        self.assertEqual((result.returncode, result.stdout), (0, b'fixture-alpha'))

    def test_complete_metadata_cbc(self):
        self.prepare_journal()
        self.run_admission_cli()

    def test_recovers_after_catalog_commit_without_prepare_inputs(self):
        self.prepare_journal()
        before = (self.witness/'witness.sqlite').read_bytes()
        result = self.invoke(self.run_args(), {'CDSE_CONTEXT_ADMISSION_CRASH': 'after-catalog'})
        self.assertEqual(result.returncode, 86)
        self.assertEqual(self.map_current(), self.next_catalog)
        self.assertEqual((self.witness/'witness.sqlite').read_bytes(), before)
        for path in (self.manifest_path, self.plan_path, self.receipt, self.acceptance,
                     self.source_key, self.registration_key, self.password_file):
            path.unlink()
        self.run_admission_cli()

    def test_recovers_lost_completion_output(self):
        self.prepare_journal()
        read_end, write_end = os.pipe()
        os.close(read_end)
        try:
            result = subprocess.run(self.args_for('complete'), stdout=write_end, stderr=subprocess.PIPE, timeout=90)
        finally:
            os.close(write_end)
        self.assertEqual(result.returncode, 1)
        self.assertIn(b'could not write admission results', result.stderr)
        self.assertEqual(self.map_current(), self.next_catalog)
        before = self.snapshots()
        self.run_admission_cli()
        self.assertEqual(self.snapshots(), before)

    def test_prepare_refuses_wrong_or_malformed_independent_approvals(self):
        before = self.snapshots()
        self.assertEqual(self.cli('prepare', approval_digest='00'*32).returncode, 1)
        for changes in (dict(schema=True), dict(unexpected='value'), dict(sourceRow=True),
                        dict(companions=[['RolesDB', True, '00'*32]]),
                        dict(acceptanceDigest='00'*32), dict(publicationDigest='00'*32),
                        dict(lookups=list(reversed(self.lookups)))):
            with self.subTest(changes=changes):
                self.assertNotEqual(self.cli('prepare', approval_digest=self.write_manifest(**changes)).returncode, 0)
                self.assertFalse(self.journal_path.exists())
        duplicate = json.dumps(self.manifest).encode().replace(b'{"schema": 1,', b'{"schema": 1, "schema": 1,', 1)
        self.manifest_path.write_bytes(duplicate)
        self.assertEqual(self.cli('prepare', approval_digest=self.sha(duplicate)).returncode, 1)
        self.assertEqual(self.snapshots(), before)

    def test_prepare_refuses_existing_paths_and_exposed_credentials(self):
        before = self.snapshots()
        for path in (self.manifest_path, self.published/'new-journal', self.authority/'new-journal'):
            self.assertEqual(self.cli('prepare', admission_journal=path).returncode, 1)
        self.source_key.chmod(0o644)
        self.assertEqual(self.cli('prepare').returncode, 1)
        self.source_key.chmod(0o600)
        self.prepare_journal()
        self.assertEqual(self.cli('prepare').returncode, 1)
        self.assertEqual(self.journal_path.read_bytes(), self.journal)
        self.assertEqual(self.snapshots(), before)

    def test_complete_rejects_changed_proof_and_unretained_digest(self):
        self.prepare_journal()
        before = self.snapshots()
        for args in (dict(admission_digest=None), dict(admission_digest='00'*32), dict(approval=self.manifest_path)):
            self.assertEqual(self.cli('complete', **args).returncode, 1)
        image = self.published/'candidate.sqlite'
        replacement = self.private('replacement', image.read_bytes())
        os.replace(replacement, image)
        self.assertEqual(self.cli('complete').returncode, 1)
        self.assertEqual(self.snapshots(), before)


for _parent in InstalledAdmissionTests.__mro__[1:]:
    for _name in vars(_parent):
        if _name.startswith('test_') and _name not in vars(InstalledAdmissionTests):
            setattr(InstalledAdmissionTests, _name, None)
del _parent

if __name__ == '__main__':
    unittest.main()
