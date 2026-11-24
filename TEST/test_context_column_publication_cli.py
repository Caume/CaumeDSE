#!/usr/bin/env python3
"""Exercise the installed publication workflow on a real staged export."""
import os
import subprocess
import unittest

import test_context_column_admission_cli as owner
import test_context_column_publication as publication


class PublicationHelpTests(unittest.TestCase):
    def test_help_and_invalid_actions(self):
        main = subprocess.run([owner.ADMIN, '--help'], capture_output=True, timeout=30, check=True)
        self.assertIn(b'context-column-publication --help', main.stdout)
        command = [owner.ADMIN, 'context-column-publication']
        result = subprocess.run([*command, '--help'], capture_output=True, timeout=30, check=True)
        for text in (b'prepare | publish | recover', b'--approval-digest', b'--publication-digest',
                     b'Retain it independently'):
            self.assertIn(text, result.stdout)
        for args in ([], ['prepare'], ['publish'], ['recover'], ['complete']):
            with self.subTest(args=args):
                result = subprocess.run([*command, *args], capture_output=True, timeout=30)
                self.assertEqual((result.returncode, result.stdout), (1, b''))


class InstalledPublicationTests(owner.OwnerApprovalFixture, publication.ProviderPublicationTests):
    def copy_setup(self):
        super().copy_setup()
        # Admission uses the copy-install catalog initialized before allocation.
        for action in ('shuffle-init', 'shuffle-pair-init', 'copy-install-init'):
            result = self.command(action, self.current(), self.map_current())
            self.assertEqual(result.returncode, 0, result.stderr)

    def setUp(self):
        self.use_profiled_export = self._testMethodName == 'test_profiled_publication_and_admission'
        super().setUp()
        self.registry = self.current()
        self.journal_path = self.root/'admission.journal'
        self.set_up_owner_approval()

    def publication_cli_args(self, action, **changes):
        options = dict(self.common(), approval=self.manifest_path, approval_digest=self.approval_pin,
                       retained_witness_token=self.retained, source_key_file=self.source_key,
                       registration_key_file=self.registration_key, password_file=self.password_file)
        if action != 'prepare':
            options['publication_digest'] = getattr(self, 'intent', None)
        options.update(changes)
        return [owner.ADMIN, 'context-column-publication', action, *self.flags(options)]

    def run_publication(self, action, **changes):
        result = self.invoke(self.publication_cli_args(action, **changes))
        for sensitive in (str(self.root).encode(), self.registry_key.read_bytes(),
                          self.witness_key.read_bytes().strip(), b'fixture-alpha'):
            self.assertNotIn(sensitive, result.stdout + result.stderr)
        return result

    def authority_snapshot(self):
        return ((self.authority/'registry.sqlite').read_bytes(), (self.witness/'witness.sqlite').read_bytes())

    @staticmethod
    def files(path):
        return {p.name: p.read_bytes() for p in sorted(path.iterdir())}

    def prepare_publication(self):
        expected = self.signed_intent()
        before = self.authority_snapshot(), self.files(self.source_root), self.files(self.candidate_root)
        result = self.run_publication('prepare')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, b'')
        self.intent = self.sha(expected)
        self.assertEqual(result.stdout, f'publication-digest={self.intent}\n'.encode())
        intent_file = self.control/self.job
        self.assertEqual(intent_file.read_bytes(), expected)
        self.assertEqual(intent_file.stat().st_mode & 0o7777, 0o600)
        self.assertFalse(self.published.exists())
        self.assertFalse((self.control/(self.job+'.done')).exists())
        self.assertEqual((self.authority_snapshot(), self.files(self.source_root), self.files(self.candidate_root)), before)

    def finish_publication(self, action):
        authority = self.authority_snapshot()
        result = self.run_publication(action)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((result.stdout, result.stderr), (b'publication-complete\n', b''))
        self.assertFalse(self.candidate_root.exists())
        self.assertTrue(self.published.is_dir())
        original = (self.control/self.job).read_bytes()
        marker = self.control/(self.job+'.done')
        self.assertEqual(marker.read_bytes(), original)
        self.assertEqual(marker.stat().st_mode & 0o7777, 0o600)
        self.assertEqual(self.sha(original), self.intent)
        self.assertEqual(self.authority_snapshot(), authority)
        self.assertEqual(self.map_read(name=self.destination).returncode, 1)

    def test_prepare_publish_and_admit_with_original_approval(self):
        approval = self.manifest_path.read_bytes()
        source = self.files(self.source_root)
        stage = self.files(self.candidate_root)
        stage_inode = self.candidate_root.stat().st_ino
        self.prepare_publication()
        intent_inode = (self.control/self.job).stat().st_ino
        self.prepare_publication()
        self.assertEqual((self.control/self.job).stat().st_ino, intent_inode)
        self.finish_publication('publish')
        self.assertEqual(self.files(self.source_root), source)
        self.assertEqual(self.files(self.published), stage)
        self.assertEqual(self.published.stat().st_ino, stage_inode)
        self.assertEqual(self.cli('prepare').returncode, 1)
        self.prepare_journal(publication_digest=self.intent)
        self.assertEqual(self.manifest_path.read_bytes(), approval)
        self.run_admission_cli()

    def test_publish_metadata_cbc(self):
        self.prepare_publication()
        self.finish_publication('publish')

    def test_profiled_publication_and_admission(self):
        self.assertEqual(self.manifest['schema'], 2)
        source = self.files(self.source_root)
        tuples = [list(entry) for entry in self.manifest['companions']]
        for entry in tuples:
            if entry[0] == 'sibling.sqlite':
                entry[3] = None
        invalid = self.write_manifest(companions=tuples)
        self.assertEqual(self.run_publication('prepare', approval_digest=invalid).returncode, 1)
        self.assertFalse((self.control / self.job).exists())
        self.assertEqual(self.write_manifest(), self.approval_pin)
        self.prepare_publication()
        self.finish_publication('publish')
        self.prepare_journal(publication_digest=self.intent)
        self.run_admission_cli()
        self.assertEqual(self.files(self.source_root), source)
        self.assertEqual((self.published / 'sibling.sqlite').read_bytes(), source['sibling.sqlite'])

    def test_recover_after_interruption_following_rename(self):
        self.prepare_publication()
        result = self.publication('publish', self.intent, env={'CDSE_CONTEXT_PUBLICATION_CRASH': 'after-rename'})
        self.assertEqual(result.returncode, 86)
        self.assertFalse(self.candidate_root.exists())
        self.assertTrue(self.published.is_dir())
        self.assertFalse((self.control/(self.job+'.done')).exists())
        self.assertEqual(self.cli('prepare', publication_digest=self.intent).returncode, 1)
        self.finish_publication('recover')
        self.finish_publication('recover')
        self.prepare_journal(publication_digest=self.intent)

    def test_recover_after_lost_publication_response(self):
        self.prepare_publication()
        read_end, write_end = os.pipe()
        os.close(read_end)
        try:
            result = subprocess.run(self.publication_cli_args('publish'), stdout=write_end,
                                    stderr=subprocess.PIPE, timeout=90)
        finally:
            os.close(write_end)
        self.assertEqual(result.returncode, 1)
        self.assertIn(b'could not write publication results', result.stderr)
        self.finish_publication('recover')

    def test_publication_requires_original_pins_and_witness(self):
        before = self.authority_snapshot()
        self.assertEqual(self.run_publication('prepare', approval_digest='00'*32).returncode, 1)
        self.assertEqual(self.run_publication('prepare', publication_digest='00'*32).returncode, 1)
        self.assertFalse((self.control/self.job).exists())
        self.prepare_publication()
        stale = self.retained[:-2] + f'{int(self.retained[-2:], 16) ^ 1:02x}'
        for action in ('publish', 'recover'):
            for options in (dict(publication_digest=None), dict(publication_digest='00'*32),
                            dict(retained_witness_token=stale)):
                self.assertNotEqual(self.run_publication(action, **options).returncode, 0)
                self.assertTrue(self.candidate_root.exists())
                self.assertFalse(self.published.exists())
        self.assertEqual(self.authority_snapshot(), before)
        self.finish_publication('recover')

    def test_different_destination_or_existing_directory_refuses(self):
        before = self.authority_snapshot()
        self.prepare_publication()
        alias = self.root/'different-export'
        self.assertEqual(self.run_publication('publish', published_export=alias).returncode, 1)
        self.assertFalse(alias.exists())
        self.published.mkdir(mode=0o700)
        sentinel = self.published/'sentinel'
        sentinel.write_bytes(b'keep')
        for action in ('publish', 'recover'):
            self.assertEqual(self.run_publication(action).returncode, 1)
            self.assertEqual(sentinel.read_bytes(), b'keep')
            self.assertTrue(self.candidate_root.exists())
        self.assertEqual(self.authority_snapshot(), before)

    def test_recover_rejects_replaced_file_after_promotion(self):
        self.prepare_publication()
        self.finish_publication('publish')
        artifact = self.published/'candidate.sqlite'
        replacement = self.private('replacement', artifact.read_bytes())
        os.replace(replacement, artifact)
        self.assertEqual(self.run_publication('recover').returncode, 1)


for _parent in InstalledPublicationTests.__mro__[1:]:
    for _name in vars(_parent):
        if _name.startswith('test_') and _name not in vars(InstalledPublicationTests):
            setattr(InstalledPublicationTests, _name, None)
del _parent

if __name__ == '__main__':
    unittest.main()
