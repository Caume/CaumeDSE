#!/usr/bin/env python3
"""Independent publication intent encoding, no-replace promotion and recovery."""
import hashlib
import hmac
import os
from pathlib import Path
import select
import shutil
import struct
import subprocess
import unittest

import test_context_column_custody as custody_tests
from test_context_crypto import available


class PublicationTests(custody_tests.CustodyTests):
    def setUp(self):
        super().setUp();self.control=self.root/'publication-control';self.control.mkdir(mode=0o700)
        self.published=self.root/'published-export';self.job='publish.intent'

    def publication_args(self,action='prepare',pin='-',control=None,job=None,destination=None):
        args=self.custody_args();args[2]='target-publication-'+action
        args.extend([str(control or self.control),job or self.job,str(destination or self.published),pin]);return args

    def publication(self,action='prepare',pin='-',env=None,**options):
        return self.invoke(self.publication_args(action,pin,**options),env)

    @unittest.skipIf(available(),'provider is compiled in')
    def test_provider_absence_cannot_persist_intent_or_publish(self):
        self.assertEqual(self.publication().returncode,3)
        self.assertEqual(list(self.control.iterdir()),[]);self.assertFalse(self.published.exists())


for _parent in PublicationTests.__mro__[1:]:
    for _name in vars(_parent):
        if _name.startswith('test_') and _name not in vars(PublicationTests):setattr(PublicationTests,_name,None)
del _parent


class ProviderPublicationTests(PublicationTests):
    @classmethod
    def setUpClass(cls):
        if not available():raise unittest.SkipTest('optional Herradura provider not compiled in')

    def setUp(self):
        super().setUp();custody_tests.acceptance_tests.registrations.transforms.images.ProviderImageTests.exported(self)
        self.rebuild_candidate();self.refresh_receipt();self.reset_companions()
        self.acceptance.write_bytes(self.acceptance_signed());self.physical()

    @staticmethod
    def text(value):
        value=value.encode();return struct.pack('>H',len(value))+value

    @staticmethod
    def stat(path,level):
        s=path.stat();values=[s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,
                             s.st_mtime_ns//10**9,s.st_mtime_ns%10**9,s.st_ctime_ns//10**9,s.st_ctime_ns%10**9]
        return b''.join(struct.pack('>Q',v) for v in values[:5 if level==0 else (9 if level==1 else 11)])

    def signed_intent(self,control=None,job=None,destination=None):
        control=control or self.control;job=job or self.job;destination=destination or self.published
        anchor=bytes.fromhex(self.current());catalog=bytes.fromhex(self.plan_catalog);witness=bytes.fromhex(self.retained)
        acceptance=hashlib.sha256(self.acceptance.read_bytes()).digest()
        manifest=(b'CDSE-HKX-COLUMN-PUBLICATION-MANIFEST-v1\0'+acceptance+bytes.fromhex(self.plan_digest)+anchor[:32]+
                  anchor[32:40]+struct.pack('>Q',anchor[40])+anchor[41:]+catalog+witness+self.text(self.destination)+
                  self.stat(control,0)+self.text(job)+self.stat(destination.parent,0)+self.text(destination.name))
        for original,actual in ((self.source_root,self.source_root),(self.candidate_root,self.candidate_root if self.candidate_root.exists() else destination)):
            files=sorted(actual.iterdir())
            manifest+=self.stat(original.parent,0)+self.text(original.name)+self.stat(actual,1)+struct.pack('>Q',len(files))
            for path in files:manifest+=self.text(path.name)+self.stat(path,2)+hashlib.sha256(path.read_bytes()).digest()
        body=b'CDSE-HKX-COLUMN-PUBLICATION-v1\0'+hashlib.sha256(manifest).digest()+acceptance
        name=self.destination.encode()
        seal=b'CDSE-HKX-COLUMN-PUBLICATION-SEAL-v1\0'+anchor+catalog+bytes([len(name)])+name+hashlib.sha256(body).digest()
        return body+hmac.digest(b'k'*32,seal,'sha256')

    def prepared(self,env=None,**options):
        expected=self.signed_intent(**options);result=self.publication(env=env,**options)
        self.assertEqual(result.returncode,0,result.stderr);pin=result.stdout.decode().strip()
        self.assertEqual(pin,hashlib.sha256(expected).hexdigest())
        control=options.get('control',self.control);job=options.get('job',self.job)
        self.assertEqual((control/job).read_bytes(),expected);self.assertEqual((control/job).stat().st_mode&0o7777,0o600)
        self.assertTrue(self.candidate_root.exists());self.assertFalse(self.published.exists());return pin

    def complete(self,action,pin,**options):
        result=self.publication(action,pin,**options)
        self.assertEqual(result.returncode,0,result.stderr);self.assertEqual(result.stdout,b'publication-complete\n')
        self.assertFalse(self.candidate_root.exists());self.assertTrue(self.published.is_dir())
        self.assertEqual((self.control/self.job).read_bytes(),(self.control/(self.job+'.done')).read_bytes())
        self.assertEqual(self.map_read(name=self.destination).returncode,1)

    def test_independent_intent_and_no_replace_promotion(self):
        source={p.name:p.read_bytes() for p in self.source_root.iterdir()};staged={p.name:p.read_bytes() for p in self.candidate_root.iterdir()}
        inode=self.candidate_root.stat().st_ino;pin=self.prepared()
        self.complete('publish',pin)
        self.assertEqual(inode,self.published.stat().st_ino);self.assertEqual(staged,{p.name:p.read_bytes() for p in self.published.iterdir()})
        self.assertEqual(source,{p.name:p.read_bytes() for p in self.source_root.iterdir()})

    def test_prepare_and_completion_are_idempotent(self):
        pin=self.prepared();inode=(self.control/self.job).stat().st_ino
        self.assertEqual(self.prepared(),pin);self.assertEqual((self.control/self.job).stat().st_ino,inode)
        self.complete('recover',pin);self.complete('recover',pin)

    def test_metadata_cbc(self):self.complete('publish',self.prepared())
    def test_null_outputs_and_consumed_custody(self):self.complete('publish',self.prepared(env={'CDSE_CONTEXT_PUBLICATION_CONTRACT':'1'}))

    def test_control_and_destination_approvals(self):
        (self.root/'different').mkdir(mode=0o700)
        for options in (dict(control=self.source_root),dict(control=self.candidate_root),dict(destination=self.root/'different'/'published'),
                        dict(job='../escape'),dict(job='x'*129),dict(destination=self.source_root)):
            with self.subTest(options=options):self.assertEqual(self.publication(**options).returncode,1)
        self.control.chmod(0o755)
        try:self.assertEqual(self.publication().returncode,1)
        finally:self.control.chmod(0o700)
        self.assertFalse(self.published.exists());self.assertFalse((self.control/self.job).exists())

    def test_destination_is_never_overwritten(self):
        pin=self.prepared();self.published.mkdir(mode=0o700);sentinel=self.published/'keep';sentinel.write_bytes(b'keep')
        self.assertEqual(self.publication('publish',pin).returncode,1);self.assertEqual(self.publication('recover',pin).returncode,1)
        self.assertEqual(sentinel.read_bytes(),b'keep');self.assertTrue(self.candidate_root.exists())

    def test_intent_pin_and_canonical_authentication(self):
        pin=self.prepared();path=self.control/self.job;original=path.read_bytes()
        self.assertEqual(self.publication('publish','ab'*32).returncode,1)
        for data in (original[:-1],original+b'x',original[:-1]+bytes([original[-1]^1])):
            path.write_bytes(data);self.assertEqual(self.publication('recover',pin).returncode,1)
        path.write_bytes(original);path.chmod(0o644);self.assertEqual(self.publication('publish',pin).returncode,1)
        path.chmod(0o600);self.assertFalse(self.published.exists())

    def test_prepared_namespace_cannot_be_substituted(self):
        pin=self.prepared();other=self.root/'other-export'
        self.assertEqual(self.publication('publish',pin,destination=other).returncode,1)
        control=self.root/'other-control';control.mkdir(mode=0o700)
        shutil.copyfile(self.control/self.job,control/self.job);(control/self.job).chmod(0o600)
        self.assertEqual(self.publication('recover',pin,control=control).returncode,1)
        self.assertFalse(other.exists());self.assertFalse(self.published.exists())

    def test_intent_cannot_be_symlink_or_hardlink(self):
        pin=self.prepared();path=self.control/self.job;copy=self.root/'intent-copy';copy.write_bytes(path.read_bytes());copy.chmod(0o600)
        path.unlink();path.symlink_to(copy);self.assertEqual(self.publication('publish',pin).returncode,1)
        path.unlink();os.link(copy,path);self.assertEqual(self.publication('recover',pin).returncode,1)

    def test_same_bytes_replaced_after_prepare_refuse_recovery(self):
        pin=self.prepared();path=self.candidate_root/'RolesDB';replacement=self.root/'replacement'
        replacement.write_bytes(path.read_bytes());replacement.chmod(0o600);os.replace(replacement,path)
        self.assertEqual(self.publication('recover',pin).returncode,1);self.assertTrue(self.candidate_root.exists());self.assertFalse(self.published.exists())

    def test_interrupted_intent_temp_retries_without_artifact_changes(self):
        result=self.publication(env={'CDSE_CONTEXT_PUBLICATION_CRASH':'intent-temp'});self.assertEqual(result.returncode,86)
        self.assertFalse((self.control/self.job).exists());self.assertTrue((self.control/(self.job+'.tmp')).exists())
        self.complete('publish',self.prepared())

    def test_interrupted_prepared_intent_reopens_and_recovers(self):
        expected=hashlib.sha256(self.signed_intent()).hexdigest()
        result=self.publication(env={'CDSE_CONTEXT_PUBLICATION_CRASH':'after-intent'});self.assertEqual(result.returncode,86)
        self.assertTrue(self.candidate_root.exists());self.assertFalse(self.published.exists())
        self.complete('recover',expected)

    def crash_publish(self,stage):
        pin=self.prepared();result=self.publication('publish',pin,env={'CDSE_CONTEXT_PUBLICATION_CRASH':stage})
        self.assertEqual(result.returncode,86);self.assertFalse(self.candidate_root.exists());self.assertTrue(self.published.exists())
        self.complete('recover',pin);self.complete('recover',pin)

    def test_recover_after_rename(self):self.crash_publish('after-rename')
    def test_recover_after_parent_sync(self):self.crash_publish('after-parent-sync')
    def test_recover_incomplete_marker_temp(self):self.crash_publish('marker-temp')
    def test_recover_after_marker(self):self.crash_publish('after-marker')

    def test_wrong_marker_and_unknown_temp_are_not_repaired(self):
        pin=self.prepared();result=self.publication('publish',pin,env={'CDSE_CONTEXT_PUBLICATION_CRASH':'after-rename'})
        self.assertEqual(result.returncode,86)
        marker=self.control/(self.job+'.done');marker.write_bytes(b'forged');marker.chmod(0o600)
        self.assertEqual(self.publication('recover',pin).returncode,1);self.assertEqual(marker.read_bytes(),b'forged')
        marker.unlink();temporary=self.control/(self.job+'.done.tmp');temporary.write_bytes(b'unknown');temporary.chmod(0o600)
        self.assertEqual(self.publication('recover',pin).returncode,1);self.assertEqual(temporary.read_bytes(),b'unknown')

    def paused_publication(self,change,expected):
        pin=self.prepared();ready_r,ready_w=os.pipe();resume_r,resume_w=os.pipe();process=None
        try:
            env=dict(os.environ,CDSE_CONTEXT_PUBLICATION_PAUSE='before-rename',CDSE_CONTEXT_PUBLICATION_READY_FD=str(ready_w),CDSE_CONTEXT_PUBLICATION_RESUME_FD=str(resume_r))
            process=subprocess.Popen(self.publication_args('publish',pin),stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env,pass_fds=(ready_w,resume_r))
            self.assertTrue(select.select([ready_r],[],[],60)[0]);self.assertEqual(os.read(ready_r,1),b'1')
            change();os.write(resume_w,b'1');out,err=process.communicate(timeout=60)
            self.assertEqual(process.returncode,expected,err);self.assertEqual(out,b'publication-complete\n' if expected==0 else b'')
        finally:
            if process:
                if process.poll() is None:process.kill()
                process.communicate()
            for fd in (ready_r,ready_w,resume_r,resume_w):os.close(fd)
        if expected==0:
            self.assertFalse(self.candidate_root.exists());self.assertTrue((self.control/(self.job+'.done')).exists())
        else:
            self.assertTrue(self.candidate_root.exists());self.assertFalse((self.control/(self.job+'.done')).exists())

    def test_concurrent_recovery_cannot_bypass_publisher_lock(self):
        def contended():
            pin=hashlib.sha256(self.signed_intent()).hexdigest()
            self.assertEqual(self.publication('recover',pin).returncode,1)
        self.paused_publication(contended,0)

    def test_late_destination_creation_is_preserved(self):
        def created():self.published.mkdir(mode=0o700);(self.published/'keep').write_bytes(b'keep')
        self.paused_publication(created,1);self.assertEqual((self.published/'keep').read_bytes(),b'keep')

    def test_late_file_mutation_withholds_promotion(self):
        def changed():
            path=self.candidate_root/'RolesDB';data=bytearray(path.read_bytes());data[-1]^=1;path.write_bytes(data)
        self.paused_publication(changed,1);self.assertFalse(self.published.exists())

    def test_late_authority_change_withholds_promotion(self):
        self.paused_publication(lambda:(self.witness/'witness.sqlite').write_bytes(self.before_witness),2);self.assertFalse(self.published.exists())

    def test_completed_files_are_reverified(self):
        pin=self.prepared();self.complete('publish',pin)
        temporary=self.control/(self.job+'.done.tmp');temporary.write_bytes(b'unknown');temporary.chmod(0o600)
        self.assertEqual(self.publication('recover',pin).returncode,1);self.assertEqual(temporary.read_bytes(),b'unknown')
        temporary.unlink()
        path=self.published/'RolesDB';data=bytearray(path.read_bytes());data[-1]^=1;path.write_bytes(data)
        self.assertEqual(self.publication('recover',pin).returncode,1)


for _name in vars(PublicationTests):
    if _name.startswith('test_'):setattr(ProviderPublicationTests,_name,None)

if __name__=='__main__':unittest.main()
