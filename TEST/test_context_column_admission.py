#!/usr/bin/env python3
"""Published-file proof, expired-capability recovery and guarded witness advance."""
from contextlib import closing
import hashlib
import hmac
import json
import os
from pathlib import Path
import select
import shutil
import sqlite3
import struct
import subprocess
import unittest

import test_context_column_publication as publication
from test_context_crypto import available

DOMAIN=b'CDSE-HKX-COLUMN-ADMISSION-v1\0'
PROOF=b'CDSE-HKX-COLUMN-ADMISSION-FILES-v1\0'


class AdmissionMixin:
    def copy_setup(self):
        super().copy_setup()
        for action in ('shuffle-init','shuffle-pair-init','copy-install-init'):
            self.assertEqual(self.command(action,self.current(),self.map_current()).returncode,0)

    def invoke(self,args,env=None):
        result=super().invoke(args,env)
        allowed=(0,1,2,3,86) if env and 'CDSE_CONTEXT_ADMISSION_CRASH' in env else (0,1,2,3)
        self.assertIn(result.returncode,allowed,'unexpected fixture/sanitizer exit')
        for message in (b'AddressSanitizer',b'LeakSanitizer',b'UndefinedBehaviorSanitizer',b'runtime error:'):
            self.assertNotIn(message,result.stderr)
        return result

    def prepare_args(self,**options):
        args=self.custody_args(candidate_root=self.published if available() else self.candidate_root,**options)
        args[2]='target-admission-prepare'
        args.extend([str(self.control),self.job,str(self.published),getattr(self,'intent','00'*32),
                     self.candidate_root.name,str(self.plan_path),self.plan_digest,self.plan_registry])
        return args


class DisabledAdmissionTests(AdmissionMixin,publication.PublicationTests):
    @unittest.skipIf(available(),'provider is compiled in')
    def test_disabled_provider_cannot_prepare_admission(self):
        before=self.current(),self.map_current(),(self.witness/'witness.sqlite').read_bytes()
        self.assertEqual(self.invoke(self.prepare_args()).returncode,3)
        self.assertEqual((self.current(),self.map_current(),(self.witness/'witness.sqlite').read_bytes()),before)
        self.assertFalse(self.published.exists());self.assertEqual(list(self.control.iterdir()),[])


class AdmissionTests(AdmissionMixin,publication.ProviderPublicationTests):
    def setUp(self):
        super().setUp()
        self.intent=self.prepared();self.complete('publish',self.intent)
        self.admission_fixture=self.prepare_args()[0]
        self.registry=self.current();self.journal_path=self.root/'admission.journal'
        if not self._testMethodName.endswith('_before_prepare'):self.retain()

    def physical_proof_bytes(self):
        proof=PROOF+hashlib.sha256(self.acceptance.read_bytes()).digest()+bytes.fromhex(self.intent+self.plan_digest)
        for root in (self.source_root,self.published):
            paths=sorted(root.iterdir())
            proof+=self.stat(root.parent,0)+self.text(root.name)+self.stat(root,2)+struct.pack('>I',len(paths))
            for path in paths:proof+=self.text(path.name)+self.stat(path,2)+hashlib.sha256(path.read_bytes()).digest()
        return proof

    def retain(self):
        before=self.current(),self.map_current(),(self.witness/'witness.sqlite').read_bytes()
        result=self.invoke(self.prepare_args());self.assertEqual(result.returncode,0,result.stderr)
        self.pin,encoded=result.stdout.decode().split();self.journal=bytes.fromhex(encoded)
        self.assertEqual(hashlib.sha256(self.journal).hexdigest(),self.pin)
        def text8(value):
            value=value.encode();return bytes([len(value)])+value
        allocation=self.plan_result();proof=self.physical_proof_bytes()
        ticket=b'CDSE-HKX-COLUMN-MAP-ADMISSION-v1\0'+bytes.fromhex(self.registry+self.plan_catalog)+hashlib.sha256(proof).digest()
        ticket+=text8(self.destination)+text8(allocation['resource'])+struct.pack('>I',len(allocation['slots']))
        for lookup,table,row,field in allocation['slots']:
            ticket+=text8(lookup)+text8(table)+struct.pack('>Q',row)+text8(field)
        ticket+=hmac.digest(b'k'*32,ticket,'sha256')
        prefix=DOMAIN+bytes.fromhex(self.registry+self.plan_catalog+self.retained)
        self.next_catalog=self.journal[len(prefix):len(prefix)+40].hex()
        expected=prefix+bytes.fromhex(self.next_catalog)+self.text(self.destination)+struct.pack('>I',len(ticket))+ticket+struct.pack('>I',len(proof))+proof
        self.assertEqual(self.journal,expected)
        self.assertEqual((self.current(),self.map_current(),(self.witness/'witness.sqlite').read_bytes()),before)
        self.assertEqual(self.map_read(name=self.destination).returncode,1)
        fd=os.open(self.journal_path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'wb') as output:
            output.write(self.journal);output.flush();os.fsync(output.fileno())
        directory=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(directory)
        finally:os.close(directory)

    def run_args(self,*,source=None,published=None,pin=None):
        fixture=self.admission_fixture
        return [fixture,str(self.authority),'column-admission-run',self.anchor.deployment,self.anchor.organization,
                str(self.witness),str(source or self.source_root),str(published or self.published),str(self.journal_path),pin or self.pin]

    def run_admission(self,env=None,**options):return self.invoke(self.run_args(**options),env)

    def completed(self,**options):
        result=self.run_admission(**options);self.assertEqual(result.returncode,0,result.stderr)
        catalog,witness=result.stdout.decode().split()
        self.assertEqual(catalog,self.next_catalog);self.assertEqual(self.current(),self.registry)
        self.assertEqual(self.map_current(),catalog)
        self.assertEqual(int(witness[:16],16),int(self.retained[:16],16)+1)
        self.assertEqual(self.command('witness-check',self.registry,catalog,directory=self.witness).returncode,0)
        for name in ('view',self.destination):
            read=self.command('admission-map-read',name,self.registry,catalog)
            self.assertEqual(read.returncode,0);self.assertEqual(json.loads(read.stdout)['blocked'],1)
            self.assertNotEqual(self.map_bind(name=name).returncode,0)
        return witness

    def test_canonical_proof_and_acknowledged_blocked_retry(self):
        witness=self.completed(env={'CDSE_CONTEXT_ADMISSION_CONTRACT':'1'})
        self.assertEqual(self.completed(),witness)
        self.assertNotEqual(self.target().returncode,0)  # Old capability expires at catalog commit.
        self.assertNotEqual(self.map_remove().returncode,0)

    def test_metadata_cbc(self):self.completed()

    def test_recovery_needs_no_old_credentials_receipts_or_controls(self):
        for path in (self.plan_path,self.receipt,self.acceptance,self.image,self.resources,self.candidate_resources):path.unlink()
        shutil.rmtree(self.control)
        self.completed()

    def crash(self,stage):
        before=(self.witness/'witness.sqlite').read_bytes()
        result=self.run_admission(env={'CDSE_CONTEXT_ADMISSION_CRASH':stage});self.assertEqual(result.returncode,86)
        if stage=='before-catalog':self.assertEqual(self.map_current(),self.plan_catalog)
        else:self.assertEqual(self.map_current(),self.next_catalog)
        if stage!='after-witness':self.assertEqual((self.witness/'witness.sqlite').read_bytes(),before)
        self.completed();self.completed()

    def test_crash_before_catalog(self):self.crash('before-catalog')
    def test_recover_after_catalog_without_old_capability(self):self.crash('after-catalog')
    def test_recover_lost_witness_ack(self):self.crash('after-witness')

    def test_publication_marker_and_pin_required_before_prepare(self):
        args=self.prepare_args();args[-5]='55'*32
        self.assertEqual(self.invoke(args).returncode,1)
        marker=self.control/(self.job+'.done');data=marker.read_bytes();marker.unlink()
        self.assertEqual(self.invoke(self.prepare_args()).returncode,1)
        marker.write_bytes(data);marker.chmod(0o600)
        (self.control/(self.job+'.done.tmp')).write_bytes(b'unknown')
        self.assertEqual(self.invoke(self.prepare_args()).returncode,1)
        self.assertEqual(self.map_current(),self.plan_catalog)

    def test_same_bytes_replacement_and_wrong_roots_are_refused(self):
        self.assertEqual(self.run_admission(source=self.published,published=self.source_root).returncode,1)
        path=self.published/'RolesDB';replacement=self.root/'replacement'
        replacement.write_bytes(path.read_bytes());replacement.chmod(0o600);os.replace(replacement,path)
        self.assertEqual(self.run_admission().returncode,1);self.assertEqual(self.map_current(),self.plan_catalog)

    def test_modified_source_refuses_before_catalog(self):
        path=self.source_root/'RolesDB';data=bytearray(path.read_bytes());data[-1]^=1;path.write_bytes(data)
        self.assertEqual(self.run_admission().returncode,1);self.assertEqual(self.map_current(),self.plan_catalog)

    def test_extra_sidecar_and_root_replacement_refuse(self):
        (self.published/'ResourcesDB-wal').write_bytes(b'sidecar')
        self.assertEqual(self.run_admission().returncode,1)
        (self.published/'ResourcesDB-wal').unlink()
        other=self.root/'other';shutil.copytree(self.published,other);self.published.rename(self.root/'retained-root');other.rename(self.published)
        self.assertEqual(self.run_admission().returncode,1);self.assertEqual(self.map_current(),self.plan_catalog)

    def test_tampering_cannot_be_approved_by_rehashing_journal(self):
        for data in (self.journal[:-1],self.journal+b'\0',b'\0',self.journal[:-1]+bytes([self.journal[-1]^1])):
            self.journal_path.write_bytes(data)
            self.assertEqual(self.run_admission(pin=hashlib.sha256(data).hexdigest()).returncode,1)
            self.assertEqual(self.map_current(),self.plan_catalog)
        self.journal_path.write_bytes(self.journal)
        self.assertEqual(self.run_admission(pin='00'*32).returncode,1)

    def test_stale_catalog_and_witness_refuse_without_adoption(self):
        self.assertEqual(self.map_store(self.source_slots,name='competing',resource=self.source_slots[0][0]).returncode,0)
        actual=self.map_current();self.assertEqual(self.run_admission().returncode,2);self.assertEqual(self.map_current(),actual)

    def test_witness_rollback_withholds_admission(self):
        (self.witness/'witness.sqlite').write_bytes(self.before_witness)
        self.assertEqual(self.run_admission().returncode,2);self.assertEqual(self.map_current(),self.plan_catalog)

    def paused(self,stage,change,expected):
        ready_r,ready_w=os.pipe();resume_r,resume_w=os.pipe();process=None
        try:
            env=dict(os.environ,CDSE_CONTEXT_ADMISSION_PAUSE=stage,CDSE_CONTEXT_ADMISSION_READY_FD=str(ready_w),CDSE_CONTEXT_ADMISSION_RESUME_FD=str(resume_r))
            process=subprocess.Popen(self.run_args(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env,pass_fds=(ready_w,resume_r))
            self.assertTrue(select.select([ready_r],[],[],90)[0]);self.assertEqual(os.read(ready_r,1),b'1')
            change();os.write(resume_w,b'1');out,err=process.communicate(timeout=90)
            self.assertEqual(process.returncode,expected,err);self.assertEqual(out,b'')
        finally:
            if process:
                if process.poll() is None:process.kill()
                process.communicate()
            for fd in (ready_r,ready_w,resume_r,resume_w):os.close(fd)

    def test_late_mutation_after_catalog_preserves_block_without_ack(self):
        before=(self.witness/'witness.sqlite').read_bytes()
        def changed():
            path=self.published/'RolesDB';data=bytearray(path.read_bytes());data[-1]^=1;path.write_bytes(data)
        self.paused('after-catalog',changed,1)
        self.assertEqual(self.map_current(),self.next_catalog);self.assertEqual((self.witness/'witness.sqlite').read_bytes(),before)
        self.assertNotEqual(self.map_bind().returncode,0);self.assertEqual(self.run_admission().returncode,1)

    def test_late_witness_change_before_catalog_prevents_commit(self):
        self.paused('before-catalog',lambda:(self.witness/'witness.sqlite').write_bytes(self.before_witness),2)
        self.assertEqual(self.map_current(),self.plan_catalog)

    def test_completed_retry_rechecks_physical_files(self):
        self.completed()
        path=self.published/'candidate.sqlite';data=bytearray(path.read_bytes());data[-1]^=1;path.write_bytes(data)
        self.assertEqual(self.run_admission().returncode,1);self.assertEqual(self.map_current(),self.next_catalog)
        self.assertNotEqual(self.map_bind().returncode,0)


for _cls in (DisabledAdmissionTests,AdmissionTests):
    for _parent in _cls.__mro__[1:]:
        for _name in vars(_parent):
            if _name.startswith('test_') and _name not in vars(_cls):setattr(_cls,_name,None)
del _cls,_parent

if __name__=='__main__':unittest.main()
