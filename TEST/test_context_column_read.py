#!/usr/bin/env python3
"""Scoped, witness-aware plaintext release; generic maps stay blocked."""
import hashlib
import os
from pathlib import Path
import select
import subprocess
import unittest

import test_context_admission as core
import test_context_column_admission as admission
from test_context_frame import PASSWORD


class ReadCoreTests(core.AdmissionTests):
    def test_read_binding_is_not_mapped_or_copy_target_authority(self):
        self.retain()
        args=[self.registry,self.catalog,self.next_catalog,self.destination,self.evidence,
              self.ticket_path,self.digest,0]
        self.assertEqual(self.command('admission-bind',*args).returncode,2)
        self.committed()
        result=self.command('admission-bind',*args)
        self.assertEqual(result.returncode,0,result.stderr);self.assertEqual(result.stdout,b'3\n')
        self.assert_blocked()


class ReadTests(admission.AdmissionTests):
    def setUp(self):
        super().setUp()
        self.acknowledged=self.retained if self._testMethodName.endswith('_unacknowledged') else self.completed()

    def read_args(self,*,ack=None,password=PASSWORD,table='data',row=1,field='value',only=False,**options):
        args=self.run_args(**options);args[2]='column-read-release' if only else 'column-read'
        args.append(ack or self.acknowledged)
        if not only:args.extend([table,str(row),field,password.hex()])
        return args

    def read(self,env=None,**options):return self.invoke(self.read_args(**options),env)

    def read_value(self,expected=b'fixture-alpha',**options):
        result=self.read(**options);self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(bytes.fromhex(result.stdout.decode().strip()),expected)

    def test_exact_published_cells_without_authority_writes(self):
        before=self.current(),self.map_current(),(self.witness/'witness.sqlite').read_bytes()
        self.read_value();self.read_value(b'fixture-beta',row=2)
        self.read_value(b'fixtureUser',field='userId')
        self.read_value(b'fixture-column',table='meta',row=2,field='attributeData')
        self.assertEqual((self.current(),self.map_current(),(self.witness/'witness.sqlite').read_bytes()),before)
        self.assertNotEqual(self.map_bind().returncode,0);self.assertNotEqual(self.map_bind(name=self.destination).returncode,0)
        self.assertNotEqual(self.map_remove().returncode,0)

    def test_metadata_cbc(self):self.read_value()

    def test_no_implicit_admission_or_witness_advance_unacknowledged(self):
        before=self.current(),self.map_current(),(self.witness/'witness.sqlite').read_bytes()
        self.assertEqual(self.read().returncode,2)
        self.assertEqual((self.current(),self.map_current(),(self.witness/'witness.sqlite').read_bytes()),before)
        self.assertEqual(self.run_admission(env={'CDSE_CONTEXT_ADMISSION_CRASH':'after-catalog'}).returncode,86)
        self.assertEqual(self.read().returncode,2)
        self.assertEqual((self.witness/'witness.sqlite').read_bytes(),before[2])

    def test_acknowledgement_is_independent_and_exact(self):
        for token in (self.retained,'00'*40,self.acknowledged[:-2]+f'{int(self.acknowledged[-2:],16)^1:02x}'):
            self.assertNotEqual(self.read(ack=token).returncode,0)
        self.read_value()

    def test_wrong_password_and_unknown_cells_return_no_plaintext(self):
        for options in (dict(password=b'wrong'),dict(row=999),dict(field='MAC'),dict(table='other'),dict(password=b'')):
            self.assertEqual(self.read(**options).returncode,1)
        self.read_value()

    def test_physical_proof_and_journal_pin_required(self):
        self.assertEqual(self.read(pin='55'*32).returncode,1)
        data=self.journal[:-1]+bytes([self.journal[-1]^1]);self.journal_path.write_bytes(data)
        self.assertEqual(self.read(pin=hashlib.sha256(data).hexdigest()).returncode,1)

    def test_same_bytes_file_replacement_refuses_read_release(self):
        path=self.published/'candidate.sqlite';other=self.root/'replace'
        other.write_bytes(path.read_bytes());other.chmod(0o600);os.replace(other,path)
        self.assertEqual(self.read().returncode,1)

    def test_source_and_published_names_remain_pinned(self):
        self.assertEqual(self.read(source=self.published,published=self.source_root).returncode,1)
        (self.source_root/'unexpected').write_bytes(b'extra')
        self.assertEqual(self.read().returncode,1)

    def test_stale_witness_and_registry_reject_before_plaintext(self):
        (self.witness/'witness.sqlite').write_bytes(self.before_witness)
        self.assertEqual(self.read().returncode,2)
        self.assertNotEqual(self.map_bind().returncode,0)

    def test_interrupted_release_can_retry_original_approvals(self):
        before=self.current(),self.map_current(),(self.witness/'witness.sqlite').read_bytes()
        self.assertEqual(self.read(env={'CDSE_CONTEXT_ADMISSION_CRASH':'before-read-release'},only=True).returncode,86)
        self.assertEqual((self.current(),self.map_current(),(self.witness/'witness.sqlite').read_bytes()),before)
        self.read_value()

    def test_old_receipts_and_keys_are_not_required(self):
        for path in (self.plan_path,self.receipt,self.acceptance,self.image,self.resources,self.candidate_resources):path.unlink()
        self.read_value()

    def paused_read(self,change,expected):
        ready_r,ready_w=os.pipe();resume_r,resume_w=os.pipe();process=None
        try:
            env=dict(os.environ,CDSE_CONTEXT_ADMISSION_PAUSE='after-read',CDSE_CONTEXT_ADMISSION_READY_FD=str(ready_w),
                     CDSE_CONTEXT_ADMISSION_RESUME_FD=str(resume_r))
            process=subprocess.Popen(self.read_args(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env,pass_fds=(ready_w,resume_r))
            self.assertTrue(select.select([ready_r],[],[],90)[0]);self.assertEqual(os.read(ready_r,1),b'1')
            change();os.write(resume_w,b'1');out,err=process.communicate(timeout=90)
            self.assertEqual(process.returncode,expected,err);self.assertEqual(out,b'')
        finally:
            if process:
                if process.poll() is None:process.kill()
                process.communicate()
            for fd in (ready_r,ready_w,resume_r,resume_w):os.close(fd)

    def test_witness_rollback_after_crypto_withholds_plaintext(self):
        self.paused_read(lambda:(self.witness/'witness.sqlite').write_bytes(self.before_witness),2)

    def test_late_file_change_after_crypto_withholds_plaintext(self):
        def changed():
            path=self.published/'RolesDB';data=bytearray(path.read_bytes());data[-1]^=1;path.write_bytes(data)
        self.paused_read(changed,1)

    def test_observed_failure_poisons_capability_after_witness_restore(self):
        ready_r,ready_w=os.pipe();resume_r,resume_w=os.pipe();process=None
        original=(self.witness/'witness.sqlite').read_bytes()
        try:
            env=dict(os.environ,CDSE_CONTEXT_ADMISSION_PAUSE='after-read',CDSE_CONTEXT_ADMISSION_READY_FD=str(ready_w),
                     CDSE_CONTEXT_ADMISSION_RESUME_FD=str(resume_r),CDSE_CONTEXT_CUSTODY_FIXTURE_PAUSE='read-poison',
                     CDSE_CONTEXT_CUSTODY_READY_FD=str(ready_w),CDSE_CONTEXT_CUSTODY_RESUME_FD=str(resume_r),CDSE_CONTEXT_READ_POISON='1')
            process=subprocess.Popen(self.read_args(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env,pass_fds=(ready_w,resume_r))
            self.assertTrue(select.select([ready_r],[],[],90)[0]);self.assertEqual(os.read(ready_r,1),b'1')
            (self.witness/'witness.sqlite').write_bytes(self.before_witness);os.write(resume_w,b'1')
            self.assertTrue(select.select([ready_r],[],[],90)[0]);self.assertEqual(os.read(ready_r,1),b'1')
            (self.witness/'witness.sqlite').write_bytes(original);os.write(resume_w,b'1')
            out,err=process.communicate(timeout=90);self.assertEqual(process.returncode,2,err);self.assertEqual(out,b'')
        finally:
            if process:
                if process.poll() is None:process.kill()
                process.communicate()
            for fd in (ready_r,ready_w,resume_r,resume_w):os.close(fd)
        self.read_value()


for _cls in (ReadCoreTests,ReadTests):
    for _parent in _cls.__mro__[1:]:
        for _name in vars(_parent):
            if _name.startswith('test_') and _name not in vars(_cls):setattr(_cls,_name,None)
del _cls,_parent

if __name__=='__main__':unittest.main()
