#!/usr/bin/env python3
"""Physical V2 reads after global v5 release; original approvals remain required."""
import hashlib
import os
import select
import subprocess
import unittest

import test_context_column_global as global_release
import herradura_registry_contract as registry_contract
from test_context_frame import PASSWORD


class ReleasedReadTests(global_release.GlobalTests):
    def setUp(self):
        super().setUp()
        self.admitted_witness=(self.witness/'witness.sqlite').read_bytes()
        if not self._testMethodName.endswith('_pending'):
            self.released()

    def read_args(self,*,ack=None,pin=None,password=PASSWORD,table='data',row=1,field='value',only=False,source=None,published=None):
        args=self.global_args(pin=pin)
        args[2]='column-global-read-release' if only else 'column-global-read'
        if source is not None:args[6]=str(source)
        if published is not None:args[7]=str(published)
        args.append(ack or getattr(self,'final_token',self.acknowledged))
        if not only:args.extend([table,str(row),field,password.hex()])
        return args

    def read(self,env=None,**options):return self.invoke(self.read_args(**options),env)

    def read_value(self,expected=b'fixture-alpha',**options):
        result=self.read(**options);self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(bytes.fromhex(result.stdout.decode().strip()),expected)

    def authority_files(self):
        return self.current(),self.map_current(),(self.witness/'witness.sqlite').read_bytes(),[
            (str(p),p.read_bytes()) for root in (self.source_root,self.published) for p in sorted(root.iterdir())]

    def test_actual_cells_and_metadata_without_writes(self):
        before=self.authority_files()
        self.read_value();self.read_value(b'fixture-beta',row=2)
        self.read_value(b'fixtureUser',field='userId')
        self.read_value(b'fixture-column',table='meta',row=2,field='attributeData')
        self.assertEqual(self.authority_files(),before)
        self.assertNotEqual(self.map_bind(name=self.destination).returncode,0)
        args=self.run_args();args[2]='column-read-release';args.append(self.acknowledged)
        self.assertNotEqual(self.invoke(args).returncode,0)

    def test_metadata_cbc(self):self.read_value()

    def test_no_implicit_global_release_or_witness_ack_pending(self):
        before=self.authority_files()
        self.assertEqual(self.read().returncode,2);self.assertEqual(self.authority_files(),before)
        self.assertEqual(self.invoke(self.global_args(),{'CDSE_CONTEXT_ADMISSION_CRASH':'global-after-catalog'}).returncode,86)
        after=self.authority_files()
        self.assertEqual(self.read().returncode,2);self.assertEqual(self.authority_files(),after)
        self.assertEqual((self.witness/'witness.sqlite').read_bytes(),self.admitted_witness)
        self.released();self.read_value()

    def test_separately_retained_witness_is_exact(self):
        for token in (self.retained,self.acknowledged,'00'*40,self.final_token[:-2]+f'{int(self.final_token[-2:],16)^1:02x}'):
            self.assertNotEqual(self.read(ack=token).returncode,0)
        self.read_value()

    def test_wrong_credentials_and_missing_cells_preserve_capability(self):
        for options in (dict(password=b'wrong'),dict(password=b''),dict(row=0),dict(row=999),dict(field='MAC'),dict(table='other')):
            result=self.read(**options);self.assertEqual(result.returncode,1);self.assertEqual(result.stdout,b'')
        self.read_value(env={'CDSE_CONTEXT_READ_CONTRACT':'1'})

    def test_release_envelope_and_original_proof_are_pinned(self):
        self.assertEqual(self.read(pin='55'*32).returncode,1)
        for index in (-1,len(global_release.GLOBAL)+4+len(self.journal)-1):
            data=bytearray(self.global_bytes);data[index]^=1;self.global_path.write_bytes(data)
            result=self.read(pin=hashlib.sha256(data).hexdigest());self.assertNotEqual(result.returncode,0)
        self.global_path.write_bytes(self.global_bytes);self.read_value()

    def test_same_bytes_image_replacement_refuses(self):
        path=self.published/'candidate.sqlite';other=self.root/'replacement'
        other.write_bytes(path.read_bytes());other.chmod(0o600);os.replace(other,path)
        self.assertEqual(self.read().returncode,1)

    def test_complete_inventory_and_names_are_pinned(self):
        self.assertEqual(self.read(source=self.published,published=self.source_root).returncode,1)
        path=self.source_root/'unexpected';path.write_bytes(b'extra')
        self.assertEqual(self.read().returncode,1)

    def test_witness_rollback_refuses(self):
        (self.witness/'witness.sqlite').write_bytes(self.admitted_witness)
        self.assertEqual(self.read().returncode,2)

    def test_registry_change_expires_release(self):
        snapshot=self.copy_snapshot()
        _,_,anchor=registry_contract.issue(snapshot,b'k'*32)
        snapshot.update(generation=snapshot['generation']+1,minimumFormat=2)
        result=self.publish(snapshot,anchor)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(self.read().returncode,2)

    def test_catalog_change_expires_release(self):
        result=self.map_remove(name='view');self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(self.read().returncode,2)

    def test_interrupted_open_retries_original_evidence(self):
        before=self.authority_files()
        self.assertEqual(self.read(only=True,env={'CDSE_CONTEXT_ADMISSION_CRASH':'before-global-read'}).returncode,86)
        self.assertEqual(self.authority_files(),before);self.read_value()

    def test_original_external_receipts_not_required(self):
        for path in (self.plan_path,self.receipt,self.acceptance,self.image,self.resources,self.candidate_resources,self.admission_path):path.unlink()
        self.read_value()

    def pause_read(self,change,expected,restore=None,stage='after-global-read'):
        ready_r,ready_w=os.pipe();resume_r,resume_w=os.pipe();process=None
        try:
            env=dict(os.environ,CDSE_CONTEXT_ADMISSION_PAUSE=stage,CDSE_CONTEXT_ADMISSION_READY_FD=str(ready_w),
                     CDSE_CONTEXT_ADMISSION_RESUME_FD=str(resume_r))
            if restore:
                env.update(CDSE_CONTEXT_READ_POISON='1',CDSE_CONTEXT_CUSTODY_FIXTURE_PAUSE='read-poison',
                           CDSE_CONTEXT_CUSTODY_READY_FD=str(ready_w),CDSE_CONTEXT_CUSTODY_RESUME_FD=str(resume_r))
            process=subprocess.Popen(self.read_args(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env,pass_fds=(ready_w,resume_r))
            self.assertTrue(select.select([ready_r],[],[],90)[0]);self.assertEqual(os.read(ready_r,1),b'1')
            change();os.write(resume_w,b'1')
            if restore:
                self.assertTrue(select.select([ready_r],[],[],90)[0]);self.assertEqual(os.read(ready_r,1),b'1')
                restore();os.write(resume_w,b'1')
            out,err=process.communicate(timeout=90);self.assertEqual(process.returncode,expected,err);self.assertEqual(out,b'')
        finally:
            if process:
                if process.poll() is None:process.kill()
                process.communicate()
            for fd in (ready_r,ready_w,resume_r,resume_w):os.close(fd)

    def test_late_witness_rollback_withholds_plaintext(self):
        self.pause_read(lambda:(self.witness/'witness.sqlite').write_bytes(self.admitted_witness),2)

    def test_late_companion_mutation_withholds_plaintext(self):
        def change():
            path=self.published/'RolesDB';data=bytearray(path.read_bytes());data[-1]^=1;path.write_bytes(data)
        self.pause_read(change,1)

    def test_open_rechecks_after_physical_change(self):
        def change():
            path=self.source_root/'RolesDB';data=bytearray(path.read_bytes());data[-1]^=1;path.write_bytes(data)
        self.pause_read(change,1,stage='before-global-read')

    def test_observed_witness_failure_stays_poisoned_after_restore(self):
        original=(self.witness/'witness.sqlite').read_bytes()
        self.pause_read(lambda:(self.witness/'witness.sqlite').write_bytes(self.admitted_witness),2,
                        lambda:(self.witness/'witness.sqlite').write_bytes(original))
        self.read_value()


for _parent in ReleasedReadTests.__mro__[1:]:
    for _name in vars(_parent):
        if _name.startswith('test_') and _name not in vars(ReleasedReadTests):setattr(ReleasedReadTests,_name,None)
del _parent

if __name__=='__main__':unittest.main()
