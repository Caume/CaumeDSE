#!/usr/bin/env python3
"""Physical inventory, descriptor custody and concurrent replacement checks."""
import hashlib
import os
from pathlib import Path
import resource
import select
import shutil
import subprocess
import unittest

import test_context_column_acceptance as acceptance_tests
from test_context_crypto import available


class CustodyTests(acceptance_tests.AcceptanceTests):
    def setUp(self):
        super().setUp()
        self.source_root=self.root/'source-export';self.candidate_root=self.root/'candidate-export'
        self.physical()

    def physical(self):
        self.root.chmod(0o700)
        for directory in (self.source_root,self.candidate_root):
            if directory.is_symlink():directory.unlink()
            elif directory.exists():shutil.rmtree(directory)
            directory.mkdir(mode=0o700)
        def copied(source,target):shutil.copyfile(source,target);target.chmod(0o600)
        for name,source,candidate,pin in self.companions:
            copied(source,self.source_root/name);copied(candidate,self.candidate_root/name)
        copied(self.resources,self.source_root/'ResourcesDB');copied(self.candidate_resources,self.candidate_root/'ResourcesDB')
        copied(self.image,self.candidate_root/'candidate.sqlite')

    def custody_args(self,source_root=None,candidate_root=None,**options):
        args=self.export_args(True,**options);args[2]='target-custody'
        args.extend([str(source_root or self.source_root),str(candidate_root or self.candidate_root)])
        return args

    def held(self,env=None,**options):return self.invoke(self.custody_args(**options),env)

    def test_missing_and_extra_inventory(self):
        for directory in (self.source_root,self.candidate_root):
            for missing in (True,False):
                self.physical()
                if missing:(directory/'RolesDB').unlink()
                else:(directory/'extra').write_bytes(b'unapproved')
                self.assertEqual(self.held().returncode,1)

    def test_actual_bytes_cannot_be_replaced_by_memory_images(self):
        for directory,name in ((self.source_root,'ResourcesDB'),(self.source_root,'source.sqlite'),
                               (self.candidate_root,'ResourcesDB'),(self.candidate_root,'candidate.sqlite'),
                               (self.candidate_root,'RolesDB')):
            self.physical();path=directory/name;data=bytearray(path.read_bytes());data[-1]^=1;path.write_bytes(data)
            self.assertEqual(self.held().returncode,1)

    def test_symlink_hardlink_fifo_directory_refuse(self):
        for kind in ('symlink','hardlink','fifo','directory'):
            self.physical();path=self.candidate_root/'RolesDB';path.unlink()
            target=self.root/'RolesDB';target.chmod(0o600)
            if kind=='symlink':path.symlink_to(target)
            elif kind=='hardlink':os.link(target,path)
            elif kind=='fifo':os.mkfifo(path,0o600)
            else:path.mkdir(mode=0o700)
            self.assertEqual(self.held().returncode,1)

    def test_file_root_and_parent_permissions(self):
        for path,mode in ((self.candidate_root/'RolesDB',0o644),(self.source_root,0o755),(self.root,0o755)):
            self.physical();path.chmod(mode)
            try:self.assertEqual(self.held().returncode,1)
            finally:path.chmod(0o600 if path.name=='RolesDB' else 0o700)

    def test_sidecars_and_wal_headers_refuse(self):
        for suffix in ('-wal','-shm','-journal'):
            self.physical();(self.source_root/('ResourcesDB'+suffix)).write_bytes(b'sidecar')
            self.assertEqual(self.held().returncode,1)
        self.physical();path=self.source_root/'source.sqlite';data=bytearray(path.read_bytes());data[18]=2;data[19]=2;path.write_bytes(data)
        self.assertEqual(self.held().returncode,1)

    def test_root_alias_symlink_and_nesting(self):
        self.assertEqual(self.held(candidate_root=self.source_root).returncode,1)
        alias=self.root/'root-alias';alias.symlink_to(self.source_root,target_is_directory=True)
        self.assertEqual(self.held(source_root=alias).returncode,1)
        nested=self.source_root/'nested';shutil.copytree(self.candidate_root,nested)
        self.assertEqual(self.held(candidate_root=nested).returncode,1)

    def test_acceptance_pin_and_signature_required(self):
        self.assertEqual(self.held(receipt_pin='ab'*32).returncode,1)
        data=bytearray(self.acceptance.read_bytes());data[-1]^=1;self.acceptance.write_bytes(data)
        self.assertEqual(self.held().returncode,1)

    @unittest.skipIf(available(),'provider is compiled in')
    def test_valid_disk_export_reaches_provider_unavailable(self):
        self.assertEqual(self.held(env={'CDSE_CONTEXT_CUSTODY_CONTRACT':'1'}).returncode,3)


for _parent in CustodyTests.__mro__[1:]:
    for _name in vars(_parent):
        if _name.startswith('test_') and _name not in vars(CustodyTests):setattr(CustodyTests,_name,None)
del _parent


class ProviderCustodyTests(CustodyTests):
    @classmethod
    def setUpClass(cls):
        if not available():raise unittest.SkipTest('optional Herradura provider not compiled in')

    def setUp(self):
        super().setUp();acceptance_tests.registrations.transforms.images.ProviderImageTests.exported(self)
        self.rebuild_candidate();self.refresh_receipt();self.reset_companions()
        self.acceptance.write_bytes(self.acceptance_signed());self.physical()

    def roundtrip_custody(self,env=None):
        files=[p for d in (self.source_root,self.candidate_root) for p in d.iterdir()]
        before={str(p):(p.read_bytes(),p.stat().st_ino,p.stat().st_mode) for p in files}
        result=self.held(env=env or {'CDSE_CONTEXT_CRYPTO_RNG_FAIL':'all'})
        self.assertEqual(result.returncode,0,result.stderr);self.assertEqual(result.stdout,b'custody-verified\n')
        self.assertEqual(before,{str(p):(p.read_bytes(),p.stat().st_ino,p.stat().st_mode) for p in files})
        self.assertEqual(self.map_read(name=self.destination).returncode,1)

    def test_disk_acceptance_and_repeated_rechecks(self):self.roundtrip_custody()
    def test_metadata_cbc(self):self.roundtrip_custody()
    def test_empty_source_empty(self):self.roundtrip_custody()
    def test_null_ownership_and_ignored_memory_buffers(self):self.roundtrip_custody(env={'CDSE_CONTEXT_CUSTODY_CONTRACT':'1'})

    def test_complete_sibling_export(self):
        self.add_sibling();self.physical();self.roundtrip_custody()

    def test_descriptor_bound_under_low_limit(self):
        def limited():resource.setrlimit(resource.RLIMIT_NOFILE,(64,64))
        result=subprocess.run(self.custody_args(),capture_output=True,timeout=90,preexec_fn=limited)
        self.assertEqual(result.returncode,0,result.stderr);self.assertEqual(result.stdout,b'custody-verified\n')

    def paused_custody(self,stage,change,expected=1,restore=None):
        ready_r,ready_w=os.pipe();resume_r,resume_w=os.pipe();process=None
        try:
            env=dict(os.environ,CDSE_CONTEXT_CUSTODY_READY_FD=str(ready_w),CDSE_CONTEXT_CUSTODY_RESUME_FD=str(resume_r))
            if stage=='between-checks':env['CDSE_CONTEXT_CUSTODY_FIXTURE_PAUSE']=stage
            else:env['CDSE_CONTEXT_CUSTODY_PAUSE']=stage
            if restore:env['CDSE_CONTEXT_CUSTODY_POISON_CHECK']='1'
            process=subprocess.Popen(self.custody_args(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env,pass_fds=(ready_w,resume_r))
            self.assertTrue(select.select([ready_r],[],[],60)[0]);self.assertEqual(os.read(ready_r,1),b'1')
            change();os.write(resume_w,b'1')
            if restore:
                self.assertTrue(select.select([ready_r],[],[],60)[0]);self.assertEqual(os.read(ready_r,1),b'1')
                restore();os.write(resume_w,b'1')
            out,err=process.communicate(timeout=60);self.assertEqual(process.returncode,expected,err);self.assertEqual(out,b'')
        finally:
            if process:
                if process.poll() is None:process.kill()
                process.communicate()
            for fd in (ready_r,ready_w,resume_r,resume_w):os.close(fd)

    def test_identical_file_replacement_after_read(self):
        def replaced():
            path=self.candidate_root/'RolesDB';replacement=self.root/'replacement';replacement.write_bytes(path.read_bytes());replacement.chmod(0o600);os.replace(replacement,path)
        self.paused_custody('after-read',replaced)

    def test_root_replacement_after_acceptance(self):
        def replaced():
            parked=self.root/'parked';self.candidate_root.rename(parked);shutil.copytree(parked,self.candidate_root)
        self.paused_custody('after-acceptance',replaced)

    def test_same_size_write_with_restored_mtime_after_hash(self):
        def modified():
            path=self.source_root/'source.sqlite';status=path.stat();data=bytearray(path.read_bytes());data[-1]^=1;path.write_bytes(data)
            os.utime(path,ns=(status.st_atime_ns,status.st_mtime_ns))
        self.paused_custody('after-files',modified)

    def test_extra_entry_after_acceptance(self):
        self.paused_custody('after-acceptance',lambda:(self.source_root/'late-extra').write_bytes(b'x'))

    def test_observed_failure_poison_survives_parent_restore(self):
        self.paused_custody('between-checks',lambda:self.root.chmod(0o755),restore=lambda:self.root.chmod(0o700))

    def test_witness_change_after_acceptance(self):
        self.paused_custody('after-acceptance',lambda:(self.witness/'witness.sqlite').write_bytes(self.before_witness),expected=2)

    def test_catalog_change_after_open(self):
        def changed():self.assertEqual(self.map_store(self.source_slots,resource=self.source_slots[0][0]).returncode,0)
        self.paused_custody('between-checks',changed,expected=2)


for _name in vars(CustodyTests):
    if _name.startswith('test_'):setattr(ProviderCustodyTests,_name,None)

if __name__=='__main__':unittest.main()
