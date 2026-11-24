#!/usr/bin/env python3
"""Complete supplied export inventory and independently encoded acceptance seals."""
from contextlib import closing
import hashlib
import hmac
import os
from pathlib import Path
import select
import shutil
import sqlite3
import struct
import subprocess
import unittest

import test_context_column_registration as registrations
from test_context_crypto import available


class AcceptanceTests(registrations.RegistrationTests):
    use_profiled_export = False

    def setUp(self):
        super().setUp()
        self.acceptance=self.root/'acceptance.receipt'
        for name in ('RolesDB','LogsDB'):
            with closing(sqlite3.connect(self.root/name)) as db:db.execute('pragma journal_mode=DELETE')
        # Committed historical LogsDB fixtures predate these required columns.
        with closing(sqlite3.connect(self.root/'LogsDB')) as db,db:
            columns={row[1] for row in db.execute('pragma table_info(transactions)')}
            for field in ('requestMethod','responseCode','authenticated'):
                if field not in columns:db.execute(f'alter table transactions add column {field} TEXT')
        self.companions=[]
        self.companion_profiles={}
        if self.use_profiled_export:
            self.add_profiled_sibling()
        self.reset_companions()
        self.acceptance.write_bytes(self.acceptance_signed())

    def reset_companions(self):
        self.companions=[]
        for name in ('LogsDB','RolesDB','source.sqlite',*(['sibling.sqlite'] if (self.root/'sibling.sqlite').exists() else [])):
            path=self.root/name;copy=self.root/('retained-'+name);shutil.copyfile(path,copy)
            self.companions.append((name,path,copy,hashlib.sha256(path.read_bytes()).hexdigest()))
        self.companions.sort()

    def export_digest(self,entries=None):
        entries=self.companions if entries is None else entries
        domain=b'CDSE-HKX-COLUMN-EXPORT-v2\0' if self.companion_profiles else b'CDSE-HKX-COLUMN-EXPORT-v1\0'
        profiles={None:0,'aes-256-gcm':1,'aes-256-cbc':2}
        body=domain+bytes.fromhex(self.registration_digest())+struct.pack('>Q',len(entries))
        for name,source,candidate,pin in entries:
            value=name.encode();body+=struct.pack('>H',len(value))+value+struct.pack('>Q',source.stat().st_size)+bytes.fromhex(pin)
            if self.companion_profiles:body+=bytes([profiles.get(self.companion_profiles.get(name),255)])
        return hashlib.sha256(body).hexdigest()

    def acceptance_signed(self,entries=None,inner=None):
        inner=self.receipt.read_bytes() if inner is None else inner
        body=b'CDSE-HKX-COLUMN-ACCEPTANCE-v1\0'+bytes.fromhex(self.export_digest(entries))+struct.pack('>H',len(inner))+inner
        registry=bytes.fromhex(self.current());catalog=bytes.fromhex(self.plan_catalog);name=self.destination.encode()
        seal=b'CDSE-HKX-COLUMN-ACCEPTANCE-SEAL-v1\0'+registry+catalog+bytes([len(name)])+name+hashlib.sha256(body).digest()
        return body+hmac.digest(b'k'*32,seal,'sha256')

    def export_args(self,verify=False,entries=None,pin=None,inner_pin=None,receipt_pin=None):
        entries=self.companions if entries is None else entries
        args=self.registered_args();args[2]='target-export-verify' if verify else 'target-export-prepare'
        args.extend([str(self.receipt),inner_pin or hashlib.sha256(self.receipt.read_bytes()).hexdigest(),pin or self.export_digest(entries),str(len(entries))])
        for name,source,candidate,digest in entries:
            profile=self.companion_profiles.get(name)
            args.extend([f'{name}:{profile}' if profile is not None else name,str(source),str(candidate),digest])
        if verify:args.extend([str(self.acceptance),receipt_pin or hashlib.sha256(self.acceptance.read_bytes()).hexdigest()])
        return args

    def accepted(self,verify=False,env=None,**options):return self.invoke(self.export_args(verify,**options),env)

    def add_sibling(self,field=None,value=None,profile=None):
        sibling=self.root/'sibling.sqlite'
        if profile:
            result=subprocess.run([registrations.transforms.images.columns.PAYLOAD,sibling,'registered-column'],
                env=dict(self.reg_env,CDSE_DEFAULT_ENC_ALG=profile,CDSE_FIXTURE_REGISTERED_TAGS='1'),
                capture_output=True,timeout=30)
            self.assertEqual(result.returncode,0,'sibling fixture creation failed')
        else:sibling.write_bytes(self.source.read_bytes())
        env=dict(self.reg_env)
        if field:env.update(CDSE_FIXTURE_V2_FIELD=field,CDSE_FIXTURE_V2_VALUE=value)
        self.payload('v2-sibling',env);self.rebuild_candidate();self.refresh_receipt();self.reset_companions()
        self.acceptance.write_bytes(self.acceptance_signed())

    def add_profiled_sibling(self):
        companion='aes-256-cbc' if self.profile=='aes-256-gcm' else 'aes-256-gcm'
        self.companion_profiles={self.source.name:self.profile,'sibling.sqlite':companion}
        self.add_sibling(profile=companion)

    def repin(self):
        self.companions=[(n,s,c,hashlib.sha256(s.read_bytes()).hexdigest()) for n,s,c,p in self.companions]
        self.acceptance.write_bytes(self.acceptance_signed())

    def test_missing_extra_duplicate_or_unsorted_entries(self):
        for entries in (self.companions[:-1],self.companions[1:],list(reversed(self.companions)),
                        [*self.companions,self.companions[-1]],
                        sorted([*self.companions,('extra.sqlite',self.source,self.source,hashlib.sha256(self.source.read_bytes()).hexdigest())])):
            with self.subTest(names=[e[0] for e in entries]):self.assertEqual(self.accepted(entries=entries).returncode,1)

    def test_approval_and_each_companion_pin_required(self):
        self.assertEqual(self.accepted(pin='ab'*32).returncode,1)
        for i in range(len(self.companions)):
            entries=list(self.companions);name,source,candidate,pin=entries[i];entries[i]=(name,source,candidate,'ab'*32)
            self.assertEqual(self.accepted(entries=entries).returncode,1)

    def test_candidate_companions_cannot_change(self):
        for name,source,candidate,pin in self.companions:
            original=candidate.read_bytes();data=bytearray(original);data[-1]^=1;candidate.write_bytes(data)
            self.assertEqual(self.accepted().returncode,1);candidate.write_bytes(original)

    def test_roles_logs_must_be_current_closed_databases(self):
        for name in ('RolesDB','LogsDB'):
            entry=next(e for e in self.companions if e[0]==name);original=entry[1].read_bytes()
            for operation in ('wal','schema','view'):
                entry[1].write_bytes(original)
                if operation=='wal':
                    data=bytearray(original);data[18]=2;data[19]=2;entry[1].write_bytes(data)
                else:
                    with closing(sqlite3.connect(entry[1])) as db,db:
                        db.execute("delete from schema_meta" if operation=='schema' else 'create view hidden as select 1')
                entry[2].write_bytes(entry[1].read_bytes());self.repin()
                self.assertEqual(self.accepted().returncode,1)
            entry[1].write_bytes(original);entry[2].write_bytes(original);self.repin()

    def test_internal_names_and_safe_leaf_names(self):
        for value in ('ResourcesDB','../outside','.hidden','bad name','source/part'):
            entries=list(self.companions);n,s,c,p=entries[-1];entries[-1]=(value,s,c,p);entries.sort()
            self.assertEqual(self.accepted(entries=entries).returncode,1)

    def test_sibling_omission_and_mac_refuse(self):
        self.add_sibling();self.assertEqual(self.accepted(entries=[e for e in self.companions if e[0]!='sibling.sqlite']).returncode,1)
        self.add_sibling('partMAC','00'*32);self.assertEqual(self.accepted().returncode,1)

    def test_unsupported_sibling_profiles_refuse(self):
        for field,value in (('type','file.raw'),('totalParts','2'),('partId','2'),('storageId','unknown-storage')):
            self.add_sibling(field,value);self.assertEqual(self.accepted().returncode,1)

    def test_receipt_pins_and_distinct_wire_format(self):
        self.assertEqual(self.accepted(True,receipt_pin='ab'*32).returncode,1)
        self.assertEqual(self.accepted(inner_pin='ab'*32).returncode,1)
        original=self.acceptance.read_bytes()
        for body in (original[:-1],original+b'x',original[:-1]+bytes([original[-1]^1]),self.receipt.read_bytes()):
            self.acceptance.write_bytes(body);self.assertEqual(self.accepted(True).returncode,1)
        self.acceptance.write_bytes(original)

    @unittest.skipIf(available(),'provider is compiled in')
    def test_valid_export_reaches_provider_unavailable(self):
        self.assertEqual(self.accepted(env={'CDSE_CONTEXT_EXPORT_CONTRACT':'1'}).returncode,3)
        self.assertEqual(self.accepted(True).returncode,3)


for _parent in AcceptanceTests.__mro__[1:]:
    for _name in vars(_parent):
        if _name.startswith('test_') and _name not in vars(AcceptanceTests):setattr(AcceptanceTests,_name,None)
del _parent


class ProviderAcceptanceTests(AcceptanceTests):
    @classmethod
    def setUpClass(cls):
        if not available():raise unittest.SkipTest('optional Herradura provider not compiled in')

    def setUp(self):
        super().setUp();registrations.transforms.images.ProviderImageTests.exported(self)
        self.rebuild_candidate();self.refresh_receipt();self.reset_companions()
        self.acceptance.write_bytes(self.acceptance_signed())

    def roundtrip_export(self,env=None):
        paths=[self.source,self.image,self.resources,self.candidate_resources,self.plan_path,
               self.authority/'registry.sqlite',self.witness/'witness.sqlite']
        paths.extend(p for n,s,c,h in self.companions for p in (s,c))
        before=[p.read_bytes() for p in paths]
        actual=self.checked();self.assertEqual(actual.returncode,0,actual.stderr)
        digest,body=(bytes.fromhex(x) for x in actual.stdout.decode().split())
        self.assertEqual(body,self.receipt.read_bytes())
        result=self.accepted(env=env or {'CDSE_CONTEXT_CRYPTO_RNG_FAIL':'all'})
        self.assertEqual(result.returncode,0,result.stderr)
        pin,body=(bytes.fromhex(x) for x in result.stdout.decode().split())
        self.assertEqual(body,self.acceptance_signed());self.assertEqual(hashlib.sha256(body).digest(),pin)
        self.acceptance.write_bytes(body)
        verified=self.accepted(True,env={'CDSE_CONTEXT_CRYPTO_RNG_FAIL':'all'})
        self.assertEqual(verified.returncode,0,verified.stderr);self.assertEqual(verified.stdout,b'export-verified\n')
        self.assertEqual(before,[p.read_bytes() for p in paths]);self.assertEqual(self.map_read(name=self.destination).returncode,1)
        self.assertLessEqual(len(body),640)

    def test_complete_export_roundtrip(self):self.roundtrip_export()
    def test_metadata_cbc(self):self.roundtrip_export()
    def test_payload_cbc(self):self.roundtrip_export()
    def test_empty_source_empty(self):self.roundtrip_export()
    def test_complete_sibling_inventory(self):self.add_sibling();self.roundtrip_export()
    def test_null_bounds_and_digest_contract(self):self.roundtrip_export(env={'CDSE_CONTEXT_EXPORT_CONTRACT':'1'})

    def test_profiled_mixed_export_and_wrong_or_missing_profile(self):
        self.add_profiled_sibling()
        self.roundtrip_export(env={'CDSE_CONTEXT_EXPORT_CONTRACT':'1'})
        approved=self.export_digest()
        for profile in (self.profile, 'aes-256-ctr', None):
            with self.subTest(profile=profile):
                self.companion_profiles['sibling.sqlite']=profile
                self.assertNotEqual(self.export_digest(),approved)
                self.assertEqual(self.accepted().returncode,1)
        self.companion_profiles['sibling.sqlite']='aes-256-cbc'
        self.companion_profiles['source.sqlite']='aes-256-cbc'
        self.assertEqual(self.accepted().returncode,1)

    def test_generic_registration_is_not_export_acceptance(self):
        self.add_sibling('partMAC','00'*32)
        self.assertEqual(self.checked(True).returncode,0)
        self.assertEqual(self.accepted().returncode,1);self.assertEqual(self.accepted(True).returncode,1)

    def test_manager_signature_does_not_skip_export_verification(self):
        entry=self.companions[0];data=bytearray(entry[1].read_bytes());data[18]=2;data[19]=2
        entry[1].write_bytes(data);entry[2].write_bytes(data);self.repin()
        self.assertEqual(self.checked(True).returncode,0)
        self.assertEqual(self.accepted(True).returncode,1)

    def paused_export(self,verify,change):
        ready_r,ready_w=os.pipe();resume_r,resume_w=os.pipe();process=None
        try:
            env=dict(os.environ,CDSE_CONTEXT_EXPORT_PAUSE='1',CDSE_CONTEXT_EXPORT_READY_FD=str(ready_w),CDSE_CONTEXT_EXPORT_RESUME_FD=str(resume_r))
            process=subprocess.Popen(self.export_args(verify),stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env,pass_fds=(ready_w,resume_r))
            self.assertTrue(select.select([ready_r],[],[],60)[0]);self.assertEqual(os.read(ready_r,1),b'1')
            if change=='catalog':self.assertEqual(self.map_store(self.source_slots,resource=self.source_slots[0][0]).returncode,0)
            else:(self.witness/'witness.sqlite').write_bytes(self.before_witness)
            os.write(resume_w,b'1');out,err=process.communicate(timeout=30)
            self.assertEqual(process.returncode,2,err);self.assertEqual(out,b'')
        finally:
            if process:
                if process.poll() is None:process.kill()
                process.communicate()
            for fd in (ready_r,ready_w,resume_r,resume_w):os.close(fd)

    def test_catalog_change_after_acceptance_signature(self):self.paused_export(False,'catalog')
    def test_witness_change_after_acceptance_signature(self):self.paused_export(True,'witness')


for _name in vars(AcceptanceTests):
    if _name.startswith('test_'):setattr(ProviderAcceptanceTests,_name,None)

if __name__=='__main__':unittest.main()
