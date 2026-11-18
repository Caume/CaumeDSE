#!/usr/bin/env python3
"""Pinned ResourcesDB clone, authenticated associations and V2 partMAC checks."""
from contextlib import closing
import hashlib
import os
from pathlib import Path
import select
import shutil
import sqlite3
import struct
import subprocess
import unittest

import test_context_column_transform as transforms
from test_context_crypto import available
from test_context_frame import PASSWORD


class RegistrationTests(transforms.TransformTests):
    def setUp(self):
        super().setUp()
        self.metadata_profile='aes-256-cbc' if 'metadata_cbc' in self._testMethodName else 'aes-256-gcm'
        self.resources=self.root/'ResourcesDB';self.candidate_resources=self.root/'CandidateResourcesDB'
        self.reg_env=dict(os.environ,CDSE_DEFAULT_ENC_ALG=self.metadata_profile)
        assets=Path(__file__).resolve().parent/'testDB_opt_cdse'
        for name in ('ResourcesDB','RolesDB','LogsDB'):
            with closing(sqlite3.connect(assets/name)) as original,closing(sqlite3.connect(self.root/name)) as db,db:
                for sql, in original.execute("select sql from sqlite_master where type='table' and name not like 'sqlite_%' and name!='schema_meta'"):
                    db.execute(sql)
                if name!='ResourcesDB':continue
                for field in ('documentIdLookup','storageIdLookup','orgResourceIdLookup'):db.execute(f'alter table documents add column {field} TEXT')
                for table in ('documents','users','storage'):
                    columns=[row[1] for row in db.execute(f'pragma table_info({table})')]
                    values=dict.fromkeys(columns,'');values.update(id=1,userId='fixtureUser',orgId='fixtureOrg',orgResourceId='fixtureOrg')
                    if table=='documents':
                        values.update(resourceInfo='fixture-info',columnFile=self.source.name,type='file.csv',documentId='fixture-document',
                                      storageId='fixtureStorage',partId='1',totalParts='1',columnId='1',lastModified='fixture-time')
                        for field in columns:
                            if field.endswith('Lookup'):values[field]=None
                    elif table=='storage':
                        values.update(storageId='fixtureStorage',type='remote' if self._testMethodName=='test_remote_storage_refuses' else 'local',accessPath='/offline-original/')
                    db.execute(f"insert into {table} ({','.join(columns)}) values ({','.join('?' for _ in columns)})",[values[c] for c in columns])
        self.payload('bundle');self.payload('registered-lookups')
        with closing(sqlite3.connect(self.resources)) as db:db.execute('pragma journal_mode=DELETE')
        self.rebuild_candidate()
        self.refresh_receipt()

    def payload(self,action,env=None):
        result=subprocess.run([transforms.images.columns.PAYLOAD,str(self.root),action],env=env or self.reg_env,
                              capture_output=True,timeout=30)
        self.assertEqual(result.returncode,0,'registration fixture creation failed')

    def rebuild_candidate(self,field=None,value=None):
        shutil.copyfile(self.resources,self.candidate_resources)
        env=dict(self.reg_env)
        if field:env.update(CDSE_FIXTURE_V2_FIELD=field,CDSE_FIXTURE_V2_VALUE=value)
        self.payload('v2-registration',env)

    def fields(self,**options):
        result=dict(source_digest=hashlib.sha256(self.source.read_bytes()).hexdigest(),image_digest=hashlib.sha256(self.image.read_bytes()).hexdigest(),
                    source_resources_digest=hashlib.sha256(self.resources.read_bytes()).hexdigest(),
                    candidate_resources_digest=hashlib.sha256(self.candidate_resources.read_bytes()).hexdigest(),
                    profile=self.profile,metadata_profile=self.metadata_profile,destination=self.destination,
                    source_row=1,destination_row=2,source_file='source.sqlite',destination_file='candidate.sqlite',
                    source_document='fixture-document',destination_document='fixture-copy',storage_id='fixtureStorage',
                    organization_resource='fixtureOrg',column_id='1',storage_path='/offline-original/')
        result.update(options);return result

    def registration_digest(self,**options):
        v=self.fields(**options)
        body=(b'CDSE-HKX-COLUMN-REGISTRATION-v1\0'+bytes([1 if v['metadata_profile']=='aes-256-gcm' else 2,
              1 if v['profile']=='aes-256-gcm' else 2])+bytes.fromhex(v['source_resources_digest']+v['candidate_resources_digest']+
              v['source_digest']+v['image_digest'])+struct.pack('>QQ',max(0,v['source_row']),max(0,v['destination_row'])))
        for key in ('source_file','destination_file','source_document','destination_document','storage_id','organization_resource','column_id','storage_path','destination'):
            text=v[key].encode();body+=struct.pack('>H',len(text))+text
        return hashlib.sha256(body).hexdigest()

    def refresh_receipt(self,**options):
        self.registration=self.registration_digest(**options)
        v=self.fields(**options)
        self.receipt.write_bytes(self.signed(source_digest=v['source_digest'],image_digest=v['image_digest'],
                                            registration=self.registration,destination=v['destination'],profile=v['profile']))

    def registered_args(self,verify=False,*,registration=None,reg_key='fixture-source-key',key='fixture-source-key',password=PASSWORD,**options):
        v=self.fields(**options)
        args=self.transform_args(False,key=key,password=password,source_digest=v['source_digest'],image_digest=v['image_digest'],
                                 registration=registration or self.registration_digest(**options),destination=v['destination'],profile=v['profile'])
        args[2]='target-registered-verify' if verify else 'target-registered-prepare'
        args.extend([str(self.resources),v['source_resources_digest'],str(self.candidate_resources),v['candidate_resources_digest'],
                     reg_key,v['metadata_profile'],str(v['source_row']),str(v['destination_row']),v['source_file'],v['destination_file'],
                     v['source_document'],v['destination_document'],v['storage_id'],v['organization_resource'],v['column_id'],v['storage_path']])
        if verify:args.extend([str(self.receipt),hashlib.sha256(self.receipt.read_bytes()).hexdigest()])
        return args

    def checked(self,verify=False,env=None,**options):return self.invoke(self.registered_args(verify,**options),env)

    def edit(self,path,sql):
        with closing(sqlite3.connect(path)) as db,db:db.executescript(sql)

    def test_registration_approval_hash_is_independently_required(self):
        self.assertEqual(self.checked(registration='ab'*32).returncode,1)

    def test_wrong_registration_key(self):self.assertEqual(self.checked(reg_key='wrong').returncode,1)
    def test_remote_storage_refuses(self):self.assertEqual(self.checked().returncode,1)

    def test_selected_fields_and_file_mac_are_authenticated(self):
        original=self.candidate_resources.read_bytes()
        for field,value in (('type','file.csv'),('partMAC','00'*32),('userId','wrong-user'),('columnFile','wrong.sqlite'),
                            ('documentId','wrong-document'),('totalParts','2'),('partId','2'),('resourceInfo','wrong-info')):
            with self.subTest(field=field):
                self.rebuild_candidate(field,value)
                self.assertEqual(self.checked().returncode,1)
        self.candidate_resources.write_bytes(original)

    def test_unrelated_rows_and_schema_cannot_change(self):
        original=self.candidate_resources.read_bytes()
        for sql in ("update users set userId='tampered'",'delete from documents where id=1',
                    'insert into documents select 3,userId,orgId,salt,resourceInfo,columnFile,type,documentId,storageId,orgResourceId,partMAC,totalParts,partId,lastModified,columnId,documentIdLookup,storageIdLookup,orgResourceIdLookup from documents where id=2',
                    'create table hidden(secret TEXT)','create trigger hidden after update on documents begin select 1; end'):
            self.candidate_resources.write_bytes(original);self.edit(self.candidate_resources,sql)
            self.assertEqual(self.checked().returncode,1)

    def test_lookup_substitution_refuses(self):
        self.edit(self.candidate_resources,"update documents set documentIdLookup=storageIdLookup where id=2")
        self.assertEqual(self.checked().returncode,1)

    def test_pins_and_selectors_cannot_be_adopted(self):
        for options in (dict(source_resources_digest='ab'*32),dict(candidate_resources_digest='ab'*32),dict(source_row=3),
                        dict(destination_row=3),dict(source_document='wrong'),dict(storage_id='wrong'),
                        dict(organization_resource='wrong'),dict(column_id='2'),dict(storage_path='/wrong/'),
                        dict(destination_file='../outside'),dict(destination_file='ResourcesDB'),dict(source_row=0),
                        dict(metadata_profile='aes-256-ctr'),dict(destination_document='fixture-document')):
            with self.subTest(options=options):self.assertEqual(self.checked(**options).returncode,1)

    def test_duplicate_source_and_storage_associations(self):
        before=self.resources.read_bytes();after=self.candidate_resources.read_bytes()
        for sql in ('insert into documents select 3,userId,orgId,salt,resourceInfo,columnFile,type,documentId,storageId,orgResourceId,partMAC,totalParts,partId,lastModified,columnId,documentIdLookup,storageIdLookup,orgResourceIdLookup from documents where id=1',
                    'insert into storage select 2,userId,orgId,salt,resourceInfo,location,type,storageId,accessPath,accessUser,accessPassword,orgResourceId from storage where id=1'):
            self.resources.write_bytes(before);self.candidate_resources.write_bytes(after)
            for path in (self.resources,self.candidate_resources):self.edit(path,sql)
            self.assertEqual(self.checked().returncode,1)

    @unittest.skipIf(available(),'provider is compiled in')
    def test_valid_registration_reaches_provider_unavailable(self):
        self.assertEqual(self.checked(env={'CDSE_CONTEXT_REGISTRATION_CONTRACT':'1'}).returncode,3)
        self.assertEqual(self.checked(True).returncode,3)


for _parent in RegistrationTests.__mro__[1:]:
    for _name in vars(_parent):
        if _name.startswith('test_') and _name not in vars(RegistrationTests):setattr(RegistrationTests,_name,None)
del _parent


class ProviderRegistrationTests(RegistrationTests):
    @classmethod
    def setUpClass(cls):
        if not available():raise unittest.SkipTest('optional Herradura provider not compiled in')

    def setUp(self):
        super().setUp();transforms.images.ProviderImageTests.exported(self)
        self.rebuild_candidate();self.refresh_receipt()

    def roundtrip(self,env=None):
        paths=[self.source,self.image,self.resources,self.candidate_resources,self.authority/'registry.sqlite',self.witness/'witness.sqlite',self.plan_path]
        before=[p.read_bytes() for p in paths]
        result=self.checked(env=env or {'CDSE_CONTEXT_CRYPTO_RNG_FAIL':'all'})
        self.assertEqual(result.returncode,0,result.stderr)
        digest,body=(bytes.fromhex(x) for x in result.stdout.decode().split())
        self.assertEqual(body,self.signed(registration=self.registration_digest()))
        self.assertEqual(hashlib.sha256(body).digest(),digest);self.receipt.write_bytes(body)
        verified=self.checked(True,env={'CDSE_CONTEXT_CRYPTO_RNG_FAIL':'all'})
        self.assertEqual(verified.returncode,0,verified.stderr);self.assertEqual(verified.stdout,b'registered-verified\n')
        self.assertEqual([p.read_bytes() for p in paths],before)
        self.assertEqual(self.map_read(name=self.destination).returncode,1)

    def test_verified_copy_registration(self):self.roundtrip()
    def test_metadata_cbc(self):self.roundtrip()
    def test_payload_cbc(self):self.roundtrip()
    def test_shuffled_source_shuffle(self):self.roundtrip()
    def test_empty_source_empty(self):self.roundtrip()
    def test_null_bounds_output_and_canonical_digest(self):self.roundtrip(env={'CDSE_CONTEXT_REGISTRATION_CONTRACT':'1'})

    def test_transform_signature_alone_cannot_accept_bad_registration(self):
        self.rebuild_candidate('type','file.csv')
        self.refresh_receipt()
        self.assertEqual(self.verify().returncode,0,'generic transformation verification deliberately ignores ResourcesDB')
        self.assertEqual(self.checked(True).returncode,1)

    def test_valid_registration_mac_cannot_skip_plaintext_comparison(self):
        sealed=self.target('target-seal',b'changed-value',table='data',row=1,field='value')
        self.assertEqual(sealed.returncode,0,sealed.stderr)
        salt,frame=(bytes.fromhex(x) for x in sealed.stdout.decode().split())
        ordinal=next(i+1 for i,slot in enumerate(self.ordered) if slot[1:]==['data',1,'value'])
        self.edit_image('update cdse_column_v2_cells set salt=?,frame=? where ordinal=?',(salt,frame,ordinal))
        self.rebuild_candidate();self.refresh_receipt()
        self.assertEqual(self.imported().returncode,0)
        self.assertEqual(self.checked().returncode,1);self.assertEqual(self.checked(True).returncode,1)

    def paused(self,verify,stage,change):
        ready_r,ready_w=os.pipe();resume_r,resume_w=os.pipe();process=None
        try:
            env=dict(os.environ,CDSE_CONTEXT_TRANSFORM_PAUSE=stage,CDSE_CONTEXT_TRANSFORM_READY_FD=str(ready_w),
                     CDSE_CONTEXT_TRANSFORM_RESUME_FD=str(resume_r))
            process=subprocess.Popen(self.registered_args(verify),stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env,
                                     pass_fds=(ready_w,resume_r))
            self.assertTrue(select.select([ready_r],[],[],60)[0]);self.assertEqual(os.read(ready_r,1),b'1')
            if change=='witness':(self.witness/'witness.sqlite').write_bytes(self.before_witness)
            else:self.assertEqual(self.map_store(self.source_slots,resource=self.source_slots[0][0]).returncode,0)
            os.write(resume_w,b'1');out,err=process.communicate(timeout=30)
            self.assertEqual(process.returncode,2,err);self.assertEqual(out,b'')
        finally:
            if process:
                if process.poll() is None:process.kill()
                process.communicate()
            for fd in (ready_r,ready_w,resume_r,resume_w):os.close(fd)

    def test_witness_change_withholds_registered_receipt(self):self.paused(False,'after-sign','witness')
    def test_catalog_change_withholds_registered_success(self):self.paused(True,'after-compare','catalog')


for _name in vars(RegistrationTests):
    if _name.startswith('test_'):setattr(ProviderRegistrationTests,_name,None)

if __name__=='__main__':unittest.main()
