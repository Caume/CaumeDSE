#!/usr/bin/env python3
"""Complete legacy source preflight and private V2 staging candidates."""
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import select
import sqlite3
import subprocess
import unittest

import test_context_target as target_tests
from test_context_crypto import available
from test_context_frame import PASSWORD, FIXTURE as FRAME_FIXTURE
import herradura_context_contract as wire
import herradura_registry_contract as registry

FIXTURE=str(Path(os.environ.get('CDSE_CONTEXT_COLUMN_FIXTURE','./context-column-fixture')).resolve())
PAYLOAD=str(Path('./reprotect-fixture').resolve())


class ColumnTests(target_tests.TargetTests):
    def copy_setup(self):
        self.source=self.root/'source.sqlite'
        self.profile='aes-256-cbc' if self._testMethodName.endswith('_cbc') else 'aes-256-gcm'
        env=dict(os.environ,CDSE_DEFAULT_ENC_ALG=self.profile)
        if self._testMethodName.endswith('_shuffle'):env['CDSE_FIXTURE_REGISTERED_SHUFFLE']='1'
        else:env['CDSE_FIXTURE_REGISTERED_TAGS']='1'
        kind='empty' if self._testMethodName.endswith('_empty') else 'registered-column'
        result=subprocess.run([PAYLOAD,str(self.source),kind],env=env,capture_output=True,timeout=30)
        self.assertEqual(result.returncode,0,'source fixture creation failed')
        self.source_slots=[]
        entries=[]
        with closing(sqlite3.connect(self.source)) as db:
            for table,fields in [('data',['value','userId','orgId','rowOrder']),
                                 ('meta',['attribute','attributeData','userId','orgId'])]:
                for row, in db.execute(f'select id from {table} order by id'):
                    for field in fields:
                        name=f'source/{table}/{row}/{field}'
                        self.source_slots.append((name,table,row,field))
                        context=dict(self.context,table=table,field=field,
                                     record=bytes([row+(100 if table=='meta' else 0)]).hex()*16)
                        entries.append(dict(lookup=name,state='active',context=context))
        if self._testMethodName.endswith('_missing_slot'):self.source_slots.pop()
        if self._testMethodName.endswith('_extra_slot'):
            context=dict(self.context,table='data',field='other',record='01'*16)
            entries.append(dict(lookup='extra',state='active',context=context))
            self.source_slots.append(('extra','data',1,'other'))
        self.assertEqual(self.publish(dict(self.snapshot,entries=entries)).returncode,0)
        self.map_init()
        self.assertEqual(self.map_store(self.source_slots,resource=self.source_slots[0][0]).returncode,0)
        self.ordered=json.loads(self.map_read().stdout)['slots']
        self.lookups=[f'copy/{i}' for i in range(len(self.ordered))]

    def column_args(self, *, source=None,digest=None,key='fixture-source-key',profile=None,password=PASSWORD):
        args=self.target_args('target-bind')
        args[0]=FIXTURE;args[2]='target-column'
        source=source or self.source
        return [*args,str(source),digest or hashlib.sha256(source.read_bytes()).hexdigest(),key,profile or self.profile,password.hex()]

    def column(self,env=None,**options):
        result=subprocess.run(self.column_args(**options),capture_output=True,timeout=90,
                              env=dict(os.environ,**(env or {})))
        if result.returncode:self.assertEqual(result.stdout,b'')
        for secret in (b'fixture-source-key',b'fixture-alpha',PASSWORD.hex().encode()):
            self.assertNotIn(secret,result.stderr)
        return result

    def edit(self,sql):
        with closing(sqlite3.connect(self.source)) as db,db:db.executescript(sql)

    def test_invalid_digest_key_profile_and_password(self):
        for options in (dict(digest='00'*32),dict(key='wrong'),dict(profile='aes-256-ctr'),dict(password=b''),
                        dict(key=''),dict(key='x'*257)):
            with self.subTest(options=options):self.assertEqual(self.column(**options).returncode,1)

    def test_missing_map_cell_missing_slot(self):self.assertEqual(self.column().returncode,1)

    def test_extra_map_cell_extra_slot(self):self.assertEqual(self.column().returncode,1)

    def test_extra_unapproved_sql_row(self):
        self.edit('insert into data select 3,userId,orgId,salt,value,rowOrder,MAC,sign,MACProtected,signProtected,otphDKey from data where id=1')
        self.assertEqual(self.column().returncode,1)

    def test_missing_sql_row(self):
        self.edit('delete from data where id=2')
        self.assertEqual(self.column().returncode,1)

    def test_unknown_schema_objects_and_malformed_image(self):
        original=self.source.read_bytes()
        for sql in ('create table hidden(secret TEXT)', 'create view hidden as select * from data',
                    'create trigger hidden after update on data begin select 1; end',
                    'alter table data add column hidden TEXT'):
            self.source.write_bytes(original);self.edit(sql)
            self.assertEqual(self.column().returncode,1)
        self.source.write_bytes(b'x'*4096)
        self.assertEqual(self.column().returncode,1)

    def test_identity_cells_are_typed_and_strictly_decoded(self):
        original=self.source.read_bytes()
        for sql in ("update data set userId=NULL where id=1", "update meta set orgId=x'00' where id=1",
                    "update data set value='!invalid!' where id=1", "update data set value='' where id=1",
                    "update data set value='YQ==' where id=1", "update data set salt='bad' where id=1",
                    "update data set userId=cast(x'610062' as TEXT) where id=1",
                    "update data set value=printf('%.*c',262145,'A') where id=1",
                    "update data set rowOrder='1' where id=2",
                    "update data set otphDKey='unsupported' where id=1"):
            self.source.write_bytes(original);self.edit(sql)
            self.assertEqual(self.column().returncode,1)

    def test_all_declared_integrity_columns_are_verified(self):
        original=self.source.read_bytes()
        for field in ('MAC','sign','MACProtected','signProtected'):
            self.source.write_bytes(original);self.edit(f"update data set {field}='' where id=2")
            self.assertEqual(self.column().returncode,1)

    def test_incorrect_profile_cbc(self):self.assertEqual(self.column(profile='aes-256-gcm').returncode,1)

    def test_disabled_integrity_helper_refuses_shuffle(self):
        self.edit("update data set MAC='unexpected' where id=1")
        self.assertEqual(self.column().returncode,1)

    def test_wal_header_is_not_a_closed_source(self):
        image=bytearray(self.source.read_bytes());image[18]=image[19]=2
        self.source.write_bytes(image)
        self.assertEqual(self.column().returncode,1)

    def test_metadata_semantics_are_required(self):
        self.edit('update meta set attribute=(select attribute from meta where id=1) where id=2')
        self.assertEqual(self.column().returncode,1)

    def test_null_bounds_ownership_and_output_contracts(self):
        self.assertEqual(self.column(env={'CDSE_CONTEXT_COLUMN_CONTRACT':'1'}).returncode,0 if available() else 3)

    @unittest.skipIf(available(),'provider is compiled in')
    def test_valid_source_refuses_missing_provider(self):self.assertEqual(self.column().returncode,3)


for _parent in ColumnTests.__mro__[1:]:
    for _name in vars(_parent):
        if _name.startswith('test_') and _name not in vars(ColumnTests):setattr(ColumnTests,_name,None)
del _parent


class ProviderColumnTests(ColumnTests):
    @classmethod
    def setUpClass(cls):
        if not available():raise unittest.SkipTest('optional Herradura provider not compiled in')

    def verified(self):
        paths=[self.source,self.authority/'registry.sqlite',self.witness/'witness.sqlite',self.plan_path]
        before=[p.read_bytes() for p in paths]
        result=self.column()
        self.assertEqual(result.returncode,0,result.stderr)
        cells=[line.split() for line in result.stdout.decode().splitlines()]
        self.assertEqual(len(cells),len(self.ordered))
        contexts={e['lookup']:registry.decode_context(e['context']) for e in self.copy_snapshot()['entries']}
        values={}
        for (name,table,row,field),lookup,line in zip(self.ordered,self.lookups,cells):
            self.assertEqual(line[:3],[table,str(row),field])
            salt,frame=map(bytes.fromhex,line[3:])
            opened=subprocess.run([FRAME_FIXTURE,'open',wire.context_bytes(contexts[lookup]).hex(),salt.hex(),
                                   PASSWORD.hex(),'02',frame.hex()],capture_output=True,timeout=30)
            self.assertEqual(opened.returncode,0,opened.stderr)
            values[(table,row,field)]=bytes.fromhex(opened.stdout.decode().strip())
            self.assertTrue(frame.startswith(b'CDSEHKX2'))
        for row in (1,2):
            order=values['data',row,'rowOrder']
            self.assertIn(order,(b'1',b'2'))
            expected=b'fixture-alpha' if order==b'1' else (b'' if self._testMethodName.endswith('_empty') else b'fixture-beta')
            self.assertEqual(values['data',row,'value'],expected)
        for (table,row,field),value in values.items():
            if field=='userId':self.assertEqual(value,b'fixtureUser')
            if field=='orgId':self.assertEqual(value,b'fixtureOrg')
            if table=='meta' and field=='attributeData' and values[table,row,'attribute'] in (b'protect',b'shuffle'):
                self.assertEqual(value,b'herradura-hske-nl-v2-profile1')
        self.assertEqual([p.read_bytes() for p in paths],before)
        self.assertEqual(self.map_current(),self.plan_catalog)
        self.assertEqual(self.map_read(name='unpublished-copy').returncode,1)
        # A fresh target frame must refuse both another target cell and its old source identity.
        first=cells[0]
        for context in (contexts[self.lookups[1]],contexts[self.ordered[0][0]]):
            refused=subprocess.run([FRAME_FIXTURE,'open',wire.context_bytes(context).hex(),first[3],
                                    PASSWORD.hex(),'02',first[4]],capture_output=True,timeout=30)
            self.assertEqual(refused.returncode,1);self.assertEqual(refused.stdout,b'')
        return cells

    def test_complete_gcm_source_stages_and_independent_readback(self):self.verified()
    def test_complete_cbc_source_stages_cbc(self):self.verified()
    def test_shuffled_source_stages_shuffle(self):self.verified()
    def test_empty_value_stages_empty(self):self.verified()

    def test_repeated_staging_has_fresh_entropy(self):
        first=self.verified();second=self.verified()
        for a,b in zip(first,second):self.assertNotEqual(a[3:],b[3:])

    def test_entropy_failure_destroys_partial_candidate(self):
        for stage in ('all','salt','nonce'):
            self.assertEqual(self.column(env={'CDSE_CONTEXT_CRYPTO_RNG_FAIL':stage}).returncode,1)

    def test_full_preflight_precedes_first_crypto_checkpoint(self):
        self.edit("update data set MAC='' where id=2")
        ready_r,ready_w=os.pipe();resume_r,resume_w=os.pipe()
        process=None
        try:
            env=dict(os.environ,CDSE_CONTEXT_CRYPTO_PAUSE='before-check',CDSE_CONTEXT_CRYPTO_READY_FD=str(ready_w),
                     CDSE_CONTEXT_CRYPTO_RESUME_FD=str(resume_r))
            process=subprocess.Popen(self.column_args(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env,
                                     pass_fds=(ready_w,resume_r))
            out,err=process.communicate(timeout=30)
            self.assertEqual(process.returncode,1,err);self.assertEqual(out,b'')
            self.assertFalse(select.select([ready_r],[],[],0)[0])
        finally:
            if process:
                if process.poll() is None:process.kill()
                process.communicate()
            for fd in (ready_r,ready_w,resume_r,resume_w):os.close(fd)

    def paused(self,stage,change,hit='1'):
        ready_r,ready_w=os.pipe();resume_r,resume_w=os.pipe()
        process=None
        try:
            env=dict(os.environ,CDSE_CONTEXT_CRYPTO_PAUSE=stage,CDSE_CONTEXT_CRYPTO_READY_FD=str(ready_w),
                     CDSE_CONTEXT_CRYPTO_RESUME_FD=str(resume_r),CDSE_CONTEXT_CRYPTO_PAUSE_HIT=hit)
            process=subprocess.Popen(self.column_args(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env,
                                     pass_fds=(ready_w,resume_r))
            self.assertTrue(select.select([ready_r],[],[],30)[0],'staging did not reach provider checkpoint')
            self.assertEqual(os.read(ready_r,1),b'1')
            if change=='witness':(self.witness/'witness.sqlite').write_bytes(self.before_witness)
            elif change=='registry':self.assertEqual(self.command('revoke',self.lookups[0],self.current()).returncode,0)
            else:self.assertEqual(self.map_store(self.source_slots,resource=self.source_slots[0][0]).returncode,0)
            os.write(resume_w,b'1')
            out,err=process.communicate(timeout=30)
            self.assertEqual(process.returncode,2,err);self.assertEqual(out,b'')
        finally:
            if process:
                if process.poll() is None:process.kill()
                process.communicate()
            for fd in (ready_r,ready_w,resume_r,resume_w):os.close(fd)

    def test_witness_change_discards_candidate(self):self.paused('after-crypto','witness')
    def test_registry_change_discards_candidate(self):self.paused('before-crypto','registry')
    def test_catalog_change_discards_candidate(self):self.paused('after-crypto','catalog')
    def test_partial_candidate_is_destroyed_on_later_witness_change(self):self.paused('after-crypto','witness','3')


for _name in vars(ColumnTests):
    if _name.startswith('test_'):setattr(ProviderColumnTests,_name,None)

if __name__=='__main__':unittest.main()
