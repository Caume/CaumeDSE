#!/usr/bin/env python3
"""Frozen offline V2 SQLite container: independent layout and auth refusals."""
from contextlib import closing
import hashlib
import os
from pathlib import Path
import select
import sqlite3
import subprocess
import unittest

import test_context_column as columns
from test_context_crypto import available
from test_context_frame import PASSWORD

HEADER_SQL='CREATE TABLE cdse_column_v2(version INTEGER NOT NULL,profile TEXT NOT NULL,integrity TEXT NOT NULL,cellCount INTEGER NOT NULL)'
CELLS_SQL='CREATE TABLE cdse_column_v2_cells(ordinal INTEGER PRIMARY KEY,salt BLOB NOT NULL,frame BLOB NOT NULL)'
PROFILE='herradura-hske-nl-v2-profile1'
INTEGRITY='aead-context+inventory+sha256-pin'


class ImageTests(columns.ColumnTests):
    def setUp(self):
        super().setUp()
        self.image=self.root/'candidate.sqlite'
        self.fake_image()

    def fake_image(self):
        self.image.unlink(missing_ok=True)
        with closing(sqlite3.connect(self.image)) as db,db:
            db.execute('pragma page_size=4096');db.execute('pragma application_id=1128551218');db.execute('pragma user_version=1')
            db.execute(HEADER_SQL);db.execute(CELLS_SQL)
            db.execute('insert into cdse_column_v2 values(1,?,?,?)',(PROFILE,INTEGRITY,len(self.ordered)))
            frame=columns.wire.metadata(1,1,1,0,bytes(32))+bytes(32)
            db.executemany('insert into cdse_column_v2_cells values(?,?,?)',
                           [(i+1,bytes(16),frame) for i in range(len(self.ordered))])

    def import_args(self, *, digest=None,password=PASSWORD):
        args=self.target_args('target-bind');args[0]=columns.FIXTURE;args[2]='target-column-import'
        return [*args,str(self.image),digest or hashlib.sha256(self.image.read_bytes()).hexdigest(),password.hex()]

    def invoke(self,args,env=None):
        result=subprocess.run(args,capture_output=True,timeout=90,env=dict(os.environ,**(env or {})))
        if result.returncode:self.assertEqual(result.stdout,b'')
        self.assertNotIn(PASSWORD.hex().encode(),result.stderr)
        self.assertNotIn(b'fixture-source-key',result.stderr)
        return result

    def imported(self,env=None,**options):return self.invoke(self.import_args(**options),env)

    def edit_image(self,sql,params=(),vacuum=True):
        with closing(sqlite3.connect(self.image)) as db,db:
            if params:db.execute(sql,params)
            else:db.executescript(sql)
        if vacuum:
            with closing(sqlite3.connect(self.image)) as db:db.execute('vacuum')

    def refused_before_crypto(self,**options):
        ready_r,ready_w=os.pipe();resume_r,resume_w=os.pipe();process=None
        try:
            env=dict(os.environ,CDSE_CONTEXT_CRYPTO_PAUSE='before-check',CDSE_CONTEXT_CRYPTO_READY_FD=str(ready_w),
                     CDSE_CONTEXT_CRYPTO_RESUME_FD=str(resume_r))
            process=subprocess.Popen(self.import_args(**options),stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                                     env=env,pass_fds=(ready_w,resume_r))
            out,err=process.communicate(timeout=30)
            self.assertEqual(process.returncode,1,err);self.assertEqual(out,b'')
            self.assertFalse(select.select([ready_r],[],[],0)[0])
        finally:
            if process:
                if process.poll() is None:process.kill()
                process.communicate()
            for fd in (ready_r,ready_w,resume_r,resume_w):os.close(fd)

    def test_external_image_pin_required(self):self.refused_before_crypto(digest='00'*32)

    def test_bad_headers_and_trailing_bytes(self):
        original=self.image.read_bytes()
        for offset,value in ((16,0),(18,2),(19,2),(20,1),(60,2),(68,0),(32,1),(36,1)):
            data=bytearray(original);data[offset]=value;self.image.write_bytes(data)
            self.refused_before_crypto()
        self.image.write_bytes(original+bytes(4096));self.refused_before_crypto()
        self.image.write_bytes(original[:-1]);self.refused_before_crypto()

    def test_strict_schema_before_provider(self):
        original=self.image.read_bytes()
        for sql in ('create table hidden(secret TEXT)','create view hidden as select * from cdse_column_v2_cells',
                    'create trigger hidden after update on cdse_column_v2 begin select 1; end',
                    'alter table cdse_column_v2_cells add column lookup TEXT',
                    'create index hidden on cdse_column_v2_cells(salt)'):
            with self.subTest(sql=sql):
                self.image.write_bytes(original);self.edit_image(sql);self.refused_before_crypto()

    def test_header_declarations_and_cardinality(self):
        original=self.image.read_bytes()
        for sql in ("update cdse_column_v2 set version=2", "update cdse_column_v2 set version='one'",
                    "update cdse_column_v2 set profile='aes-256-gcm'", "update cdse_column_v2 set integrity='sha256'",
                    "update cdse_column_v2 set cellCount=cellCount-1", 'delete from cdse_column_v2',
                    'insert into cdse_column_v2 select * from cdse_column_v2',
                    'update cdse_column_v2 set rowid=2'):
            with self.subTest(sql=sql):
                self.image.write_bytes(original);self.edit_image(sql,vacuum=not sql.endswith('rowid=2'));self.refused_before_crypto()

    def test_complete_ordinal_inventory(self):
        original=self.image.read_bytes()
        for sql in ('delete from cdse_column_v2_cells where ordinal=1',
                    'update cdse_column_v2_cells set ordinal=0 where ordinal=1',
                    'update cdse_column_v2_cells set ordinal=1000 where ordinal=1',
                    'insert into cdse_column_v2_cells select 1000,salt,frame from cdse_column_v2_cells where ordinal=1'):
            self.image.write_bytes(original);self.edit_image(sql);self.refused_before_crypto()

    def test_exact_blob_types_and_bounds(self):
        original=self.image.read_bytes()
        for sql,params in (("update cdse_column_v2_cells set salt=? where ordinal=1",('x'*16,)),
                           ("update cdse_column_v2_cells set salt=? where ordinal=1",(bytes(15),)),
                           ("update cdse_column_v2_cells set frame=? where ordinal=1",('x'*80,)),
                           ("update cdse_column_v2_cells set frame=? where ordinal=1",(bytes(79),)),
                           ("update cdse_column_v2_cells set frame=? where ordinal=1",(bytes(262225),))):
            self.image.write_bytes(original);self.edit_image(sql,params);self.refused_before_crypto()

    def test_sparse_source_map_refuses_missing_slot(self):self.refused_before_crypto()
    def test_unknown_source_map_field_refuses_extra_slot(self):self.refused_before_crypto()

    def test_legacy_image_has_no_container_fallback(self):
        self.image.write_bytes(self.source.read_bytes());self.refused_before_crypto()

    def test_legacy_staging_refuses_new_container(self):
        self.assertEqual(self.column(source=self.image).returncode,1)

    @unittest.skipIf(available(),'provider is compiled in')
    def test_independent_layout_reaches_missing_provider(self):self.assertEqual(self.imported().returncode,3)


for _parent in ImageTests.__mro__[1:]:
    for _name in vars(_parent):
        if _name.startswith('test_') and _name not in vars(ImageTests):setattr(ImageTests,_name,None)
del _parent


class ProviderImageTests(ImageTests):
    @classmethod
    def setUpClass(cls):
        if not available():raise unittest.SkipTest('optional Herradura provider not compiled in')

    def exported(self,env=None,password=PASSWORD):
        args=self.column_args(password=password);args[2]='target-column-export'
        paths=[self.source,self.authority/'registry.sqlite',self.witness/'witness.sqlite',self.plan_path]
        before=[p.read_bytes() for p in paths]
        result=self.invoke(args,env);self.assertEqual(result.returncode,0,result.stderr)
        digest,image=(bytes.fromhex(x) for x in result.stdout.decode().split())
        self.assertEqual(hashlib.sha256(image).digest(),digest)
        self.image.write_bytes(image)
        self.assertEqual([p.read_bytes() for p in paths],before)
        self.assertEqual(self.map_read(name='unpublished-copy').returncode,1)
        return image,digest

    def verify_image(self):
        image,digest=self.exported(env={'CDSE_CONTEXT_COLUMN_SERIALIZE_NO_RNG':'1'})
        result=self.imported(env={'CDSE_CONTEXT_CRYPTO_RNG_FAIL':'all'})
        self.assertEqual(result.returncode,0,result.stderr)
        cells=[line.split() for line in result.stdout.decode().splitlines()]
        self.assertEqual(len(cells),len(self.ordered))
        with closing(sqlite3.connect(self.image)) as db:
            self.assertEqual(db.execute('pragma application_id').fetchone(),(0x43445332,))
            self.assertEqual(db.execute('pragma user_version').fetchone(),(1,))
            self.assertEqual(db.execute('select * from cdse_column_v2').fetchall(),[(1,PROFILE,INTEGRITY,len(cells))])
            self.assertEqual(db.execute('select sql from sqlite_master order by name').fetchall(),[(HEADER_SQL,),(CELLS_SQL,)])
            records=db.execute('select * from cdse_column_v2_cells order by ordinal').fetchall()
        contexts={e['lookup']:columns.registry.decode_context(e['context']) for e in self.copy_snapshot()['entries']}
        values={}
        for index,(line,record,slot,lookup) in enumerate(zip(cells,records,self.ordered,self.lookups)):
            self.assertEqual(line[:3],[slot[1],str(slot[2]),slot[3]])
            self.assertEqual(record,(index+1,bytes.fromhex(line[3]),bytes.fromhex(line[4])))
            opened=self.invoke([columns.FRAME_FIXTURE,'open',columns.wire.context_bytes(contexts[lookup]).hex(),line[3],
                                PASSWORD.hex(),'02',line[4]])
            self.assertEqual(opened.returncode,0,opened.stderr)
            values[tuple(slot[1:])]=bytes.fromhex(opened.stdout.decode().strip())
        for row in (1,2):
            order=values['data',row,'rowOrder']
            expected=b'fixture-alpha' if order==b'1' else (b'' if self._testMethodName.endswith('_empty') else b'fixture-beta')
            self.assertEqual(values['data',row,'value'],expected)
        for (table,row,field),value in values.items():
            if table=='meta' and field=='attributeData' and values[table,row,'attribute'] in (b'protect',b'shuffle'):
                self.assertEqual(value,PROFILE.encode())
        for secret in (b'fixture-alpha',b'fixture-source-key',PASSWORD):self.assertNotIn(secret,image)
        return image,digest

    def test_serialized_layout_and_independent_readback(self):self.verify_image()
    def test_cbc_conversion_cbc(self):self.verify_image()
    def test_shuffled_rows_shuffle(self):self.verify_image()
    def test_empty_values_empty(self):self.verify_image()

    def test_binary_password_and_wrong_key(self):
        password=b'fixture\0binary-password'
        self.exported(password=password)
        self.assertEqual(self.imported(password=password).returncode,0)
        self.assertEqual(self.imported(password=b'fixture').returncode,1)

    def test_null_bounds_and_output_ownership_contracts(self):self.exported(env={'CDSE_CONTEXT_COLUMN_IMAGE_CONTRACT':'1'})

    def test_cell_salt_frame_and_context_substitution(self):
        original,_=self.exported()
        with closing(sqlite3.connect(self.image)) as db:
            a,b=db.execute('select salt,frame from cdse_column_v2_cells order by ordinal limit 2').fetchall()
        for salt,frame in ((b[0],b[1]),(bytes(16),a[1]),(a[0],a[1][:-1]+bytes([a[1][-1]^1])),(a[0],b'legacy-aes'*9)):
            self.image.write_bytes(original);self.edit_image('update cdse_column_v2_cells set salt=?,frame=? where ordinal=1',(salt,frame))
            self.assertEqual(self.imported().returncode,1)

    def test_physical_bytes_need_independent_pin(self):
        original,digest=self.exported();modified=bytearray(original);modified[24]^=1
        self.image.write_bytes(modified)
        self.assertEqual(self.imported(digest=digest.hex()).returncode,1)

    def test_authenticated_but_invalid_plaintext_semantics(self):
        original,_=self.exported()
        for table,row,field,value in (('data',1,'rowOrder',b'999'),('data',1,'value',b'bad\0text'),
                                      ('meta',1,'attributeData',b'aes-256-gcm'),('meta',2,'attribute',b'protect')):
            self.image.write_bytes(original)
            sealed=self.target('target-seal',value,table=table,row=row,field=field)
            self.assertEqual(sealed.returncode,0,sealed.stderr)
            salt,frame=(bytes.fromhex(x) for x in sealed.stdout.decode().split())
            ordinal=next(i+1 for i,slot in enumerate(self.ordered) if slot[1:]==[table,row,field])
            self.edit_image('update cdse_column_v2_cells set salt=?,frame=? where ordinal=?',(salt,frame,ordinal))
            self.assertEqual(self.imported().returncode,1)

    def paused(self,action,change,hit):
        if action=='import':self.exported();args=self.import_args()
        else:args=self.column_args();args[2]='target-column-export'
        ready_r,ready_w=os.pipe();resume_r,resume_w=os.pipe();process=None
        try:
            env=dict(os.environ,CDSE_CONTEXT_CRYPTO_PAUSE='after-crypto',CDSE_CONTEXT_CRYPTO_PAUSE_HIT=str(hit),
                     CDSE_CONTEXT_CRYPTO_READY_FD=str(ready_w),CDSE_CONTEXT_CRYPTO_RESUME_FD=str(resume_r))
            process=subprocess.Popen(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env,pass_fds=(ready_w,resume_r))
            self.assertTrue(select.select([ready_r],[],[],60)[0],'container codec did not reach checkpoint')
            self.assertEqual(os.read(ready_r,1),b'1')
            if change=='witness':(self.witness/'witness.sqlite').write_bytes(self.before_witness)
            elif change=='registry':self.assertEqual(self.command('revoke',self.lookups[0],self.current()).returncode,0)
            else:self.assertEqual(self.map_store(self.source_slots,resource=self.source_slots[0][0]).returncode,0)
            os.write(resume_w,b'1');out,err=process.communicate(timeout=30)
            self.assertEqual(process.returncode,2,err);self.assertEqual(out,b'')
        finally:
            if process:
                if process.poll() is None:process.kill()
                process.communicate()
            for fd in (ready_r,ready_w,resume_r,resume_w):os.close(fd)

    def test_reader_partial_plaintext_withheld_after_witness_change(self):self.paused('import','witness',2)
    def test_reader_registry_change_withholds_output(self):self.paused('import','registry',1)
    def test_serializer_readback_catalog_change_withholds_image(self):self.paused('export','catalog',2*len(self.ordered)+2)


for _name in vars(ImageTests):
    if _name.startswith('test_'):setattr(ProviderImageTests,_name,None)

if __name__=='__main__':unittest.main()
