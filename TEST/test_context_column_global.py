#!/usr/bin/env python3
"""Explicit v5 transition, old-reader rejection and witness-gated mapped crypto."""
from contextlib import closing
import hashlib
import hmac
import json
import os
from pathlib import Path
import select
import sqlite3
import struct
import subprocess
import unittest

import test_context_admission as core
import test_context_column_admission as admission
import test_context_manager as manager
from test_context_frame import PASSWORD

GLOBAL=b'CDSE-HKX-COLUMN-GLOBAL-RELEASE-v1\0'
POLICY=b'CDSE-HKX-COLUMN-GLOBAL-POLICY-v1\0'


class GlobalCoreTests(core.AdmissionTests):
    def setUp(self):
        super().setUp();self.retain();self.committed()
        self.request=hashlib.sha256(b'owner-reviewed physical release').hexdigest()

    def global_args(self,**changes):
        values=dict(registry=self.registry,original=self.catalog,admitted=self.next_catalog,name=self.destination,
                    evidence=self.evidence,ticket=self.ticket_path,digest=self.digest,request=self.request)
        values.update(changes);return list(values.values())

    def preview(self):
        before=self.current(),self.map_current()
        result=self.command('admission-global-plan',*self.global_args());self.assertEqual(result.returncode,0,result.stderr)
        self.released=result.stdout.decode().strip();self.assertEqual((self.current(),self.map_current()),before)
        return self.released

    def step_global(self,commit=0,**changes):
        return self.command('admission-global-step',*self.global_args(**changes),self.released,commit)

    def test_independent_v5_wire_and_old_reader_rejection(self):
        old=os.environ.get('CDSE_CONTEXT_OLD_MANAGER_FIXTURE')
        def old_read(catalog):
            args=self.args('map-read',self.destination,self.registry,catalog);args[0]=old
            return subprocess.run(args,capture_output=True,timeout=30)
        if old:self.assertEqual(old_read(self.next_catalog).returncode,0)
        self.preview();self.assertEqual(self.step_global().stdout,b'1\n')
        with closing(sqlite3.connect(self.authority/'registry.sqlite')) as db:
            self.assertNotIn('witness_version',[row[1] for row in db.execute('pragma table_info(registry_meta)')])
        self.assertEqual(self.step_global(1).stdout,b'2\n');self.assertEqual(self.step_global(1).stdout,b'2\n')
        with closing(sqlite3.connect(self.authority/'registry.sqlite')) as db:
            maps=db.execute('select name,resource,role,active from context_maps').fetchall()
            slots=db.execute('select map_name,table_name,slot,field_name,lookup from context_map_slots').fetchall()
            jobs=db.execute('select name,job,body,state,finished from context_copies').fetchall()
            policy,=db.execute('select body from context_read_policy').fetchone()
            revision,tag=db.execute('select revision,tag from context_map_head').fetchone()
            self.assertEqual(db.execute('select witness_version from registry_meta').fetchone()[0],1)
        def text(value):return bytes([len(value)])+value.encode()
        expected=POLICY+bytes.fromhex(self.registry+self.catalog+self.next_catalog+self.digest+self.evidence+self.request)+text(self.destination)
        self.assertEqual(policy,expected)
        body=manager.catalog_bytes(self.anchor.deployment,self.anchor.organization,int.from_bytes(revision,'big'),maps,slots,shuffles=[],pairs=[])
        body=body.replace(b'CDSE-HKX-MAP-v3\0',b'CDSE-HKX-MAP-v4\0',1)+struct.pack('>I',len(jobs))
        for name,digest,ticket,state,finished in jobs:body+=text(name)+digest+struct.pack('>I',len(ticket))+ticket+bytes([state])+finished
        self.assertNotEqual(hmac.digest(b'k'*32,body,'sha256'),tag)  # Unmodified v4 readers reject.
        v5=body.replace(b'CDSE-HKX-MAP-v4\0',b'CDSE-HKX-MAP-v5\0',1)+struct.pack('>I',len(policy))+policy
        self.assertEqual(hmac.digest(b'k'*32,v5,'sha256'),tag)
        self.assertEqual((revision+hashlib.sha256(v5).digest()).hex(),self.released)
        self.assertEqual(self.map_current(),self.released);self.assertNotEqual(self.map_bind().returncode,0)
        self.assertEqual(json.loads(self.command('admission-map-read',self.destination,self.registry,self.released).stdout)['blocked'],0)
        if old:self.assertEqual(old_read(self.released).returncode,1)

    def test_wrong_pins_requests_and_policy_tampering_refuse(self):
        self.preview()
        self.assertNotEqual(self.step_global(1,request='55'*32).returncode,0)
        self.assertEqual(self.map_current(),self.next_catalog)
        self.assertEqual(self.step_global(1).returncode,0)
        self.assertNotEqual(self.step_global(registry=self.plan_registry).returncode,0)
        path=self.authority/'registry.sqlite';before=path.read_bytes()
        for sql in ("update context_read_policy set body=x'00'",'drop table context_read_policy',
                    'pragma ignore_check_constraints=ON; update registry_meta set witness_version=2'):
            path.write_bytes(before)
            with closing(sqlite3.connect(path)) as db,db:db.executescript(sql)
            self.assertNotEqual(self.step_global().returncode,0)
            self.assertNotEqual(self.map_bind(catalog=self.released).returncode,0)

    def crash_global(self,point):
        self.preview()
        result=self.command('admission-global-step',*self.global_args(),self.released,1,env={'CDSE_CONTEXT_MANAGER_CRASH':point})
        self.assertEqual(result.returncode,86)
        self.assertEqual(self.map_current(),self.released if point=='global-after-commit' else self.next_catalog)
        self.assertEqual(self.step_global(1).stdout,b'2\n')

    def test_core_crash_after_begin(self):self.crash_global('global-after-begin')
    def test_core_crash_after_write(self):self.crash_global('global-after-write')
    def test_core_crash_after_commit(self):self.crash_global('global-after-commit')


class GlobalTests(admission.AdmissionTests):
    def setUp(self):
        super().setUp();self.acknowledged=self.completed()
        self.global_path=self.root/'global-release.journal';self.admission_path=self.journal_path;self.admission_pin=self.pin
        self.retain_global()

    def retain_global(self):
        before=self.current(),self.map_current(),(self.witness/'witness.sqlite').read_bytes()
        args=self.run_args();args[2]='column-global-prepare';args.append(self.acknowledged)
        result=self.invoke(args);self.assertEqual(result.returncode,0,result.stderr)
        self.global_pin,data=result.stdout.decode().split();self.global_bytes=bytes.fromhex(data)
        self.assertEqual(hashlib.sha256(self.global_bytes).hexdigest(),self.global_pin)
        prefix=GLOBAL+struct.pack('>I',len(self.journal))+self.journal+bytes.fromhex(self.acknowledged)
        self.assertEqual(self.global_bytes[:-40],prefix);self.final_catalog=self.global_bytes[-40:].hex()
        self.assertEqual((self.current(),self.map_current(),(self.witness/'witness.sqlite').read_bytes()),before)
        fd=os.open(self.global_path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'wb') as output:output.write(self.global_bytes);output.flush();os.fsync(output.fileno())
        directory=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(directory)
        finally:os.close(directory)

    def global_args(self,pin=None):
        args=self.run_args();args[2]='column-global-run';args[8]=str(self.global_path);args[9]=pin or self.global_pin;return args

    def released(self):
        result=self.invoke(self.global_args());self.assertEqual(result.returncode,0,result.stderr)
        catalog,token=result.stdout.decode().split();self.assertEqual(catalog,self.final_catalog)
        self.assertEqual(self.current(),self.registry);self.assertEqual(self.map_current(),catalog)
        self.assertEqual(int(token[:16],16),int(self.acknowledged[:16],16)+1)
        self.assertNotEqual(self.map_bind(name=self.destination).returncode,0)  # Old API cannot bypass v5.
        self.assertEqual(json.loads(self.command('admission-map-read',self.destination,self.registry,catalog).stdout)['blocked'],0)
        self.final_token=token;return token

    def codec_args(self,token=None,password=PASSWORD):
        index=next(i+1 for i,slot in enumerate(self.ordered) if slot[1:]==['data',1,'value'])
        with closing(sqlite3.connect(f'file:{self.published/"candidate.sqlite"}?mode=ro',uri=True)) as db:
            salt,frame=db.execute('select salt,frame from cdse_column_v2_cells where ordinal=?',(index,)).fetchone()
        return [self.admission_fixture,str(self.authority),'witness-open',self.anchor.deployment,self.anchor.organization,
                self.registry,self.final_catalog,str(self.witness),token or getattr(self,'final_token',self.acknowledged),
                self.destination,'data','1','value',password.hex(),salt.hex(),frame.hex()]

    def test_global_release_retry_and_witnessed_plaintext(self):
        token=self.released();self.assertEqual(self.released(),token)
        result=self.invoke(self.codec_args());self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(bytes.fromhex(result.stdout.decode().strip()),b'fixture-alpha')
        self.assertEqual(self.invoke(self.codec_args(token=self.acknowledged)).returncode,2)
        self.assertEqual(self.invoke(self.codec_args(password=b'wrong')).returncode,1)
        self.assertNotEqual(self.run_admission().returncode,0)  # Old C1 approvals expire.

    def crash_release(self,stage):
        result=self.invoke(self.global_args(),{'CDSE_CONTEXT_ADMISSION_CRASH':stage});self.assertEqual(result.returncode,86)
        self.assertEqual(self.map_current(),self.next_catalog if stage=='global-before-catalog' else self.final_catalog)
        self.released();self.released()

    def test_interrupted_before_catalog(self):self.crash_release('global-before-catalog')
    def test_interrupted_catalog_commit(self):
        self.assertEqual(self.invoke(self.global_args(),{'CDSE_CONTEXT_ADMISSION_CRASH':'global-after-catalog'}).returncode,86)
        self.assertEqual(self.invoke(self.codec_args(token=self.acknowledged)).returncode,2)
        self.assertNotEqual(self.map_bind(name=self.destination).returncode,0)
        self.released()
    def test_lost_witness_ack(self):self.crash_release('global-after-witness')

    def test_tampered_envelope_and_rehashed_proof_refuse(self):
        data=self.global_bytes[:-1]+bytes([self.global_bytes[-1]^1]);self.global_path.write_bytes(data)
        self.assertNotEqual(self.invoke(self.global_args(hashlib.sha256(data).hexdigest())).returncode,0)
        self.assertEqual(self.map_current(),self.next_catalog)

    def test_same_bytes_file_replacement_withholds_release(self):
        path=self.published/'RolesDB';other=self.root/'replacement'
        other.write_bytes(path.read_bytes());other.chmod(0o600);os.replace(other,path)
        self.assertEqual(self.invoke(self.global_args()).returncode,1);self.assertEqual(self.map_current(),self.next_catalog)

    def test_stale_witness_prevents_catalog_commit(self):
        (self.witness/'witness.sqlite').write_bytes(self.before_witness)
        self.assertEqual(self.invoke(self.global_args()).returncode,2);self.assertEqual(self.map_current(),self.next_catalog)

    def paused(self,args,env,change,expected):
        ready_r,ready_w=os.pipe();resume_r,resume_w=os.pipe();process=None
        try:
            values=dict(os.environ,**env)
            for prefix in ('CDSE_CONTEXT_ADMISSION','CDSE_CONTEXT_CRYPTO'):
                values[prefix+'_READY_FD']=str(ready_w);values[prefix+'_RESUME_FD']=str(resume_r)
            process=subprocess.Popen(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=values,pass_fds=(ready_w,resume_r))
            self.assertTrue(select.select([ready_r],[],[],90)[0]);self.assertEqual(os.read(ready_r,1),b'1')
            change();os.write(resume_w,b'1');out,err=process.communicate(timeout=90)
            self.assertEqual(process.returncode,expected,err);self.assertEqual(out,b'')
        finally:
            if process:
                if process.poll() is None:process.kill()
                process.communicate()
            for fd in (ready_r,ready_w,resume_r,resume_w):os.close(fd)

    def test_physical_change_between_catalog_and_witness_withholds_ack(self):
        witness=(self.witness/'witness.sqlite').read_bytes()
        def change():
            path=self.source_root/'RolesDB';data=bytearray(path.read_bytes());data[-1]^=1;path.write_bytes(data)
        self.paused(self.global_args(),{'CDSE_CONTEXT_ADMISSION_PAUSE':'global-after-catalog'},change,1)
        self.assertEqual(self.map_current(),self.final_catalog);self.assertEqual((self.witness/'witness.sqlite').read_bytes(),witness)
        self.assertEqual(self.invoke(self.codec_args(token=self.acknowledged)).returncode,2)

    def test_late_witness_rollback_after_crypto_withholds_plaintext(self):
        before=(self.witness/'witness.sqlite').read_bytes();self.released()
        self.paused(self.codec_args(),{'CDSE_CONTEXT_CRYPTO_PAUSE':'after-crypto'},
                    lambda:(self.witness/'witness.sqlite').write_bytes(before),2)

    def test_original_approvals_required_after_release(self):
        self.released()
        self.assertNotEqual(self.invoke(self.global_args('00'*32)).returncode,0)
        self.assertEqual(self.map_current(),self.final_catalog)


for _cls in (GlobalCoreTests,GlobalTests):
    for _parent in _cls.__mro__[1:]:
        for _name in vars(_parent):
            if _name.startswith('test_') and _name not in vars(_cls):setattr(_cls,_name,None)
del _cls,_parent

if __name__=='__main__':unittest.main()
