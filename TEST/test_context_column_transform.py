#!/usr/bin/env python3
"""Retained, independently encoded transformation receipts and deep rechecks."""
from contextlib import closing
import hashlib
import hmac
import os
import select
import sqlite3
import subprocess
import unittest

import test_context_column_image as images
from test_context_frame import PASSWORD
from test_context_crypto import available


class TransformTests(images.ImageTests):
    def setUp(self):
        super().setUp()
        self.destination='accepted-copy'
        self.registration=hashlib.sha256(b'fixture-independent-registration-approval-v1').hexdigest()
        self.receipt=self.root/'transform.receipt'
        self.receipt.write_bytes(self.signed())

    def approval(self,source_digest=None,image_digest=None,registration=None,destination=None,profile=None):
        return (source_digest or hashlib.sha256(self.source.read_bytes()).hexdigest(),
                image_digest or hashlib.sha256(self.image.read_bytes()).hexdigest(),
                registration or self.registration,self.destination if destination is None else destination,profile or self.profile)

    def signed(self,**options):
        source,image,registration,destination,profile=self.approval(**options)
        registry=bytes.fromhex(self.current());catalog=bytes.fromhex(self.plan_catalog)
        name=destination.encode();text=bytes([len(name)])+name
        body=(b'CDSE-HKX-COLUMN-TRANSFORM-v1\0'+bytes.fromhex(self.plan_digest)+registry+catalog+bytes.fromhex(self.retained)
              +bytes([1 if profile=='aes-256-gcm' else 2])+bytes.fromhex(source+image+registration)+text)
        request=hashlib.sha256(body).digest()
        seal=b'CDSE-HKX-COLUMN-TRANSFORM-SEAL-v1\0'+registry+catalog+text+request
        return body+hmac.digest(b'k'*32,seal,'sha256')

    def transform_args(self,verify=False,*,key='fixture-source-key',password=PASSWORD,receipt_digest=None,**options):
        source,image,registration,destination,profile=self.approval(**options)
        args=self.target_args('target-bind');args[0]=images.columns.FIXTURE
        args[2]='target-transform-verify' if verify else 'target-transform-prepare'
        args.extend([str(self.source),source,key,profile,str(self.image),image,registration,destination,password.hex()])
        if verify:args.extend([str(self.receipt),receipt_digest or hashlib.sha256(self.receipt.read_bytes()).hexdigest()])
        return args

    def prepare(self,env=None,**options):return self.invoke(self.transform_args(**options),env)
    def verify(self,env=None,**options):return self.invoke(self.transform_args(True,**options),env)

    def test_receipt_hash_signature_and_framing(self):
        original=self.receipt.read_bytes()
        self.assertEqual(self.verify(receipt_digest='00'*32).returncode,1)
        for body in (original[:-1],original+b'x',bytes([original[0]^1])+original[1:],original[:-1]+bytes([original[-1]^1]),b'x'*32):
            self.receipt.write_bytes(body);self.assertEqual(self.verify().returncode,1)

    def test_approved_request_fields_cannot_be_substituted(self):
        for options in (dict(destination='other-copy'),dict(registration='ab'*32),dict(source_digest='ab'*32),
                        dict(image_digest='ab'*32),dict(profile='aes-256-cbc')):
            with self.subTest(options=options):self.assertEqual(self.verify(**options).returncode,1)

    def test_missing_or_invalid_approval(self):
        for options in (dict(destination=''),dict(destination='x'*129),dict(destination='bad.map'),
                        dict(registration='00'*32),dict(profile='aes-256-ctr')):
            with self.subTest(options=options):self.assertEqual(self.prepare(**options).returncode,1)

    def test_existing_destination_is_not_available(self):
        self.receipt.write_bytes(self.signed(destination='view'))
        self.assertEqual(self.verify(destination='view').returncode,1)

    def test_signature_does_not_skip_source_validation(self):
        self.assertEqual(self.verify(key='wrong').returncode,1)
        self.receipt.write_bytes(self.signed(source_digest='ab'*32))
        self.assertEqual(self.verify(source_digest='ab'*32).returncode,1)

    def test_signature_does_not_skip_candidate_hash(self):
        self.receipt.write_bytes(self.signed(image_digest='ab'*32))
        self.assertEqual(self.verify(image_digest='ab'*32).returncode,1)

    @unittest.skipIf(available(),'provider is compiled in')
    def test_valid_independent_receipt_reaches_provider_unavailable(self):
        self.assertEqual(self.prepare(env={'CDSE_CONTEXT_TRANSFORM_CONTRACT':'1'}).returncode,3)
        self.assertEqual(self.verify().returncode,3)


for _parent in TransformTests.__mro__[1:]:
    for _name in vars(_parent):
        if _name.startswith('test_') and _name not in vars(TransformTests):setattr(TransformTests,_name,None)
del _parent


class ProviderTransformTests(TransformTests):
    @classmethod
    def setUpClass(cls):
        if not available():raise unittest.SkipTest('optional Herradura provider not compiled in')

    def setUp(self):
        super().setUp()
        images.ProviderImageTests.exported(self)
        self.receipt.write_bytes(self.signed())

    def checked_receipt(self,env=None,**options):
        paths=[self.source,self.image,self.authority/'registry.sqlite',self.witness/'witness.sqlite',self.plan_path]
        before=[p.read_bytes() for p in paths]
        result=self.prepare(env=env or {'CDSE_CONTEXT_CRYPTO_RNG_FAIL':'all'},**options)
        self.assertEqual(result.returncode,0,result.stderr)
        digest,body=(bytes.fromhex(x) for x in result.stdout.decode().split())
        self.assertEqual(body,self.signed(**{k:v for k,v in options.items() if k not in ('password','key')}))
        self.assertEqual(hashlib.sha256(body).digest(),digest)
        self.assertLessEqual(len(body),512)
        self.receipt.write_bytes(body)
        verified=self.verify(env={'CDSE_CONTEXT_CRYPTO_RNG_FAIL':'all'},**options)
        self.assertEqual(verified.returncode,0,verified.stderr);self.assertEqual(verified.stdout,b'verified\n')
        self.assertEqual([p.read_bytes() for p in paths],before)
        self.assertEqual(self.map_read(name=self.destination).returncode,1)
        for secret in (b'fixture-source-key',PASSWORD,b'fixture-alpha'):self.assertNotIn(secret,body)
        return body

    def test_independent_receipt_encoding_and_read_only_roundtrip(self):self.checked_receipt()
    def test_cbc_source_cbc(self):self.checked_receipt()
    def test_shuffled_source_shuffle(self):self.checked_receipt()
    def test_empty_source_empty(self):self.checked_receipt()
    def test_null_bounds_and_output_contracts(self):self.checked_receipt(env={'CDSE_CONTEXT_TRANSFORM_CONTRACT':'1'})

    def test_registration_pin_and_destination_are_explicit_approvals(self):
        first=self.checked_receipt()
        second=self.checked_receipt(registration='ab'*32,destination='other-copy')
        self.assertNotEqual(first,second)
        self.assertEqual(self.verify().returncode,1)

    def test_binary_target_credentials_and_wrong_key(self):
        password=b'fixture\0binary-target'
        images.ProviderImageTests.exported(self,password=password)
        self.checked_receipt(password=password)
        self.assertEqual(self.verify(password=b'fixture').returncode,1)

    def test_valid_aead_changes_still_require_source_equality(self):
        original=self.image.read_bytes()
        for table,row,field,value in (('data',1,'value',b'changed-value'),('data',1,'userId',b'changed-user'),
                                      ('meta',2,'attributeData',b'changed-name')):
            with self.subTest(field=field):
                self.image.write_bytes(original)
                sealed=self.target('target-seal',value,table=table,row=row,field=field)
                self.assertEqual(sealed.returncode,0,sealed.stderr)
                salt,frame=(bytes.fromhex(x) for x in sealed.stdout.decode().split())
                ordinal=next(i+1 for i,slot in enumerate(self.ordered) if slot[1:]==[table,row,field])
                self.edit_image('update cdse_column_v2_cells set salt=?,frame=? where ordinal=?',(salt,frame,ordinal))
                self.assertEqual(self.imported().returncode,0,'candidate should be valid on its own')
                self.receipt.write_bytes(self.signed()) # Even a correctly signed receipt cannot skip comparison.
                self.assertEqual(self.prepare().returncode,1);self.assertEqual(self.verify().returncode,1)

    def test_new_valid_source_requires_new_plaintext_comparison(self):
        self.source.unlink()
        result=subprocess.run([images.columns.PAYLOAD,str(self.source),'empty'],capture_output=True,
                              env=dict(os.environ,CDSE_DEFAULT_ENC_ALG=self.profile),timeout=30)
        self.assertEqual(result.returncode,0,result.stderr)
        self.receipt.write_bytes(self.signed())
        self.assertEqual(self.prepare().returncode,1);self.assertEqual(self.verify().returncode,1)

    def test_changed_authority_expires_receipt(self):
        self.checked_receipt()
        self.assertEqual(self.command('revoke',self.lookups[0],self.current()).returncode,0)
        self.assertEqual(self.verify().returncode,2)

    def paused(self,verify,stage,change):
        ready_r,ready_w=os.pipe();resume_r,resume_w=os.pipe();process=None
        try:
            env=dict(os.environ,CDSE_CONTEXT_TRANSFORM_PAUSE=stage,CDSE_CONTEXT_TRANSFORM_READY_FD=str(ready_w),
                     CDSE_CONTEXT_TRANSFORM_RESUME_FD=str(resume_r))
            process=subprocess.Popen(self.transform_args(verify),stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                                     env=env,pass_fds=(ready_w,resume_r))
            self.assertTrue(select.select([ready_r],[],[],60)[0],'receipt operation missed checkpoint')
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

    def test_catalog_change_after_comparison_withholds_receipt(self):self.paused(False,'after-compare','catalog')
    def test_witness_change_after_signature_withholds_receipt(self):self.paused(False,'after-sign','witness')
    def test_revocation_after_verify_comparison_withholds_success(self):self.paused(True,'after-compare','registry')


for _name in vars(TransformTests):
    if _name.startswith('test_'):setattr(ProviderTransformTests,_name,None)

if __name__=='__main__':unittest.main()
