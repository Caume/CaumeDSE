#!/usr/bin/env python3
"""Read-only, witness-guarded unpublished copy target capabilities."""
import hashlib
import os
from pathlib import Path
import select
import subprocess
import unittest

import test_context_manager as manager_tests
from test_context_crypto import FIXTURE, available
from test_context_frame import FIXTURE as FRAME_FIXTURE, PASSWORD
import herradura_context_contract as wire
import herradura_registry_contract as registry_contract


class TargetTests(manager_tests.CopyPlanTests):
    def copy_setup(self):
        super().copy_setup()
        if self._testMethodName.endswith('_zero_slot'):
            self.source_slots=[(lookup,table,0 if table=='data' and row==10 else row,field)
                               for lookup,table,row,field in self.source_slots]
            self.assertEqual(self.map_store(self.source_slots).returncode,0)
            import json
            self.ordered=json.loads(self.map_read().stdout)['slots']

    def setUp(self):
        manager_tests.ManagerTests.setUp(self)
        self.plan_setup()
        self.witness, self.retained = self.init_plan_witness()
        self.previous_retained = self.retained
        self.before_witness = (self.witness/'witness.sqlite').read_bytes()
        if self._testMethodName.endswith('_fork'):
            self.alternate_plan = self.root/'alternate.plan'
            self.alternate_digest, _ = self.prepare_plan(path=self.alternate_plan)
        if not self._testMethodName.endswith('_ready'):
            self.plan_result(witness=(self.witness, self.retained))
            if not self._testMethodName.endswith('_unadvanced'):
                result = self.command('witness-advance', self.current(), self.map_current(), self.retained,
                                      directory=self.witness)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.retained = result.stdout.decode().strip()

    def target_args(self, action='target-bind', data=b'', *, plan=None, digest=None, registry=None, catalog=None,
                    token=None, lookups=None, source='view', table='data', row=10, field='value', password=PASSWORD,
                    salt=bytes(16)):
        names = self.lookups if lookups is None else lookups
        args = [FIXTURE, str(self.authority), action, self.anchor.deployment, self.anchor.organization,
                registry or self.plan_registry, catalog or self.plan_catalog, str(self.witness),
                token or self.retained, str(plan or self.plan_path), digest or self.plan_digest, source,
                str(len(names)), *names]
        if action in ('target-bind', 'target-contract'):
            return args
        args.extend([table, str(row), field, password.hex()])
        if action == 'target-open': args.append(salt.hex())
        return [*args, data.hex()]

    def target(self, action='target-bind', data=b'', *, env=None, **options):
        result = subprocess.run(self.target_args(action, data, **options), capture_output=True, timeout=30,
                                env=dict(os.environ, **(env or {})))
        if result.returncode: self.assertEqual(result.stdout, b'')
        self.assertNotIn(PASSWORD.hex().encode(), result.stderr)
        self.assertNotIn(str(self.authority).encode(), result.stderr)
        return result

    def seal(self, data=b'fixture\x00plaintext', **options):
        result = self.target('target-seal', data, **options)
        self.assertEqual(result.returncode, 0, result.stderr)
        salt, frame = result.stdout.decode().split()
        return bytes.fromhex(salt), bytes.fromhex(frame)

    def lookup_for(self, table='data', row=10, field='value'):
        return next(name for slot, name in zip(self.ordered, self.lookups) if slot[1:]==[table,row,field])

    def context_for(self, table='data', row=10, field='value'):
        name = self.lookup_for(table,row,field)
        entry = next(e for e in self.copy_snapshot()['entries'] if e['lookup']==name)
        return registry_contract.decode_context(entry['context'])

    def source_crypto(self, action, data=b'', *, salt=bytes(16)):
        args = [FIXTURE,str(self.authority),action,self.anchor.deployment,self.anchor.organization,
                self.current(),self.map_current(),'view','data','10','value',PASSWORD.hex()]
        if action=='open': args.append(salt.hex())
        return subprocess.run([*args,data.hex()],capture_output=True,timeout=30)

    def test_committed_target_bind_is_read_only_and_unpublished(self):
        paths = [self.authority/'registry.sqlite', self.witness/'witness.sqlite', self.plan_path]
        before = [p.read_bytes() for p in paths]
        self.assertEqual(self.target().returncode, 0)
        self.assertEqual(self.target('target-contract').returncode, 0)
        self.assertEqual([p.read_bytes() for p in paths], before)
        self.assertEqual(self.map_current(), self.plan_catalog)
        self.assertEqual(self.map_read(name='unpublished-copy').returncode, 1)

    def test_target_rejects_nonpositive_column_rows_zero_slot(self):
        before=self.current(),self.map_current()
        self.assertEqual(self.target().returncode,1)
        self.assertEqual((self.current(),self.map_current()),before)

    def test_target_refuses_ready(self):
        before = self.current(), self.map_current()
        self.assertEqual(self.target().returncode, 2)
        self.assertEqual((self.current(), self.map_current()), before)

    def test_target_requires_explicit_witness_ack_unadvanced(self):
        self.assertEqual(self.target().returncode, 2)
        self.assertEqual((self.witness/'witness.sqlite').read_bytes(), self.before_witness)

    def test_previous_or_malformed_witness_token_is_not_adopted(self):
        self.assertEqual(self.target(token=self.previous_retained).returncode, 2)
        self.assertEqual(self.target(token='00'*40).returncode, 1)

    def test_digest_signature_and_original_pins_are_required(self):
        self.assertEqual(self.target(digest='00'*32).returncode, 1)
        self.assertEqual(self.target(registry=self.current()).returncode, 1)
        self.assertEqual(self.target(catalog='00'*40).returncode, 1)
        data = self.plan_path.read_bytes()
        mutated = data[:-1]+bytes([data[-1]^1])
        self.plan_path.write_bytes(mutated)
        self.assertEqual(self.target(digest=hashlib.sha256(mutated).hexdigest()).returncode, 1)
        self.plan_path.write_bytes(data)

    def test_separately_approved_source_and_lookup_vector_match_exactly(self):
        for options in (dict(source='another'),dict(lookups=[]),dict(lookups=self.lookups[::-1]),
                        dict(lookups=['replacement',*self.lookups[1:]])):
            self.assertEqual(self.target(**options).returncode, 1)

    def test_uncommitted_alternative_signed_plan_is_not_a_target_fork(self):
        self.assertEqual(self.target(plan=self.alternate_plan, digest=self.alternate_digest).returncode, 2)
        self.assertEqual(self.target().returncode, 0)

    def test_later_registry_or_catalog_publication_expires_the_capability(self):
        self.assertEqual(self.target().returncode, 0)
        self.assertEqual(self.map_store(self.source_slots).returncode, 0)
        self.assertEqual(self.target().returncode, 2)

    def test_witness_rollback_and_private_custody_refuse(self):
        current = (self.witness/'witness.sqlite').read_bytes()
        (self.witness/'witness.sqlite').write_bytes(self.before_witness)
        self.assertEqual(self.target().returncode, 2)
        (self.witness/'witness.sqlite').write_bytes(current)
        self.witness.chmod(0o755)
        self.assertEqual(self.target().returncode, 1)
        self.witness.chmod(0o700)

    def test_floor_raise_expires_target_and_legacy_plan_refuses_floor2(self):
        witness_bytes=(self.witness/'witness.sqlite').read_bytes()
        snapshot=self.copy_snapshot()
        _,_,anchor=registry_contract.issue(snapshot,b'k'*32)
        snapshot.update(generation=snapshot['generation']+1,minimumFormat=2)
        self.assertEqual(self.publish(snapshot,anchor).returncode,0)
        self.assertEqual(self.target().returncode,2)
        self.assertEqual(self.command('copy-plan-prepare',*self.copy_args(names=['floor2/'+str(i) for i in range(len(self.lookups))])).returncode,1)
        self.assertEqual((self.witness/'witness.sqlite').read_bytes(),witness_bytes)

    def test_provider_unavailable_is_explicit_after_binding(self):
        self.assertEqual(self.target('target-seal', b'fixture').returncode, 0 if available() else 3)


for _parent in (manager_tests.ManagerTests, manager_tests.CopyProvisionTests, manager_tests.CopyPlanTests):
    for _name in vars(_parent):
        if _name.startswith('test_'):
            setattr(TargetTests,_name,None)
del _parent


class ProviderTargetTests(TargetTests):
    @classmethod
    def setUpClass(cls):
        if not available(): raise unittest.SkipTest('optional NLA1 provider unavailable')

    def test_unpublished_target_crypto_preserves_source_and_authority(self):
        plain = b'fixture\x00copy'
        source = self.source_crypto('seal',plain)
        self.assertEqual(source.returncode, 0, source.stderr)
        source_salt,source_frame = (bytes.fromhex(x) for x in source.stdout.decode().split())
        before = [(self.authority/'registry.sqlite').read_bytes(),(self.witness/'witness.sqlite').read_bytes()]
        salt,frame = self.seal(plain)
        self.assertNotEqual(source_frame,frame)
        opened=self.target('target-open',frame,salt=salt)
        self.assertEqual(opened.returncode,0,opened.stderr)
        self.assertEqual(bytes.fromhex(opened.stdout.decode().strip()),plain)
        self.assertEqual(self.target('target-open',source_frame,salt=source_salt).returncode,1)
        self.assertEqual(self.source_crypto('open',frame,salt=salt).returncode,1)
        self.assertEqual(self.source_crypto('open',source_frame,salt=source_salt).stdout.strip(),plain.hex().encode())
        result=subprocess.run([FRAME_FIXTURE,'open',wire.context_bytes(self.context_for()).hex(),salt.hex(),
                               PASSWORD.hex(),'02',frame.hex()],capture_output=True,timeout=30)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(bytes.fromhex(result.stdout.decode().strip()),plain)
        self.assertEqual([(self.authority/'registry.sqlite').read_bytes(),(self.witness/'witness.sqlite').read_bytes()],before)
        self.assertEqual(self.map_read(name='unpublished-copy').returncode,1)

    def test_each_allocated_slot_has_its_own_context(self):
        frames=[]
        for slot in self.ordered:
            _,table,row,field=slot
            salt,frame=self.seal(b'fixture',table=table,row=row,field=field)
            self.assertEqual(self.target('target-open',frame,salt=salt,table=table,row=row,field=field).returncode,0)
            frames.append((salt,frame))
        salt,frame=frames[0]
        _,table,row,field=self.ordered[-1]
        self.assertEqual(self.target('target-open',frame,salt=salt,table=table,row=row,field=field).returncode,1)
        self.assertEqual(self.target('target-seal',b'fixture',row=999).returncode,1)

    def test_invalid_frames_credentials_and_rng_never_release_output(self):
        salt,frame=self.seal()
        for options,value in ((dict(password=b'wrong'),frame),(dict(salt=bytes(16)),frame),({},frame[:-1]),
                              ({},b'CDSEHKX1'+bytes(96))):
            self.assertEqual(self.target('target-open',value,salt=options.pop('salt',salt),**options).returncode,1)
        for stage in ('salt','nonce'):
            self.assertEqual(self.target('target-seal',b'fixture',env={'CDSE_CONTEXT_CRYPTO_RNG_FAIL':stage}).returncode,1)

    def paused_change(self,action,stage,change):
        salt,frame=self.seal()
        ready_read,ready_write=os.pipe(); resume_read,resume_write=os.pipe()
        proc=None
        try:
            args=self.target_args(action,frame if action=='target-open' else b'fixture',salt=salt)
            env=dict(os.environ,CDSE_CONTEXT_CRYPTO_PAUSE=stage,CDSE_CONTEXT_CRYPTO_READY_FD=str(ready_write),
                     CDSE_CONTEXT_CRYPTO_RESUME_FD=str(resume_read))
            if stage=='before-check': env['CDSE_CONTEXT_CRYPTO_RNG_FAIL']='all'
            proc=subprocess.Popen(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,pass_fds=(ready_write,resume_read),env=env)
            os.close(ready_write);ready_write=-1;os.close(resume_read);resume_read=-1
            self.assertTrue(select.select([ready_read],[],[],30)[0])
            self.assertEqual(os.read(ready_read,1),b'1')
            if change=='registry':
                self.assertEqual(self.command('revoke',self.lookup_for(),self.current()).returncode,0)
            elif change=='catalog':
                self.assertEqual(self.map_remove().returncode,0)
            else:
                (self.witness/'witness.sqlite').write_bytes(self.before_witness)
            os.write(resume_write,b'1')
            stdout,stderr=proc.communicate(timeout=30)
            self.assertEqual(proc.returncode,2,stderr)
            self.assertEqual(stdout,b'')
        finally:
            for fd in (ready_read,ready_write,resume_read,resume_write):
                if fd>=0:os.close(fd)
            if proc:
                if proc.poll() is None:proc.kill()
                proc.communicate()

    def test_witness_replay_before_check_is_refused_before_rng(self):
        self.paused_change('target-seal','before-check','witness')

    def test_witness_replay_after_open_discards_plaintext(self):
        self.paused_change('target-open','after-crypto','witness')

    def test_target_revocation_after_seal_discards_result(self):
        self.paused_change('target-seal','after-crypto','registry')

    def test_catalog_change_after_open_discards_plaintext(self):
        self.paused_change('target-open','after-crypto','catalog')

    def test_witness_change_after_precheck_is_caught_by_postcheck(self):
        self.paused_change('target-open','before-crypto','witness')


for _name in vars(TargetTests):
    if _name.startswith('test_'):setattr(ProviderTargetTests,_name,None)


if __name__=='__main__':unittest.main()
