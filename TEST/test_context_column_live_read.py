#!/usr/bin/env python3
"""Exercise the witnessed reader through the real DEBUG HTTPS server."""
from contextlib import closing, contextmanager
import http.client
import json
import os
from pathlib import Path
import re
import shutil
import socket
import sqlite3
import ssl
import subprocess
import time
import unittest
from urllib.parse import urlencode

import test_context_column_read_cli as read_cli
from test_context_crypto import available
from test_context_column import PAYLOAD


SERVER = Path(os.environ.get('CDSE_CONTEXT_LIVE_SERVER', './CaumeDSE-debug-tests')).resolve()
CERTS = Path(__file__).resolve().parent / 'testCertAuth'
ROUTE = '/organizations/EngineOrg/storage/EngineStorage/documentTypes/file.csv.cdse-v2/documents/released/contentRows'
PLAINTEXT = b'fixture-alpha'


@unittest.skipUnless(available(), 'requires the V2 provider')
class LiveReadTests(read_cli.ReleasedReadCommandTests):
    registration_org = 'EngineOrg'
    registration_storage = 'EngineStorage'

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        capabilities = json.loads(subprocess.check_output([SERVER, '--capabilities'], timeout=15))
        if not capabilities['debugBuild']:
            raise unittest.SkipTest('requires a DEBUG server with an isolated data directory')

    def setUp(self):
        super().setUp()
        self.data = self.root / 'engine'
        self.data.mkdir(mode=0o700)
        for name in ('ca.pem', 'server.pem', 'server.key'):
            shutil.copyfile(CERTS / name, self.data / name)
        chain = self.private('client.pem', (CERTS / 'engineAdmin.pem').read_bytes() +
                             (CERTS / 'engineOrg.pem').read_bytes())
        self.ca = ssl.create_default_context(cafile=CERTS / 'ca.pem')
        self.client = ssl.create_default_context(cafile=CERTS / 'ca.pem')
        self.client.load_cert_chain(chain, CERTS / 'engineAdmin.key')
        self.key = None
        self.environment = {
            'CDSE_V2_READ_ENABLED': '1',
            'CDSE_V2_READ_ORG': 'EngineOrg',
            'CDSE_V2_READ_STORAGE': 'EngineStorage',
            'CDSE_V2_READ_DOCUMENT': 'released',
            'CDSE_V2_READ_DEPLOYMENT': self.anchor.deployment,
            'CDSE_V2_READ_ORGANIZATION': self.anchor.organization,
            'CDSE_V2_READ_REGISTRY_DIRECTORY': str(self.authority),
            'CDSE_V2_READ_WITNESS_DIRECTORY': str(self.witness),
            'CDSE_V2_READ_SOURCE_EXPORT': str(self.source_root),
            'CDSE_V2_READ_PUBLISHED_EXPORT': str(self.published),
            'CDSE_V2_READ_RELEASE_ENVELOPE': str(self.global_path),
            'CDSE_V2_READ_RELEASE_DIGEST': self.global_pin,
            'CDSE_V2_READ_WITNESS_TOKEN': self.final_token,
            'CDSE_V2_READ_REGISTRY_KEY_FILE': str(self.registry_key),
            'CDSE_V2_READ_WITNESS_KEY_FILE': str(self.witness_key),
            'CDSE_V2_READ_PASSWORD_FILE': str(self.password_file),
        }

    @contextmanager
    def server(self, protocol='https', **overrides):
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            port = listener.getsockname()[1]
        env = dict(os.environ, **self.environment)
        env['CDSE_DEBUG_TEST_SKIP_AUTHZ'] = '0'
        env['CDSE_V2_READ_CATALOG'] = '0'
        env[f'CDSE_DEBUG_TEST_{protocol.upper()}_PORT'] = str(port)
        env.update(overrides)
        log = self.root / 'live-service.log'
        with log.open('wb') as stream:
            process = subprocess.Popen(
                [SERVER, '--web-service', protocol, '--data-dir', self.data],
                env=env, stdout=stream, stderr=subprocess.STDOUT,
            )
            try:
                marker = f'{protocol.upper()} server started on port {port}.'.encode()
                deadline = time.monotonic() + 20
                while time.monotonic() < deadline and process.poll() is None:
                    startup = log.read_bytes()
                    if marker in startup:
                        if self.key is None:
                            match = re.search(rb'Default Admin orgKey\s*:\s*(\S+)', startup)
                            self.assertIsNotNone(match, 'fixture administrator key missing')
                            self.key = match.group(1).decode()
                        break
                    time.sleep(0.05)
                else:
                    self.fail(f'{protocol} fixture server did not start (exit {process.poll()})')
                yield port
            finally:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=15)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)
                log_bytes = log.read_bytes()
                for marker in (PLAINTEXT, PLAINTEXT.hex().encode(), b'AddressSanitizer',
                               b'LeakSanitizer', b'UndefinedBehaviorSanitizer', b'runtime error:'):
                    self.assertFalse(marker in log_bytes, f'unexpected marker in server log: {marker!r}')
                self.assertEqual(process.returncode, 0, 'fixture server did not exit cleanly')

    def request(self, port, row='1', *, route=ROUTE, method='GET', extra=(), tls=True, cert=True):
        query = urlencode([('userId', 'EngineAdmin'), ('orgId', 'EngineOrg'), ('orgKey', self.key), *extra])
        if tls:
            connection = http.client.HTTPSConnection('localhost', port, timeout=60,
                                                     context=self.client if cert else self.ca)
        else:
            connection = http.client.HTTPConnection('localhost', port, timeout=60)
        try:
            connection.request(method, f'{route}/{row}?{query}')
            response = connection.getresponse()
            return response.status, dict(response.headers), response.read()
        finally:
            connection.close()

    def assert_refused(self, response, statuses):
        status, headers, body = response
        self.assertIn(status, statuses, body)
        self.assertEqual(headers.get('Cache-Control'), 'no-store')
        self.assertNotIn(b'valueHex', body)
        self.assertNotIn(PLAINTEXT.hex().encode(), body)

    def test_live_release_checks_scope_authorization_and_physical_identity(self):
        before = self.authority_files()
        with self.server() as port:
            for row, expected in [('1', PLAINTEXT), ('2', b'fixture-beta')]:
                status, headers, body = self.request(port, row)
                self.assertEqual(status, 200, body)
                self.assertEqual(headers.get('Content-Type'), 'application/json')
                self.assertEqual(headers.get('Cache-Control'), 'no-store')
                self.assertEqual(json.loads(body), {'valueHex': expected.hex()})
            self.assert_refused(self.request(port, cert=False), (401, 403))
            self.assert_refused(self.request(port, route=ROUTE.replace('/released/', '/other/')), (404,))
            self.assert_refused(self.request(port, route=ROUTE.replace('/contentRows', '/contentColumns')), (404,))
            self.assert_refused(self.request(port, method='DELETE'), (405,))
            for row in ('0', '1.0', '9223372036854775808'):
                self.assert_refused(self.request(port, row), (400,))
            self.assert_refused(self.request(port, extra=(('passwordFile', 'unrecognized'),)), (400,))
            self.assert_refused(self.request(port, '999'), (503,))
            roles = '/organizations/EngineOrg/users/EngineAdmin/roleTables'
            status, _, body = self.request(port, 'contentRows', route=roles, method='PUT',
                                           extra=(('*_get', '0'),))
            self.assertEqual(status, 200, body)
            self.assert_refused(self.request(port), (403,))
            status, _, body = self.request(port, 'contentRows', route=roles, method='PUT',
                                           extra=(('*_get', '1'),))
            self.assertEqual(status, 200, body)
            self.assertEqual(self.authority_files(), before)
            image = self.published / 'candidate.sqlite'
            os.replace(self.private('replacement', image.read_bytes()), image)
            self.assert_refused(self.request(port), (503,))

    def test_live_reader_requires_explicit_enablement_and_independent_pins(self):
        for overrides, status in (
            ({'CDSE_V2_READ_ENABLED': '0'}, 404),
            ({'CDSE_V2_READ_RELEASE_DIGEST': '00' * 32}, 503),
            ({'CDSE_V2_READ_WITNESS_TOKEN': self.acknowledged}, 503),
            ({'CDSE_DEBUG_TEST_SKIP_AUTHZ': '1'}, 403),
        ):
            with self.subTest(overrides=overrides), self.server(**overrides) as port:
                self.assert_refused(self.request(port), (status,))
        with self.server(protocol='http') as port:
            self.assert_refused(self.request(port, tls=False), (401, 403))

    def initialize_catalog(self):
        setup = subprocess.run([PAYLOAD, self.data, 'init-test-engine'], env=self.reg_env,
                               capture_output=True, timeout=30)
        self.assertEqual(setup.returncode, 0, 'engine fixture initialization failed')
        self.key = 'fixture-source-key'
        self.registration_key = self.private('catalog.key', self.key.encode())
        active = self.data / 'ResourcesDB'
        active.chmod(0o600)
        return active

    def register_args(self, **overrides):
        fields = self.fields()
        options = dict(password_file=None, table=None, row=None, field=None,
                       active_resources=self.data / 'ResourcesDB', registration_key_file=self.registration_key,
                       metadata_profile=self.metadata_profile, org_resource_id=fields['organization_resource'],
                       storage_id=fields['storage_id'], document_id=fields['destination_document'])
        options.update(overrides)
        return [*read_cli.REGISTER, *self.command_options(**options)]

    def register(self, expected=0, **overrides):
        result = self.invoke(self.register_args(**overrides))
        self.assertEqual(result.returncode, expected, result.stderr)
        self.assertNotIn(self.key.encode(), result.stderr)
        self.assertNotIn(str(self.root).encode(), result.stderr)
        self.assertEqual(result.stdout, b'' if expected else b'registration=present\n')
        if not expected:
            self.assertEqual(result.stderr, b'')

    def approved_registration(self):
        published = self.published / 'ResourcesDB'
        with closing(sqlite3.connect(f'{published.as_uri()}?mode=ro', uri=True)) as db:
            return db.execute('SELECT * FROM documents WHERE id=?', (self.fields()['destination_row'],)).fetchone()

    def test_active_catalog_requires_exact_released_registration(self):
        active = self.initialize_catalog()
        route = ROUTE.replace('/released/', f'/{self.fields()["destination_document"]}/')
        settings = dict(CDSE_V2_READ_CATALOG='1', CDSE_DEFAULT_ENC_ALG=self.metadata_profile)
        with self.server(**settings) as port:
            self.assert_refused(self.request(port, route=route), (404,))
            self.assert_refused(self.request(port), (404,))
        authority = self.authority_files()
        self.register()
        before = active.read_bytes()
        self.register()
        self.assertEqual(active.read_bytes(), before)
        self.assertEqual(self.authority_files(), authority)
        with closing(sqlite3.connect(active)) as db:
            row = db.execute('SELECT * FROM documents').fetchone()
        self.assertEqual(row[1:], self.approved_registration()[1:])
        insert = 'INSERT INTO documents VALUES (' + ','.join('?' for _ in row) + ')'
        with self.server(**settings) as port:
            before = active.read_bytes()
            status, headers, body = self.request(port, route=route)
            self.assertEqual(status, 200, body)
            self.assertEqual(headers.get('Cache-Control'), 'no-store')
            self.assertEqual(json.loads(body), {'valueHex': PLAINTEXT.hex()})
            self.assertEqual(active.read_bytes(), before)
            self.assert_refused(self.request(port, route=route, cert=False), (401, 403))

            with closing(sqlite3.connect(active)) as db, db:
                db.execute(insert, (row[0] + 1, *row[1:]))
            self.assert_refused(self.request(port, route=route), (503,))
            with closing(sqlite3.connect(active)) as db, db:
                db.execute('DELETE FROM documents WHERE id=?', (row[0] + 1,))
                db.execute("UPDATE documents SET partMAC='' WHERE id=?", (row[0],))
            self.assert_refused(self.request(port, route=route), (503,))
            with closing(sqlite3.connect(active)) as db, db:
                db.execute('DELETE FROM documents WHERE id=?', (row[0],))
            self.assert_refused(self.request(port, route=route), (404,))

        with self.server(**settings, CDSE_V2_READ_WITNESS_TOKEN=self.acknowledged) as port:
            self.assert_refused(self.request(port, route=route), (503,))

    def test_registration_refuses_conflicts_and_rolls_back_busy_commit(self):
        active = self.initialize_catalog()
        before = active.read_bytes()
        wrong_key = self.private('wrong-catalog.key', b'invalid')
        alias = self.root / 'alias'
        alias.mkdir(mode=0o700)
        (alias / 'ResourcesDB').symlink_to(active)
        for status, options in (
            (2, {'retained_witness_token': self.acknowledged}),
            (1, {'release_digest': '00' * 32}),
            (1, {'registration_key_file': wrong_key}),
            (1, {'active_resources': self.published / 'ResourcesDB'}),
            (1, {'active_resources': alias / 'ResourcesDB'}),
        ):
            with self.subTest(status=status, options=options):
                self.register(status, **options)
                self.assertEqual(active.read_bytes(), before)

        approved = self.approved_registration()
        insert = 'INSERT INTO documents VALUES (' + ','.join('?' for _ in approved) + ')'
        for rows in (
            [(*approved[:-3], None, None, None)],
            [(3, *approved[1:10], '', *approved[11:])],
            [approved, (3, *approved[1:])],
        ):
            with closing(sqlite3.connect(active)) as db, db:
                db.executemany(insert, rows)
            before = active.read_bytes()
            self.register(1)
            self.assertEqual(active.read_bytes(), before)
            with closing(sqlite3.connect(active)) as db, db:
                db.execute('DELETE FROM documents')
        with closing(sqlite3.connect(active)) as db, db:
            db.execute('CREATE TRIGGER fixture_guard AFTER INSERT ON documents BEGIN SELECT 1; END')
        before = active.read_bytes()
        self.register(1)
        self.assertEqual(active.read_bytes(), before)
        with closing(sqlite3.connect(active)) as db, db:
            db.execute('DROP TRIGGER fixture_guard')
        with closing(sqlite3.connect(active)) as db:
            db.execute('PRAGMA journal_mode=DELETE').fetchone()
            before = active.read_bytes()
            db.execute('BEGIN')
            self.assertEqual(db.execute('SELECT count(*) FROM documents').fetchone()[0], 0)
            self.register(1)
            self.assertEqual(active.read_bytes(), before)
            self.assertFalse(active.with_name('ResourcesDB-journal').exists())
            db.rollback()
        if Path('/dev/full').exists():
            with open('/dev/full', 'wb') as output:
                lost = subprocess.run(self.register_args(), stdout=output, stderr=subprocess.PIPE, timeout=90)
            self.assertEqual(lost.returncode, 1)
            self.assertIn(b'could not report registration status', lost.stderr)
            with closing(sqlite3.connect(active)) as db:
                self.assertEqual(db.execute('SELECT count(*) FROM documents').fetchone()[0], 1)
        self.register()
        with closing(sqlite3.connect(active)) as db:
            self.assertEqual(db.execute('SELECT count(*) FROM documents').fetchone()[0], 1)

    def test_offline_registration_metadata_cbc(self):
        active = self.initialize_catalog()
        self.register()
        with closing(sqlite3.connect(active)) as db:
            row = db.execute('SELECT * FROM documents').fetchone()
        self.assertEqual(row[1:], self.approved_registration()[1:])


for _parent in LiveReadTests.__mro__[1:]:
    for _name in vars(_parent):
        if _name.startswith('test_') and _name not in vars(LiveReadTests):
            setattr(LiveReadTests, _name, None)


if __name__ == '__main__':
    unittest.main()
