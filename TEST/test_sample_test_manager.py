#!/usr/bin/env python3
"""Sample manager, proxy configuration and DEBUG-runner contracts."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import threading
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('sample_manager', ROOT / 'samples/hsm-db-crypto/cdse_test_manager.py')
manager = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(manager)
PROXY_SPEC = importlib.util.spec_from_file_location('sample_proxy', ROOT / 'samples/hsm-db-crypto/a-web/proxy.py')
proxy = importlib.util.module_from_spec(PROXY_SPEC)
PROXY_SPEC.loader.exec_module(proxy)


class ProxyTests(unittest.TestCase):
    def test_default_listener_and_help(self):
        with mock.patch.object(sys, 'argv', ['proxy.py', '--help']), \
                mock.patch.object(proxy.http.server, 'HTTPServer') as server, \
                contextlib.redirect_stdout(io.StringIO()) as output:
            with self.assertRaises(SystemExit) as exit_code:
                proxy.main()
            self.assertEqual(exit_code.exception.code, 0)
            self.assertIn('default: 8088', output.getvalue())
            server.assert_not_called()
        server = mock.Mock(server_address=('', 8088))
        server.serve_forever.side_effect = KeyboardInterrupt
        with mock.patch.object(sys, 'argv', ['proxy.py']), \
                mock.patch.dict(os.environ, {}, clear=True), \
                mock.patch.object(proxy.http.server, 'HTTPServer', return_value=server) as constructor, \
                contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit) as exit_code:
                proxy.main()
            self.assertEqual(exit_code.exception.code, 0)
            self.assertEqual(constructor.call_args.args[0], ('', 8088))
            server.server_close.assert_called_once()

    def test_loopback_self_forwarding(self):
        for upstream in ('http://localhost:8088', 'http://127.0.0.1:8088',
                         'https://localhost:8088', 'localhost:8088',
                         'http://[::1]:8088', 'http://127.0.0.2:8088'):
            with self.subTest(upstream=upstream), self.assertRaisesRegex(ValueError, 'distinct ports'):
                proxy.validate_upstream(upstream, '', 8088)
        with self.assertRaisesRegex(ValueError, 'distinct ports'):
            proxy.validate_upstream('http://localhost:8088', '127.0.0.1', 8088)

    def test_documented_startup_recipes(self):
        recipes = ((['--bind', '127.0.0.1', '--port', '8088', '--insecure'], 8088, 'localhost:8443'),
                   (['--bind', '127.0.0.1', '--port', '8088', '--cdse-server', 'http://localhost:8080'],
                    8088, 'http://localhost:8080'),
                   (['--bind', '127.0.0.1', '--insecure', '--port', '8090'], 8090, 'localhost:8443'),
                   (['--bind', '127.0.0.1', '--port', '8088', '--cdse-server', 'localhost:8443'],
                    8088, 'localhost:8443'))
        for options, port, upstream in recipes:
            server = mock.Mock(server_address=('127.0.0.1', port))
            server.serve_forever.side_effect = KeyboardInterrupt
            env = {'CDSE_CLIENT_CERT': 'client.pem', 'CDSE_CLIENT_KEY': 'client.key', 'CDSE_CA_CERT': 'ca.pem'}
            with self.subTest(options=options), mock.patch.object(sys, 'argv', ['proxy.py', *options]), \
                    mock.patch.dict(os.environ, env, clear=True), \
                    mock.patch.object(proxy.ssl, 'create_default_context') as context, \
                    mock.patch.object(proxy, 'make_handler') as handler, \
                    mock.patch.object(proxy.http.server, 'HTTPServer', return_value=server) as constructor, \
                    contextlib.redirect_stdout(io.StringIO()) as output:
                with self.assertRaises(SystemExit) as exit_code:
                    proxy.main()
                self.assertEqual(exit_code.exception.code, 0)
                self.assertEqual(constructor.call_args.args[0], ('127.0.0.1', port))
                handler.assert_called_once_with(upstream, context.return_value)
                context.return_value.load_cert_chain.assert_called_once_with('client.pem', 'client.key')
                self.assertIn(f'http://localhost:{port}/', output.getvalue())
                if '--insecure' in options:
                    self.assertFalse(context.return_value.check_hostname)
                    self.assertEqual(context.return_value.verify_mode, proxy.ssl.CERT_NONE)
                else:
                    context.assert_called_once_with(cafile='ca.pem')

    def test_resolved_alias_self_forwarding(self):
        address = [(proxy.socket.AF_INET, proxy.socket.SOCK_STREAM, 6, '', ('192.0.2.5', 0))]
        with mock.patch.object(proxy.socket, 'getaddrinfo', return_value=address):
            for bind in ('listener.example', ''):
                with self.subTest(bind=bind), self.assertRaisesRegex(ValueError, 'distinct ports'):
                    proxy.validate_upstream('http://upstream.example:8088', bind, 8088)

    def test_distinct_endpoints_are_allowed(self):
        with mock.patch.object(proxy.socket, 'getaddrinfo') as resolve:
            for upstream in ('http://localhost:8080', 'https://localhost:8443', 'localhost:8443'):
                proxy.validate_upstream(upstream, '', 8088)
            resolve.assert_not_called()
        proxy.validate_upstream('http://127.0.0.2:8088', '127.0.0.1', 8088)
        with mock.patch.object(proxy.socket, 'getaddrinfo', side_effect=proxy.socket.gaierror):
            proxy.validate_upstream('http://unresolved.example:8088', '', 8088)

    def test_invalid_configuration_fails_before_listening(self):
        options = (['--cdse-server', 'http://localhost:8088'],
                   ['--port', '8080', '--cdse-server', 'http://localhost:8080'],
                   ['--port', '-1'], ['--port', '65536'],
                   ['--cdse-server', 'ftp://localhost:8080'],
                   ['--cdse-server', 'http://localhost:bad'])
        for option in options:
            with self.subTest(option=option), mock.patch.object(sys, 'argv', ['proxy.py', *option]), \
                    mock.patch.object(proxy.http.server, 'HTTPServer') as server, \
                    contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as exit_code:
                    proxy.main()
                self.assertEqual(exit_code.exception.code, 2)
                server.assert_not_called()
        with mock.patch.object(sys, 'argv', ['proxy.py']), \
                mock.patch.dict(os.environ, {'CDSE_SERVER': 'http://localhost:8088'}), \
                mock.patch.object(proxy.http.server, 'HTTPServer') as server, \
                contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as exit_code:
                proxy.main()
            self.assertEqual(exit_code.exception.code, 2)
            server.assert_not_called()

    def test_ephemeral_port_is_reported_and_closed(self):
        server = mock.Mock(server_address=('127.0.0.1', 19088))
        server.serve_forever.side_effect = KeyboardInterrupt
        with mock.patch.object(sys, 'argv', ['proxy.py', '--port', '0']), \
                mock.patch.dict(os.environ, {}, clear=True), \
                mock.patch.object(proxy.http.server, 'HTTPServer', return_value=server), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            with self.assertRaises(SystemExit):
                proxy.main()
            self.assertIn('http://localhost:19088/', output.getvalue())
            server.server_close.assert_called_once()

    def test_ephemeral_self_forwarding_closes_listener(self):
        server = mock.Mock(server_address=('127.0.0.1', 19088))
        with mock.patch.object(sys, 'argv', ['proxy.py', '--port', '0', '--cdse-server', 'http://localhost:19088']), \
                mock.patch.object(proxy.http.server, 'HTTPServer', return_value=server), \
                contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as exit_code:
                proxy.main()
            self.assertEqual(exit_code.exception.code, 2)
            server.serve_forever.assert_not_called()
            server.server_close.assert_called_once()


class ManagerTests(unittest.TestCase):
    def command_process(self, returncode=0, stdout=b'', stderr=b''):
        process = mock.Mock(returncode=returncode)
        process.poll.return_value = returncode
        process.communicate.return_value = (stdout, stderr)
        return process

    def test_help_does_not_launch(self):
        with mock.patch.object(manager.subprocess, 'Popen') as run, contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit) as exit_code:
                manager.main(['--help', '--binary', '/nonexistent'])
            self.assertEqual(exit_code.exception.code, 0)
            run.assert_not_called()

    def test_invalid_options_do_not_launch(self):
        for option in (['--http-port', '-1'], ['--https-port', '65536'], ['--proxy-port', 'abc'],
                       ['--startup-timeout', 'nan'], ['--clients', 'unknown'], ['--clients', 'go,go']):
            with self.subTest(option=option), mock.patch.object(manager.subprocess, 'Popen') as run:
                with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                    manager.main(option)
                run.assert_not_called()

    def test_environment_is_private_and_not_mutated(self):
        with mock.patch.dict(os.environ, {'CDSE_ORG_KEY': 'private-marker', 'CDSE_CONFIG_FILE': '/private',
                                         'CDSE_DEBUG_TEST_SKIP_AUTHZ': '1', 'HTTPS_PROXY': 'http://external'}):
            original = dict(os.environ)
            env = manager.child_environment()
            self.assertNotIn('CDSE_ORG_KEY', env)
            self.assertNotIn('CDSE_CONFIG_FILE', env)
            self.assertNotIn('CDSE_DEBUG_TEST_SKIP_AUTHZ', env)
            self.assertNotIn('HTTPS_PROXY', env)
            self.assertEqual(dict(os.environ), original)

    def test_zero_exit_http_error_is_a_failure(self):
        for output in (b'[ERROR] HTTP 401 private-marker', b'HTTP error: 500 private-marker'):
            result = self.command_process(stdout=output)
            with mock.patch.object(manager.subprocess, 'Popen', return_value=result), \
                    mock.patch.object(manager, 'stop_process'):
                with self.assertRaises(manager.TestFailure) as failure:
                    manager.run_command(['client'], {}, 1)
                self.assertNotIn('private-marker', str(failure.exception))

    def test_failed_child_output_is_withheld(self):
        result = self.command_process(returncode=1, stdout=b'secret payload', stderr=b'orgKey=private-marker')
        with mock.patch.object(manager.subprocess, 'Popen', return_value=result), \
                mock.patch.object(manager, 'stop_process'):
            with self.assertRaises(manager.TestFailure) as failure:
                manager.run_command(['client'], {}, 1)
            self.assertNotIn('private-marker', str(failure.exception))

    def test_command_timeout_is_withheld(self):
        process = self.command_process()
        process.communicate.side_effect = subprocess.TimeoutExpired(['private-marker'], 1)
        with mock.patch.object(manager.subprocess, 'Popen', return_value=process), \
                mock.patch.object(manager, 'stop_process') as stop:
            with self.assertRaises(manager.TestFailure) as failure:
                manager.run_command(['client'], {}, 1)
            self.assertNotIn('private-marker', str(failure.exception))
            stop.assert_called_once_with(process)

    def test_interrupt_reaps_command(self):
        process = self.command_process()
        process.communicate.side_effect = KeyboardInterrupt
        with mock.patch.object(manager.subprocess, 'Popen', return_value=process), \
                mock.patch.object(manager, 'stop_process') as stop:
            with self.assertRaises(KeyboardInterrupt):
                manager.run_command(['client'], {}, 1)
            stop.assert_called_once_with(process)

    def test_signal_handler_is_restored(self):
        original = signal.getsignal(signal.SIGTERM)
        def interrupted(*args):
            os.kill(os.getpid(), signal.SIGTERM)
        with mock.patch.object(manager, 'run_command', side_effect=interrupted), \
                contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(manager.main(['--protocol', 'http']), 130)
        self.assertEqual(signal.getsignal(signal.SIGTERM), original)

    def test_capture_is_bounded_and_not_printed(self):
        service = manager.Service.__new__(manager.Service)
        service.key = ''
        service.ready = threading.Event()
        service.marker = b'HTTP server started on port 1234.'
        key = b'AB' * 32
        service.process = types.SimpleNamespace(stdout=io.BytesIO(
            b'Default Admin orgKey      : ' + key + b'\nHTTP server started on port 1234.\nprivate payload\n'))
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            service.monitor()
        self.assertEqual(service.key, key.decode())
        self.assertTrue(service.ready.is_set())
        self.assertEqual(output.getvalue(), '')
        self.assertFalse(hasattr(service, 'log_lines'))

    def test_early_exit_fails_without_waiting(self):
        service = manager.Service.__new__(manager.Service)
        service.process = types.SimpleNamespace(poll=lambda: 2)
        with mock.patch.object(manager.time, 'sleep') as sleep:
            with self.assertRaises(manager.TestFailure):
                service.wait_ready(60)
            sleep.assert_not_called()

    def test_failed_service_shutdown_is_not_success(self):
        service = manager.Service.__new__(manager.Service)
        service.process = mock.Mock(returncode=1)
        service.thread = mock.Mock()
        service.key = 'private-marker'
        with mock.patch.object(manager, 'stop_process') as stop:
            with self.assertRaises(manager.TestFailure):
                service.close(check_exit=True)
            stop.assert_called_once_with(service.process)
        self.assertEqual(service.key, '')

    def test_shutdown_escalates_and_reaps(self):
        process = mock.Mock(pid=123)
        process.poll.return_value = None
        process.wait.side_effect = [subprocess.TimeoutExpired('service', 1), 0]
        with mock.patch.object(manager.os, 'killpg') as kill:
            manager.stop_process(process, timeout=1)
        self.assertEqual(kill.call_args_list, [mock.call(123, signal.SIGTERM), mock.call(123, signal.SIGKILL)])
        self.assertEqual(process.wait.call_count, 2)

    def test_shutdown_cleans_descendants_of_exited_leader(self):
        process = mock.Mock(pid=123)
        process.poll.return_value = 0
        with mock.patch.object(manager.os, 'killpg') as kill:
            manager.stop_process(process)
        self.assertEqual(kill.call_args_list, [mock.call(123, signal.SIGTERM), mock.call(123, signal.SIGKILL)])

    def test_real_command_timeout_leaves_no_running_group(self):
        created = []
        original = subprocess.Popen
        def launch(*args, **kwargs):
            process = original(*args, **kwargs)
            created.append(process)
            return process
        with mock.patch.object(manager.subprocess, 'Popen', side_effect=launch):
            with self.assertRaises(manager.TestFailure):
                manager.run_command([sys.executable, '-c', 'import time; time.sleep(30)'], dict(os.environ), 0.05)
        self.assertIsNotNone(created[0].poll())
        with self.assertRaises(ProcessLookupError):
            os.killpg(created[0].pid, 0)

    def test_old_runner_is_rejected_before_temp_data(self):
        caps = b'{"debugBuild":true,"isolatedDataDir":false}'
        with mock.patch.object(manager, 'run_command', return_value=caps), \
                mock.patch.object(manager.tempfile, 'TemporaryDirectory') as temporary, \
                contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(manager.main(['--protocol', 'http']), 1)
            temporary.assert_not_called()

    def test_http_requires_debug_tls_bypass(self):
        caps = b'{"debugBuild":true,"isolatedDataDir":true,"httpTlsAuthBypass":false}'
        with mock.patch.object(manager, 'run_command', return_value=caps), \
                mock.patch.object(manager.tempfile, 'TemporaryDirectory') as temporary, \
                contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(manager.main(['--protocol', 'http']), 1)
            temporary.assert_not_called()

    def test_missing_clients_are_not_silent_success(self):
        with tempfile.TemporaryDirectory() as work, \
                mock.patch.object(manager.shutil, 'which', return_value=None):
            with self.assertRaises(manager.TestFailure):
                manager.prepare_clients(['go'], Path(work), {}, 1, False)
            with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(manager.TestFailure):
                manager.prepare_clients(['go'], Path(work), {}, 1, True)


@unittest.skipUnless(Path('./CaumeDSE-debug-tests').is_file(), 'configured build required')
class RunnerTests(unittest.TestCase):
    def test_capabilities_without_runtime(self):
        result = subprocess.run(['./CaumeDSE-debug-tests', '--capabilities'], capture_output=True, timeout=10,
                                env=dict(os.environ, LANG='invalid-locale', CDSE_CONFIG_FILE='/nonexistent'))
        self.assertEqual(result.returncode, 0)
        caps = json.loads(result.stdout)
        self.assertIsInstance(caps['debugBuild'], bool)
        self.assertEqual(caps['isolatedDataDir'], caps['debugBuild'])

    def test_unsafe_paths_and_protocol_fail_before_startup(self):
        with tempfile.TemporaryDirectory() as work:
            root = Path(work)
            public = root / 'public'
            public.mkdir(mode=0o755)
            private = root / 'private'
            private.mkdir(mode=0o700)
            link = root / 'link'
            link.symlink_to(private, target_is_directory=True)
            for path in (public, link, root / 'missing'):
                result = subprocess.run(['./CaumeDSE-debug-tests', '--web-service', 'http', '--data-dir', str(path)],
                                        capture_output=True, timeout=10)
                self.assertEqual(result.returncode, 2)
                self.assertNotIn(b'server started', result.stdout)
            result = subprocess.run(['./CaumeDSE-debug-tests', '--web-service', 'invalid', '--data-dir', str(private)],
                                    capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(list(private.iterdir()), [])

    def test_invalid_debug_port_does_not_create_databases(self):
        with tempfile.TemporaryDirectory() as directory:
            for port in ('0', '-1', '65536', '123garbage'):
                result = subprocess.run(['./CaumeDSE-debug-tests', '--web-service', 'http', '--data-dir', directory],
                                        capture_output=True, timeout=10,
                                        env=dict(os.environ, CDSE_DEBUG_TEST_HTTP_PORT=port))
                self.assertEqual(result.returncode, 2)
                self.assertNotIn(b'server started', result.stdout)
            self.assertEqual(list(Path(directory).iterdir()), [])


if __name__ == '__main__':
    unittest.main()
