#!/usr/bin/env python3
"""Run sample secret lifecycles against isolated DEBUG HTTP/HTTPS services."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

SAMPLES = Path(__file__).resolve().parent
ROOT = SAMPLES.parents[1]
CLIENTS = ('python', 'go', 'perl', 'web')


class TestFailure(Exception):
    pass


def port_number(value):
    try:
        port = int(value)
        if 0 <= port <= 65535:
            return port
    except ValueError:
        pass
    raise argparse.ArgumentTypeError('port must be 0 (automatic) or 1-65535')


def positive_seconds(value):
    try:
        seconds = float(value)
        if 0 < seconds <= 600:
            return seconds
    except ValueError:
        pass
    raise argparse.ArgumentTypeError('timeout must be greater than 0 and at most 600 seconds')


def select_port(requested, excluded=()):
    for _ in range(20):
        try:
            with socket.socket() as probe:
                probe.bind(('127.0.0.1', requested))
                port = probe.getsockname()[1]
                if port not in excluded:
                    return port
        except OSError:
            raise TestFailure('requested loopback port is unavailable') from None
        if requested:
            break
    raise TestFailure('service and proxy ports must be distinct')


def child_environment():
    env = dict(os.environ)
    for name in tuple(env):
        if name.startswith('CDSE_') or name.lower() in ('http_proxy', 'https_proxy', 'all_proxy'):
            env.pop(name)
    env.update(CDSE_DEFAULT_ENC_ALG='aes-256-gcm', NO_PROXY='localhost,127.0.0.1',
               no_proxy='localhost,127.0.0.1', PYTHONDONTWRITEBYTECODE='1')
    return env


def run_command(command, env, timeout, cwd=None):
    process = None
    try:
        process = subprocess.Popen(command, env=env, cwd=cwd, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   start_new_session=True)
        stdout, stderr = process.communicate(timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        raise TestFailure('child command failed to launch or timed out') from None
    finally:
        if process is not None:
            stop_process(process)
            if process.stdout:
                process.stdout.close()
            if process.stderr:
                process.stderr.close()
    # Legacy clients may print HTTP errors but return zero. Do not echo bodies
    # that can contain credentials or decrypted secret contents.
    if process.returncode or re.search(rb'\[ERROR\]|HTTP error:|\[FAIL\]', stdout + stderr):
        raise TestFailure('client command failed (output withheld)')
    return stdout


def stop_process(process, timeout=5):
    if process is None:
        return
    # The leader can exit while descendants still hold captured pipes open.
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait()


class Service:
    def __init__(self, binary, protocol, port, data, env):
        self.key = ''
        self.ready = threading.Event()
        self.process = subprocess.Popen(
            [str(binary), '--web-service', protocol, '--data-dir', str(data)],
            env=dict(env, CDSE_DEBUG_TEST_HTTP_PORT=str(port), CDSE_DEBUG_TEST_HTTPS_PORT=str(port)),
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            start_new_session=True)
        self.marker = f'{protocol.upper()} server started on port {port}.'.encode()
        self.thread = threading.Thread(target=self.monitor, daemon=True)
        self.thread.start()

    def monitor(self):
        try:
            while True:
                line = self.process.stdout.readline(65536)
                if not line:
                    break
                match = re.fullmatch(rb'Default Admin orgKey\s*:\s*([0-9A-Fa-f]{64})\s*', line)
                if match:
                    self.key = match.group(1).decode('ascii')
                if self.marker in line:
                    self.ready.set()
        finally:
            self.process.stdout.close()

    def wait_ready(self, timeout, previous_key=''):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise TestFailure('DEBUG service exited before readiness (output withheld)')
            if self.ready.is_set() and (self.key or previous_key):
                return self.key or previous_key
            time.sleep(0.05)
        raise TestFailure('DEBUG service startup timed out (output withheld)')

    def close(self, check_exit=False):
        stop_process(self.process)
        self.thread.join(timeout=5)
        self.key = ''
        if check_exit and self.process.returncode:
            raise TestFailure('DEBUG service did not shut down cleanly (output withheld)')


class API:
    def __init__(self, base, key, context=None, timeout=10):
        self.base, self.key, self.timeout = base, key, timeout
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context))

    def request(self, path, expected=200, method='GET'):
        params = urllib.parse.urlencode(dict(userId='EngineAdmin', orgId='EngineOrg', orgKey=self.key))
        request = urllib.request.Request(self.base + path + '?' + params, method=method)
        try:
            response = self.opener.open(request, timeout=self.timeout)
        except urllib.error.HTTPError as error:
            response = error
        except (OSError, urllib.error.URLError):
            raise TestFailure('API transport failed (details withheld)') from None
        with response:
            body = response.read()
            if response.code != expected:
                raise TestFailure(f'API returned HTTP {response.code}, expected {expected}')
            return body


def prepare_certificates(data, env, timeout):
    run_command(['bash', str(ROOT / 'TEST/testCertAuth/gen_test_certs.sh'), '--algo', 'ecp256',
                 '--output-dir', str(data), '--server-cn', 'localhost'], env, timeout)
    chain = data / 'client-chain.pem'
    chain.write_bytes((data / 'engineAdmin.pem').read_bytes() + (data / 'engineOrg.pem').read_bytes())
    # The fixture generator uses this public development-only password.
    # Generated keys stay inside the private temporary run directory.
    key = data / 'client.key'
    run_command(['openssl', 'pkey', '-in', str(data / 'engineAdmin.key'), '-passin', 'pass:engineAdmin',
                 '-out', str(key)], env, timeout)
    for path in data.iterdir():
        if path.is_file():
            path.chmod(0o600)
    context = ssl.create_default_context(cafile=str(data / 'ca.pem'))
    context.load_cert_chain(str(chain), str(key))
    return context


def prepare_clients(selected, work, env, timeout, allow_missing):
    prepared = {}
    for client in selected:
        available = True
        if client in ('python', 'web'):
            available = importlib.util.find_spec('requests') is not None
        elif client == 'go':
            available = shutil.which('go') is not None
        elif client == 'perl':
            available = shutil.which('perl') is not None
            if available:
                try:
                    run_command(['perl', '-MLWP::UserAgent', '-MURI::Escape', '-MHTTP::Request::Common',
                                 '-MIO::Socket::SSL', '-e', 'exit 0'], env, timeout)
                except TestFailure:
                    available = False
        if not available:
            if not allow_missing:
                raise TestFailure(f'{client} dependencies are unavailable')
            print(f'SKIP {client}: dependencies unavailable')
            continue
        if client == 'go':
            binary = work / 'go-client'
            run_command(['go', 'build', '-o', str(binary), '.'], env, timeout,
                        cwd=SAMPLES / 'c-golang')
            prepared[client] = [str(binary)]
        elif client == 'python':
            prepared[client] = [sys.executable, str(SAMPLES / 'b-python/cdse_client.py')]
        elif client == 'perl':
            prepared[client] = ['perl', str(SAMPLES / 'd-perl/cdse_client.pl')]
        else:
            prepared[client] = []
    if not prepared:
        raise TestFailure('no clients available; refusing an empty successful run')
    return prepared


DOCS = '/organizations/EngineOrg/storage/EngineStorage/documentTypes/file.raw/documents'
INFO = '/organizations/EngineOrg/users/EngineAdmin'


def check_cli(client, command, api, env, work, protocol, timeout):
    name = f'{protocol}-{client}-secret'
    payload = b'\x00sample secret lifecycle\xff\n' + os.urandom(32)
    source, target = work / (name + '.in'), work / (name + '.out')
    source.write_bytes(payload)
    api.request(DOCS + '/' + name + '/content', expected=404)
    if not run_command(command + ['info'], env, timeout):
        raise TestFailure('client info returned an empty response')
    print(f'PASS {protocol} {client} info')
    run_command(command + ['store-secret', name, str(source)], env, timeout)
    if api.request(DOCS + '/' + name + '/content') != payload:
        raise TestFailure('stored secret did not match input bytes')
    print(f'PASS {protocol} {client} store-secret')
    listing = run_command(command + ['list-secrets'], env, timeout)
    if name.encode() not in listing:
        raise TestFailure('stored secret missing from client listing')
    print(f'PASS {protocol} {client} list-secrets')
    run_command(command + ['get-secret', name, str(target)], env, timeout)
    if not target.is_file() or target.read_bytes() != payload:
        raise TestFailure('retrieved secret did not match input bytes')
    print(f'PASS {protocol} {client} get-secret')
    run_command(command + ['delete-secret', name], env, timeout)
    api.request(DOCS + '/' + name + '/content', expected=404)
    print(f'PASS {protocol} {client} delete-secret')


def check_web(api, env, work, protocol, port, timeout, startup_timeout):
    import requests
    proxy = subprocess.Popen(
        [sys.executable, str(SAMPLES / 'a-web/proxy.py'), '--bind', '127.0.0.1',
         '--cdse-server', api.base, '--port', str(port)], env=env, stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    try:
        base = f'http://127.0.0.1:{port}'
        with requests.Session() as session:
            session.trust_env = False
            deadline = time.monotonic() + startup_timeout
            while True:
                if proxy.poll() is not None:
                    raise TestFailure('web proxy exited before readiness')
                try:
                    index = session.get(base + '/', timeout=1)
                    if index.status_code == 200 and 'CaumeDSE' in index.text:
                        break
                except requests.RequestException:
                    pass
                if time.monotonic() >= deadline:
                    raise TestFailure('web proxy startup timed out')
                time.sleep(0.05)
            print(f'PASS {protocol} web index')
            params = dict(userId='EngineAdmin', orgId='EngineOrg', orgKey=api.key)
            name = protocol + '-web-secret'
            path = base + '/cdse' + DOCS + '/' + name
            payload = b'\x00web secret lifecycle\xff\n' + os.urandom(32)
            def expect(response, status):
                if response.status_code != status:
                    raise TestFailure(f'web proxy returned HTTP {response.status_code}, expected {status}')
            expect(session.get(base + '/cdse' + INFO, params=params, timeout=timeout), 200)
            print(f'PASS {protocol} web info')
            expect(session.post(path, data=dict(params, **{'*resourceInfo': 'sample lifecycle'}),
                                files={'file': ('sample.bin', payload)}, timeout=timeout), 201)
            if api.request(DOCS + '/' + name + '/content') != payload:
                raise TestFailure('web store did not match input bytes')
            print(f'PASS {protocol} web store-secret')
            listing = session.get(base + '/cdse' + DOCS, params=params, timeout=timeout)
            expect(listing, 200)
            if name not in listing.text:
                raise TestFailure('web listing omitted stored secret')
            print(f'PASS {protocol} web list-secrets')
            response = session.get(path + '/content', params=params, timeout=timeout)
            expect(response, 200)
            if response.content != payload:
                raise TestFailure('web download did not match input bytes')
            print(f'PASS {protocol} web get-secret')
            expect(session.delete(path, params=params, timeout=timeout), 200)
            api.request(DOCS + '/' + name + '/content', expected=404)
            print(f'PASS {protocol} web delete-secret')
    except requests.RequestException:
        raise TestFailure('web request failed (details withheld)') from None
    finally:
        stop_process(proxy)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=os.environ.get('CDSE_BIN', ROOT / 'CaumeDSE-debug-tests'))
    parser.add_argument('--protocol', choices=('http', 'https', 'both'), default='both')
    parser.add_argument('--clients', default=','.join(CLIENTS), help='comma-separated python,go,perl,web')
    parser.add_argument('--allow-missing-clients', action='store_true')
    parser.add_argument('--http-port', type=port_number, default=os.environ.get('CDSE_DEBUG_TEST_HTTP_PORT', '0'))
    parser.add_argument('--https-port', type=port_number, default=os.environ.get('CDSE_DEBUG_TEST_HTTPS_PORT', '0'))
    parser.add_argument('--proxy-port', type=port_number, default='0')
    parser.add_argument('--startup-timeout', type=positive_seconds, default=60)
    parser.add_argument('--command-timeout', type=positive_seconds, default=60)
    args = parser.parse_args(argv)
    selected = args.clients.split(',')
    if not selected or len(selected) != len(set(selected)) or any(client not in CLIENTS for client in selected):
        parser.error('--clients must name distinct known clients')
    old_umask = os.umask(0o077)
    def interrupt(signum, frame):
        raise KeyboardInterrupt
    old_sigterm = signal.signal(signal.SIGTERM, interrupt)
    current, key = None, ''
    try:
        env = child_environment()
        capabilities = json.loads(run_command([str(args.binary.resolve()), '--capabilities'], env, 10))
        if not isinstance(capabilities, dict) or capabilities.get('debugBuild') is not True or capabilities.get('isolatedDataDir') is not True:
            raise TestFailure('binary must be a current DEBUG CaumeDSE-debug-tests runner')
        if args.protocol in ('http', 'both') and capabilities.get('httpTlsAuthBypass') is not True:
            raise TestFailure('HTTP testing requires --enable-BYPASSTLSAUTHINHTTP')
        with tempfile.TemporaryDirectory(prefix='cdse-samples-') as directory:
            work = Path(directory)
            data = work / 'data'
            data.mkdir(mode=0o700)
            (data / 'secureTmp' / 'parser').mkdir(parents=True, mode=0o700)
            shutil.copyfile(ROOT / 'favicon.ico', data / 'favicon.ico')
            context = prepare_certificates(data, env, args.command_timeout) if args.protocol != 'http' else None
            clients = prepare_clients(selected, work, env, args.command_timeout, args.allow_missing_clients)
            protocols = ('http', 'https') if args.protocol == 'both' else (args.protocol,)
            for protocol in protocols:
                port = select_port(args.http_port if protocol == 'http' else args.https_port)
                proxy_port = select_port(args.proxy_port, (port,)) if 'web' in clients else None
                print(f'RUN {protocol}: service port {port}' + (f', proxy port {proxy_port}' if proxy_port else ''), flush=True)
                current = Service(args.binary.resolve(), protocol, port, data, env)
                try:
                    key = current.wait_ready(args.startup_timeout, key)
                    api = API(f'{protocol}://localhost:{port}', key, context if protocol == 'https' else None,
                              args.command_timeout)
                    api.request(INFO)
                    client_env = dict(env, CDSE_SERVER=api.base, CDSE_USER_ID='EngineAdmin', CDSE_ORG_ID='EngineOrg',
                                      CDSE_ORG_KEY=key, CDSE_STORAGE='EngineStorage')
                    if protocol == 'https':
                        client_env.update(CDSE_CA_CERT=str(data / 'ca.pem'),
                                          CDSE_CLIENT_CERT=str(data / 'client-chain.pem'),
                                          CDSE_CLIENT_KEY=str(data / 'client.key'))
                    for client, command in clients.items():
                        if current.process.poll() is not None:
                            raise TestFailure('DEBUG service exited during client tests')
                        if client == 'web':
                            check_web(api, client_env, work, protocol, proxy_port, args.command_timeout, args.startup_timeout)
                        else:
                            check_cli(client, command, api, client_env, work, protocol, args.command_timeout)
                finally:
                    finished = current
                    current = None
                    finished.close(check_exit=True)
            print(f'RESULT clients={len(clients)} protocols={len(protocols)} failed=0')
        return 0
    except (TestFailure, OSError, ValueError) as error:
        print('FAIL ' + (str(error) if isinstance(error, TestFailure) else 'setup failed (details withheld)'), file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        print('FAIL interrupted', file=sys.stderr)
        return 130
    finally:
        if current:
            current.close()
        key = ''
        signal.signal(signal.SIGTERM, old_sigterm)
        os.umask(old_umask)


if __name__ == '__main__':
    sys.exit(main())
