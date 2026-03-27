#!/usr/bin/env python3
"""
CaumeDSE CORS Proxy
===================
Serves index.html at http://localhost:8080 and proxies /cdse/* requests
to https://localhost:8443/* (or a configurable CDSE server).

This proxy is required because browsers enforce the Same-Origin Policy,
preventing JavaScript in index.html from calling the CDSE HTTPS API
directly from a file:// URL or a different origin.

Usage:
    python3 proxy.py [--port 8080] [--cdse-server localhost:8443] [--insecure]

NOTE: Use --insecure only in development/testing when the CDSE server uses
a self-signed TLS certificate. Do NOT use --insecure in production.
"""

import argparse
import http.server
import os
import ssl
import sys
import urllib.request
import urllib.error


def make_handler(cdse_server, ssl_context):
    """Factory that creates a request handler class bound to the given CDSE server."""

    class ProxyHandler(http.server.BaseHTTPRequestHandler):
        log_message_format = '%s - - [%s] %s'

        def _proxy(self, method):
            """Forward any request (except GET /) to the CDSE server."""
            # Strip the /cdse prefix; pass everything else verbatim.
            path = self.path
            if path.startswith('/cdse'):
                target_path = path[len('/cdse'):]
                if not target_path:
                    target_path = '/'
            else:
                # Unrecognised path — return 404.
                self.send_error(404, 'Not found (use /cdse/... to reach CDSE)')
                return

            url = f'https://{cdse_server}{target_path}'

            # Collect request body if present.
            length = int(self.headers.get('Content-Length', 0) or 0)
            body = self.rfile.read(length) if length > 0 else None

            # Build forwarded headers (skip hop-by-hop headers).
            hop_by_hop = {
                'connection', 'keep-alive', 'proxy-authenticate',
                'proxy-authorization', 'te', 'trailers', 'transfer-encoding',
                'upgrade', 'host',
            }
            fwd_headers = {
                k: v for k, v in self.headers.items()
                if k.lower() not in hop_by_hop
            }

            req = urllib.request.Request(url, data=body, headers=fwd_headers,
                                         method=method)
            try:
                with urllib.request.urlopen(req, context=ssl_context) as resp:
                    self.send_response(resp.status)
                    for k, v in resp.headers.items():
                        if k.lower() not in hop_by_hop:
                            self.send_header(k, v)
                    self.end_headers()
                    self.wfile.write(resp.read())
            except urllib.error.HTTPError as exc:
                self.send_response(exc.code)
                for k, v in exc.headers.items():
                    if k.lower() not in hop_by_hop:
                        self.send_header(k, v)
                self.end_headers()
                self.wfile.write(exc.read())
            except urllib.error.URLError as exc:
                msg = f'Proxy error: {exc.reason}'.encode()
                self.send_response(502)
                self.send_header('Content-Type', 'text/plain')
                self.send_header('Content-Length', str(len(msg)))
                self.end_headers()
                self.wfile.write(msg)

        def do_GET(self):
            # Serve index.html for the root path; proxy everything else.
            if self.path == '/' or self.path == '/index.html':
                here = os.path.dirname(os.path.abspath(__file__))
                index_path = os.path.join(here, 'index.html')
                try:
                    with open(index_path, 'rb') as f:
                        data = f.read()
                    self.send_response(200)
                    self.send_header('Content-Type', 'text/html; charset=utf-8')
                    self.send_header('Content-Length', str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
                except FileNotFoundError:
                    self.send_error(404, 'index.html not found')
            else:
                self._proxy('GET')

        def do_POST(self):
            self._proxy('POST')

        def do_PUT(self):
            self._proxy('PUT')

        def do_DELETE(self):
            self._proxy('DELETE')

        def do_HEAD(self):
            self._proxy('HEAD')

        def log_message(self, fmt, *args):
            print(fmt % args)

    return ProxyHandler


def main():
    parser = argparse.ArgumentParser(
        description='CaumeDSE CORS proxy — serves the web client and forwards '
                    '/cdse/* to the CDSE HTTPS server.')
    parser.add_argument('--port', type=int, default=8080,
                        help='Local port to listen on (default: 8080)')
    parser.add_argument('--cdse-server', default='localhost:8443',
                        metavar='HOST:PORT',
                        help='CDSE server address (default: localhost:8443)')
    parser.add_argument('--insecure', action='store_true',
                        help='Skip TLS certificate verification for the CDSE '
                             'server (development/self-signed certs only)')
    args = parser.parse_args()

    # Build the SSL context used when contacting the CDSE server.
    if args.insecure:
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        print('WARNING: TLS certificate verification disabled (--insecure).')
    else:
        ssl_context = ssl.create_default_context()

    handler = make_handler(args.cdse_server, ssl_context)
    server = http.server.HTTPServer(('', args.port), handler)
    print(f'CaumeDSE proxy running.')
    print(f'  Open: http://localhost:{args.port}/')
    print(f'  Forwarding /cdse/* -> https://{args.cdse_server}/*')
    print('Press Ctrl+C to stop.')
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print('\nStopped.')
        sys.exit(0)


if __name__ == '__main__':
    main()
