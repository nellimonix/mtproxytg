import json
import os
import pathlib
import secrets
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit


class Router(BaseHTTPRequestHandler):
    def do_GET(self):
        self.respond(False)

    def do_HEAD(self):
        self.respond(True)

    def respond(self, head_only):
        path = urlsplit(self.path)
        headers = {
            'Cache-Control': 'no-store, private, max-age=0',
            'Pragma': 'no-cache',
            'X-Robots-Tag': 'noindex, nofollow, noarchive, nosnippet, noimageindex',
            'Referrer-Policy': 'no-referrer',
        }
        status = 404
        body = b''
        if path.path == '/go':
            target = 'https://' + secrets.choice(self.server.domains) + '/'
            if path.query:
                target += '?' + path.query
            headers['Location'] = target
            status = 302
        elif path.path == '/_check':
            host = self.headers.get('X-Original-Host', '').lower().rstrip('.')
            if host in self.server.domain_set:
                status = 200
        elif path.path == '/health':
            status = 200
            body = b'{"status":"ok"}'
            headers['Content-Type'] = 'application/json'
        self.send_response_only(status)
        for key, value in headers.items():
            self.send_header(key, value)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        if body and not head_only:
            self.wfile.write(body)

    def log_message(self, format, *args):
        pass


def make_server(address, domains):
    server = ThreadingHTTPServer(address, Router)
    server.daemon_threads = True
    server.domains = tuple(domains)
    server.domain_set = frozenset(domains)
    return server


if __name__ == '__main__':
    credential_directory = pathlib.Path(os.environ['CREDENTIALS_DIRECTORY'])
    domains = json.loads((credential_directory / 'subdomains').read_text())
    if not domains or len(set(domains)) != len(domains):
        raise SystemExit('Expected a non-empty list of unique destinations')
    make_server(('127.0.0.1', 8791), domains).serve_forever()
