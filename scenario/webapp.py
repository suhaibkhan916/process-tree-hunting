"""A deliberately vulnerable lab web app. Runs only inside the disposable sensor container,
bound to 127.0.0.1. /ping passes the host parameter to a shell, which is the bug."""
import subprocess
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        url = urlparse(self.path)
        if url.path == "/health":
            body = b"ok\n"
        elif url.path == "/ping":
            host = parse_qs(url.query).get("host", ["127.0.0.1"])[0]
            # Command injection on purpose: shell=True with user input.
            out = subprocess.run(f"ping -c 1 -W 1 {host}", shell=True, capture_output=True, timeout=10)
            body = out.stdout[-200:] or b"no output\n"
        else:
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


HTTPServer(("127.0.0.1", 8080), Handler).serve_forever()
