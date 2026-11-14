#!/usr/bin/python3
"""Serve a sample .vv download for testing the Chrome handler.

Run this, open the printed URL in Chrome, and click the download link.  If
the extension and native host are installed, ryll should open and fail to
connect to 127.0.0.1:5900 -- which is the point: the launch itself is what is
being tested.

    ./test/serve.py [--port 8765]
"""

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SAMPLE_VV = """[virt-viewer]
type=spice
host=127.0.0.1
port=5900
title=ryll Chrome handler test
delete-this-file=1
"""

PAGE = """<!doctype html>
<html lang="en">
<meta charset="utf-8">
<title>ryll .vv handler test</title>
<h1>ryll .vv handler test</h1>
<p>Clicking this link downloads a .vv file.  The Chrome extension should
launch <code>ryll --file &lt;downloaded path&gt;</code> as soon as the
download completes.</p>
<p><a href="/console.vv">Download console.vv</a></p>
<p>The file points at <code>127.0.0.1:5900</code>, so ryll will report that
it cannot connect.  That is expected.</p>
</html>
"""


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.split("?", 1)[0] == "/console.vv":
            self.send_bytes(
                SAMPLE_VV.encode("utf-8"),
                "application/octet-stream",
                'attachment; filename="console.vv"',
            )
        elif self.path in ("/", "/index.html"):
            self.send_bytes(PAGE.encode("utf-8"), "text/html; charset=utf-8")
        else:
            self.send_error(404)

    def do_HEAD(self):
        if self.path.split("?", 1)[0] == "/console.vv":
            self.send_bytes(b"", "application/octet-stream", None, head=True)
        else:
            self.send_bytes(b"", "text/html; charset=utf-8", head=True)

    def send_bytes(self, body, content_type, disposition=None, head=False):
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if disposition:
            self.send_header("Content-Disposition", disposition)
        self.end_headers()
        if not head:
            self.wfile.write(body)

    def log_message(self, fmt, *args):
        print(f"{self.address_string()} {fmt % args}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--bind", default="127.0.0.1")
    args = parser.parse_args()

    server = ThreadingHTTPServer((args.bind, args.port), Handler)
    print(f"Serving on http://{args.bind}:{args.port}/ -- open that in Chrome.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
